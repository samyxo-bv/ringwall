// SPDX-License-Identifier: Apache-2.0
package patcher

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/samyxo-bv/ringwall/internal/scanner"
)

const (
	maxABImageBytes  = 2 << 30 // 2 GiB safety cap
	defaultBootTries = 2
)

// GenerateABKeypair creates a new Ed25519 keypair (base64-encoded) for signing immutable A/B release manifests.
func GenerateABKeypair() (pubB64, privB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// canonicalManifestPayload builds the exact deterministic byte string signed by Ed25519.
func canonicalManifestPayload(m ABManifest) []byte {
	cves := append([]string(nil), m.CVEsFixed...)
	sort.Strings(cves)
	obj := struct {
		Version     string   `json:"version"`
		MinVersion  string   `json:"min_version,omitempty"`
		ReleaseURL  string   `json:"release_url"`
		ImageSHA256 string   `json:"image_sha256"`
		ImageSize   int64    `json:"image_size"`
		CVEsFixed   []string `json:"cves_fixed,omitempty"`
		PublishedAt string   `json:"published_at"`
	}{
		Version:     strings.TrimSpace(m.Version),
		MinVersion:  strings.TrimSpace(m.MinVersion),
		ReleaseURL:  strings.TrimSpace(m.ReleaseURL),
		ImageSHA256: strings.ToLower(strings.TrimSpace(m.ImageSHA256)),
		ImageSize:   m.ImageSize,
		CVEsFixed:   cves,
		PublishedAt: strings.TrimSpace(m.PublishedAt),
	}
	b, _ := json.Marshal(obj)
	return b
}

// SignManifest computes the Ed25519 signature over canonicalManifestPayload and stores it on m.
func SignManifest(privB64 string, m *ABManifest) error {
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key")
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), canonicalManifestPayload(*m))
	m.SignatureEd25519B64 = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyManifest validates the Ed25519 signature, HTTPS URL, SHA-256 format, MinVersion floor,
// and anti-downgrade monotonicity.
func VerifyManifest(pubB64, currentVersion string, m ABManifest) error {
	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid trusted ed25519 public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m.SignatureEd25519B64))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("missing or malformed ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonicalManifestPayload(m), sigBytes) {
		return errors.New("ed25519 signature verification FAILED (manifest tampered or untrusted key)")
	}
	if strings.TrimSpace(m.Version) == "" {
		return errors.New("manifest version is empty")
	}
	if len(m.ImageSHA256) != 64 {
		return errors.New("manifest image_sha256 must be 64 hex chars")
	}
	if _, err := hex.DecodeString(m.ImageSHA256); err != nil {
		return fmt.Errorf("manifest image_sha256 invalid hex: %w", err)
	}
	if m.ImageSize <= 0 || m.ImageSize > maxABImageBytes {
		return fmt.Errorf("manifest image_size %d out of allowed bounds", m.ImageSize)
	}
	if err := validateABURL(m.ReleaseURL); err != nil {
		return err
	}

	cur := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	nxt := strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	if cur != "" {
		if scanner.CompareVersions(nxt, cur) < 0 {
			return fmt.Errorf("anti-downgrade rejected: manifest %s < current %s", m.Version, currentVersion)
		}
		if minV := strings.TrimPrefix(strings.TrimSpace(m.MinVersion), "v"); minV != "" {
			if scanner.CompareVersions(cur, minV) < 0 {
				return fmt.Errorf("upgrade floor rejected: current %s < manifest min_version %s", currentVersion, m.MinVersion)
			}
		}
	}
	return nil
}

// ReadBootedSlotFromCmdline parses `ringwall.slot=A` or `ringwall.slot=B` from /proc/cmdline.
// Returns "" if the kernel cmdline does not declare a Ringwall A/B slot.
func ReadBootedSlotFromCmdline(cmdlinePath string) string {
	if cmdlinePath == "" {
		cmdlinePath = "/proc/cmdline"
	}
	b, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return ""
	}
	for _, tok := range strings.Fields(string(b)) {
		if strings.HasPrefix(tok, "ringwall.slot=") {
			val := strings.ToUpper(strings.TrimPrefix(tok, "ringwall.slot="))
			if val == "A" || val == "B" {
				return val
			}
		}
	}
	return ""
}

// ABUpdater manages verified A/B immutable slot staging, boot-env switching, and automatic rollback.
// Security invariant (P1-5): ConfirmBootHealth ONLY promotes or rolls back PendingSlot when the
// actually booted kernel slot (ringwall.slot=...) matches PendingSlot — a daemon restart without
// rebooting into the new slot NEVER falsely promotes an unbooted image.
type ABUpdater struct {
	Enabled        bool
	StatePath      string
	BootEnvPath    string
	SlotAPath      string
	SlotBPath      string
	TrustedPubKey  string
	CurrentVersion string
	BootedSlotFunc func() string
	HTTPClient     *http.Client
}

func (u *ABUpdater) bootedSlot() string {
	if u.BootedSlotFunc != nil {
		return strings.ToUpper(strings.TrimSpace(u.BootedSlotFunc()))
	}
	return ReadBootedSlotFromCmdline("/proc/cmdline")
}

func (u *ABUpdater) LoadState() ABSlotState {
	st := ABSlotState{
		ActiveSlot:        "A",
		LastKnownGoodSlot: "A",
		CurrentVersion:    u.CurrentVersion,
		HealthConfirmed:   true,
	}
	if bSlot := u.bootedSlot(); bSlot == "A" || bSlot == "B" {
		st.ActiveSlot = bSlot
		st.LastKnownGoodSlot = bSlot
	}
	if u.StatePath == "" {
		return st
	}
	b, err := os.ReadFile(u.StatePath)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	if st.ActiveSlot != "A" && st.ActiveSlot != "B" {
		st.ActiveSlot = "A"
	}
	if st.LastKnownGoodSlot != "A" && st.LastKnownGoodSlot != "B" {
		st.LastKnownGoodSlot = st.ActiveSlot
	}
	return st
}

func atomicWriteFileFsync(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	_ = f.Chmod(perm)
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func (u *ABUpdater) saveState(st ABSlotState) error {
	if u.StatePath == "" {
		return nil
	}
	st.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFileFsync(u.StatePath, append(b, '\n'), 0o600)
}

func (u *ABUpdater) writeBootEnv(nextSlot string, tries int) error {
	if u.BootEnvPath == "" {
		return nil
	}
	content := fmt.Sprintf("RINGWALL_BOOT_SLOT=%s\nRINGWALL_BOOT_TRIES=%d\n", nextSlot, tries)
	return atomicWriteFileFsync(u.BootEnvPath, []byte(content), 0o600)
}

// StageUpdate verifies the signed manifest, downloads & SHA-256 verifies the image into the inactive slot,
// and arms the boot-counter so the next reboot tests the new slot with automatic rollback protection.
func (u *ABUpdater) StageUpdate(ctx context.Context, m ABManifest) (ABSlotState, error) {
	st := u.LoadState()
	if !u.Enabled {
		return st, errors.New("A/B immutable updates are disabled in config (patcher.ab_update.enabled: false)")
	}
	curVer := st.CurrentVersion
	if curVer == "" {
		curVer = u.CurrentVersion
	}
	if err := VerifyManifest(u.TrustedPubKey, curVer, m); err != nil {
		return st, err
	}

	targetSlot := "B"
	targetPath := u.SlotBPath
	if st.ActiveSlot == "B" {
		targetSlot = "A"
		targetPath = u.SlotAPath
	}
	if targetPath == "" {
		return st, errors.New("inactive A/B slot path not configured")
	}

	var baseTransport http.RoundTripper
	timeout := 5 * time.Minute
	if u.HTTPClient != nil {
		baseTransport = u.HTTPClient.Transport
		if u.HTTPClient.Timeout > 0 {
			timeout = u.HTTPClient.Timeout
		}
	}
	client := &http.Client{
		Transport: baseTransport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return validateABURL(req.URL.String())
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.ReleaseURL, nil)
	if err != nil {
		return st, err
	}
	req.Header.Set("User-Agent", "Ringwall-ABUpdater/0.2")
	resp, err := client.Do(req)
	if err != nil {
		return st, fmt.Errorf("download image: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("download image HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
		return st, err
	}
	// Reject symlink target paths before staging.
	if linfo, err := os.Lstat(targetPath); err == nil && linfo.Mode()&os.ModeSymlink != 0 {
		return st, fmt.Errorf("refusing to write A/B image to symlink %q", targetPath)
	}

	tmpPath := targetPath + ".staging"
	_ = os.Remove(tmpPath)
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return st, err
	}

	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, m.ImageSize+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return st, fmt.Errorf("stream image: %w", copyErr)
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return st, syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return st, closeErr
	}
	if written != m.ImageSize {
		_ = os.Remove(tmpPath)
		return st, fmt.Errorf("image size mismatch: got %d, manifest expects %d", written, m.ImageSize)
	}
	gotHash := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHash, m.ImageSHA256) {
		_ = os.Remove(tmpPath)
		return st, fmt.Errorf("image SHA-256 mismatch: got %s, manifest expects %s", gotHash, m.ImageSHA256)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return st, err
	}

	st.PendingSlot = targetSlot
	st.PendingVersion = m.Version
	st.TriesRemaining = defaultBootTries
	st.HealthConfirmed = false
	st.RolledBackFrom = ""
	if err := u.writeBootEnv(targetSlot, defaultBootTries); err != nil {
		return st, err
	}
	if err := u.saveState(st); err != nil {
		return st, err
	}
	return st, nil
}

// ConfirmBootHealth runs on startup ONLY when the kernel actually booted into PendingSlot
// (verified via ringwall.slot=... from /proc/cmdline). A plain daemon restart while still
// booted in the old slot is a safe no-op and never promotes or disarms rollback (P1-5).
func (u *ABUpdater) ConfirmBootHealth(healthOK bool) (ABSlotState, bool, error) {
	st := u.LoadState()
	if !u.Enabled || st.PendingSlot == "" {
		return st, false, nil
	}
	booted := u.bootedSlot()
	if booted == "" || booted != st.PendingSlot {
		// Still running in the previous slot (e.g. systemctl restart before reboot): do NOT promote!
		return st, false, nil
	}

	if healthOK {
		st.ActiveSlot = st.PendingSlot
		st.LastKnownGoodSlot = st.PendingSlot
		if st.PendingVersion != "" {
			st.CurrentVersion = st.PendingVersion
		}
		st.PendingSlot = ""
		st.PendingVersion = ""
		st.TriesRemaining = 0
		st.HealthConfirmed = true
		if err := u.writeBootEnv(st.ActiveSlot, 0); err != nil {
			return st, false, err
		}
		return st, false, u.saveState(st)
	}

	if st.TriesRemaining > 0 {
		st.TriesRemaining--
	}
	rolledBack := false
	if st.TriesRemaining <= 0 {
		st.RolledBackFrom = st.PendingVersion
		st.PendingSlot = ""
		st.PendingVersion = ""
		st.ActiveSlot = st.LastKnownGoodSlot
		st.HealthConfirmed = true
		rolledBack = true
		if err := u.writeBootEnv(st.LastKnownGoodSlot, 0); err != nil {
			return st, true, err
		}
	} else {
		if err := u.writeBootEnv(st.PendingSlot, st.TriesRemaining); err != nil {
			return st, false, err
		}
	}
	return st, rolledBack, u.saveState(st)
}

func validateABURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid release_url %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (h == "127.0.0.1" || h == "localhost" || h == "::1") {
		return nil
	}
	return fmt.Errorf("release_url %q must use https", raw)
}
