// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/samyxo-bv/ringwall/internal/api"
	"github.com/samyxo-bv/ringwall/internal/audit"
	"github.com/samyxo-bv/ringwall/internal/config"
	"github.com/samyxo-bv/ringwall/internal/daemon"
	"github.com/samyxo-bv/ringwall/internal/enforcer"
	"github.com/samyxo-bv/ringwall/internal/guardian"
	"github.com/samyxo-bv/ringwall/internal/lineage"
	"github.com/samyxo-bv/ringwall/internal/policy"
	"github.com/samyxo-bv/ringwall/internal/sensor"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/ringwall/ringwall.yaml", "path to YAML configuration file")
	policyDir := flag.String("policy-dir", "", "override policy directory")
	modeFlag := flag.String("mode", "", "override mode (audit|interactive|strict)")
	sensorFlag := flag.String("sensor", "", "override sensor mode (auto|ebpf|procfs|none)")
	listenFlag := flag.String("listen", "", "override API listen address")
	flag.Parse()

	var cfg *config.Config
	var err error
	if _, statErr := os.Stat(*cfgPath); statErr == nil {
		cfg, err = config.Load(*cfgPath)
		if err != nil {
			log.Fatalf("ringwalld: %v", err)
		}
	} else {
		cfg = config.Default()
	}

	if *policyDir != "" {
		cfg.PolicyDirs = []string{*policyDir}
	}
	if *modeFlag != "" {
		cfg.Mode = config.Mode(*modeFlag)
	}
	if *sensorFlag != "" {
		cfg.Sensor.Mode = *sensorFlag
	}
	if *listenFlag != "" {
		cfg.API.ListenAddr = *listenFlag
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("ringwalld: invalid config: %v", err)
	}

	pol, err := policy.LoadDirs(cfg.PolicyDirs)
	if err != nil {
		log.Fatalf("ringwalld: load policies: %v", err)
	}
	if pol.Count() == 0 {
		log.Printf("ringwalld: warning: 0 policy rules loaded from %v", cfg.PolicyDirs)
	}

	alog, err := audit.Open(cfg.AuditLogPath)
	if err != nil {
		log.Fatalf("ringwalld: open audit log: %v", err)
	}

	sens, err := sensor.New(cfg.Sensor)
	if err != nil {
		log.Fatalf("ringwalld: init sensor: %v", err)
	}

	lin := lineage.NewTracker(nil)
	enf := enforcer.New(cfg.Mode, cfg.Enforcer, nil, nil)
	guard := guardian.New(cfg.AI, nil)

	d := daemon.New(version, cfg, sens, lin, pol, enf, guard, alog)
	d.SetStoragePaths(*cfgPath, filepath.Join(filepath.Dir(*cfgPath), "keys"))
	if _, err := os.Stat("/run"); err == nil {
		_ = os.MkdirAll("/run/ringwall-status", 0o755)
		_ = os.Chmod("/run/ringwall-status", 0o755)
		d.SetPublicStatusPath("/run/ringwall-status/status.json")
	}

	srv, err := api.NewServer(d, cfg.API)
	if err != nil {
		log.Fatalf("ringwalld: init api server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("ringwalld %s starting (mode=%s sensor=%s policies=%d api=%s ai=%s)",
		version, cfg.Mode, sens.Mode(), pol.Count(), cfg.API.ListenAddr, cfg.AI.Strategy)

	go func() {
		if err := srv.Start(ctx); err != nil {
			log.Printf("ringwalld: api server error: %v", err)
			stop()
		}
	}()

	if err := d.Run(ctx); err != nil {
		log.Fatalf("ringwalld: runtime error: %v", err)
	}
	log.Printf("ringwalld stopped cleanly")
}
