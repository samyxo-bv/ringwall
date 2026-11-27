// SPDX-License-Identifier: Apache-2.0
// Ringwall Linux eBPF LSM + tracing + tracepoint sensor (v0.2).
// Tier 1 (kernels with BPF LSM active, e.g. Ringwall ISO):
//   - lsm/file_open: FAIL-CLOSED synchronous -EPERM pre-read kernel blocking on SSH private keys &
//     pinned secret inodes (computed BEFORE ringbuf reserve so ringbuf floods NEVER fail open).
//   - lsm/mmap_file + BPF_MAP_TYPE_TASK_STORAGE: taints allowlisted ssh/ssh-keygen processes that
//     map non-root-owned or world-writable PROT_EXEC objects (defeats LD_PRELOAD / PKCS11Provider).
//   - lsm/ptrace_access_check: blocks non-root ptrace into allowlisted ssh processes.
//   - lsm/bprm_check_security: synchronous -EPERM execution blocking for zero-day virtual-patched binaries.
// Tier 2 (BTF kernels without lsm=...,bpf): fentry/security_file_open + bpf_d_path.
// Tier 3 (older kernels): hardened syscall open tracepoints.
// Always traces: execve/execveat, rename/renameat/renameat2, link/linkat/symlink/symlinkat, connect/sendto, io_uring_setup.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef BPF_LOCAL_STORAGE_GET_F_CREATE
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#endif

#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

// Minimal CO-RE kernel VFS/task structs.
// Placing f_flags before f_path ensures f_path has a non-zero stub offset so Clang always emits
// a CO-RE BPF_FIELD_BYTE_OFFSET relocation for bpf_d_path(&file->f_path, ...).
struct vfsmount;
struct dentry;

typedef struct {
    __u32 val;
} __attribute__((preserve_access_index)) kuid_t;

struct super_block {
    __u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
    __u16 i_mode;
    kuid_t i_uid;
    unsigned long i_ino;
    struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    unsigned int f_flags;
    struct path f_path;
    struct inode *f_inode;
} __attribute__((preserve_access_index));

struct mm_struct {
    struct file *exe_file;
} __attribute__((preserve_access_index));

struct task_struct {
    struct mm_struct *mm;
} __attribute__((preserve_access_index));

struct linux_binprm {
    struct file *file;
} __attribute__((preserve_access_index));

#define EVENT_EXEC          1
#define EVENT_OPENAT        2
#define EVENT_CONNECT       3
#define EVENT_SENDTO        4
#define EVENT_IO_URING      5
#define EVENT_OPEN_RESOLVED 6
#define EVENT_OPEN_BLOCKED  7
#define EVENT_LINK_DEST     8
#define EVENT_EXEC_BLOCKED  9

#define AF_INET  2
#define AF_INET6 10

#define AT_FDCWD (-100)

#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0040
#define O_TRUNC  0x0200
#define WRITE_FLAGS (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)

#define PATH_MAX_LEN 256
#define COMM_MAX_LEN 16
#define ARG_MAX_LEN  128
#define MAX_ARGS     8

// Fixed, padding-free 1344-byte event layout shared byte-for-byte with Go userspace.
struct ringwall_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 flags;
    __s32 dirfd;
    __u16 dport;
    __u16 family;
    __u32 _pad;
    __u8  addr[16];
    char  comm[COMM_MAX_LEN];
    char  path[PATH_MAX_LEN];
    char  argv[MAX_ARGS][ARG_MAX_LEN];
};

// Kernel (s_dev, i_ino) identifier immune to hardlinks, symlinks, renames, and comm spoofing.
struct file_key {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};

struct path_buf {
    char data[PATH_MAX_LEN];
};

// Kernel sys_enter tracepoint ABI layout on 64-bit Linux.
struct sys_enter_ctx {
    __u64 common;
    long  syscall_nr;
    unsigned long args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 << 20); // 4 MiB ring buffer
} events SEC(".maps");

// Per-CPU 256-byte scratch buffer so lsm/file_open resolves paths and decides should_block
// BEFORE attempting bpf_ringbuf_reserve (guarantees fail-closed -EPERM even under ringbuf floods).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_buf);
} path_scratch_map SEC(".maps");

// Index 0: ringwalld's own PID (never self-triggers or self-blocks).
// Index 1: enforce_lsm (0 = monitor/audit only, 1 = synchronous -EPERM kernel blocking active).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

// Index 0 counts ringbuf reserve drops per CPU (eliminates silent fail-open under floods).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Kernel-verified (s_dev, i_ino) of legitimate SSH binaries allowed to read SSH private keys.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct file_key);
    __type(value, __u32);
} allowed_ssh_exe_inodes SEC(".maps");

// Per-task taint flag set by lsm/mmap_file when an allowlisted SSH binary loads a non-root or
// world-writable PROT_EXEC object (defeats LD_PRELOAD & PKCS11Provider hijacks).
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u32);
} task_taint_map SEC(".maps");

// Pinned secret file inodes (defeats hardlink & source-rename bypasses synchronously in lsm/file_open).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct file_key);
    __type(value, __u32);
} lsm_deny_file_inodes SEC(".maps");

// Dynamically updated virtual-patch blocked executables (synchronous -EPERM in lsm/bprm_check_security).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct file_key);
    __type(value, __u32);
} lsm_deny_exec_inodes SEC(".maps");

static __always_inline void record_drop(void) {
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &key);
    if (cnt) {
        (*cnt)++;
    }
}

static __always_inline void init_event(struct ringwall_event *e) {
    __builtin_memset(e, 0, 64);
    e->path[0] = '\0';
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        e->argv[i][0] = '\0';
    }
}

static __always_inline void copy_path_256(char *dst, const char *src) {
    __u64 *d = (__u64 *)dst;
    const __u64 *s = (const __u64 *)src;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < PATH_MAX_LEN / 8; i++) {
        d[i] = s[i];
    }
}

static __always_inline int is_self_pid(__u32 pid) {
    __u32 key = 0;
    __u32 *self = bpf_map_lookup_elem(&config_map, &key);
    if (self && *self != 0 && *self == pid) {
        return 1;
    }
    return 0;
}

static __always_inline int is_lsm_enforce_enabled(void) {
    __u32 key = 1;
    __u32 *val = bpf_map_lookup_elem(&config_map, &key);
    return (val && *val != 0) ? 1 : 0;
}

static __always_inline int get_file_key(struct file *file, struct file_key *out) {
    if (!file || !out) {
        return 0;
    }
    struct inode *ino_p = 0;
    bpf_probe_read_kernel(&ino_p, sizeof(ino_p), __builtin_preserve_access_index(&file->f_inode));
    if (!ino_p) {
        return 0;
    }
    unsigned long ino = 0;
    bpf_probe_read_kernel(&ino, sizeof(ino), __builtin_preserve_access_index(&ino_p->i_ino));
    if (ino == 0) {
        return 0;
    }
    struct super_block *sb = 0;
    bpf_probe_read_kernel(&sb, sizeof(sb), __builtin_preserve_access_index(&ino_p->i_sb));
    __u32 dev = 0;
    if (sb) {
        bpf_probe_read_kernel(&dev, sizeof(dev), __builtin_preserve_access_index(&sb->s_dev));
    }
    out->ino = (__u64)ino;
    out->dev = dev;
    out->_pad = 0;
    return 1;
}

static __always_inline int is_task_exe_allowlisted(struct task_struct *task) {
    if (!task) {
        return 0;
    }
    struct mm_struct *mm = 0;
    bpf_probe_read_kernel(&mm, sizeof(mm), __builtin_preserve_access_index(&task->mm));
    if (!mm) {
        return 0;
    }
    struct file *exe = 0;
    bpf_probe_read_kernel(&exe, sizeof(exe), __builtin_preserve_access_index(&mm->exe_file));
    if (!exe) {
        return 0;
    }
    struct file_key ek = {};
    if (!get_file_key(exe, &ek)) {
        return 0;
    }
    return bpf_map_lookup_elem(&allowed_ssh_exe_inodes, &ek) != 0 ? 1 : 0;
}

static __always_inline int is_allowed_ssh_exe(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!is_task_exe_allowlisted(task)) {
        return 0;
    }
    // Revoke exemption if process mapped any non-root or world-writable PROT_EXEC library (LD_PRELOAD / PKCS11).
    __u32 *taint = bpf_task_storage_get(&task_taint_map, task, 0, 0);
    if (taint && *taint != 0) {
        return 0;
    }
    return 1;
}

static __always_inline int starts_with_4(const char *s, char a, char b, char c, char d) {
    return s[0] == a && s[1] == b && s[2] == c && s[3] == d;
}

static __always_inline int starts_with_5(const char *s, char a, char b, char c, char d, char e) {
    return s[0] == a && s[1] == b && s[2] == c && s[3] == d && s[4] == e;
}

// Single bounded scan matching **/.ssh/id_* (excluding *.pub), **/.ssh/*.pem, and **/.ssh/*.key.
static __always_inline int is_ssh_private_key_path(const char *p) {
    int in_ssh = 0;
    int matched = 0;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < PATH_MAX_LEN - 10; i++) {
        char c = p[i];
        if (c == '\0') {
            break;
        }
        if (c == '/' && p[i + 1] == '.' && p[i + 2] == 's' && p[i + 3] == 's' && p[i + 4] == 'h' && p[i + 5] == '/') {
            in_ssh = 1;
            if (p[i + 6] == 'i' && p[i + 7] == 'd' && p[i + 8] == '_') {
                matched = 1;
            }
        }
        if (in_ssh && c == '.' && p[i + 4] == '\0') {
            if (p[i + 1] == 'p' && p[i + 2] == 'u' && p[i + 3] == 'b') {
                return 0;
            }
            if ((p[i + 1] == 'p' && p[i + 2] == 'e' && p[i + 3] == 'm') ||
                (p[i + 1] == 'k' && p[i + 2] == 'e' && p[i + 3] == 'y')) {
                matched = 1;
            }
        }
    }
    return matched;
}

static __always_inline int is_sensitive_etc_read(const char *p) {
    if (p[5] == 's' && (p[6] == 'h' || p[6] == 's' || p[6] == 'u')) {
        return 1; // shadow, ssh, sudoers
    }
    if (p[5] == 'g' && p[6] == 's') {
        return 1; // gshadow
    }
    if (p[5] == 'r' && p[6] == 'i') {
        return 1; // ringwall
    }
    if (p[5] == 'c' && p[6] == 'r') {
        return 1; // cron
    }
    if (p[5] == '.' || p[5] == '/') {
        return 1; // traversal normalization
    }
    return 0;
}

// Fast filter for kernel-resolved VFS paths returned by bpf_d_path (already canonical, no symlinks, no ..).
static __always_inline int is_interesting_resolved_path(const char *p, __u32 flags) {
    if (p[0] != '/') {
        return 0; // discard pseudo-files: pipe:[...], socket:[...], anon_inode:[...]
    }
    if (starts_with_5(p, '/', 'h', 'o', 'm', 'e') ||
        starts_with_5(p, '/', 'r', 'o', 'o', 't')) {
        return 1;
    }
    if (starts_with_5(p, '/', 'e', 't', 'c', '/')) {
        if (flags & WRITE_FLAGS) {
            return 1;
        }
        return is_sensitive_etc_read(p);
    }
    if (flags & WRITE_FLAGS) {
        if (starts_with_5(p, '/', 'v', 'a', 'r', '/') ||
            starts_with_5(p, '/', 'u', 's', 'r', '/') ||
            starts_with_5(p, '/', 'b', 'o', 'o', 't') ||
            starts_with_4(p, '/', 'l', 'i', 'b') ||
            starts_with_5(p, '/', 'r', 'u', 'n', '/')) {
            return 1;
        }
    }
    if (starts_with_5(p, '/', 'r', 'u', 'n', '/') && p[5] == 'r' && p[6] == 'i') {
        return 1; // /run/ringwall
    }
    // Catch any dot-directory component anywhere in the resolved path (/.ssh, /.aws, /.kube,
    // /.gnupg, /.docker, /.config) — including inside chroot, userns, bind-mounts, or custom homes.
    #pragma clang loop unroll(disable)
    for (int i = 0; i < PATH_MAX_LEN - 1; i++) {
        char c = p[i];
        if (c == '\0') {
            break;
        }
        if (c == '/' && p[i + 1] == '.') {
            return 1;
        }
    }
    return 0;
}

static __always_inline int is_proc_bypass_path(const char *p) {
    if (p[6] == '/' || p[6] == '.') {
        return 1;
    }
    #pragma unroll
    for (int i = 6; i < 20; i++) {
        if (p[i] == '/') {
            if (p[i + 1] == 'r' && p[i + 2] == 'o' && p[i + 3] == 'o' && p[i + 4] == 't') {
                return 1;
            }
            if (p[i + 1] == 'c' && p[i + 2] == 'w' && p[i + 3] == 'd') {
                return 1;
            }
            if (p[i + 1] == 'f' && p[i + 2] == 'd' && (p[i + 3] == '/' || p[i + 3] == '\0')) {
                return 1;
            }
            if (p[i + 1] == '/' || p[i + 1] == '.') {
                return 1;
            }
        }
    }
    return 0;
}

// Raw syscall path filter (used by rename*/link*/symlink* tracepoints and non-fentry kernel fallback).
static __always_inline int is_interesting_path(const char *p, __u32 flags, long read_len) {
    if (p[0] == '\0') {
        return 0;
    }
    if (read_len >= PATH_MAX_LEN) {
        return 1;
    }
    if (p[0] != '/') {
        return 1;
    }
    #pragma clang loop unroll(disable)
    for (int i = 0; i < PATH_MAX_LEN - 1; i++) {
        char c = p[i];
        if (c == '\0') {
            break;
        }
        if (c == '/' && (p[i + 1] == '.' || p[i + 1] == '/')) {
            return 1;
        }
    }
    if (starts_with_5(p, '/', 'h', 'o', 'm', 'e') ||
        starts_with_5(p, '/', 'r', 'o', 'o', 't') ||
        starts_with_5(p, '/', 't', 'm', 'p', '/')) {
        return 1;
    }
    if (starts_with_5(p, '/', 'v', 'a', 'r', '/') &&
        p[5] == 't' && p[6] == 'm' && p[7] == 'p' && p[8] == '/') {
        return 1;
    }
    if (starts_with_5(p, '/', 'd', 'e', 'v', '/')) {
        if ((p[5] == 's' && p[6] == 'h' && p[7] == 'm' && p[8] == '/') ||
            (p[5] == 'f' && p[6] == 'd' && p[7] == '/')) {
            return 1;
        }
    }
    if (starts_with_5(p, '/', 'r', 'u', 'n', '/')) {
        if ((p[5] == 'u' && p[6] == 's' && p[7] == 'e' && p[8] == 'r' && p[9] == '/') ||
            (p[5] == 'l' && p[6] == 'o' && p[7] == 'c' && p[8] == 'k' && p[9] == '/') ||
            (p[5] == 'r' && p[6] == 'i')) {
            return 1;
        }
    }
    if (starts_with_5(p, '/', 'e', 't', 'c', '/')) {
        if (flags & WRITE_FLAGS) {
            return 1;
        }
        return is_sensitive_etc_read(p);
    }
    if (starts_with_5(p, '/', 'p', 'r', 'o', 'c') && p[5] == '/') {
        return is_proc_bypass_path(p);
    }
    if (flags & WRITE_FLAGS) {
        if (starts_with_5(p, '/', 'v', 'a', 'r', '/') ||
            starts_with_5(p, '/', 'u', 's', 'r', '/') ||
            starts_with_5(p, '/', 'b', 'o', 'o', 't') ||
            starts_with_4(p, '/', 'l', 'i', 'b') ||
            starts_with_5(p, '/', 'r', 'u', 'n', '/')) {
            return 1;
        }
    }
    return 0;
}

static __always_inline void read_exec_argv(struct ringwall_event *e, const char *const *argv) {
    if (!argv) {
        return;
    }
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0 || !argp) {
            break;
        }
        bpf_probe_read_user_str(e->argv[i], ARG_MAX_LEN, argp);
    }
}

static __always_inline int emit_exec(__s32 dirfd, const void *filename, const void *argv_ptr) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    init_event(e);
    e->type = EVENT_EXEC;
    e->pid = pid;
    e->dirfd = dirfd;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (filename) {
        bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
    }
    read_exec_argv(e, (const char *const *)argv_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int emit_open_typed(__u32 ev_type, __s32 dirfd, const void *filename, __u32 flags) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    init_event(e);
    e->flags = flags;
    e->dirfd = dirfd;
    long n = bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
    if (n <= 1 || !is_interesting_path(e->path, flags, n)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    e->type = ev_type;
    e->pid = pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int emit_sockaddr(__u32 ev_type, const void *user_addr, long addrlen) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }
    if (!user_addr || addrlen < 16) {
        return 0;
    }

    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), user_addr) != 0) {
        return 0;
    }
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    unsigned char sa[24] = {};
    if (family == AF_INET) {
        if (bpf_probe_read_user(sa, 16, user_addr) != 0) {
            return 0;
        }
    } else {
        if (addrlen < 24 || bpf_probe_read_user(sa, 24, user_addr) != 0) {
            return 0;
        }
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    init_event(e);
    e->type = ev_type;
    e->pid = pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->family = family;
    e->dport = bpf_ntohs(*(__u16 *)(sa + 2));

    if (family == AF_INET) {
        __builtin_memcpy(e->addr, sa + 4, 4);
    } else {
        __builtin_memcpy(e->addr, sa + 8, 16);
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tier 1: Synchronous eBPF LSM file_open hook (pre-read -EPERM kernel enforcement + bpf_d_path).
// Evaluates should_block in a per-CPU scratch buffer BEFORE reserving ringbuf space so even a
// deliberate ringbuf flood NEVER fails open (P1-1) and ordinary opens avoid ringbuf churn (P2).
SEC("lsm/file_open")
int trace_lsm_file_open(__u64 *ctx) {
    struct file *file = (struct file *)ctx[0];
    int ret = (int)ctx[1];
    if (ret != 0 || !file) {
        return ret;
    }
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    __u32 zero = 0;
    struct path_buf *pb = bpf_map_lookup_elem(&path_scratch_map, &zero);
    if (!pb) {
        return 0;
    }
    pb->data[0] = '\0';

    __u32 flags = file->f_flags;
    long n = bpf_d_path(__builtin_preserve_access_index(&file->f_path), pb->data, PATH_MAX_LEN);
    int path_ok = (n > 1 && pb->data[0] == '/');

    int should_block = 0;
    if (is_lsm_enforce_enabled()) {
        struct file_key fk = {};
        if (get_file_key(file, &fk) && bpf_map_lookup_elem(&lsm_deny_file_inodes, &fk)) {
            if (!is_allowed_ssh_exe()) {
                should_block = 1;
            }
        } else if (path_ok && is_ssh_private_key_path(pb->data)) {
            if (!is_allowed_ssh_exe()) {
                should_block = 1;
            }
        }
    }

    if (!should_block && (!path_ok || !is_interesting_resolved_path(pb->data, flags))) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        // FAIL-CLOSED: even under ringbuf saturation, synchronous -EPERM STILL enforces!
        return should_block ? -1 : 0;
    }

    init_event(e);
    e->type = should_block ? EVENT_OPEN_BLOCKED : EVENT_OPEN_RESOLVED;
    e->pid = pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->flags = flags;
    e->dirfd = AT_FDCWD;
    if (path_ok) {
        copy_path_256(e->path, pb->data);
    }
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    return should_block ? -1 : 0;
}

// Tier 1: Taint allowlisted SSH binaries that mmap non-root or world-writable PROT_EXEC objects
// (defeats LD_PRELOAD=~/x.so ssh-keygen and ssh -o PKCS11Provider=~/x.so hijacks).
SEC("lsm/mmap_file")
int trace_lsm_mmap_file(__u64 *ctx) {
    struct file *file = (struct file *)ctx[0];
    unsigned long reqprot = (unsigned long)ctx[1];
    unsigned long prot = (unsigned long)ctx[2];
    int ret = (int)ctx[4];
    if (ret != 0 || !file || !((reqprot | prot) & PROT_EXEC)) {
        return ret;
    }
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!is_task_exe_allowlisted(task)) {
        return 0;
    }
    struct inode *ino_p = 0;
    bpf_probe_read_kernel(&ino_p, sizeof(ino_p), __builtin_preserve_access_index(&file->f_inode));
    if (!ino_p) {
        return 0;
    }
    __u32 owner_uid = 0;
    __u16 mode = 0;
    bpf_probe_read_kernel(&owner_uid, sizeof(owner_uid), __builtin_preserve_access_index(&ino_p->i_uid.val));
    bpf_probe_read_kernel(&mode, sizeof(mode), __builtin_preserve_access_index(&ino_p->i_mode));
    if (owner_uid != 0 || (mode & 0002)) {
        __u32 one = 1;
        __u32 *slot = bpf_task_storage_get(&task_taint_map, task, &one, BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (slot) {
            *slot = 1;
        }
    }
    return 0;
}

// Tier 1: Prevent non-root ptrace injection into allowlisted SSH binaries (even when yama.ptrace_scope <= 1).
SEC("lsm/ptrace_access_check")
int trace_lsm_ptrace_access_check(__u64 *ctx) {
    struct task_struct *child = (struct task_struct *)ctx[0];
    int ret = (int)ctx[2];
    if (ret != 0 || !child || !is_lsm_enforce_enabled()) {
        return ret;
    }
    if ((__u32)bpf_get_current_uid_gid() == 0) {
        return 0;
    }
    if (is_task_exe_allowlisted(child)) {
        return -1; // -EPERM
    }
    return 0;
}

// Tier 1: Synchronous eBPF LSM bprm_check_security hook (blocks virtual-patched vulnerable binaries before execve).
SEC("lsm/bprm_check_security")
int trace_lsm_bprm_check(__u64 *ctx) {
    struct linux_binprm *bprm = (struct linux_binprm *)ctx[0];
    int ret = (int)ctx[1];
    if (ret != 0 || !bprm || !is_lsm_enforce_enabled()) {
        return ret;
    }
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }
    struct file *file = 0;
    bpf_probe_read_kernel(&file, sizeof(file), __builtin_preserve_access_index(&bprm->file));
    if (!file) {
        return 0;
    }
    struct file_key fk = {};
    if (!get_file_key(file, &fk)) {
        return 0;
    }
    if (!bpf_map_lookup_elem(&lsm_deny_exec_inodes, &fk)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        init_event(e);
        e->type = EVENT_EXEC_BLOCKED;
        e->pid = pid;
        e->uid = (__u32)bpf_get_current_uid_gid();
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    } else {
        record_drop();
    }
    return -1; // -EPERM: zero-day virtual-patched binary blocked pre-execution
}

// Tier 2: Kernel-resolved file open hook on BTF kernels without lsm=...,bpf.
SEC("fentry/security_file_open")
int trace_security_file_open(__u64 *ctx) {
    struct file *file = (struct file *)ctx[0];
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid) || !file) {
        return 0;
    }

    __u32 zero = 0;
    struct path_buf *pb = bpf_map_lookup_elem(&path_scratch_map, &zero);
    if (!pb) {
        return 0;
    }
    pb->data[0] = '\0';

    __u32 flags = file->f_flags;
    long n = bpf_d_path(__builtin_preserve_access_index(&file->f_path), pb->data, PATH_MAX_LEN);
    if (n <= 1 || !is_interesting_resolved_path(pb->data, flags)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    init_event(e);
    e->type = EVENT_OPEN_RESOLVED;
    e->pid = pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->flags = flags;
    e->dirfd = AT_FDCWD;
    copy_path_256(e->path, pb->data);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct sys_enter_ctx *ctx) {
    return emit_exec(AT_FDCWD, (const void *)ctx->args[0], (const void *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct sys_enter_ctx *ctx) {
    return emit_exec((__s32)ctx->args[0], (const void *)ctx->args[1], (const void *)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_OPENAT, (__s32)ctx->args[0], (const void *)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct sys_enter_ctx *ctx) {
    __u64 how_flags = 0;
    const void *how = (const void *)ctx->args[2];
    if (how) {
        bpf_probe_read_user(&how_flags, sizeof(how_flags), how);
    }
    return emit_open_typed(EVENT_OPENAT, (__s32)ctx->args[0], (const void *)ctx->args[1], (__u32)how_flags);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_OPENAT, AT_FDCWD, (const void *)ctx->args[0], (__u32)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_OPENAT, AT_FDCWD, (const void *)ctx->args[0], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, AT_FDCWD, (const void *)ctx->args[1], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, (__s32)ctx->args[2], (const void *)ctx->args[3], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, (__s32)ctx->args[2], (const void *)ctx->args[3], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_link(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, AT_FDCWD, (const void *)ctx->args[1], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_linkat(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, (__s32)ctx->args[2], (const void *)ctx->args[3], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_symlink(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, AT_FDCWD, (const void *)ctx->args[1], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct sys_enter_ctx *ctx) {
    return emit_open_typed(EVENT_LINK_DEST, (__s32)ctx->args[1], (const void *)ctx->args[2], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct sys_enter_ctx *ctx) {
    return emit_sockaddr(EVENT_CONNECT, (const void *)ctx->args[1], (long)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct sys_enter_ctx *ctx) {
    return emit_sockaddr(EVENT_SENDTO, (const void *)ctx->args[4], (long)ctx->args[5]);
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int trace_io_uring_setup(struct sys_enter_ctx *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        record_drop();
        return 0;
    }

    init_event(e);
    e->type = EVENT_IO_URING;
    e->pid = pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->flags = (__u32)ctx->args[0]; // entries
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
