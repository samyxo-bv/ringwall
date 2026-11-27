// SPDX-License-Identifier: Apache-2.0
// Ringwall Linux eBPF tracepoint sensor.
// Traces execve, execveat, openat, openat2, open, creat, renameat2, connect, sendto, and io_uring_setup.
// Uses a 4 MiB ring buffer plus a per-CPU drop counter so ringbuf pressure is never silent.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVENT_EXEC     1
#define EVENT_OPENAT   2
#define EVENT_CONNECT  3
#define EVENT_SENDTO   4
#define EVENT_IO_URING 5

#define AF_INET  2
#define AF_INET6 10

#define AT_FDCWD (-100)

#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0040

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

// Index 0 stores ringwalld's own PID so the daemon never self-triggers.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
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

static __always_inline int is_self_pid(__u32 pid) {
    __u32 key = 0;
    __u32 *self = bpf_map_lookup_elem(&config_map, &key);
    if (self && *self != 0 && *self == pid) {
        return 1;
    }
    return 0;
}

static __always_inline int starts_with_4(const char *s, char a, char b, char c, char d) {
    return s[0] == a && s[1] == b && s[2] == c && s[3] == d;
}

static __always_inline int starts_with_5(const char *s, char a, char b, char c, char d, char e) {
    return s[0] == a && s[1] == b && s[2] == c && s[3] == d && s[4] == e;
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

static __always_inline int is_proc_bypass_path(const char *p) {
    // Emit /proc/<self|thread-self|pid>/(root|cwd|fd) and any /proc// or /proc/./ traversal.
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

static __always_inline int is_interesting_path(const char *p, __u32 flags, long read_len) {
    if (p[0] == '\0') {
        return 0;
    }
    // Fail-closed on truncated paths (>= PATH_MAX_LEN) so long ././ padding cannot evade detection.
    if (read_len >= PATH_MAX_LEN) {
        return 1;
    }
    // Relative paths (e.g. 'cd ~/.ssh && cat id_rsa' or openat(dirfd, 'id_rsa'))
    if (p[0] != '/') {
        return 1;
    }
    // Any unnormalized leading // or /./ or /../ bypass (e.g. //home/..., /./etc/shadow)
    if (p[1] == '/' || p[1] == '.') {
        return 1;
    }
    // User & root homes + /tmp (including directory symlinks)
    if (starts_with_5(p, '/', 'h', 'o', 'm', 'e') ||
        starts_with_5(p, '/', 'r', 'o', 'o', 't') ||
        starts_with_5(p, '/', 't', 'm', 'p', '/')) {
        return 1;
    }
    // /var/tmp/... (symlinks)
    if (starts_with_5(p, '/', 'v', 'a', 'r', '/') &&
        p[5] == 't' && p[6] == 'm' && p[7] == 'p' && p[8] == '/') {
        return 1;
    }
    // /dev/shm/... (symlinks) and /dev/fd/... (fd path traversal)
    if (starts_with_5(p, '/', 'd', 'e', 'v', '/')) {
        if ((p[5] == 's' && p[6] == 'h' && p[7] == 'm' && p[8] == '/') ||
            (p[5] == 'f' && p[6] == 'd' && p[7] == '/')) {
            return 1;
        }
    }
    // /etc/ — all writes, or sensitive reads only
    if (starts_with_5(p, '/', 'e', 't', 'c', '/')) {
        if (flags & (O_WRONLY | O_RDWR | O_CREAT)) {
            return 1;
        }
        return is_sensitive_etc_read(p);
    }
    // /proc/<pid|self>/(root|cwd|fd)/... bypass attempts
    if (starts_with_5(p, '/', 'p', 'r', 'o', 'c') && p[5] == '/') {
        return is_proc_bypass_path(p);
    }
    // Persistence writes to /var, /usr, /boot, /lib, /run
    if (flags & (O_WRONLY | O_RDWR | O_CREAT)) {
        if (starts_with_5(p, '/', 'v', 'a', 'r', '/') ||
            starts_with_5(p, '/', 'u', 's', 'r', '/') ||
            starts_with_5(p, '/', 'b', 'o', 'o', 't') ||
            starts_with_4(p, '/', 'l', 'i', 'b') ||
            starts_with_5(p, '/', 'r', 'u', 'n', '/')) {
            return 1;
        }
    }
    // Reads of /run/ringwall (e.g. token theft probes)
    if (starts_with_5(p, '/', 'r', 'u', 'n', '/') && p[5] == 'r' && p[6] == 'i') {
        return 1;
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

static __always_inline int emit_open(__s32 dirfd, const void *filename, __u32 flags) {
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

    e->type = EVENT_OPENAT;
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
    return emit_open((__s32)ctx->args[0], (const void *)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct sys_enter_ctx *ctx) {
    __u64 how_flags = 0;
    const void *how = (const void *)ctx->args[2];
    if (how) {
        bpf_probe_read_user(&how_flags, sizeof(how_flags), how);
    }
    return emit_open((__s32)ctx->args[0], (const void *)ctx->args[1], (__u32)how_flags);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct sys_enter_ctx *ctx) {
    return emit_open(AT_FDCWD, (const void *)ctx->args[0], (__u32)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct sys_enter_ctx *ctx) {
    return emit_open(AT_FDCWD, (const void *)ctx->args[0], O_WRONLY | O_CREAT);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct sys_enter_ctx *ctx) {
    // Check destination (newdfd=args[2], newpath=args[3]) as a write to catch mv into authorized_keys/cron.
    return emit_open((__s32)ctx->args[2], (const void *)ctx->args[3], O_WRONLY | O_CREAT);
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
