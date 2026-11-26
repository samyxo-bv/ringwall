// SPDX-License-Identifier: Apache-2.0
// Ringwall Linux eBPF tracepoint sensor.
// Traces execve, sensitive openat, and IPv4/IPv6 connect syscalls and emits
// compact fixed-layout events to a BPF ring buffer for userspace evaluation.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVENT_EXEC    1
#define EVENT_OPENAT  2
#define EVENT_CONNECT 3

#define AF_INET  2
#define AF_INET6 10

#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0040

#define PATH_MAX_LEN 192
#define COMM_MAX_LEN 16
#define ARG_MAX_LEN  64
#define MAX_ARGS     4

/* Fixed, padding-free 504-byte event layout shared with Go userspace. */
struct ringwall_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 flags;
    __u16 dport;
    __u16 family;
    __u8  addr[16];
    char  comm[COMM_MAX_LEN];
    char  path[PATH_MAX_LEN];
    char  argv[MAX_ARGS][ARG_MAX_LEN];
};

/* Kernel sys_enter tracepoint ABI layout on 64-bit Linux. */
struct sys_enter_ctx {
    __u64 common;
    long  syscall_nr;
    unsigned long args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB ring buffer */
} events SEC(".maps");

/* Index 0 stores ringwalld's own PID so the daemon never self-triggers. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

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

static __always_inline int is_interesting_path(const char *p, __u32 flags) {
    if (starts_with_5(p, '/', 'e', 't', 'c', '/')) {
        return 1;
    }
    if (starts_with_5(p, '/', 'h', 'o', 'm', 'e') || starts_with_5(p, '/', 'r', 'o', 'o', 't')) {
        return 1;
    }
    if (flags & (O_WRONLY | O_RDWR | O_CREAT)) {
        if (starts_with_5(p, '/', 'v', 'a', 'r', '/') ||
            starts_with_5(p, '/', 'u', 's', 'r', '/') ||
            starts_with_5(p, '/', 'b', 'o', 'o', 't') ||
            starts_with_4(p, '/', 'l', 'i', 'b')) {
            return 1;
        }
    }
    if (p[0] == '.') {
        return 1;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct sys_enter_ctx *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_EXEC;
    e->pid = pid;
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const void *)ctx->args[0]);

    const char *const *argv = (const char *const *)ctx->args[1];
    if (argv) {
        const char *argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[0]) == 0 && argp) {
            bpf_probe_read_user_str(e->argv[0], ARG_MAX_LEN, argp);
        }
        argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[1]) == 0 && argp) {
            bpf_probe_read_user_str(e->argv[1], ARG_MAX_LEN, argp);
        }
        argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[2]) == 0 && argp) {
            bpf_probe_read_user_str(e->argv[2], ARG_MAX_LEN, argp);
        }
        argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[3]) == 0 && argp) {
            bpf_probe_read_user_str(e->argv[3], ARG_MAX_LEN, argp);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_ctx *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    struct ringwall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->flags = (__u32)ctx->args[2];
    long n = bpf_probe_read_user_str(&e->path, sizeof(e->path), (const void *)ctx->args[1]);
    if (n <= 1 || !is_interesting_path(e->path, e->flags)) {
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

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct sys_enter_ctx *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (is_self_pid(pid)) {
        return 0;
    }

    const void *user_addr = (const void *)ctx->args[1];
    long addrlen = (long)ctx->args[2];
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
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_CONNECT;
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
