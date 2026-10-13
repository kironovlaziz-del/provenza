// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (c) 2026 Laziz Kironov
// Part of Provenza - https://github.com/kironovlaziz-del/provenza
//
// Provenza egress sensor: the kernel half.
//
// Governed workloads are cgroups (and everything below them) and user ids
// the sensor's daemon names in `cgroups` / `uids`. Their network is held to
// the workload's policy here, where a process cannot go around it:
//
//   cgroup/connect4|6, sendmsg4|6   every TCP connect and UDP destination;
//                                   DNS (port 53, any server) is rewritten to
//                                   the daemon's DNS proxy for the workload
//   cgroup/recvmsg4|6, getpeername4|6  the rewrite stays invisible to libc
//   cgroup/sock_create              only TCP and UDP sockets (no raw, ICMP,
//                                   SCTP, MPTCP)
//   cgroup_skb/egress|ingress       every packet: the backstop for anything
//                                   that does not pass through connect()
//                                   (TCP Fast Open, connections made before
//                                   a policy change or an isolation) and the
//                                   inbound side (a workload listening for an
//                                   outsider to pull data out)
//   lsm/socket_create               (when BPF LSM is active) no socket
//                                   families but unix, IP and netlink
//   raw_tracepoint/cgroup_mkdir     a new cgroup whose path a workload names
//                                   literally is governed before anything in
//                                   it runs; the daemon is told of all of them
//
// Policy lives in generations: the daemon writes generation N+1 completely,
// then flips `globals.gen` in one write, so a policy change never passes
// through an empty (open) state.
//
// Nothing here decides for processes that are not governed: they return
// "allow" after one or a few map lookups.

#include "uapi.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_LEVEL 16
#define PATH_LEN 512
#define PENDING_NS (2ULL * 1000000000ULL)
#define EVENT_GAP_NS (1000000000ULL)
#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL

enum { MODE_OBSERVE = 0, MODE_ALERT = 1, MODE_ENFORCE = 2 };
enum { DNS_OFF = 0, DNS_LISTED = 1, DNS_ANY = 2 };
enum { CG_GOVERNED = 1, CG_EXEMPT = 2, CG_PENDING = 3 };
enum { ACT_OBSERVED = 1, ACT_ALERTED = 2, ACT_BLOCKED = 3 };
enum { KIND_CONNECT = 1, KIND_SEND = 2, KIND_SOCKET = 3, KIND_PACKET = 4, KIND_INGRESS = 5, KIND_FAMILY = 7 };
enum { EV_VIOLATION = 1, EV_MKDIR = 2, EV_RMDIR = 3 };
enum { DIR_EGRESS = 0, DIR_INGRESS = 1 };
enum { CLS_NONE = 0, CLS_GOVERNED = 1, CLS_HOLD = 2 };
enum { NOTE_UNKNOWN = 0, NOTE_FREE = 1, NOTE_GOVERNED = 2, NOTE_PENDING = 3 };
enum { STAT_EVENTS_LOST = 0, STAT_MKDIR_LOST = 1, STAT_MAX = 4 };

#define WL_DNS_V6 0x1

struct cg_entry {
	__u32 wid;
	__u32 kind;
	__u64 since; /* CG_PENDING: when, bpf_ktime_get_ns */
};

struct wl_key {
	__u32 gen;
	__u32 wid;
};

struct wl_cfg {
	__u8 mode;
	__u8 isolated;
	__u8 dns;
	__u8 flags;
	__u16 dns_port; /* the daemon's DNS proxy for this workload, 127.0.0.1 / ::1 */
	__u16 pad;
};

/* LPM keys: everything before the address is matched exactly (96 bits),
 * the address by prefix. port 0 = any port. */
struct lpm4 {
	__u32 prefixlen;
	__u32 gen;
	__u32 wid;
	__u8 dir;
	__u8 proto;
	__u16 port;
	__u8 addr[4];
};

struct lpm6 {
	__u32 prefixlen;
	__u32 gen;
	__u32 wid;
	__u8 dir;
	__u8 proto;
	__u16 port;
	__u8 addr[16];
};

struct globals {
	__u32 gen;
	__u32 epoch; /* bumped by the daemon when cgroups/uids change: sockets re-classify */
};

struct sk_note {
	__u32 epoch;
	__u32 wid;
	__u8 state;
	__u8 dns_redir;
	__u16 dns_port;
	__u16 orig_port;
	__u8 orig_v6;
	__u8 pad;
	__u32 orig_ip4;
	__u32 orig_ip6[4];
	__u64 since;
};

struct rl_key {
	__u32 wid;
	__u8 action;
	__u8 kind;
	__u8 proto;
	__u8 family;
	__u16 port;
	__u8 isolated;
	__u8 pad;
	__u8 addr[16];
};

struct rl_val {
	__u64 last;
	__u64 suppressed;
};

struct event {
	__u8 type;
	__u8 action;
	__u8 kind;
	__u8 proto;
	__u8 family;
	__u8 isolated;
	__u16 port;
	__u32 wid;
	__u32 pid;
	__u32 uid;
	__u32 count;
	__u64 cgid;
	__u8 addr[16];
	char comm[16];
};

struct mkdir_event {
	__u8 type;
	__u8 pad[7];
	__u64 cgid;
	char path[PATH_LEN];
};

struct path_buf {
	char path[PATH_LEN];
};

struct pkt {
	__u8 v6;
	__u8 proto;
	__u8 syn_only;
	__u8 first_frag;
	__u16 sport;
	__u16 dport;
	__u8 saddr[16];
	__u8 daddr[16];
};

struct cls {
	__u32 wid;
	__u32 kind;
	__u64 cgid;
};

/* keeps the event layouts in the object's BTF, for the daemon's layout test */
const struct event *unused_event __attribute__((unused));
const struct mkdir_event *unused_mkdir_event __attribute__((unused));

/* ------------------------------------------------------------------ maps */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct cg_entry);
	__uint(max_entries, 65536);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4096);
} uids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct wl_key);
	__type(value, struct wl_cfg);
	__uint(max_entries, 8192);
} workloads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm4);
	__type(value, __u8);
	__uint(max_entries, 262144);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm6);
	__type(value, __u8);
	__uint(max_entries, 262144);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct globals);
	__uint(max_entries, 1);
} globals SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__type(key, int);
	__type(value, struct sk_note);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} notes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct rl_key);
	__type(value, struct rl_val);
	__uint(max_entries, 16384);
} ratelimit SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* cgroup paths ("/system.slice/x.service") a workload names literally,
 * FNV-1a 64 -> workload id; and parents whose new children wait (pending)
 * for the daemon to match them against wildcard patterns. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 4096);
} literal_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u8);
	__uint(max_entries, 4096);
} watch_parents SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct path_buf);
	__uint(max_entries, 1);
} scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* --------------------------------------------------------------- helpers */

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += 1;
}

static __always_inline struct globals *get_globals(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&globals, &zero);
}

/* CLS_NONE: not governed (or exempt); CLS_GOVERNED: c->wid; CLS_HOLD: a new
 * cgroup the daemon has not matched yet - refuse for now. */
static __always_inline int resolve(struct cg_entry *e, struct cls *c)
{
	if (e->kind == CG_EXEMPT)
		return CLS_NONE;
	if (e->kind == CG_PENDING) {
		if (bpf_ktime_get_ns() - e->since < PENDING_NS)
			return CLS_HOLD;
		return CLS_NONE; /* the daemon did not answer in time: it is not running */
	}
	c->wid = e->wid;
	c->kind = e->kind;
	return CLS_GOVERNED;
}

/* The calling task: the deepest of its cgroups the daemon named, then its
 * real uid. */
static __always_inline int classify_task(struct cls *c)
{
	c->cgid = bpf_get_current_cgroup_id();
#pragma unroll
	for (int lvl = MAX_LEVEL - 1; lvl >= 1; lvl--) {
		__u64 id = bpf_get_current_ancestor_cgroup_id(lvl);
		if (!id)
			continue;
		struct cg_entry *e = bpf_map_lookup_elem(&cgroups, &id);
		if (e)
			return resolve(e, c);
	}
	__u32 uid = (__u32)bpf_get_current_uid_gid();
	__u32 *w = bpf_map_lookup_elem(&uids, &uid);
	if (w) {
		c->wid = *w;
		c->kind = CG_GOVERNED;
		return CLS_GOVERNED;
	}
	return CLS_NONE;
}

/* A packet: by the cgroup its socket was created in, and the socket's uid;
 * cached on the socket until the daemon changes cgroups/uids (epoch). */
static __always_inline int classify_skb(struct __sk_buff *skb, struct cls *c, __u32 epoch)
{
	struct bpf_sock *sk = skb->sk;
	struct sk_note *n = 0;
	if (!sk)
		return CLS_NONE;
	sk = bpf_sk_fullsock(sk);
	if (sk)
		n = bpf_sk_storage_get(&notes, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (n && n->epoch == epoch && n->state != NOTE_UNKNOWN) {
		if (n->state == NOTE_FREE)
			return CLS_NONE;
		if (n->state == NOTE_PENDING) {
			if (bpf_ktime_get_ns() - n->since < PENDING_NS)
				return CLS_HOLD;
			return CLS_NONE;
		}
		c->wid = n->wid;
		c->kind = CG_GOVERNED;
		c->cgid = bpf_skb_cgroup_id(skb);
		return CLS_GOVERNED;
	}

	int r = CLS_NONE;
	__u8 state = NOTE_FREE;
	__u64 since = 0;
	c->cgid = bpf_skb_cgroup_id(skb);
	int found = 0;
#pragma unroll
	for (int lvl = MAX_LEVEL - 1; lvl >= 1; lvl--) {
		if (found)
			break;
		__u64 id = bpf_skb_ancestor_cgroup_id(skb, lvl);
		if (!id)
			continue;
		struct cg_entry *e = bpf_map_lookup_elem(&cgroups, &id);
		if (!e)
			continue;
		found = 1;
		if (e->kind == CG_EXEMPT) {
			r = CLS_NONE;
		} else if (e->kind == CG_PENDING) {
			state = NOTE_PENDING;
			since = e->since;
			r = bpf_ktime_get_ns() - e->since < PENDING_NS ? CLS_HOLD : CLS_NONE;
		} else {
			c->wid = e->wid;
			c->kind = CG_GOVERNED;
			state = NOTE_GOVERNED;
			r = CLS_GOVERNED;
		}
	}
	if (!found) {
		__u32 uid = bpf_get_socket_uid(skb);
		__u32 *w = bpf_map_lookup_elem(&uids, &uid);
		if (w) {
			c->wid = *w;
			c->kind = CG_GOVERNED;
			state = NOTE_GOVERNED;
			r = CLS_GOVERNED;
		}
	}
	if (n) {
		n->epoch = epoch;
		n->state = state;
		n->wid = c->wid;
		n->since = since;
	}
	return r;
}

static __always_inline int policy_allows(__u32 gen, __u32 wid, __u8 dir, __u8 proto, __u16 port, int v6,
					 const __u8 *addr)
{
	if (!v6) {
		struct lpm4 k = {.prefixlen = 96 + 32, .gen = gen, .wid = wid, .dir = dir, .proto = proto, .port = port};
		__builtin_memcpy(k.addr, addr, 4);
		if (bpf_map_lookup_elem(&allow4, &k))
			return 1;
		k.port = 0;
		return bpf_map_lookup_elem(&allow4, &k) != 0;
	}
	struct lpm6 k = {.prefixlen = 96 + 128, .gen = gen, .wid = wid, .dir = dir, .proto = proto, .port = port};
	__builtin_memcpy(k.addr, addr, 16);
	if (bpf_map_lookup_elem(&allow6, &k))
		return 1;
	k.port = 0;
	return bpf_map_lookup_elem(&allow6, &k) != 0;
}

/* One event per distinct (workload, action, kind, destination) per second at
 * most; repeats in between are counted into the next one. */
static __always_inline void emit(struct cls *c, __u8 action, __u8 kind, __u8 proto, __u8 family, __u16 port,
				 const __u8 *addr, __u8 isolated, __u32 uid, int task)
{
	struct rl_key k = {.wid = c->wid, .action = action, .kind = kind, .proto = proto, .family = family,
			   .port = port, .isolated = isolated};
	if (addr)
		__builtin_memcpy(k.addr, addr, 16);
	__u64 now = bpf_ktime_get_ns();
	__u32 count = 1;
	struct rl_val *v = bpf_map_lookup_elem(&ratelimit, &k);
	if (v) {
		if (now - v->last < EVENT_GAP_NS) {
			__sync_fetch_and_add(&v->suppressed, 1);
			return;
		}
		count = (__u32)v->suppressed + 1;
		v->last = now;
		v->suppressed = 0;
	} else {
		struct rl_val nv = {.last = now};
		bpf_map_update_elem(&ratelimit, &k, &nv, BPF_ANY);
	}

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_EVENTS_LOST);
		return;
	}
	e->type = EV_VIOLATION;
	e->action = action;
	e->kind = kind;
	e->proto = proto;
	e->family = family;
	e->isolated = isolated;
	e->port = port;
	e->wid = c->wid;
	e->count = count;
	e->cgid = c->cgid;
	__builtin_memcpy(e->addr, k.addr, 16);
	if (task) {
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->uid = (__u32)bpf_get_current_uid_gid();
		bpf_get_current_comm(e->comm, sizeof(e->comm));
	} else {
		e->pid = 0;
		e->uid = uid;
		__builtin_memset(e->comm, 0, sizeof(e->comm));
	}
	bpf_ringbuf_submit(e, 0);
}

static __always_inline __u8 action_for(struct wl_cfg *w)
{
	if (w->isolated || w->mode == MODE_ENFORCE)
		return ACT_BLOCKED;
	return w->mode == MODE_ALERT ? ACT_ALERTED : ACT_OBSERVED;
}

static __always_inline int is_v4_mapped(const __u8 *a)
{
	return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 && a[4] == 0 && a[5] == 0 && a[6] == 0 &&
	       a[7] == 0 && a[8] == 0 && a[9] == 0 && a[10] == 0xff && a[11] == 0xff;
}

static __always_inline int is_loopback(int v6, const __u8 *a)
{
	if (!v6)
		return a[0] == 127;
	for (int i = 0; i < 15; i++)
		if (a[i])
			return 0;
	return a[15] == 1;
}

static __always_inline struct wl_cfg *workload_of(struct globals *g, __u32 wid)
{
	struct wl_key k = {.gen = g->gen, .wid = wid};
	return bpf_map_lookup_elem(&workloads, &k);
}

/* ------------------------------------------------- connect / sendmsg hooks */

static __always_inline int on_addr(struct bpf_sock_addr *ctx, int v6, __u8 kind)
{
	struct cls c = {};
	int r = classify_task(&c);
	if (r == CLS_NONE)
		return 1;
	if (r == CLS_HOLD)
		return 0;
	struct globals *g = get_globals();
	if (!g)
		return 0;
	struct wl_cfg *w = workload_of(g, c.wid);
	if (!w)
		return 0; /* governed, but not in the policy in force: fail closed */

	__u8 proto = ctx->type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
	__u8 a[16] = {};
	int fam6 = 0;
	if (v6) {
		__u32 w0 = ctx->user_ip6[0], w1 = ctx->user_ip6[1], w2 = ctx->user_ip6[2], w3 = ctx->user_ip6[3];
		__builtin_memcpy(a, &w0, 4);
		__builtin_memcpy(a + 4, &w1, 4);
		__builtin_memcpy(a + 8, &w2, 4);
		__builtin_memcpy(a + 12, &w3, 4);
		if (is_v4_mapped(a)) {
			__builtin_memcpy(a, &w3, 4);
			__builtin_memset(a + 4, 0, 12);
		} else {
			fam6 = 1;
		}
	} else {
		__u32 ip = ctx->user_ip4;
		__builtin_memcpy(a, &ip, 4);
	}
	__u16 port = bpf_ntohs((__u16)ctx->user_port);
	__u8 family = fam6 ? AF_INET6 : AF_INET;

	if (w->isolated) {
		emit(&c, ACT_BLOCKED, kind, proto, family, port, a, 1, 0, 1);
		return 0;
	}

	if (port == 53 && w->dns != DNS_OFF) {
		int can = w->dns_port && (!fam6 || (w->flags & WL_DNS_V6));
		if (!can) {
			__u8 act = action_for(w);
			emit(&c, act, kind, proto, family, port, a, 0, 0, 1);
			return act != ACT_BLOCKED;
		}
		struct sk_note *n = 0;
		if (ctx->sk)
			n = bpf_sk_storage_get(&notes, ctx->sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (n) {
			n->dns_redir = 1;
			n->dns_port = w->dns_port;
			n->orig_port = port;
			n->orig_v6 = v6;
			if (v6) {
				n->orig_ip6[0] = ctx->user_ip6[0];
				n->orig_ip6[1] = ctx->user_ip6[1];
				n->orig_ip6[2] = ctx->user_ip6[2];
				n->orig_ip6[3] = ctx->user_ip6[3];
			} else {
				n->orig_ip4 = ctx->user_ip4;
			}
		}
		if (!v6) {
			ctx->user_ip4 = bpf_htonl(0x7f000001);
		} else if (!fam6) {
			ctx->user_ip6[0] = 0;
			ctx->user_ip6[1] = 0;
			ctx->user_ip6[2] = bpf_htonl(0x0000ffff);
			ctx->user_ip6[3] = bpf_htonl(0x7f000001);
		} else {
			ctx->user_ip6[0] = 0;
			ctx->user_ip6[1] = 0;
			ctx->user_ip6[2] = 0;
			ctx->user_ip6[3] = bpf_htonl(1);
		}
		ctx->user_port = bpf_htons(w->dns_port);
		return 1;
	}

	if (policy_allows(g->gen, c.wid, DIR_EGRESS, proto, port, fam6, a))
		return 1;
	__u8 act = action_for(w);
	emit(&c, act, kind, proto, family, port, a, 0, 0, 1);
	return act != ACT_BLOCKED;
}

SEC("cgroup/connect4")
int pvz_connect4(struct bpf_sock_addr *ctx)
{
	return on_addr(ctx, 0, KIND_CONNECT);
}

SEC("cgroup/connect6")
int pvz_connect6(struct bpf_sock_addr *ctx)
{
	return on_addr(ctx, 1, KIND_CONNECT);
}

SEC("cgroup/sendmsg4")
int pvz_sendmsg4(struct bpf_sock_addr *ctx)
{
	return on_addr(ctx, 0, KIND_SEND);
}

SEC("cgroup/sendmsg6")
int pvz_sendmsg6(struct bpf_sock_addr *ctx)
{
	return on_addr(ctx, 1, KIND_SEND);
}

/* An answer from the DNS proxy is shown as coming from the server the
 * process asked (resolvers check that). Must return 1. */
static __always_inline int restore_addr(struct bpf_sock_addr *ctx, int v6)
{
	if (!ctx->sk)
		return 1;
	struct sk_note *n = bpf_sk_storage_get(&notes, ctx->sk, 0, 0);
	if (!n || !n->dns_redir)
		return 1;
	if (bpf_ntohs((__u16)ctx->user_port) != n->dns_port)
		return 1;
	if (!v6) {
		if (ctx->user_ip4 != bpf_htonl(0x7f000001) || n->orig_v6)
			return 1;
		ctx->user_ip4 = n->orig_ip4;
	} else {
		if (!n->orig_v6)
			return 1;
		__u32 w3 = ctx->user_ip6[3];
		if (w3 != bpf_htonl(1) && w3 != bpf_htonl(0x7f000001))
			return 1;
		ctx->user_ip6[0] = n->orig_ip6[0];
		ctx->user_ip6[1] = n->orig_ip6[1];
		ctx->user_ip6[2] = n->orig_ip6[2];
		ctx->user_ip6[3] = n->orig_ip6[3];
	}
	ctx->user_port = bpf_htons(n->orig_port);
	return 1;
}

SEC("cgroup/recvmsg4")
int pvz_recvmsg4(struct bpf_sock_addr *ctx)
{
	return restore_addr(ctx, 0);
}

SEC("cgroup/recvmsg6")
int pvz_recvmsg6(struct bpf_sock_addr *ctx)
{
	return restore_addr(ctx, 1);
}

SEC("cgroup/getpeername4")
int pvz_getpeername4(struct bpf_sock_addr *ctx)
{
	return restore_addr(ctx, 0);
}

SEC("cgroup/getpeername6")
int pvz_getpeername6(struct bpf_sock_addr *ctx)
{
	return restore_addr(ctx, 1);
}

/* ------------------------------------------------------------ sock_create */

SEC("cgroup/sock_create")
int pvz_sock_create(struct bpf_sock *ctx)
{
	struct cls c = {};
	int r = classify_task(&c);
	if (r == CLS_NONE)
		return 1;
	if (r == CLS_HOLD)
		return 0;
	struct globals *g = get_globals();
	if (!g)
		return 0;
	struct wl_cfg *w = workload_of(g, c.wid);
	if (!w)
		return 0;
	__u32 type = ctx->type, protocol = ctx->protocol;
	__u8 family = (__u8)ctx->family;
	if (!w->isolated) {
		if (type == SOCK_STREAM && (protocol == 0 || protocol == IPPROTO_TCP))
			return 1;
		if (type == SOCK_DGRAM && (protocol == 0 || protocol == IPPROTO_UDP))
			return 1;
	}
	__u8 act = action_for(w);
	emit(&c, act, KIND_SOCKET, (__u8)protocol, family, (__u16)type, 0, w->isolated, 0, 1);
	return act != ACT_BLOCKED;
}

/* ----------------------------------------------------------- packet hooks */

static __always_inline int parse(struct __sk_buff *skb, struct pkt *p)
{
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		__u8 h[20];
		if (bpf_skb_load_bytes(skb, 0, h, sizeof(h)))
			return -1;
		__u32 ihl = (h[0] & 0x0f) * 4;
		if (ihl < 20)
			return -1;
		p->v6 = 0;
		p->proto = h[9];
		__u16 frag = ((__u16)h[6] << 8) | h[7];
		p->first_frag = (frag & 0x1fff) == 0;
		__builtin_memcpy(p->saddr, h + 12, 4);
		__builtin_memcpy(p->daddr, h + 16, 4);
		if (!p->first_frag)
			return 0;
		if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
			__u8 l4[14];
			__u32 len = p->proto == IPPROTO_TCP ? 14 : 4;
			if (ihl > 60)
				return -1;
			if (len == 14) {
				if (bpf_skb_load_bytes(skb, ihl, l4, 14))
					return -1;
				p->syn_only = (l4[13] & 0x12) == 0x02;
			} else {
				if (bpf_skb_load_bytes(skb, ihl, l4, 4))
					return -1;
			}
			p->sport = ((__u16)l4[0] << 8) | l4[1];
			p->dport = ((__u16)l4[2] << 8) | l4[3];
		}
		return 0;
	}
	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		__u8 h[40];
		if (bpf_skb_load_bytes(skb, 0, h, sizeof(h)))
			return -1;
		p->v6 = 1;
		p->first_frag = 1;
		__builtin_memcpy(p->saddr, h + 8, 16);
		__builtin_memcpy(p->daddr, h + 24, 16);
		__u8 next = h[6];
		__u32 off = 40;
		if (next == IPPROTO_FRAGMENT) {
			__u8 f[8];
			if (bpf_skb_load_bytes(skb, off, f, 8))
				return -1;
			__u16 fo = ((__u16)f[2] << 8) | f[3];
			p->first_frag = (fo & 0xfff8) == 0;
			next = f[0];
			off += 8;
		}
		p->proto = next;
		if (!p->first_frag)
			return 0;
		if (next == IPPROTO_TCP) {
			__u8 l4[14];
			if (bpf_skb_load_bytes(skb, off, l4, 14))
				return -1;
			p->syn_only = (l4[13] & 0x12) == 0x02;
			p->sport = ((__u16)l4[0] << 8) | l4[1];
			p->dport = ((__u16)l4[2] << 8) | l4[3];
		} else if (next == IPPROTO_UDP) {
			__u8 l4[4];
			if (bpf_skb_load_bytes(skb, off, l4, 4))
				return -1;
			p->sport = ((__u16)l4[0] << 8) | l4[1];
			p->dport = ((__u16)l4[2] << 8) | l4[3];
		}
		return 0;
	}
	return -1;
}

static __always_inline int skb_hook(struct __sk_buff *skb, int ingress)
{
	struct globals *g = get_globals();
	if (!g)
		return 1;
	struct cls c = {};
	int r = classify_skb(skb, &c, g->epoch);
	if (r == CLS_NONE)
		return 1;
	if (r == CLS_HOLD)
		return 0;
	struct wl_cfg *w = workload_of(g, c.wid);
	if (!w)
		return 0;

	struct pkt p = {};
	__u32 uid = bpf_get_socket_uid(skb);
	if (parse(skb, &p) < 0) {
		/* not IP, or truncated: nothing a governed socket should send */
		if (w->isolated || w->mode == MODE_ENFORCE)
			return 0;
		return 1;
	}
	__u8 family = p.v6 ? AF_INET6 : AF_INET;
	__u8 kind = ingress ? KIND_INGRESS : KIND_PACKET;
	const __u8 *peer = ingress ? p.saddr : p.daddr;

	if (w->isolated) {
		emit(&c, ACT_BLOCKED, kind, p.proto, family, p.dport, peer, 1, uid, 0);
		return 0;
	}
	if (!p.first_frag)
		return 1; /* the first fragment carried the ports and was judged */

	int ok = 0;
	__u16 shown = p.dport;
	if (!ingress) {
		if (p.proto == IPPROTO_TCP || p.proto == IPPROTO_UDP) {
			if (w->dns_port && p.dport == w->dns_port && is_loopback(p.v6, p.daddr))
				ok = 1;
			else if (policy_allows(g->gen, c.wid, DIR_EGRESS, p.proto, p.dport, p.v6, p.daddr))
				ok = 1;
			else if (policy_allows(g->gen, c.wid, DIR_INGRESS, p.proto, p.sport, p.v6, p.daddr))
				ok = 1; /* the reply side of a connection the workload may accept */
		}
		/* outside enforce mode the connect/sendmsg hooks already reported it */
		if (!ok && w->mode != MODE_ENFORCE)
			return 1;
	} else {
		if (p.proto == IPPROTO_TCP) {
			if (!p.syn_only)
				ok = 1; /* a connection the workload made or was allowed to accept */
			else
				ok = policy_allows(g->gen, c.wid, DIR_INGRESS, IPPROTO_TCP, p.dport, p.v6, p.saddr);
		} else if (p.proto == IPPROTO_UDP) {
			if (w->dns_port && p.sport == w->dns_port && is_loopback(p.v6, p.saddr))
				ok = 1;
			else if (policy_allows(g->gen, c.wid, DIR_EGRESS, IPPROTO_UDP, p.sport, p.v6, p.saddr))
				ok = 1; /* an answer from a destination the workload may reach */
			else
				ok = policy_allows(g->gen, c.wid, DIR_INGRESS, IPPROTO_UDP, p.dport, p.v6, p.saddr);
		}
	}
	if (ok)
		return 1;
	__u8 act = action_for(w);
	emit(&c, act, kind, p.proto, family, shown, peer, 0, uid, 0);
	return act != ACT_BLOCKED;
}

SEC("cgroup_skb/egress")
int pvz_egress(struct __sk_buff *skb)
{
	return skb_hook(skb, 0);
}

SEC("cgroup_skb/ingress")
int pvz_ingress(struct __sk_buff *skb)
{
	return skb_hook(skb, 1);
}

/* ------------------------------------------------------------------- LSM */

SEC("lsm/socket_create")
int pvz_socket_family(__u64 *ctx)
{
	int family = (int)ctx[0];
	int kern = (int)ctx[3];
	int ret = (int)ctx[4];
	if (ret)
		return ret;
	if (kern)
		return 0;
	if (family == AF_UNIX || family == AF_INET || family == AF_INET6 || family == AF_NETLINK)
		return 0;
	struct cls c = {};
	int r = classify_task(&c);
	if (r == CLS_NONE)
		return 0;
	if (r == CLS_HOLD)
		return -EPERM;
	struct globals *g = get_globals();
	if (!g)
		return -EPERM;
	struct wl_cfg *w = workload_of(g, c.wid);
	if (!w)
		return -EPERM;
	__u8 act = action_for(w);
	emit(&c, act, KIND_FAMILY, (__u8)family, (__u8)family, (__u16)ctx[1], 0, w->isolated, 0, 1);
	return act == ACT_BLOCKED ? -EPERM : 0;
}

/* ------------------------------------------------------------ new cgroups */

struct kernfs_node {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup_root {
	int hierarchy_id;
} __attribute__((preserve_access_index));

struct cgroup {
	struct kernfs_node *kn;
	struct cgroup_root *root;
} __attribute__((preserve_access_index));

static __always_inline int dfl_cgroup_id(struct cgroup *cg, __u64 *id)
{
	struct cgroup_root *root = 0;
	struct kernfs_node *kn = 0;
	int hid = -1;
	if (bpf_probe_read_kernel(&root, sizeof(root), &cg->root) || !root)
		return -1;
	if (bpf_probe_read_kernel(&hid, sizeof(hid), &root->hierarchy_id) || hid != 0)
		return -1; /* a cgroup v1 hierarchy */
	if (bpf_probe_read_kernel(&kn, sizeof(kn), &cg->kn) || !kn)
		return -1;
	if (bpf_probe_read_kernel(id, sizeof(*id), &kn->id))
		return -1;
	return 0;
}

SEC("raw_tracepoint/cgroup_mkdir")
int pvz_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *cg = (struct cgroup *)ctx->args[0];
	const char *path = (const char *)ctx->args[1];
	__u64 id = 0;
	if (dfl_cgroup_id(cg, &id))
		return 0;

	__u32 zero = 0;
	struct path_buf *b = bpf_map_lookup_elem(&scratch, &zero);
	if (!b)
		return 0;
	if (bpf_probe_read_kernel_str(b->path, sizeof(b->path), path) <= 0)
		return 0;

	__u64 h = FNV_OFFSET, parent = FNV_OFFSET;
	for (int i = 0; i < PATH_LEN; i++) {
		char ch = b->path[i];
		if (!ch)
			break;
		if (ch == '/')
			parent = h;
		h ^= (__u8)ch;
		h *= FNV_PRIME;
	}

	__u32 *wid = bpf_map_lookup_elem(&literal_paths, &h);
	if (wid) {
		struct cg_entry e = {.wid = *wid, .kind = CG_GOVERNED};
		bpf_map_update_elem(&cgroups, &id, &e, BPF_NOEXIST);
	} else if (bpf_map_lookup_elem(&watch_parents, &parent)) {
		struct cg_entry e = {.kind = CG_PENDING, .since = bpf_ktime_get_ns()};
		bpf_map_update_elem(&cgroups, &id, &e, BPF_NOEXIST);
	}

	struct mkdir_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_MKDIR_LOST);
		return 0;
	}
	e->type = EV_MKDIR;
	e->cgid = id;
	bpf_probe_read_kernel(e->path, sizeof(e->path), b->path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("raw_tracepoint/cgroup_rmdir")
int pvz_cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 id = 0;
	if (dfl_cgroup_id((struct cgroup *)ctx->args[0], &id))
		return 0;
	struct cg_entry *e = bpf_map_lookup_elem(&cgroups, &id);
	if (!e || e->kind == CG_EXEMPT)
		return 0;
	bpf_map_delete_elem(&cgroups, &id);
	struct mkdir_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;
	ev->type = EV_RMDIR;
	ev->cgid = id;
	ev->path[0] = 0;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}
