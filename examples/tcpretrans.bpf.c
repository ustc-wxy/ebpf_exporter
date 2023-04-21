#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcpretrans.h"

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct ipv4_flow_key_t *);
	__type(value, uint);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static int handle_tcp_retransmit_process(void *ctx,struct sock *sk, struct sk_buff *skb){
    if (sk == NULL) return 0;

    struct event event = {};
    event.af = BPF_CORE_READ(sk, __sk_common.skc_family);
    event.state = BPF_CORE_READ(sk,__sk_common.skc_state);
    event.lport = BPF_CORE_READ(sk,__sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk,__sk_common.skc_dport);
	event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			&event, sizeof(event));

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(tcp_retransmit_process, struct sock *sk, struct sk_buff *skb)
{
	return handle_tcp_retransmit_process(ctx, sk, skb);
}

char LICENSE[] SEC("license") = "GPL";