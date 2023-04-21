#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcpconnlat.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

u16 bpf_ntohs(u16 val) {
  /* will be recognized by gcc into rotate insn and eventually rolw 8 */
  return (val << 8) | (val >> 8);
}

static int handle_tcp_drop_process(void *ctx, struct sock *sk){
	struct event event = {};

	event.af = BPF_CORE_READ(sk, __sk_common.skc_family);

	event.lport = BPF_CORE_READ(sk,__sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk,__sk_common.skc_dport);

	event.dport = bpf_ntohs(event.dport);

	event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			&event, sizeof(event));
	return 0;
}

SEC("kprobe/tcp_drop")
int BPF_KPROBE(tcp_drop_process, struct sock *sk)
{
	return handle_tcp_drop_process(ctx, sk);
}

char LICENSE[] SEC("license") = "GPL";