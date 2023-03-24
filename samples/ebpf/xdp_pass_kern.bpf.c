/*
 * The MIT License (MIT)
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/sched.h>

extern int bpf_opa_eval(char *input) __ksym;

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u16);
    __type(value, __u64);
    __uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, char[256]);
    __uint(max_entries, 1);
} xdp_opa_input_map SEC(".maps");

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data + sizeof(struct ethhdr) > data_end)
    {
        bpf_printk("Not an eth hdr");
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    __be16 h_proto = bpf_ntohs(eth->h_proto);

    __u32 key = 0;
    char *json = bpf_map_lookup_elem(&xdp_opa_input_map, &key);
    BPF_SNPRINTF(json, 256, "{\"proto\":%d}", h_proto);

    int res = bpf_opa_eval(json);
    bpf_printk("bpf_opa_eval(input=%s) -> %d", json, res);

    if (!res)
    {
        return XDP_PASS;
    }

    __u64 *cnt = bpf_map_lookup_elem(&xdp_stats_map, &h_proto);
    if (cnt == NULL)
    {
        __u32 cpu = bpf_get_smp_processor_id();
        bpf_printk("New protocol packet with type: 0x%04X on CPU: %d", h_proto, cpu);

        __u64 value = 0;
        bpf_map_update_elem(&xdp_stats_map, &h_proto, &value, BPF_ANY);
        cnt = bpf_map_lookup_elem(&xdp_stats_map, &h_proto);

        // Can't realy happen, but we need to make the verifier happy.
        if (!cnt)
            return XDP_DROP;
    }

    *cnt += 1;

    if (h_proto == ETH_P_IP || h_proto == ETH_P_IPV6)
    {
        bpf_printk("Hello %d. IPv4/6 packet from the eBPF/xdp World!", *cnt);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
