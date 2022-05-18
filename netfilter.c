#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "dns_header.h"
#include "netfilter.h"
#include "runtime.h"

#define DNS_HEADER_SIZE 12

DEFINE_SPINLOCK(hook_spinlock);

static struct nf_hook_ops nfho_in;  // net filter hook option struct
static struct nf_hook_ops nfho_out; // net filter hook option struct

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;   // ip header struct
    struct udphdr *udp_header; // udp header struct

    if (!skb)
    {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb); // grab network header using accessor

    if (ip_header->protocol == IPPROTO_UDP)
    {
        udp_header = udp_hdr(skb);
        if (ntohs(udp_header->dest) == 53)
        {
            unsigned dnsPacketLen = ntohs(udp_header->len);
            char *data = (char *)udp_header + sizeof(struct udphdr);
            struct dns_h dns_header;
            memcpy(&dns_header, data, DNS_HEADER_SIZE);

            printk("wasm3: dns question (%d bytes) in request id %u questions: %u", dnsPacketLen, ntohs(dns_header.id), ntohs(dns_header.qdcount));

            unsigned long flags;
            spin_lock_irqsave(&hook_spinlock, flags);

            // Get the VM memory if there is at least one module loaded,
            // if not, accept the packet regardless.
            uint8_t *mem = repl_get_memory();
            if (!mem)
            {
                return NF_ACCEPT;
            }

            i32 dnsPacketPtr = wasm_malloc(dnsPacketLen);

            char *dnsPacket = mem + dnsPacketPtr;
            memcpy(dnsPacket, data, dnsPacketLen);

            unsigned dnsId = ntohs(dns_header.id);
            unsigned dnsSource = ntohl(ip_header->saddr);
            unsigned dnsDestination = ntohl(ip_header->daddr);

            M3Result result = repl_call_void("dns_query",
                                             dnsId,
                                             dnsSource,
                                             dnsDestination,
                                             dnsPacketPtr,
                                             dnsPacketLen);
            if (result)
            {
                FATAL("wasm3: netfilter dns_query error: %s", result);
                goto unlock;
            }

        unlock:
            wasm_free(dnsPacketPtr, dnsPacketLen);
            spin_unlock_irqrestore(&hook_spinlock, flags);
        }
    }

    return NF_ACCEPT;
}

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;   // ip header struct
    struct udphdr *udp_header; // udp header struct

    if (!skb)
    {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb); // grab network header using accessor

    if (ip_header->protocol == IPPROTO_UDP)
    {
        udp_header = udp_hdr(skb);
        if (ntohs(udp_header->source) == 53)
        {
            unsigned dnsPacketLen = ntohs(udp_header->len);
            char *data = (char *)udp_header + sizeof(struct udphdr);
            struct dns_h dns_header;
            memcpy(&dns_header, data, DNS_HEADER_SIZE);

            printk("wasm3: dns answer (%d bytes) in request id %u answers: %u", dnsPacketLen, ntohs(dns_header.id), ntohs(dns_header.ancount));

            unsigned long flags;
            spin_lock_irqsave(&hook_spinlock, flags);

            // Get the VM memory if there is at least one module loaded,
            // if not, accept the packet regardless.
            uint8_t *mem = repl_get_memory();
            if (!mem)
            {
                return NF_ACCEPT;
            }

            i32 dnsPacketPtr = wasm_malloc(dnsPacketLen);

            char *dnsPacket = mem + dnsPacketPtr;
            memcpy(dnsPacket, data, dnsPacketLen);

            unsigned dnsId = ntohs(dns_header.id);
            unsigned dnsSource = ntohl(ip_header->saddr);
            unsigned dnsDestination = ntohl(ip_header->daddr);

            M3Result result = repl_call_void("dns_response",
                                             dnsId,
                                             dnsSource,
                                             dnsDestination,
                                             dnsPacketPtr,
                                             dnsPacketLen);
            if (result)
            {
                FATAL("wasm3: netfilter dns_response error: %s", result);
                goto unlock;
            }

        unlock:
            wasm_free(dnsPacketPtr, dnsPacketLen);
            spin_unlock_irqrestore(&hook_spinlock, flags);
        }
    }

    return NF_ACCEPT;
}

static int init_network(struct net *net)
{
    int ret = 0;

    printk("wasm3: init_network: %u\n", net->ns.inum);

    // register hook for outgoing traffic
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;

    ret += nf_register_net_hook(net, &nfho_out);

    // register hook for outgoing traffic
    nfho_in.hook = hook_func_in;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;

    ret += nf_register_net_hook(net, &nfho_in);

    printk("wasm3: init_network: %u returned: %d\n", net->ns.inum, ret);

    return 0;
}

static void exit_network(struct net *net)
{
    printk("wasm3: exit_network: %u\n", net->ns.inum);
    nf_unregister_net_hook(net, &nfho_in);
    nf_unregister_net_hook(net, &nfho_out);
}

static struct pernet_operations net_operations = {
    .init = init_network,
    .exit = exit_network,
};

int start_netfilter_submodule(void)
{
    pr_info("---- netfilter submodule init() ---");

    register_pernet_device(&net_operations);

    pr_info("---- netfilter submodule started ----");

    return 0;
}

int stop_netfilter_submodule(void)
{
    pr_info("---- netfilter submodule exit() ---");

    unregister_pernet_device(&net_operations);

    pr_info("---- netfilter submodule exited ---");

    return 0;
}
