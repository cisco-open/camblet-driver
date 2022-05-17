#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "dns_header.h"
#include "wasm_module.h"
#include "netfilter.h"

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
            unsigned udp_length = ntohs(udp_header->len);
            char *data = (char *)udp_header + sizeof(struct udphdr);
            struct dns_h dns_header;
            memcpy(&dns_header, data, DNS_HEADER_SIZE);

            printk("wasm3: dns question (%d bytes) in request id %u questions: %u", udp_length, ntohs(dns_header.id), ntohs(dns_header.qdcount));

            // Get the VM memory if there is at least one module loaded,
            // if not, accept the packet regardless.
            uint8_t *mem = repl_get_memory();
            if (!mem)
            {
                return NF_ACCEPT;
            }

            uint64_t sourceAddr = repl_global_get("SOURCE");
            if (!sourceAddr)
            {
                return NF_ACCEPT;
            }

            uint64_t destinationAddr = repl_global_get("DESTINATION");
            if (!destinationAddr)
            {
                return NF_ACCEPT;
            }

            uint64_t dnsPacketAddr = repl_global_get("DNS_PACKET");
            if (!dnsPacketAddr)
            {
                return NF_ACCEPT;
            }

            // From this part we are writing global memory in the wasm runtime,
            // needs to be exclusive until we find a better solution.
            unsigned long flags;
            spin_lock_irqsave(&hook_spinlock, flags);

            char *source = mem + sourceAddr;
            snprintf(source, 20, "%pI4", &ip_header->saddr);

            char *destination = mem + destinationAddr;
            snprintf(destination, 20, "%pI4", &ip_header->daddr);

            char *dnsPacket = mem + dnsPacketAddr;
            memcpy(dnsPacket, data, udp_length);

            const char *argv[1];
            char dnsId[10];
            snprintf(dnsId, 10, "%d", ntohs(dns_header.id));
            argv[0] = dnsId;

            M3Result result = repl_call("dns_query", 1, argv);
            if (result)
            {
                FATAL("netfilter.repl_call dns_query: %s", result);
                goto unlock;
            }

        unlock:
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
            unsigned udp_length = ntohs(udp_header->len);
            char *data = (char *)udp_header + sizeof(struct udphdr);
            struct dns_h dns_header;
            memcpy(&dns_header, data, DNS_HEADER_SIZE);

            printk("wasm3: dns answer (%d bytes) in request id %u answers: %u", udp_length, ntohs(dns_header.id), ntohs(dns_header.ancount));

            // Get the VM memory if there is at least one module loaded,
            // if not, accept the packet regardless.
            uint8_t *mem = repl_get_memory();
            if (!mem)
            {
                return NF_ACCEPT;
            }

            uint64_t sourceAddr = repl_global_get("SOURCE");
            if (!sourceAddr)
            {
                return NF_ACCEPT;
            }

            uint64_t destinationAddr = repl_global_get("DESTINATION");
            if (!destinationAddr)
            {
                return NF_ACCEPT;
            }

            uint64_t dnsPacketAddr = repl_global_get("DNS_PACKET");
            if (!dnsPacketAddr)
            {
                return NF_ACCEPT;
            }

            unsigned long flags;
            spin_lock_irqsave(&hook_spinlock, flags);

            char *source = mem + sourceAddr;
            snprintf(source, 20, "%pI4", &ip_header->saddr);

            char *destination = mem + destinationAddr;
            snprintf(destination, 20, "%pI4", &ip_header->daddr);

            char *dnsPacket = mem + dnsPacketAddr;
            memcpy(dnsPacket, data, udp_length);

            const char *argv[1];
            char dnsId[10];
            snprintf(dnsId, 10, "%d", ntohs(dns_header.id));
            argv[0] = dnsId;

            M3Result result = repl_call("dns_response", 1, argv);
            if (result)
            {
                FATAL("netfilter.repl_call dns_response: %s", result);
                goto unlock;
            }

        unlock:
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
