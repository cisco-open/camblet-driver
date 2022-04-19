#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "wasm_module.h"
#include "netfilter.h"

char *outiplist[50]; // array holding outgoing ip address to block

int in_index = 0, out_index = 0; // index for iniplist and outiplist

struct net n;
static struct nf_hook_ops nfho_out; // net filter hook option struct
struct sk_buff *sock_buff;

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header; // ip header struct

    sock_buff = skb;
    if (!sock_buff)
    {
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(sock_buff); // grab network header using accessor

    // Get the VM memory if there is at least one module loaded,
    // if not, accept the packet anyhow.
    uint8_t* mem = repl_get_memory();
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

    printk("source: %lld, destination: %lld", sourceAddr, destinationAddr);

    char *source = mem + sourceAddr;
    int len = snprintf(source, 20, "%pI4", &ip_header->saddr);

    char *destination = mem + destinationAddr;
    len = snprintf(destination, 20, "%pI4", &ip_header->daddr);

    int i;
    // const char *argv[4] = {source, source_len, destination, destination_len};
    // for (i = 0; i < 4; i++) {
    //     printk(argv[i]);
    // }
    M3Result result = repl_call("ip_debugger", 0, NULL);
    if (result)
    {
        FATAL("netfilter.repl_call ip_debugger: %s", result);
    }

    // for debug purpose
    // printk(KERN_INFO "got source address: %s\n", source);
    // printk(KERN_INFO "got destination address: %s\n", destination);

    // for debug purpose
    // printk("length of source: %d\n", strlen(source));
    // printk("iniplist[0] length: %d\n", strlen(iniplist[0]));

    // if the source address and destination address is in the proc file, drop it;

    for (i = 0; i < out_index; i++)
    {
        if (strcmp(destination, outiplist[i]) == 0)
        {
            printk("Drop outgoing packet to %s\n", destination);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

int start_netfilter_submodule(void)
{
    pr_info("---- netfilter submodule init() ---");

    // register hook for outgoing traffic
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho_out);

    pr_info("---- netfilter started ----");

    return 0;
}

int stop_netfilter_submodule(void)
{
    nf_unregister_net_hook(&init_net, &nfho_out);

    return 0;
}
