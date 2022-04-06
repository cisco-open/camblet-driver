#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

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

    char destination[50];
    snprintf(destination, 50, "%pI4", &ip_header->daddr);

    char source[50];
    snprintf(source, 50, "%pI4", &ip_header->saddr);

    // for debug purpose
    // printk(KERN_INFO "got source address: %s\n", source);
    // printk(KERN_INFO "got destination address: %s\n", destination);

    // for debug purpose
    // printk("length of source: %d\n", strlen(source));
    // printk("iniplist[0] length: %d\n", strlen(iniplist[0]));

    // if the source address and destination address is in the proc file, drop it;
    int i;

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
