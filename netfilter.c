#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "netfilter.h"
#include "runtime.h"

#define DNS_MODULE "dns"

static struct nf_hook_ops nfho_in;  // net filter hook option struct
static struct nf_hook_ops nfho_out; // net filter hook option struct

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!skb)
    {
        goto accept;
    }

    unsigned char *packetData = skb->data;
    unsigned packetLen = skb->len;

    wasm_vm *vm = current_wasm_vm();
    wasm_vm_lock(vm);

    // printk("wasm3: skb_is_nonlinear %s (len: %d, data_len: %d)", skb_is_nonlinear(skb) ? "true" : "false", skb->len, skb->data_len);

    // Get the VM memory if there is at least one module loaded,
    // if not, accept the packet regardless.
    uint8_t *mem = wasm_vm_memory(vm);
    if (!mem)
    {
        goto accept;
    }

    wasm_vm_module *module = wasm_vm_get_module(vm, DNS_MODULE);
    if (!module)
    {
        goto accept;
    }

    wasm_vm_result result = wasm_vm_malloc(vm, DNS_MODULE, packetLen);
    if (result.err)
    {
        FATAL("netfilter wasm_vm_malloc error: %s", result.err);
        goto accept;
    }

    i32 wasmPacket = result.data[0].i32;

    char *wasmPacketPtr = mem + wasmPacket;
    memcpy(wasmPacketPtr, packetData, packetLen);

    result = wasm_vm_call(vm,
                          DNS_MODULE,
                          "packet_out",
                          wasmPacket,
                          packetLen);

    wasm_vm_free(vm, DNS_MODULE, wasmPacket, packetLen);

    if (result.err)
    {
        FATAL("netfilter packet_out error: %s", result.err);
        goto accept;
    }

accept:
    wasm_vm_unlock(vm);
    return NF_ACCEPT;
}

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!skb)
    {
        goto accept;
    }

    unsigned char *packetData = skb->data;
    unsigned packetLen = skb->len;

    wasm_vm *vm = current_wasm_vm();
    wasm_vm_lock(vm);

    // Get the VM memory if there is at least one module loaded,
    // if not, accept the packet regardless.
    uint8_t *mem = wasm_vm_memory(vm);
    if (!mem)
    {
        goto accept;
    }

    wasm_vm_module *module = wasm_vm_get_module(vm, DNS_MODULE);
    if (!module)
    {
        goto accept;
    }

    wasm_vm_result result = wasm_vm_malloc(vm, DNS_MODULE, packetLen);
    if (result.err)
    {
        FATAL("netfilter wasm_vm_malloc error: %s", result.err);
        goto accept;
    }

    i32 wasmPacket = result.data[0].i32;

    char *wasmPacketPtr = mem + wasmPacket;
    memcpy(wasmPacketPtr, packetData, packetLen);

    result = wasm_vm_call(vm,
                          DNS_MODULE,
                          "packet_in",
                          wasmPacket,
                          packetLen);

    wasm_vm_free(vm, DNS_MODULE, wasmPacket, packetLen);

    if (result.err)
    {
        FATAL("netfilter packet_in error: %s", result.err);
        goto accept;
    }

accept:
    wasm_vm_unlock(vm);
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

    // register hook for incoming traffic
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
