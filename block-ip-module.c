#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/timekeeping.h>
#include <linux/hash.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Basic IP Blocking Module Based on SYN/RST Counts and Packet Volume");

#define MAX_PACKETS 50                             // Maximum packet count threshold
#define OBSERVATION_PERIOD msecs_to_jiffies(30000) // 30 seconds in jiffies
#define BLOCK_DURATION msecs_to_jiffies(60000)     // 1 minute in jiffies
#define MAX_SYN_RST_COUNT 5                        // Threshold for SYN or RST counts to block

struct ip_entry {
    u32 ip;
    unsigned long first_seen;
    unsigned long block_until;
    int packet_count;
    int syn_count;  // Count of SYN packets
    int rst_count;  // Count of RST packets
    struct hlist_node hnode;
};

DEFINE_HASHTABLE(ip_table, 8); // 2^8 = 256 buckets
static struct nf_hook_ops nfho;

unsigned int ip_hashfn(u32 ip) {
    return hash_32(ip, 8);
}

static struct ip_entry *find_or_create_ip_entry(u32 ip) {
    struct ip_entry *entry;
    unsigned long now = jiffies;

    hash_for_each_possible(ip_table, entry, hnode, ip_hashfn(ip)) {
        if (entry->ip == ip) {
            if (time_after(now, entry->first_seen + OBSERVATION_PERIOD)) {
                entry->first_seen = now;
                entry->packet_count = 0;
                entry->syn_count = 0;
                entry->rst_count = 0;
            }
            return entry;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return NULL;

    entry->ip = ip;
    entry->first_seen = now;
    entry->block_until = 0;
    entry->packet_count = 0;
    entry->syn_count = 0;
    entry->rst_count = 0;
    hash_add(ip_table, &entry->hnode, ip_hashfn(ip));
    return entry;
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct ip_entry *entry;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;  // Only proceed if there's an IP header and TCP protocol

    tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
    if (!tcph)
        return NF_ACCEPT;

    entry = find_or_create_ip_entry(iph->saddr);
    if (!entry)
        return NF_ACCEPT;

    // Check for SYN and RST flags
    if (tcph->syn)
        entry->syn_count++;
    if (tcph->rst)
        entry->rst_count++;

    entry->packet_count++;
    printk(KERN_INFO "Received packet from IP: %pI4, SYN Count: %d, RST Count: %d, Total Count: %d\n",
           &iph->saddr, entry->syn_count, entry->rst_count, entry->packet_count);

    // Check if IP is currently blocked and if the block period has ended
    if (entry->block_until && time_after(jiffies, entry->block_until)) {
        printk(KERN_INFO "IP Blocking Module: IP %pI4 is no longer blocked. Block lifted.\n", &iph->saddr);
        entry->block_until = 0;  // Reset blocking timer
    }

    // If still within the blocking period, continue to block the IP
    if (time_before(jiffies, entry->block_until)) {
        printk(KERN_INFO "IP Blocking Module: Continuing to block IP: %pI4\n", &iph->saddr);
        return NF_DROP;
    }

    // Block if SYN and RST counts are both above 5
    if (entry->syn_count > MAX_SYN_RST_COUNT && entry->rst_count > MAX_SYN_RST_COUNT) {
        entry->block_until = jiffies + BLOCK_DURATION;
        printk(KERN_INFO "IP Blocking Module: Blocking IP: %pI4 for exceeding SYN/RST packet threshold\n", &iph->saddr);
        return NF_DROP;
    }

    // Block if the total packet count is above 50
    if (entry->packet_count > MAX_PACKETS) {
        entry->block_until = jiffies + BLOCK_DURATION;
        printk(KERN_INFO "IP Blocking Module: Blocking IP: %pI4 for exceeding packet count threshold\n", &iph->saddr);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int __init my_init_module(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    return nf_register_net_hook(&init_net, &nfho);
}

static void __exit my_cleanup_module(void) {
    nf_unregister_net_hook(&init_net, &nfho);

    struct ip_entry *tmp;
    struct hlist_node *tmp_node;
    int bkt;

    hash_for_each_safe(ip_table, bkt, tmp_node, tmp, hnode) {
        hash_del(&tmp->hnode);
        kfree(tmp);
    }

    printk(KERN_INFO "IP Blocking Module: Module Unloaded\n");
}

module_init(my_init_module);
module_exit(my_cleanup_module);
