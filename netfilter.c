/*

                Christian Papathanasiou 
Netfilter Kernel Module which acts as a Network  Based IDS. 

*/

#include <linux/syscalls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/byteorder/generic.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/kmod.h>
#include "httprules.h"



static char * __ntoa(u32 ip);
unsigned long global_ip;

static char *
__ntoa (u32 ip)
{
        static char address[32];        // made into a word just for the sake of it
        unsigned char A = (char) ((ntohl (ip) >> 24) & 0xff);
        unsigned char B = (char) ((ntohl (ip) >> 16) & 0xff);
        unsigned char C = (char) ((ntohl (ip) >> 8) & 0xff);
        unsigned char D = (char) ((ntohl (ip) >> 0) & 0xff);
        /* is the address valid ? */
        if ((A + B + C + D) <= 1020)
        {
                /* return the address as a string */
                sprintf ((char *) address, "%d.%d.%d.%d%c", A, B, C, D, 0);
                return (char *) address;
        }
        else
        {
                return NULL;
        }
}



/* Start NetFilter Hooks */ 
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfhw;

unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb,
const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
struct sk_buff *sb = *skb;
struct tcphdr *tcp;
tcp = (struct tcphdr *)(sb->data + (sb->nh.iph->ihl * 4));
return NF_ACCEPT; 
}

void findnops(struct sk_buff *skb) 
{
struct tcphdr *tcp;
char *data;
char src[17];

int t;
unsigned long global_ip;
tcp = (struct tcphdr *)(skb->data + (skb->nh.iph->ihl * 4));
data = (char *)((int)tcp + (int)(tcp->doff * 4));

for (t = 0; t<3478; t++) { 
	if (strstr(data,exploit[t].target) != NULL) {
		printk(KERN_ALERT "detected attack: %s\n",exploit[t].target);
	break;
	}
}
	


}


unsigned int watch_out(unsigned int hooknum, struct sk_buff **skb,
const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
struct sk_buff *sb = *skb;
struct tcphdr *tcp;

tcp = (struct tcphdr *)(sb->data + (sb->nh.iph->ihl * 4));


if (tcp->dest == htons(80)) { 
printk(KERN_ALERT "accepted http request\n");
findnops(sb);
return NF_ACCEPT;
}
else { return NF_ACCEPT; } 



}



static int __init ho_start(void)
{
//START

nfho.hook = hook_func;
nfho.hooknum = NF_IP_PRE_ROUTING;
nfho.pf = PF_INET;
nfho.priority = NF_IP_PRI_FIRST;
nf_register_hook(&nfho);

nfhw.hook = watch_out;
nfhw.pf = PF_INET;
nfhw.priority = NF_IP_PRI_FIRST;
nfhw.hooknum = NF_IP_POST_ROUTING;

nf_register_hook(&nfhw);


return 0;
}

static void __exit ho_exit(void)
{
//EXIT
nf_unregister_hook(&nfho);

}

module_init(ho_start);
module_exit(ho_exit);
MODULE_LICENSE("GPL");
