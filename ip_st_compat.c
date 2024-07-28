/* Compatibility framework for ipchains and ipfwadm support; designed
   to look as much like the 2.2 infrastructure as possible. */
struct notifier_block;

#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/icmp.h>
#include <linux/if.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/netfilter_ipv4/compat_firewall.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/bitops.h>
#include <asm/semaphore.h>
#include <linux/vmalloc.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/seq_file.h>
#include <linux/smp_lock.h>
#include <linux/delay.h>
#include <linux/locks.h>
#include <linux/kernel_stat.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapctl.h>
#include <linux/blkdev.h>
#include <linux/iobuf.h>

/* #define DEBUG 1 */

#define BUFFER_SIZE 2048
#if (PAGE_SIZE < BUF_SIZE)
#define BUFFER_SIZE PAGE_SIZE   /* for not enough page size system */
#endif

static struct file *gfilp;

/*
 * fs file open / read / write / close
 */
#define file_err(format, arg...)  printk(KERN_ERR "%s : " format "\n", __FUNCTION__, ## arg)
#ifdef DEBUG
#define file_dbg(format, arg...)  printk(KERN_ERR "%s : " format "\n", __FUNCTION__, ## arg)
#else
#define file_dbg(format, arg...) do {} while (0)
#endif

/* Theoretically, we could one day use 2.4 helpers, but for now it
   just confuses depmod --RR */
EXPORT_NO_SYMBOLS;

static struct firewall_ops *fwops;

/* They call these; we do what they want. */
int ipsm_register_firewall(int pf, struct firewall_ops *fw)
{
	if (pf != PF_INET) {
		printk("Attempt to register non-IP firewall module.\n");
		return -EINVAL;
	}
	if (fwops) {
		printk("Attempt to register multiple firewall modules.\n");
		return -EBUSY;
	}

	fwops = fw;
	return 0;
}

int ipsm_unregister_firewall(int pf, struct firewall_ops *fw)
{
	fwops = NULL;
	return 0;
}

static unsigned int
fw_in(unsigned int hooknum,
      struct sk_buff **pskb,
      const struct net_device *in,
      const struct net_device *out,
      int (*okfn)(struct sk_buff *))
{
	int ret = FW_BLOCK;
	u_int16_t redirpt;

	/* Assume worse case: any hook could change packet */
	(*pskb)->nfcache |= NFC_UNKNOWN | NFC_ALTERED;
	if ((*pskb)->ip_summed == CHECKSUM_HW)
		(*pskb)->ip_summed = CHECKSUM_NONE;

	/* Firewall rules can alter TOS: raw socket (tcpdump) may have
           clone of incoming skb: don't disturb it --RR */
	if (skb_cloned(*pskb) && !(*pskb)->sk) {
		struct sk_buff *nskb = skb_copy(*pskb, GFP_ATOMIC);
		if (!nskb)
			return NF_DROP;
		kfree_skb(*pskb);
		*pskb = nskb;
	}

	switch (hooknum) {
	case NF_IP_PRE_ROUTING:
		if ((*pskb)->nh.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		  file_dbg("!!(*pskb)->nh.iph->frag_off & htons()!!\n"); /*** DDD **/
		}

		ret = fwops->fw_input(fwops, PF_INET, (struct net_device *)in,
				      (*pskb)->nh.raw, &redirpt, pskb);
		break;
	}

	switch (ret) {
	case FW_REJECT: {
		/* Alexey says:
		 *
		 * Generally, routing is THE FIRST thing to make, when
		 * packet enters IP stack. Before packet is routed you
		 * cannot call any service routines from IP stack.  */
		struct iphdr *iph = (*pskb)->nh.iph;

		if ((*pskb)->dst != NULL
		    || ip_route_input(*pskb, iph->daddr, iph->saddr, iph->tos,
				      (struct net_device *)in) == 0)
			icmp_send(*pskb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH,
				  0);
		return NF_DROP;
	}

	case FW_ACCEPT:
	case FW_SKIP:
		return NF_ACCEPT;
	default:
		/* FW_BLOCK */
		return NF_DROP;
	}
}

extern int ipsm_ctl(int optval, void *m, unsigned int len);

static struct nf_hook_ops preroute_ops
/* = { { NULL, NULL }, fw_in, PF_INET, NF_IP_PRE_ROUTING, NF_IP_PRI_FILTER }; */
= { { NULL, NULL }, fw_in, PF_INET, NF_IP_PRE_ROUTING, NF_IP_PRI_CONNTRACK-20};

extern int ipsm_init_or_cleanup(int init);

static int init_or_cleanup(int init)
{
	int ret = 0;

	if (!init) goto cleanup;

	if (ret < 0)
		goto cleanup_nothing;

	ret = ipsm_init_or_cleanup(1);
	if (ret < 0)
		goto cleanup_sockopt;

	if (ret < 0)
		goto cleanup_ipsm;

	nf_register_hook(&preroute_ops);

	return ret;

 cleanup:
	nf_unregister_hook(&preroute_ops);

 cleanup_ipsm:
	ipsm_init_or_cleanup(0);

 cleanup_sockopt:

 cleanup_nothing:
	return ret;
}

static int __init init(void)
{
	return init_or_cleanup(1);
}

static void __exit fini(void)
{
	init_or_cleanup(0);
}

MODULE_LICENSE("GPL");
module_init(init);
module_exit(fini);

struct file *
file_open(char *filename, int flags, int mode)
{
	struct file *filp;

	filp = filp_open(filename, flags, mode);
	if (filp==NULL || IS_ERR(filp)) {
		file_err("cannot open file = %s", filename);
		return NULL;  /* Or do something else */
	}
	if (filp->f_op->read == NULL || filp->f_op->write == NULL) {
		file_err("File(system) doesn't allow reads / writes");
		return NULL;
	}
	if (!S_ISREG(filp->f_dentry->d_inode->i_mode)) {
		filp_close(filp, NULL);
		file_err("%s is NOT a regular file", filename);
		return NULL;  /* Or do something else */
	}
	file_dbg("file mode = %08x, f_pos = %d",
		 filp->f_dentry->d_inode->i_mode, (int) filp->f_pos);
	return(filp);
}

int
file_read(struct file *filp, void *buf, int count)
{
	mm_segment_t oldfs;
	int BytesRead;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	BytesRead = filp->f_op->read(filp, buf, count, &filp->f_pos);

	file_dbg("BytesRead = %d", BytesRead);

	set_fs(oldfs);
	return BytesRead;
}

int
file_write(struct file *filp, void *buf, int count)
{
	mm_segment_t oldfs;
	int BytesWrite;

	if (buf == NULL) printk("before get_fs(): buf == NULL\n");
        oldfs = get_fs();
        set_fs(KERNEL_DS);
	/* filp->f_pos = StartPos; */
	/*if (buf == NULL) printk("after get_fs(): buf == NULL\n");*/

        BytesWrite = filp->f_op->write(filp, buf, count, &filp->f_pos);

	file_dbg("BytesWrite = %d", BytesWrite);
/*	file_err("BytesWrite = %d, buf = %08x, bufsiz = %d",
		 count, buf, sizeof(buf));
*/
        set_fs(oldfs);
	return BytesWrite;
}

void
file_close(struct file *filp)
{
	fput(filp);
	filp_close(filp, NULL);
}

/*
 */
struct spacket {
        int len;
        char *buf;
};

int
ip_st_opened(void)
{
	return(gfilp != NULL);
}

/*
 *
 */
static unsigned long kth_cmd = 0;

#ifdef DEBUG
static int debug;
#endif

/*
 * ring buffer
 */
#define RX_BUFSIZE      1024

#define HSIO_SUCCESS    0
#define HSIO_RECEIVED   1
#define HSIO_TRANSMITTED 2
#define HSIO_FRAMING    -1
#define HSIO_PARITY     -2
#define HSIO_OVERRUN    -3
#define HSIO_USEROFLO   -4
#define HSIO_USERUFLO   -5
#define HSIO_NODATA     -6
#define HSIO_UNKNOWN    -7

struct sci {
        int rxstat;
        int rxsys;
        int rxusr;
        int rxcnt;
        char *data[RX_BUFSIZE];
} sci_port[1];

void ring_alloc(void)
{
        struct sci *pp;
	int i;

        pp = &sci_port[0];
        for(i = 0; i < RX_BUFSIZE; i++) {
                pp->data[i] = kmalloc(BUFFER_SIZE, GFP_KERNEL);
		if (pp->data[i] == NULL) {
			printk("kmalloc fail\n");
			break;
		}
        }
}

void ring_free(void)
{
        struct sci *pp;
	int i;

        pp = &sci_port[0];
        for(i = 0; i < RX_BUFSIZE; i++) {
		if (pp->data[i] != NULL) {
			kfree(pp->data[i]);
			pp->data[i] = NULL;
		}
        }
}

char *ring_qget(void)
{
        struct sci *pp;
        char *b;

        pp = &sci_port[0];
        if(pp->rxcnt > 0) {
                /* file_dbg("cnt = %d\n", pp->rxcnt); */

                b = pp->data[pp->rxusr];
                pp->rxusr++;
                pp->rxusr &= (RX_BUFSIZE - 1); /* rotete to top, if overed */
                if(--pp->rxcnt == 0 && pp->rxstat == HSIO_RECEIVED)
                        pp->rxstat = HSIO_SUCCESS;
        }
        else {  /* no data, error only */
                b = NULL;
                pp->rxstat = HSIO_SUCCESS;
                file_dbg("no data!\n");
        }
        return(b);
}

void ring_qput(char *b)
{
        struct sci *pp;

        pp = &sci_port[0];
        memcpy(pp->data[pp->rxsys], b, 1024);
	pp->rxstat = HSIO_RECEIVED;
        pp->rxcnt++;
        pp->rxsys++;
        pp->rxsys &= (RX_BUFSIZE - 1); /* rotete to top, if overed */
        if (pp->rxsys == pp->rxusr){    /* Check the previous User Status */
                pp->rxstat = HSIO_USEROFLO;
                file_dbg("overrup error!\n");
        }
}

/*
 * kernel thread
 */
typedef struct kth_thread_s {
        void                    (*run) (void *data);
        void                    *data;
        wait_queue_head_t    wqueue;
        unsigned long           flags;
        struct completion       *event;
        struct task_struct      *tsk;
        const char              *name;
} kth_thread_t;

static inline void kth_init_signals (void)
{
        current->exit_signal = SIGCHLD;
        siginitsetinv(&current->blocked, sigmask(SIGKILL));
}

static inline void kth_flush_signals (void)
{
        spin_lock(&current->sigmask_lock);
        flush_signals(current);
        spin_unlock(&current->sigmask_lock);
}

static kth_thread_t *kth_write_thread;

#define THREAD_WAKEUP  0

/*
 * thread main
 */
void kth_do_write(void *data)
{
	int len;
	char *p;

        file_dbg("*** KTH sleep thread got woken up ...\n");
	while(gfilp && (p = ring_qget())) {
		len = file_write(gfilp, p, 1024 /* (fixed now) or BUFFER_SIZE, length */);
		/* vfree(p); */
		file_dbg("*** KTH wrote length = %d\n", len);
	}
        file_dbg("*** KTH sleep thread finished ...\n");
}

int kth_thread(void *arg)
{
        kth_thread_t *thread = arg;

        lock_kernel();
        daemonize();
        sprintf(current->comm, thread->name);
        kth_init_signals();
        kth_flush_signals();

        thread->tsk = current;
        current->policy = SCHED_OTHER;
        /* current->nice = -20; */
        unlock_kernel();
        complete(thread->event);

	gfilp = file_open("/tmp/packetlog", O_CREAT|O_WRONLY|O_TRUNC, 0666);

        while (thread->run) {
                void (*run)(void *data);
                DECLARE_WAITQUEUE(wait, current);

                add_wait_queue(&thread->wqueue, &wait);
                set_task_state(current, TASK_INTERRUPTIBLE);
                if (!test_bit(THREAD_WAKEUP, &thread->flags)) {
                        file_dbg("*** thread %p went to sleep.\n", thread);
                        schedule();
                        file_dbg("*** thread %p woke up.\n", thread);
                }
                current->state = TASK_RUNNING;
                remove_wait_queue(&thread->wqueue, &wait);
                clear_bit(THREAD_WAKEUP, &thread->flags);

                run = thread->run;
                if (run) {
                        run(thread->data);
                        run_task_queue(&tq_disk);
                }
                if (signal_pending(current))
                        kth_flush_signals();
        }
	if (gfilp) {
		file_close(gfilp);
		gfilp = NULL;
	}

        complete(thread->event);

	return(0);
}

/*
 * support routines
 */
void kth_wakeup_thread(kth_thread_t *thread)
{
        file_dbg("** waking up KTH thread %p.\n", thread);

	if (gfilp == NULL)
		gfilp = file_open("/tmp/packetlog", O_CREAT|O_WRONLY|O_TRUNC, 0666);

        set_bit(THREAD_WAKEUP, &thread->flags);
        wake_up(&thread->wqueue);
}

kth_thread_t *kth_register_thread(void (*run) (void *),
				void *data, const char *name)
{
	int ret;
	kth_thread_t *thread;
        struct completion event;

        thread = (kth_thread_t *) kmalloc(sizeof(kth_thread_t), GFP_KERNEL);
        if (!thread)
                return NULL;

        memset(thread, 0, sizeof(kth_thread_t));
        init_waitqueue_head(&thread->wqueue);

	init_completion(&event);
	thread->event=&event;
	thread->run=run;
	thread->data=data;
	thread->name=name;

        ret = kernel_thread(kth_thread, thread, 0);
        if (ret < 0) {
                kfree(thread);
                return NULL;
        }

        wait_for_completion(&event);
	return(thread);
}

void kth_interrupt_thread(kth_thread_t *thread)
{
        if (!thread->tsk) {
                printk("** interrupt error\n");
                return;
        }
        file_dbg("** interrupting KTH-thread pid %d\n", thread->tsk->pid);
	if (gfilp != NULL) {
		file_close(gfilp);
		gfilp = NULL;
	}
        send_sig(SIGKILL, thread->tsk, 1);
}

void kth_unregister_thread(kth_thread_t *thread)
{
        struct completion event;

        init_completion(&event);

        thread->event = &event;
        thread->run = NULL;
        thread->name = NULL;
        kth_interrupt_thread(thread);
        wait_for_completion(&event);

        kfree(thread);
}

/*
 * kth_read_proc -- called when user reading, 
 * it makes interrupt capture, and close file
 */
int kth_read_proc(char *buf, char **start, off_t offset,
                   int count, int *eof, void *data)
{
	char in_data[BUFFER_SIZE];
	unsigned long req_cmd = 0;
	int return_length = 0;

	file_dbg("**read_proc(), count = %d, off = %d\n",
	       count, (int) offset);
	if (offset == 0) {

		req_cmd = kth_cmd;

		memset(in_data, 0, BUFFER_SIZE);
		return_length = sprintf(in_data, "%lu\n", req_cmd);
		memcpy(buf, in_data, return_length);
		file_dbg("**read_proc(), cmd = %lu\n", simple_strtoul(in_data, NULL, 10));

		kth_interrupt_thread(kth_write_thread);
	}
	*eof = 1;
	*start = buf + offset;
	return return_length;
}

/*
 * kth_write_proc -- called when user writing
 * it makes restart capture
 */
int kth_write_proc(struct file *file, const char *buf,
                     unsigned long count, void *data)
{
	char out_data[BUFFER_SIZE];
	int length;
	char *p;
 
	file_dbg("**write_proc(), count = %d\n", (int) count);

	length = count > BUFFER_SIZE ? BUFFER_SIZE : count; /* limit of max size */
	   
	copy_from_user(out_data, buf, length);
	kth_cmd = simple_strtoul(out_data, &p, 10);
	file_dbg("write_file(), cmd = %ld\n", kth_cmd);

	kth_wakeup_thread(kth_write_thread);

	return length;
}

void
ip_st_wakeup(void)
{
	kth_wakeup_thread(kth_write_thread);
}

void
ip_st_register(void)
{
	kth_write_thread = kth_register_thread(kth_do_write, (void *) 5, "kthwrite");
}

void
ip_st_unregister(void)
{
	kth_unregister_thread(kth_write_thread);
}
