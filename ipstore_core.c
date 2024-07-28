/* Minor modifications to fit on compatibility framework:
   Rusty.Russell@rustcorp.com.au
*/

#include <linux/config.h>
#define CONFIG_IP_FIREWALL
#if defined(CONFIG_NETLINK_DEV) || defined(CONFIG_NETLINK_DEV_MODULE)
#define CONFIG_IP_FIREWALL_NETLINK
#endif

/*
 *	IP firewalling code. This is taken from 4.4BSD. Please note the
 *	copyright message below. As per the GPL it must be maintained
 *	and the licenses thus do not conflict. While this port is subject
 *	to the GPL I also place my modifications under the original
 *	license in recognition of the original copyright.
 *				-- Alan Cox.
 *
 *	$Id: ipfwadm_core.c,v 1.9.2.2 2002/01/24 15:50:42 davem Exp $
 *
 *	Ported from BSD to Linux,
 *		Alan Cox 22/Nov/1994.
 *	Zeroing /proc and other additions
 *		Jos Vos 4/Feb/1995.
 *	Merged and included the FreeBSD-Current changes at Ugen's request
 *	(but hey it's a lot cleaner now). Ugen would prefer in some ways
 *	we waited for his final product but since Linux 1.2.0 is about to
 *	appear it's not practical - Read: It works, it's not clean but please
 *	don't consider it to be his standard of finished work.
 *		Alan Cox 12/Feb/1995
 *	Porting bidirectional entries from BSD, fixing accounting issues,
 *	adding struct ip_fwpkt for checking packets with interface address
 *		Jos Vos 5/Mar/1995.
 *	Established connections (ACK check), ACK check on bidirectional rules,
 *	ICMP type check.
 *		Wilfred Mollenvanger 7/7/1995.
 *	TCP attack protection.
 *		Alan Cox 25/8/95, based on information from bugtraq.
 *	ICMP type printk, IP_FW_F_APPEND
 *		Bernd Eckenfels 1996-01-31
 *	Split blocking chain into input and output chains, add new "insert" and
 *	"append" commands to replace semi-intelligent "add" command, let "delete".
 *	only delete the first matching entry, use 0xFFFF (0xFF) as ports (ICMP
 *	types) when counting packets being 2nd and further fragments.
 *		Jos Vos <jos@xos.nl> 8/2/1996.
 *	Add support for matching on device names.
 *		Jos Vos <jos@xos.nl> 15/2/1996.
 *	Transparent proxying support.
 *		Willy Konynenberg <willy@xos.nl> 10/5/96.
 *	Make separate accounting on incoming and outgoing packets possible.
 *		Jos Vos <jos@xos.nl> 18/5/1996.
 *	Added trap out of bad frames.
 *		Alan Cox <alan@cymru.net> 17/11/1996
 *
 *
 * Masquerading functionality
 *
 * Copyright (c) 1994 Pauline Middelink
 *
 * The pieces which added masquerading functionality are totally
 * my responsibility and have nothing to with the original authors
 * copyright or doing.
 *
 * Parts distributed under GPL.
 *
 * Fixes:
 *	Pauline Middelink	:	Added masquerading.
 *	Alan Cox		:	Fixed an error in the merge.
 *	Thomas Quinot		:	Fixed port spoofing.
 *	Alan Cox		:	Cleaned up retransmits in spoofing.
 *	Alan Cox		:	Cleaned up length setting.
 *	Wouter Gadeyne		:	Fixed masquerading support of ftp PORT commands
 *
 *	Juan Jose Ciarlante	:	Masquerading code moved to ip_masq.c
 *	Andi Kleen :		Print frag_offsets and the ip flags properly.
 *
 *	All the real work was done by .....
 *
 */


/*
 * Copyright (c) 1993 Daniel Boulet
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/page.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/icmp.h>
#include <linux/netlink.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/netfilter_ipv4/compat_firewall.h>
#include "ipsimple_core.h"
/* #include <linux/netfilter_ipv4/ipsimple_core.h> */
#include <linux/netfilter_ipv4/lockhelp.h>
#include <linux/netfilter_ipv4/ip_nat_core.h>

#include <net/checksum.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/version.h>
/* #include <linux/tqueue.h> */

extern int ip_st_opened(void);
extern void ip_st_wakeup(void);
extern void ip_st_register(void);
extern void ip_st_unregister(void);
extern void ring_qput(char *b);
extern void ring_alloc(void);
extern void ring_free(void);

/*
 *	Implement IP packet firewall
 */
#ifdef DEBUG_IP_FIREWALL
#define dprintf1(a)		printk(a)
#define dprintf2(a1,a2)		printk(a1,a2)
#define dprintf3(a1,a2,a3)	printk(a1,a2,a3)
#define dprintf4(a1,a2,a3,a4)	printk(a1,a2,a3,a4)
#else
#define dprintf1(a)
#define dprintf2(a1,a2)
#define dprintf3(a1,a2,a3)
#define dprintf4(a1,a2,a3,a4)
#endif

#define print_ip(a)	 printk("%u.%u.%u.%u", NIPQUAD(a));

#ifdef DEBUG_IP_FIREWALL
#define dprint_ip(a)	print_ip(a)
#else
#define dprint_ip(a)
#endif

static DECLARE_RWLOCK(ip_fw_lock);

#if defined(CONFIG_IP_ACCT) || defined(CONFIG_IP_FIREWALL)

struct ip_fw *ipsm_fwd_chain;
struct ip_fw *ipsm_in_chain;
struct ip_fw *ipsm_out_chain;
struct ip_fw *ipsm_acct_chain;
struct ip_fw *ipsm_masq_chain;

static struct ip_fw **chains[] =
	{&ipsm_fwd_chain, &ipsm_in_chain, &ipsm_out_chain, &ipsm_acct_chain,
	 &ipsm_masq_chain
	};
#endif /* CONFIG_IP_ACCT || CONFIG_IP_FIREWALL */

#ifdef CONFIG_IP_FIREWALL
int ipsm_fwd_policy=IP_FW_F_ACCEPT;
int ipsm_in_policy=IP_FW_F_ACCEPT;
int ipsm_out_policy=IP_FW_F_ACCEPT;

static int *policies[] =
	{&ipsm_fwd_policy, &ipsm_in_policy, &ipsm_out_policy};

#endif

#ifdef CONFIG_IP_FIREWALL_NETLINK
/*struct sock *ipsmsk; */
#endif

/*
 *	Returns 1 if the port is matched by the vector, 0 otherwise
 */

extern inline int port_match(unsigned short *portptr,int nports,unsigned short port,int range_flag)
{
	if (!nports)
		return 1;
	if ( range_flag )
	{
		if ( portptr[0] <= port && port <= portptr[1] )
		{
			return( 1 );
		}
		nports -= 2;
		portptr += 2;
	}
	while ( nports-- > 0 )
	{
		if ( *portptr++ == port )
		{
			return( 1 );
		}
	}
	return(0);
}

#if defined(CONFIG_IP_ACCT) || defined(CONFIG_IP_FIREWALL)

/*
 *	Returns one of the generic firewall policies, like FW_ACCEPT.
 *	Also does accounting so you can feed it the accounting chain.
 *
 *	The modes is either IP_FW_MODE_FW (normal firewall mode),
 *	IP_FW_MODE_ACCT_IN or IP_FW_MODE_ACCT_OUT (accounting mode,
 *	steps through the entire chain and handles fragments
 *	differently), or IP_FW_MODE_CHK (handles user-level check,
 *	counters are not updated).
 */

static
int ipsm_chk(struct iphdr *ip, struct net_device *rif, __u16 *redirport,
	      struct ip_fw *chain, int policy, int mode)
{
	struct tcphdr		*tcp=(struct tcphdr *)((__u32 *)ip+ip->ihl);
	struct udphdr		*udp=(struct udphdr *)((__u32 *)ip+ip->ihl);
	/* struct icmphdr		*icmp=(struct icmphdr *)((__u32 *)ip+ip->ihl); */
	__u32			src, dst;
	__u16			src_port=0xFFFF, dst_port=0xFFFF; /*, icmp_type=0xFF; */
	unsigned short		offset;
	extern int debug;

	/*
	 *	If the chain is empty follow policy. The BSD one
	 *	accepts anything giving you a time window while
	 *	flushing and rebuilding the tables.
	 */

	src = ip->saddr;
	dst = ip->daddr;

	offset = ntohs(ip->frag_off) & IP_OFFSET;

	if (!offset) {
		if (ip->protocol==IPPROTO_TCP) {
			src_port=ntohs(tcp->source);
			dst_port=ntohs(tcp->dest);
		}
		else if (ip->protocol==IPPROTO_UDP) {
			src_port=ntohs(udp->source);
			dst_port=ntohs(udp->dest);
		}
	}

#if 0 /* def DEBUG_IP_FIREWALL */
	dprint_ip(ip->saddr);
	dprintf2(":%d -> ", src_port);
	dprint_ip(ip->daddr);
	dprintf2(":%d\n", dst_port);
#endif

	if (ip_st_opened() && ip->protocol == IPPROTO_TCP) {
		if (debug)
			printk("ipsm_chk(%d) [%s]\n", smp_processor_id(),
			       current->comm);
		ring_qput((char *)ip);
		ip_st_wakeup();
		/*printk("packet chained\n");*/
	}
	return FW_ACCEPT;
}

static void zero_fw_chain(struct ip_fw *chainptr)
{
	struct ip_fw *ctmp=chainptr;
        WRITE_LOCK(&ip_fw_lock);
	while(ctmp)
	{
		ctmp->fw_pcnt=0L;
		ctmp->fw_bcnt=0L;
		ctmp=ctmp->fw_next;
	}
	WRITE_UNLOCK(&ip_fw_lock);
}

static void free_fw_chain(struct ip_fw *volatile* chainptr)
{
        WRITE_LOCK(&ip_fw_lock);
	while ( *chainptr != NULL )
	{
		struct ip_fw *ftmp;
		ftmp = *chainptr;
		*chainptr = ftmp->fw_next;
		kfree(ftmp);
		/* MOD_DEC_USE_COUNT; */
	}
	WRITE_UNLOCK(&ip_fw_lock);
}

/*** DDD ***/
static void
print_fw(struct ip_fw *p)
{
  int i;

  printk("*fw_chain: src = %08x, dst = %08x, via = %08x, flg = %04x, nsp = %04x, ndp = %04x\n",
	 p->fw_src.s_addr,
	 p->fw_dst.s_addr,
	 p->fw_via.s_addr,
	 p->fw_flg,
	 p->fw_nsp,
	 p->fw_ndp);

  if ((i = (int) p->fw_viadev) != 0 && i != -1)
    printk("*      : viadev.name = %s, vianame = %s\n",
	   p->fw_viadev->name ? p->fw_viadev->name : "(null)",
	   p->fw_vianame ? p->fw_vianame : "(null)");
}
/*** DDD ***/


/* Volatiles to keep some of the compiler versions amused */

static int insert_in_chain(struct ip_fw *volatile* chainptr, struct ip_fw *frwl,int len)
{
	struct ip_fw *ftmp;

	ftmp = kmalloc( sizeof(struct ip_fw), GFP_ATOMIC );
	if ( ftmp == NULL )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("ipsm_ctl:  malloc said no\n");
#endif
		return( ENOMEM );
	}

	memcpy(ftmp, frwl, len);
	/*
	 *	Allow the more recent "minimise cost" flag to be
	 *	set. [Rob van Nieuwkerk]
	 */
	ftmp->fw_tosand |= 0x01;
	ftmp->fw_tosxor &= 0xFE;
	ftmp->fw_pcnt=0L;
	ftmp->fw_bcnt=0L;

        WRITE_LOCK(&ip_fw_lock);

	if ((ftmp->fw_vianame)[0]) {
		if (!(ftmp->fw_viadev = dev_get_by_name(ftmp->fw_vianame)))
			ftmp->fw_viadev = (struct net_device *) -1;
	} else
		ftmp->fw_viadev = NULL;

	ftmp->fw_next = *chainptr;
       	*chainptr=ftmp;
	WRITE_UNLOCK(&ip_fw_lock);

	/* MOD_INC_USE_COUNT; */

	/*** DDD ***/
	print_fw(ftmp);

	return(0);
}

static int append_to_chain(struct ip_fw *volatile* chainptr, struct ip_fw *frwl,int len)
{
	struct ip_fw *ftmp;
	struct ip_fw *chtmp=NULL;
	struct ip_fw *volatile chtmp_prev=NULL;

	ftmp = kmalloc( sizeof(struct ip_fw), GFP_ATOMIC );
	if ( ftmp == NULL )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("ipsm_ctl:  malloc said no\n");
#endif
		return( ENOMEM );
	}

	memcpy(ftmp, frwl, len);
	/*
	 *	Allow the more recent "minimise cost" flag to be
	 *	set. [Rob van Nieuwkerk]
	 */
	ftmp->fw_tosand |= 0x01;
	ftmp->fw_tosxor &= 0xFE;
	ftmp->fw_pcnt=0L;
	ftmp->fw_bcnt=0L;

	ftmp->fw_next = NULL;

        WRITE_LOCK(&ip_fw_lock);

	if ((ftmp->fw_vianame)[0]) {
		if (!(ftmp->fw_viadev = dev_get_by_name(ftmp->fw_vianame)))
			ftmp->fw_viadev = (struct net_device *) -1;
	} else
		ftmp->fw_viadev = NULL;

	chtmp_prev=NULL;
	for (chtmp=*chainptr;chtmp!=NULL;chtmp=chtmp->fw_next)
		chtmp_prev=chtmp;

	if (chtmp_prev)
		chtmp_prev->fw_next=ftmp;
	else
        	*chainptr=ftmp;
	WRITE_UNLOCK(&ip_fw_lock);
	/* MOD_INC_USE_COUNT; */

	/*** DDD ***/
	print_fw(ftmp);

	return(0);
}

static int del_from_chain(struct ip_fw *volatile*chainptr, struct ip_fw *frwl)
{
	struct ip_fw 	*ftmp,*ltmp;
	unsigned short	tport1,tport2,tmpnum;
	char		matches,was_found;

        WRITE_LOCK(&ip_fw_lock);

	ftmp=*chainptr;

	if ( ftmp == NULL )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("ipsm_ctl:  chain is empty\n");
#endif
		return( EINVAL );
	}

	ltmp=NULL;
	was_found=0;

	while( !was_found && ftmp != NULL )
	{
		matches=1;
		if (ftmp->fw_src.s_addr!=frwl->fw_src.s_addr
		     ||  ftmp->fw_dst.s_addr!=frwl->fw_dst.s_addr
		     ||  ftmp->fw_smsk.s_addr!=frwl->fw_smsk.s_addr
		     ||  ftmp->fw_dmsk.s_addr!=frwl->fw_dmsk.s_addr
		     ||  ftmp->fw_via.s_addr!=frwl->fw_via.s_addr
		     ||  ftmp->fw_flg!=frwl->fw_flg)
        		matches=0;

		tport1=ftmp->fw_nsp+ftmp->fw_ndp;
		tport2=frwl->fw_nsp+frwl->fw_ndp;
		if (tport1!=tport2)
		        matches=0;
		else if (tport1!=0)
		{
			for (tmpnum=0;tmpnum < tport1 && tmpnum < IP_FW_MAX_PORTS;tmpnum++)
        		if (ftmp->fw_pts[tmpnum]!=frwl->fw_pts[tmpnum])
				matches=0;
		}
		if (strncmp(ftmp->fw_vianame, frwl->fw_vianame, IFNAMSIZ))
		        matches=0;
		if(matches)
		{
			was_found=1;
			if (ltmp)
			{
				ltmp->fw_next=ftmp->fw_next;
				kfree(ftmp);
				ftmp=ltmp->fw_next;
        		}
      			else
      			{
      				*chainptr=ftmp->fw_next;
	 			kfree(ftmp);
				ftmp=*chainptr;
			}
		}
		else
		{
			ltmp = ftmp;
			ftmp = ftmp->fw_next;
		 }
	}
	WRITE_UNLOCK(&ip_fw_lock);
	if (was_found) {
		/* MOD_DEC_USE_COUNT; */
		return 0;
	} else
		return(EINVAL);
}

#endif  /* CONFIG_IP_ACCT || CONFIG_IP_FIREWALL */

struct ip_fw *check_ipsm_struct(struct ip_fw *frwl, int len)
{

	if ( len != sizeof(struct ip_fw) )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: len=%d, want %d\n",len, sizeof(struct ip_fw));
#endif
		return(NULL);
	}

	if ( (frwl->fw_flg & ~IP_FW_F_MASK) != 0 )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: undefined flag bits set (flags=%x)\n",
			frwl->fw_flg);
#endif
		return(NULL);
	}

#ifndef CONFIG_IP_TRANSPARENT_PROXY
	if (frwl->fw_flg & IP_FW_F_REDIR) {
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: unsupported flag IP_FW_F_REDIR\n");
#endif
		return(NULL);
	}
#endif

#ifndef CONFIG_IP_MASQUERADE
	if (frwl->fw_flg & IP_FW_F_MASQ) {
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: unsupported flag IP_FW_F_MASQ\n");
#endif
		return(NULL);
	}
#endif

	if ( (frwl->fw_flg & IP_FW_F_SRNG) && frwl->fw_nsp < 2 )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: src range set but fw_nsp=%d\n",
			frwl->fw_nsp);
#endif
		return(NULL);
	}

	if ( (frwl->fw_flg & IP_FW_F_DRNG) && frwl->fw_ndp < 2 )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: dst range set but fw_ndp=%d\n",
			frwl->fw_ndp);
#endif
		return(NULL);
	}

	if ( frwl->fw_nsp + frwl->fw_ndp > (frwl->fw_flg & IP_FW_F_REDIR ? IP_FW_MAX_PORTS - 1 : IP_FW_MAX_PORTS) )
	{
#ifdef DEBUG_IP_FIREWALL
		printk("check_ipsm_struct: too many ports (%d+%d)\n",
			frwl->fw_nsp,frwl->fw_ndp);
#endif
		return(NULL);
	}

	return frwl;
}

#ifdef CONFIG_IP_FIREWALL
static
int ipsm_ctl(int stage, void *m, int len)
{
	int cmd, fwtype;

	cmd = stage & IP_FW_COMMAND;
	fwtype = (stage & IP_FW_TYPE) >> IP_FW_SHIFT;

	printk("ipsm_ctl: cmd = %d, fwtype = %d\n",
	       cmd, fwtype); /*** DDD ***/

	if ( cmd == IP_FW_FLUSH )
	{
		free_fw_chain(chains[fwtype]);
		return(0);
	}

	if ( cmd == IP_FW_ZERO )
	{
		zero_fw_chain(*chains[fwtype]);
		return(0);
	}

	if ( cmd == IP_FW_POLICY )
	{
		int *tmp_policy_ptr;
		tmp_policy_ptr=(int *)m;
		*policies[fwtype] = *tmp_policy_ptr;
		return 0;
	}

	if ( cmd == IP_FW_CHECK )
	{
		struct net_device *viadev;
		struct ip_fwpkt *ipsmp;
		struct iphdr *ip;

		if ( len != sizeof(struct ip_fwpkt) )
		{
#ifdef DEBUG_IP_FIREWALL
			printk("ipsm_ctl: length=%d, expected %d\n",
				len, sizeof(struct ip_fwpkt));
#endif
			return( EINVAL );
		}

	 	ipsmp = (struct ip_fwpkt *)m;
	 	ip = &(ipsmp->fwp_iph);

		if ( !(viadev = dev_get_by_name(ipsmp->fwp_vianame)) ) {
#ifdef DEBUG_IP_FIREWALL
			printk("ipsm_ctl: invalid device \"%s\"\n", ipsmp->fwp_vianame);
#endif
			return(EINVAL);
		} else if ( ip->ihl != sizeof(struct iphdr) / sizeof(int)) {
#ifdef DEBUG_IP_FIREWALL
			printk("ipsm_ctl: ip->ihl=%d, want %d\n",ip->ihl,
					sizeof(struct iphdr)/sizeof(int));
#endif
			return(EINVAL);
		}

		switch (ipsm_chk(ip, viadev, NULL, *chains[fwtype],
				*policies[fwtype], IP_FW_MODE_CHK))
		{
			case FW_ACCEPT:
				return(0);
	    		case FW_REDIRECT:
				return(ECONNABORTED);
	    		case FW_MASQUERADE:
				return(ECONNRESET);
	    		case FW_REJECT:
				return(ECONNREFUSED);
			default: /* FW_BLOCK */
				return(ETIMEDOUT);
		}
	}
/*
 *	Here we really working hard-adding new elements
 *	to blocking/forwarding chains or deleting 'em
 */

	if ( cmd == IP_FW_INSERT || cmd == IP_FW_APPEND || cmd == IP_FW_DELETE )
	{
		struct ip_fw *frwl;
		int fwtype;

		frwl=check_ipsm_struct(m,len);
		if (frwl==NULL)
			return (EINVAL);
		fwtype = (stage & IP_FW_TYPE) >> IP_FW_SHIFT;

		switch (cmd)
		{
			case IP_FW_INSERT:
				return(insert_in_chain(chains[fwtype],frwl,len));
			case IP_FW_APPEND:
				return(append_to_chain(chains[fwtype],frwl,len));
			case IP_FW_DELETE:
				return(del_from_chain(chains[fwtype],frwl));
			default:
			/*
	 		 *	Should be panic but... (Why are BSD people panic obsessed ??)
			 */
#ifdef DEBUG_IP_FIREWALL
				printk("ipsm_ctl:  unknown request %d\n",stage);
#endif
				return(EINVAL);
		}
	}

#ifdef DEBUG_IP_FIREWALL
	printk("ipsm_ctl:  unknown request %d\n",stage);
#endif
	return(ENOPROTOOPT);
}
#endif /* CONFIG_IP_FIREWALL */

#if defined(CONFIG_IP_FIREWALL) || defined(CONFIG_IP_ACCT)

static int ipsm_chain_procinfo(int stage, char *buffer, char **start,
			     off_t offset, int length, int reset)
{
	off_t pos=0, begin=0;
	struct ip_fw *i;
	int len, p;
	int last_len = 0;


	switch(stage)
	{
#ifdef CONFIG_IP_FIREWALL
		case IP_FW_IN:
			i = ipsm_in_chain;
			len=sprintf(buffer, "IP firewall input rules, default %d\n",
				ipsm_in_policy);
			break;
#endif
		default:
			/* this should never be reached, but safety first... */
			i = NULL;
			len=0;
			break;
	}

        READ_LOCK(&ip_fw_lock);

	while(i!=NULL)
	{
		len+=sprintf(buffer+len,"%08X/%08X->%08X/%08X %.16s %08X %X ",
			ntohl(i->fw_src.s_addr),ntohl(i->fw_smsk.s_addr),
			ntohl(i->fw_dst.s_addr),ntohl(i->fw_dmsk.s_addr),
			(i->fw_vianame)[0] ? i->fw_vianame : "-",
			ntohl(i->fw_via.s_addr), i->fw_flg);
		/* 10 is enough for a 32 bit box but the counters are 64bit on
		   the Alpha and Ultrapenguin */
		len+=sprintf(buffer+len,"%u %u %-20lu %-20lu",
			i->fw_nsp,i->fw_ndp, i->fw_pcnt,i->fw_bcnt);
		for (p = 0; p < IP_FW_MAX_PORTS; p++)
			len+=sprintf(buffer+len, " %u", i->fw_pts[p]);
		len+=sprintf(buffer+len, " A%02X X%02X", i->fw_tosand, i->fw_tosxor);
		buffer[len++]='\n';
		buffer[len]='\0';
		pos=begin+len;
		if(pos<offset)
		{
			len=0;
			begin=pos;
		}
		else if(pos>offset+length)
		{
			len = last_len;
			break;
		}
		else if(reset)
		{
			/* This needs to be done at this specific place! */
			i->fw_pcnt=0L;
			i->fw_bcnt=0L;
		}
		last_len = len;
		i=i->fw_next;
	}
        READ_UNLOCK(&ip_fw_lock);
	*start=buffer+(offset-begin);
	len-=(offset-begin);
	if(len>length)
		len=length;
	return len;
}
#endif

#ifdef CONFIG_IP_FIREWALL

static int ipsm_in_procinfo(char *buffer, char **start, off_t offset,
			      int length
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,29)
			     , int reset
#endif
	)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,29)
	/* FIXME: No more `atomic' read and reset.  Wonderful 8-( --RR */
	int reset = 0;
#endif
	return ipsm_chain_procinfo(IP_FW_IN, buffer,start,offset,length,
				 reset);
}
#endif


#ifdef CONFIG_IP_FIREWALL
/*
 *	Interface to the generic firewall chains.
 */

static
int ipsm_input_check(struct firewall_ops *this, int pf,
		     struct net_device *dev, void *arg,
		     struct sk_buff **pskb)
{
       	return ipsm_chk((*pskb)->nh.iph, dev, arg, ipsm_in_chain, ipsm_in_policy,
			 IP_FW_MODE_FW);
}

struct firewall_ops ipsm_ops={
	.fw_input=ipsm_input_check,
};

#endif

#if defined(CONFIG_IP_ACCT) || defined(CONFIG_IP_FIREWALL)

static
int ipsm_device_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev=ptr;
	char *devname = dev->name;
	struct ip_fw *fw;
	int chn;

        WRITE_LOCK(&ip_fw_lock);

	if (event == NETDEV_UP) {
		for (chn = 0; chn < IP_FW_CHAINS; chn++)
			for (fw = *chains[chn]; fw; fw = fw->fw_next)
				if ((fw->fw_vianame)[0] && !strncmp(devname,
						fw->fw_vianame, IFNAMSIZ))
					fw->fw_viadev = dev;
	} else if (event == NETDEV_DOWN) {
		for (chn = 0; chn < IP_FW_CHAINS; chn++)
			for (fw = *chains[chn]; fw; fw = fw->fw_next)
				/* we could compare just the pointers ... */
				if ((fw->fw_vianame)[0] && !strncmp(devname,
						fw->fw_vianame, IFNAMSIZ))
					fw->fw_viadev = (struct net_device*)-1;
	}

        WRITE_UNLOCK(&ip_fw_lock);
	return NOTIFY_DONE;
}

static struct notifier_block ipsm_dev_notifier={
	ipsm_device_event,
	NULL,
	0
};

#endif

/*
 * "/proc" File handler to get command
 */
#define BUFFER_SIZE (1024 * 32) /* 32 KB estimates enough for this buffer size */
#if (PAGE_SIZE < BUF_SIZE)
#define BUFFER_SIZE PAGE_SIZE   /* for not enough page size system */
#endif

static char cmd_file[] = "net/ipsm_control";
static char *st_b = NULL; /* data buffer */

struct datas {
  int cmd;
  int length;
  char data[0];
};

/*
 * file_read_proc -- called when user reading
 */
static int file_read_proc(char *buf, char **start, off_t offset,
                   int count, int *eof, void *data)
{
    int return_length;

    printk("**read_proc(), count = %d, off = %d\n",
           count, (int) offset);

    return_length = count > BUFFER_SIZE ? BUFFER_SIZE : count;

    memcpy(buf, st_b + offset, return_length);

    *start = buf + offset; /* update next start point */

    return return_length;
}

/*
 * file_read_proc -- called when user writing
 */
static int file_write_proc(struct file *file, const char *buf,
                     unsigned long count, void *data)
{
    int i, ret, cmd, length, datalen;
    struct datas *p;

    printk("**write_proc(), count = %d\n", (int) count);

    length = count > BUFFER_SIZE ? BUFFER_SIZE : count; /* limit of max size */

    copy_from_user(st_b, buf, length);

    for(i = 0; i < length;) {
      p = (struct datas *) &st_b[i];
      cmd = p->cmd;
      datalen = p->length;

      printk("write_file(), cmd = %d, point = %d, datalen = %d\n",
           cmd, i, datalen);

      ret = ipsm_ctl(cmd, p->data, datalen);
      if (ret)
	printk("write_file(), ret = %d\n", ret);

      i += datalen + sizeof(struct datas);
    }
    return length;
}

extern
int kth_read_proc(char *buf, char **start, off_t offset,
		  int count, int *eof, void *data);
extern
int kth_write_proc(struct file *file, const char *buf,
		   unsigned long count, void *data);

static void file_create_proc(void)
{
    struct proc_dir_entry *entry;
    entry = create_proc_entry(cmd_file, 0, 0); /* "file" registration */
    entry->read_proc = file_read_proc; /* read routine */
    entry->write_proc = file_write_proc; /* write routine */

    entry = create_proc_entry("net/ipstctl", 0, 0); /* "file" registration */
    entry->read_proc = kth_read_proc; /* read routine */
    entry->write_proc = kth_write_proc; /* write routine */

    ip_st_register();
}

static void file_remove_proc(void)
{
    ip_st_unregister();
    remove_proc_entry("net/ipstctl", NULL);
    remove_proc_entry(cmd_file, NULL);
}

static void init_file_module(void)
{
    file_create_proc();
    st_b = (char *) vmalloc(BUFFER_SIZE);
    if (st_b == NULL) {
      printk("File, cannot vmalloc = %d\n", BUFFER_SIZE);
      file_remove_proc();
    }
    ring_alloc();
    printk("init_file_module\n");
}

static void cleanup_file_module(void)
{
    ring_free();
    if (st_b == NULL) {
      vfree(st_b);
    }
    file_remove_proc();
    printk("cleanup_file_module\n");
}

/*
 *
 */
int ipsm_init_or_cleanup(int init)
{
	int ret = 0;

	if (!init)
		goto cleanup;

	ret = ipsm_register_firewall(PF_INET, &ipsm_ops);
	if (ret < 0)
		goto cleanup_nothing;

	proc_net_create("ipsm_input", S_IFREG | S_IRUGO | S_IWUSR, ipsm_in_procinfo);

	init_file_module();

	/* Register for device up/down reports */
	register_netdevice_notifier(&ipsm_dev_notifier);

	return ret;

 cleanup:
	unregister_netdevice_notifier(&ipsm_dev_notifier);

	cleanup_file_module();

	proc_net_remove("ipsm_input");
	free_fw_chain(chains[IP_FW_IN]);
	ipsm_unregister_firewall(PF_INET, &ipsm_ops);

 cleanup_nothing:
	return ret;
}
