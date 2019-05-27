#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock_api_smp.h>
#include <linux/module.h>
#include <linux/kernel.h>       // //printk
#include <linux/init.h>
#include <linux/errno.h>        // error codes
#include <asm/atomic.h>
#include<linux/file.h>                          // struct file_struct, fcheck_files
#include<linux/fs.h>                            // struct file
#include<net/udp.h>
#include<linux/dcache.h>                        // struct dentry
#include<net/sock.h>                            //sk_for_each , socket_i
#include<linux/net.h>                           //struct socket
#include<net/tcp.h>                             //tcp_get_info()
#include<linux/tcp.h>                           //struct tcp_info
#include<net/sock.h>                            //lock_sock, release_sock -socket locking fuctions and struct sock
#include<linux/rcupdate.h>                      //rcu_read_lock unlock
#include<net/inet_sock.h>


#define DRIVER_AUTHOR "Pranay B. Kolakkar"
#define DRIVER_DESC "Bloomberg LP Module for extracting the TCP statistics for each process per TCP socket it uses"
#define SUPPORTED_DEV "Dell/HP Bloomberg Appliances"
#define MODULE_VERSION_NUMBER "1.0"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_SUPPORTED_DEVICE(SUPPORTED_DEV);
MODULE_VERSION(MODULE_VERSION_NUMBER);

int fds;
int nexttask;
struct tcp_info tcpstats;
u16 dport;
u16 sport;
u32 daddr;
u32 recvaddr;
int valid_stat=0;
int check_sockstat(struct task_struct *, struct fdtable *fdt);
static void *ct_seq_start(struct seq_file *s, loff_t *pos)
{
	struct task_struct *task;
	struct fdtable *fdt;
	if(*pos == 0){
		task = &init_task;
		seq_printf(s, "pid comm sockid wscale sacktcpi_state sndr:sport recv:rcvport tcpi_ca_state tcpi_retransmits tcpi_probes tcpi_backoff tcpi_options tcpi_snd_wscale tcpi_rcv_wscale tcpi_rto tcpi_ato tcpi_snd_mss tcpi_rcv_mss tcpi_unacked tcpi_sacked tcpi_lost tcpi_retrans tcpi_fackets tcpi_last_data_sent tcpi_last_ack_sent tcpi_last_data_recv tcpi_last_ack_recv tcpi_pmtu tcpi_rcv_ssthresh tcpi_rtt tcpi_rttvar tcpi_snd_ssthresh tcpi_snd_cwnd tcpi_advmss tcpi_reordering tcpi_rcv_rtt tcpi_rcv_space tcpi_total_retrans\n");
		goto taskchk;
 	}

	task = s->private;
	if(nexttask == 2)
		goto taskchk;
	
start:
	if(next_task(task) == &init_task) 
		return NULL;
	
	task = next_task(task);
	fds = 0;
taskchk:
	s->private = task;
	if(task->files)
		fdt = files_fdtable(task->files);
	else
		goto start;
	
	if(!fdt)
                goto start;
        
	valid_stat = 0;
	valid_stat = check_sockstat(task,fdt);
	if(valid_stat < 0){
		nexttask = 1;
		goto start;
	}

	nexttask = 2;		
	return fdt;
} 

static int ct_seq_show(struct seq_file *s, void *v)
{
	int wscale;
        int sack;
	u8 rcv_wscale = 0;
	u8 snd_wscale = 0;
	struct task_struct *task=s->private;
	if((tcpstats.tcpi_options & TCPI_OPT_WSCALE )== TCPI_OPT_WSCALE)
		wscale = 1;
        else
                wscale = 0;
        
        if((tcpstats.tcpi_options & TCPI_OPT_SACK )== TCPI_OPT_SACK)
                sack = 1;
        else
                sack = 0;
        
        rcv_wscale |= tcpstats.tcpi_rcv_wscale;
        snd_wscale |= tcpstats.tcpi_snd_wscale;		
	seq_printf(s,"%d %s %d %d %d %u.%u.%u.%u:%hu %u.%u.%u.%u:%hu %hd %hd %hd %hd %hd %hd %hd %hd %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",task->pid, task->comm,fds-1, wscale,sack, ((unsigned char *)&recvaddr)[0],((unsigned char *)&recvaddr)[1],((unsigned char *)&recvaddr)[2],((unsigned char *)&recvaddr)[3],sport,((unsigned char *)&daddr)[0],((unsigned char *)&daddr)[1],((unsigned char *)&daddr)[2],((unsigned char *)&daddr)[3],dport, tcpstats.tcpi_state, tcpstats.tcpi_ca_state, tcpstats.tcpi_retransmits, tcpstats.tcpi_probes, tcpstats.tcpi_backoff, tcpstats.tcpi_options, snd_wscale, rcv_wscale, tcpstats.tcpi_rto, tcpstats.tcpi_ato, tcpstats.tcpi_snd_mss, tcpstats.tcpi_rcv_mss, tcpstats.tcpi_unacked, tcpstats.tcpi_sacked, tcpstats.tcpi_lost, tcpstats.tcpi_retrans, tcpstats.tcpi_fackets, tcpstats.tcpi_last_data_sent, tcpstats.tcpi_last_ack_sent, tcpstats.tcpi_last_data_recv,tcpstats.tcpi_last_ack_recv,tcpstats.tcpi_pmtu, tcpstats.tcpi_rcv_ssthresh, tcpstats.tcpi_rtt, tcpstats.tcpi_rttvar, tcpstats.tcpi_snd_ssthresh, tcpstats.tcpi_snd_cwnd, tcpstats.tcpi_advmss, tcpstats.tcpi_reordering, tcpstats.tcpi_rcv_rtt, tcpstats.tcpi_rcv_space, tcpstats.tcpi_total_retrans);
	return 0;
}

static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return NULL;
}
	
int check_sockstat(struct task_struct *task, struct fdtable *fdt)
{
	int i;
	int valid_stat = 0;
	struct sock *sk_pointer;
	struct socket *st_pointer;
	unsigned int hash;	
	struct inet_ehash_bucket *head;
	struct inet_sock *inSock;
	struct file *f_ptr;
	struct dentry *d_ptr;
	struct inode *i_ptr;
	if(!fdt)
		return -1;
	
	for(i=fds;i<=fdt->max_fdset;i++){	
		rcu_read_lock();
                if(!FD_ISSET(i, fdt->open_fds)){
			rcu_read_unlock();
                      	break;
                }

		f_ptr = rcu_dereference(fdt->fd[i]);
		if(!f_ptr){	
			rcu_read_unlock();
                        continue;
		}

		if(! atomic_inc_not_zero(&f_ptr->f_count)){
			rcu_read_unlock();
			continue;
		}

		rcu_read_unlock();
		d_ptr = f_ptr->f_dentry;
		if(!d_ptr){
			fput(f_ptr);
			continue;
		}

		if(d_ptr->d_flags & DCACHE_UNHASHED){
			fput(f_ptr);
                        continue;
                }
	
		i_ptr = d_ptr->d_inode;
		if(! i_ptr){
			fput(f_ptr);
                        continue;
		}
		
                if(!S_ISSOCK(d_ptr->d_inode->i_mode)){
                        fput(f_ptr);
                        continue;
                }
		i_ptr = d_ptr->d_inode;
		if(!i_ptr){
			fput(f_ptr);
                        continue;
		}

		st_pointer = SOCKET_I(i_ptr);
		if(!st_pointer){
			fput(f_ptr);
			continue;
		}

                sk_pointer = st_pointer->sk;
                if(sk_pointer == NULL){
			fput(f_ptr);
			continue;
                }	

		if(st_pointer->type == SOCK_STREAM){
			local_bh_disable();
			cond_resched_softirq();
			hash = inet_sk_ehashfn(sk_pointer);
                        head = inet_ehash_bucket(&tcp_hashinfo, hash);
			read_lock(&head->lock);	
			if(((sk_pointer->sk_family == PF_INET)||(sk_pointer->sk_family == PF_INET6)||(sk_pointer->sk_family == AF_INET)||(sk_pointer->sk_family == AF_INET6))&&(sk_pointer->sk_state == 1)){
				inSock = inet_sk(sk_pointer);
                                dport = ntohs(inSock->dport);
                                sport = ntohs(inSock->sport);
                                daddr = inSock->daddr;
                                recvaddr = inSock->rcv_saddr;
                                tcp_get_info(sk_pointer, &tcpstats);
				valid_stat = 1;
			}

			read_unlock(&head->lock);
			local_bh_enable();
                        if(valid_stat == 1){
				fds = i+1;
				fput(f_ptr);
	                        return 0;
			}
		}
                fput(f_ptr);
		
	}
	return -1;
}
static  void ct_seq_stop(struct seq_file *s, void *v)
{
}

static struct seq_operations ct_seq_ops = {
     .start = ct_seq_start,
     .next  = ct_seq_next,
     .stop  = ct_seq_stop,
     .show  = ct_seq_show
 };

static int ct_open(struct inode *inode, struct file *file)
{
     return seq_open(file, &ct_seq_ops);
}

static struct file_operations ct_file_ops = {
     .owner   = THIS_MODULE,
     .open    = ct_open,
     .read    = seq_read,
     .llseek  = seq_lseek,
     .release = seq_release
};

static int ct_init(void){
     struct proc_dir_entry *entry;
     entry = create_proc_entry("bbtcpstat", 0, NULL);

     if (entry)
         entry->proc_fops = &ct_file_ops;

     return 0;
 }

static void ct_exit(void)
{
    remove_proc_entry("bbtcpstat", NULL);
}

struct files_struct *get_files_struct(struct task_struct *task){
	struct files_struct *files;
	task_lock(task);
	files = task->files;
	if(files)
		atomic_inc(&files->count);
	
	task_unlock(task);
	return files;
}

module_init(ct_init);
module_exit(ct_exit);
MODULE_LICENSE("GPL");  
