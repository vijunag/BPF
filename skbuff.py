from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse
import ctypes as ct

# define BPF program
bpf_text_kprobe = """

#include <uapi/linux/ptrace.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/fdtable.h>

typedef struct SockStats {
  int rmem;
  int wmem;
} Sockstats;

typedef struct SocketInfo {
  int pid;
  int fd;
  u64 sock; //struct sock
} SocketInfo;

BPF_HASH(sockmap,u32,u64);
BPF_HASH(sockfdmap,u32,SocketInfo);
BPF_HASH(pid_map, u32, Sockstats);
int kprobe__tcp_v4_rcv(struct pt_regs *ctx,struct sk_buff *skb)
{
  u32 pid = bpf_get_current_pid_tgid();
  struct sock *sk = skb->sk;
  Sockstats ss = {0};

//  if (pid!=21829)
//    return 0;

  if (!sk)
    return 0;

  ss.rmem = sk->sk_rmem_alloc.counter;
  ss.wmem = sk->sk_wmem_alloc.refs.counter+skb->truesize;
//  bpf_trace_printk("PID=%d,sk->pid=%d\\n",pid,sk->sk_socket->file->f_owner.pid);
  pid_map.update(&pid,&ss);
  return 0;
}

int kretprobe____sys_socket(struct pt_regs *ctx, int family, int type, int protocol)
{
  u32 pid = bpf_get_current_pid_tgid();
  int fd = PT_REGS_RC(ctx);
  SocketInfo si = {0};

  si.pid = pid;
  si.fd = fd;
  sockfdmap.update(&pid,&si);
  bpf_trace_printk("PID=%d opening a new socket\\n");
  return 0;
}

int kretprobe__sock_alloc(struct pt_regs *ctx)
{
  u32 pid = bpf_get_current_pid_tgid();
  struct task_struct *cur = (struct task_struct*)bpf_get_current_task();
  SocketInfo *si;
  struct socket *sock;
  struct fdtable *files;
  struct file *sock_filp;
  int sockfd=-1;
  int i=0;

  sock=(struct socket*)PT_REGS_RC(ctx);
  if (!sock)
    return 0;

  files=cur->files->fdt;
  sock_filp=sock->file;

#if 0
#pragma clang loop unroll(full)
  for(i=0;i<20000;++i) {
    if (sock_filp == files[i].fd[i]) {
      sockfd = i;
      break;
    }
  }
#endif
  bpf_trace_printk("PID=%d allocated socket=%p\\n", pid,sock);
//  sockmap.update(&pid,&sock);
  return 0;
}

int kprobe____sock_release(struct pt_regs *ctx, struct socket *sock, struct inode *inode)
{
  u32 pid = bpf_get_current_pid_tgid();

  bpf_trace_printk("Pid=%d releasing socket=%p\\n",pid,sock);
  return 0;
}

int kprobe__sock_queue_rcv_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
  return 0;
}

/*
int kprobe__kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
  u32 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("PID=%d called kfree_skb()\\n",skb->sk->sk_socket->file->f_owner.pid);
  return 0;
}
*/
"""

b = BPF(text=bpf_text_kprobe)
pidMap=b["pid_map"]

while True:
  for k,v in pidMap.items():
    pass
#		print("Socket-id=%s, skb_set_owner_w()"%(str(k)))
pidMap.clear()
