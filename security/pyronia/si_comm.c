/* Netlink socket family used by a Pyronia-aware language runtime
 * to send callstack information to the Pyronia LSM for access control
 * decisions.
 *
 *@author Marcela S. Melara
 */

#include <net/genetlink.h>
#include <net/sock.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <uapi/linux/pyronia_netlink.h>
#include <uapi/linux/pyronia_mac.h>

#include "include/policy.h"

#define MAX_RECV_LEN 1024

struct sock *upcall_sock = NULL;
int runtime_responded = 0;
char cg_buf[MAX_RECV_LEN];

/* family definition */
static struct genl_family si_comm_gnl_family = {
    .id = GENL_ID_GENERATE,         //genetlink should generate an id
    .hdrsize = 0,
    .name = "SI_COMM", // name of this family, used by userspace
    .version = VERSION_NR,                   //version number
    .maxattr = SI_COMM_A_MAX,
};

static int send_to_runtime(struct sock *nl_sock, u32 port_id, int cmd, int attr, int msg/*, int nonblocking*/) {
    struct sk_buff *skb;
    void *msg_head;
    int ret = -1;
    char buf[12];

     // allocate the message memory
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL) {
        printk(KERN_ERR "[%s] Could not allocate skb for cmd message %d for port %d\n",
               __func__, cmd, port_id);
        goto out;
    }

    //Create the message headers
    /* arguments of genlmsg_put:
       struct sk_buff *,
       int (sending) pid,
       int sequence number,
       struct genl_family *,
       int flags,
       u8 command index (why do we need this?)
    */
    msg_head = genlmsg_put(skb, 0, 0, &si_comm_gnl_family,
                           0, cmd);

    if (msg_head == NULL) {
        ret = -ENOMEM;
        printk("[%s] genlmsg_put() returned error for %d\n", __func__, port_id);
        goto out;
    }

    if (cmd == SI_COMM_C_STACK_REQ && attr == SI_COMM_A_KERN_REQ) {
        // create the message
        ret = nla_put_u8(skb, attr, STACK_REQ_CMD);
        if (ret != 0) {
            printk(KERN_ERR "[%s] Could not create the message for %d\n", __func__, port_id);
            goto out;
        }
    }
    else {
        sprintf(buf, "%d", msg);
        ret = nla_put_string(skb, SI_COMM_A_USR_MSG, buf);
        if (ret != 0)
            goto out;
    }

    // finalize the message
    genlmsg_end(skb, msg_head);

    // send the message
    ret = nlmsg_unicast(nl_sock, skb, port_id);
    // ret here will contain the length of the sent message (> 0), or
    // an error (< 0)
    if (ret < 0) {
        printk("[%s] Error %d sending message to %d\n", __func__, ret, port_id);
        goto out;
    }
    ret = 0;

 out:
    if (ret) {
        // TODO: release the kraken here
    }
    return ret;
}

/* STACK_REQ command: send a message requesting the current language
 * runtime's callstack from the given process, and return the callgraph
 * to the caller. */
pyr_cg_node_t *pyr_stack_request(u32 pid)
{
    int err;
    pyr_cg_node_t *cg = NULL;

    printk(KERN_INFO "[%s] Requesting callstack from runtime at %d\n", __func__, pid);
    
    err = send_to_runtime(upcall_sock, pid, SI_COMM_C_STACK_REQ,
                          SI_COMM_A_KERN_REQ, STACK_REQ_CMD/*, 0*/);
    if (err) {
        goto out;
    }

    // TODO: synchronize here bc we might have more than one thread
    runtime_responded = 0;
    while(!runtime_responded){}

    // TODO: parse the callgraph

    printk(KERN_INFO "[%s] Successfully received user response: %s\n", __func__, cg_buf);

 out:
    return cg;
}

/* REGISTER_PROC command: receive a message with a process' PID. This
 * handler then stores this PID as part of the process' ACL to enable
 * the kernel to request callstack information from the process
 * upon sensitive system calls.
 */
static int pyr_register_proc(struct sk_buff *skb,  struct genl_info *info)
{
    struct nlattr *na;
    char * mydata = NULL;
    int err = 0;
    u32 snd_port;
    struct task_struct *tsk;
    struct pyr_profile *profile;

    if (info == NULL)
        goto out;

    /*for each attribute there is an index in info->attrs which points
     * to a nlattr structure in this structure the data is given */
    na = info->attrs[SI_COMM_A_USR_MSG];
    // TODO: Need to check here that the command we received was a REG_PROC
    if (na) {
        mydata = (char *)nla_data(na);
        if (mydata == NULL)
            printk(KERN_ERR "[smv_netlink.c] error while receiving data\n");
    }
    else
        printk(KERN_CRIT "no info->attrs %i\n", SI_COMM_A_USR_MSG);

    /* Parse the received message here */
    err = kstrtou32(mydata, 10, &snd_port);
    if (err)
      return -1;

    /*    if (valid_pid) {
        // TODO: Can the port ID ever be different that the PID?
        tsk = pid_task(find_vpid(snd_port), PIDTYPE_PID);
        if (!tsk) {
            valid_pid = 0;
            goto out;
        }
        profile = pyr_get_task_profile(tsk);
        if (!profile) {
            valid_pid = 0;
            goto out;
        }
        profile->port_id = snd_port;
        }*/

    printk(KERN_INFO "[%s] userspace at port %d registered SI port ID: %d\n", __func__, info->snd_portid, snd_port);
    
 out:
    /* This serves as an ACK from the kernel */
    err = send_to_runtime(genl_info_net(info)->genl_sock, info->snd_portid,
                          SI_COMM_C_REGISTER_PROC, SI_COMM_A_USR_MSG,
                          0/*, MSG_DONTWAIT*/);
    if (err)
      printk(KERN_ERR "[%s] Error responding to runtime: %d\n", __func__, err);

    // FIXME: remove after testing
    //pyr_stack_request(snd_port);

    return 0;
}

static int pyr_get_callstack(struct sk_buff *skb, struct genl_info *info) {
  struct nlattr *na;
  char * mydata = NULL;

  if (info == NULL)
    goto out;
  
  /*for each attribute there is an index in info->attrs which points
     * to a nlattr structure in this structure the data is given */
  na = info->attrs[SI_COMM_A_USR_MSG];
  // TODO: Need to check here that the command we received was a STACK_REQ
  if (na) {
    mydata = (char *)nla_data(na);
    if (mydata == NULL)
      printk(KERN_ERR "[smv_netlink.c] error while receiving data\n");
  }
  else
    printk(KERN_CRIT "no info->attrs %i\n", SI_COMM_A_USR_MSG);

  memset(cg_buf, 0, MAX_RECV_LEN);
  memcpy(cg_buf, mydata, MAX_RECV_LEN);
  runtime_responded = 1;

 out:
  return 0;
}

/* SAVE_CONTEXT command: receive a message with callstack information
 * to store in the specified process' Pyronia ACL. */
static int pyr_save_context(struct sk_buff *skb,  struct genl_info *info)
{
    return 0;
}

/* commands:
 *
 * - REGISTER_PROC: register a language runtime instance with the LSM.
 * - SAVE_CONTEXT: pre-emptively save
 * callstack info as part of a process' access policy.*/
static const struct genl_ops si_comm_gnl_ops[] = {
    {
        .cmd = SI_COMM_C_REGISTER_PROC,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = pyr_register_proc,
    },
    {
        .cmd = SI_COMM_C_SAVE_CONTEXT,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = pyr_save_context,
    },
    {
        .cmd = SI_COMM_C_STACK_REQ,
        .flags = 0,
        .policy = si_comm_genl_policy,
        .doit = pyr_get_callstack,
    },
};

static int __init kernel_comm_init(void)
{
    int rc;

    upcall_sock = init_net.genl_sock;
    if (!upcall_sock) {
        printk("upcall socket create\n");
	struct netlink_kernel_cfg cfg = {
	  .flags = NL_CFG_F_NONROOT_RECV,
	};
	upcall_sock = netlink_kernel_create(&init_net, NETLINK_GENERIC, &cfg);
	if (!upcall_sock)
	  goto fail;
    }

    /*register new family*/
    rc = genl_register_family_with_ops(&si_comm_gnl_family, si_comm_gnl_ops);
    if (rc != 0){
        printk("register ops: %i\n",rc);
        goto fail;
    }

    printk(KERN_INFO "[pyronia] Initialized SI communication channel\n");
    return 0;

fail:
    genl_unregister_family(&si_comm_gnl_family);
    printk(KERN_CRIT "[pyronia] Error occured while creating SI netlink channel\n");
    return -1;
}

static void __exit kernel_comm_exit(void)
{
    int ret;

    /*unregister the family*/
    ret = genl_unregister_family(&si_comm_gnl_family);
    if(ret !=0){
        printk("unregister family %i\n",ret);
    }

    printk(KERN_INFO "[pyronia] SI channel teardown complete\n");
}


module_init(kernel_comm_init);
module_exit(kernel_comm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcela S. Melara");
MODULE_DESCRIPTION("Main component for stack inspection-related LSM-to-userspace communication.");
