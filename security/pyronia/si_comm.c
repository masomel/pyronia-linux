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
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <uapi/linux/pyronia_netlink.h>
#include <uapi/linux/pyronia_mac.h>

#define MAX_RECV_LEN 1024

struct sock *upcall_sock = NULL;

/* family definition */
static struct genl_family si_comm_gnl_family = {
    .id = GENL_ID_GENERATE,         //genetlink should generate an id
    .hdrsize = 0,
    .name = "SI_COMM", // name of this family, used by userspace
    .version = VERSION_NR,                   //version number
    .maxattr = SI_COMM_A_MAX,
};

static int send_to_runtime(struct sock *nl_sock, u32 port_id, int cmd, int attr, int msg) {
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
    if (ret != 0) {
        printk("[%s] Error sending message to %d\n", __func__, port_id);
        goto out;
    }

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
    int ret;
    struct msghdr recv_hdr;
    struct kvec recv_vec;
    char *recv_buf[MAX_RECV_LEN];

    ret = send_to_runtime(upcall_sock, pid, SI_COMM_C_STACK_REQ,
                          SI_COMM_A_KERN_REQ, STACK_REQ_CMD);
    if (ret) {
        goto out;
    }

    // recv message on upcall_sock here
    /*    recv_vec.iov_base = recv_buf;
    recv_vec.iov_len = MAX_RECV_LEN;
    recv_hdr.msg_iov = &recv_vec;
    recv_hdr.msg_iovlen = 1;*/

    ret = sk_wait_data(upcall_sock, &timeo, last);

    if (ret < 0) {
        printk(KERN_ERR "[%s] Error receiving response from user space: %d\n", __func__, ret);
        ret = -1;
        goto out;
    }

    printk(KERN_INFO "[%s] Received %d bytes from the runtime at port %d\n", __func__,
           ret, pid);

 out:
    return NULL;
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
    int valid_pid = 0;
    int err = 0;
    u32 snd_port;

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
    printk(KERN_INFO "[%s] userspace trying to register port ID: %s\n", __func__, mydata);

    err = kstrtou32(mydata, 10, &snd_port);
    if (err)
      return -1;

    valid_pid = info->snd_portid == snd_port ? 1 : 0;

    if (valid_pid) {
        // TODO: Save the port ID in the corresponding process' AA policy
    }

    /* This serves as an ACK from the kernel */
    ret = send_to_runtime(genl_info_net(info), info->snd_portid, SI_COMM_C_REGISTER_PROC,
                          SI_COMM_A_USR_MSG, !valid_pid);
    return 0;

 out:
    printk(KERN_ERR "[%s] Error with sender info\n", __func__);
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
