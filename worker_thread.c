#include <linux/in.h>
#include <linux/un.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#define SOCK_PATH "/tmp/wasm3"
#define LISTEN 10

static struct socket *sock;
static struct socket *c_sock;
static bool c_connected = false;

static void accept_work(struct work_struct *);
static int send_msg(struct socket *sock, char *);

static DECLARE_WORK(sock_accept, accept_work);

struct metric_work_struct
{
    struct work_struct work;
    char *metric_line;
};

static int make_server_socket(void)
{
    int ret;
    struct sockaddr_un addr;

    // create
    ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &sock);
    if (ret)
        goto err;

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCK_PATH);

    // bind
    ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret)
        goto err;

    // listen
    ret = kernel_listen(sock, LISTEN);
    if (ret)
        goto err;

    schedule_work(&sock_accept);

    return 0;

err:
    printk("Socket server setup failed");

    if (sock)
        sock_release(sock);
    return ret;
}

static void accept_work(struct work_struct *dummy)
{
    int ret;

    ret = kernel_accept(sock, &c_sock, 0);
    if (ret)
    {
        printk(KERN_INFO "kernel_accept failed: %d\n", ret);
    }
    else
    {
        printk(KERN_INFO "Accepted connection from on domain socket");
        c_connected = true;
    }
}

static int send_msg(struct socket *sock, char *msg)
{
    int ret = 0, len;
    struct msghdr hdr;
    struct kvec iov;

    len = strlen(msg);

    iov.iov_base = msg;
    iov.iov_len = len;

    memset(&hdr, 0, sizeof(hdr));

    ret = kernel_sendmsg(sock, &hdr, &iov, 1, iov.iov_len);

    return ret;
}

void submit_metric_handler(struct work_struct *work)
{
    struct metric_work_struct *my_work = container_of(work, struct metric_work_struct, work);

    int ret = send_msg(c_sock, my_work->metric_line); // TODO loop here for all sockets
    if (ret < 0)
    {
        printk(KERN_INFO "wasm3: message send failed: %d\n", ret);
    }

    kfree(my_work->metric_line);
    kfree(my_work);
}

void submit_metric(char *metric_line)
{
    printk("wasm3: submit_metric: %s", metric_line);

    if (!c_connected)
    {
        printk("wasm3: submit_metric: no clients, dropping metric");
        kfree(metric_line);
        return;
    }

    struct metric_work_struct *my_work =
        (struct metric_work_struct *)kmalloc(sizeof(struct metric_work_struct), GFP_KERNEL);
    my_work->metric_line = metric_line;

    INIT_WORK(&my_work->work, submit_metric_handler);

    schedule_work(&my_work->work);
}

int worker_thread_init(void)
{
    printk("Initializing socket workqueue module\n");

    int ret = make_server_socket();
    if (ret)
    {
        printk(KERN_INFO "Server socket creation failed: %d\n", ret);
        return ret;
    }

    return 0;
}

void worker_thread_exit(void)
{
    printk(KERN_INFO "Socket workqueue module unload\n");
    if (sock)
        sock_release(sock);
}
