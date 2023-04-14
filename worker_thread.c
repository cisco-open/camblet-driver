/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include <linux/in.h>
#include <linux/un.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#define LISTEN 10

static struct socket *sock;
static struct socket *c_sock;
static bool c_connected = false;

static char *sock_path = "/run/wasm.socket";

module_param(sock_path, charp, 0000);
MODULE_PARM_DESC(sock_path, "communication socket path");

static void accept_work(struct work_struct *);
static int send_msg(struct socket *, void *, size_t);

static DECLARE_WORK(sock_accept, accept_work);

struct metric_work_struct
{
    struct work_struct work;
    char *metric_line;
    size_t metric_line_len;
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
    strcpy(addr.sun_path, sock_path);

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
    printk(KERN_ERR "socket server setup failed");

    if (sock)
        kernel_sock_shutdown(sock, SHUT_RDWR);
    return ret;
}

static void accept_work(struct work_struct *dummy)
{
    printk("wasm: waiting for client connection...");

    int ret;

    ret = kernel_accept(sock, &c_sock, 0);
    if (ret)
    {
        pr_err("wasm: kernel_accept failed: %d", ret);
    }
    else
    {
        printk("wasm: accepted connection from socket");
        c_connected = true;
    }
}

static int send_msg(struct socket *sock, void *msg, size_t len)
{
    struct msghdr hdr;
    struct kvec iov;

    iov.iov_base = msg;
    iov.iov_len = len;

    memset(&hdr, 0, sizeof(hdr));

    return kernel_sendmsg(sock, &hdr, &iov, 1, iov.iov_len);
}

void submit_metric_handler(struct work_struct *work)
{
    struct metric_work_struct *my_work = container_of(work, struct metric_work_struct, work);

    // TODO loop here for all sockets
    int ret = send_msg(c_sock, my_work->metric_line, my_work->metric_line_len);
    if (ret < 0)
    {
        pr_err("wasm: message send failed: %d\n", ret);
        if (c_sock != NULL)
        {
            kernel_sock_shutdown(c_sock, SHUT_RDWR);
            c_connected = false;
            pr_err("wasm: socket closed");
            schedule_work(&sock_accept);
        }
    }

    kfree(my_work->metric_line);
    kfree(my_work);
}

void submit_metric(char *metric_line, size_t metric_line_len)
{
    printk("wasm: submit_metric: %.*s", (int)metric_line_len, metric_line);

    if (!c_connected)
    {
        printk("wasm: submit_metric: no clients, dropping metric");
        kfree(metric_line);
        return;
    }

    struct metric_work_struct *my_work =
        (struct metric_work_struct *)kmalloc(sizeof(struct metric_work_struct), GFP_KERNEL);
    my_work->metric_line = metric_line;
    my_work->metric_line_len = metric_line_len;

    INIT_WORK(&my_work->work, submit_metric_handler);

    schedule_work(&my_work->work);
}

int worker_thread_init(void)
{
    printk("wasm: initializing socket workqueue module");

    int ret = make_server_socket();
    if (ret)
    {
        pr_err("wasm: server socket creation failed: %d", ret);
        return ret;
    }

    return 0;
}

void worker_thread_exit(void)
{
    printk("wasm: socket workqueue module unload");
    if (sock)
        kernel_sock_shutdown(sock, SHUT_RDWR);
}
