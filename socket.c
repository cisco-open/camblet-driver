/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 * 
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied, 
 * modified, or distributed except according to those terms.
 */

#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <net/protocol.h>
// #include <linux/file.h>
// #include <linux/jiffies.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/inet_common.h>
#include <net/inet_timewait_sock.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/uaccess.h>

#include "bearssl.h"
#include "socket.h"

#define RSA_OR_EC 0

#if !RSA_OR_EC
#include "certificate_rsa.h"
#elif
#include "certificate_ec.h"
#endif

struct proto wasm_prot;
struct proto inet_wasm_prot;
struct proto_ops inet_wasm_ops;
static struct inet_protosw wasm_sw = {
	.type = SOCK_WASM,
	.protocol = IPPROTO_TCP,
	.prot = &inet_wasm_prot,
	.ops = &inet_wasm_ops,
	.flags = INET_PROTOSW_ICSK,
};

typedef struct
{
	union {
		br_ssl_server_context *sc;
		struct {
			br_ssl_client_context *cc;
			br_x509_minimal_context *xc;
			br_x509_trust_anchor *tas;
			unsigned tas_len;
		};
	};
	unsigned char *iobuf;
	br_sslio_context *ioc;
} ssl_socket_context;

static ssl_socket_context* new_server_ssl_socket_context(void)
{
	ssl_socket_context *sc = kmalloc(sizeof(ssl_socket_context), GFP_KERNEL);
	sc->sc = kmalloc(sizeof(br_ssl_server_context), GFP_KERNEL);
	sc->ioc = kmalloc(sizeof(br_sslio_context), GFP_KERNEL);
	sc->iobuf = kmalloc(BR_SSL_BUFSIZE_BIDI, GFP_KERNEL);
	return sc;
}

static ssl_socket_context *new_client_ssl_socket_context(void)
{
	ssl_socket_context *sc = kmalloc(sizeof(ssl_socket_context), GFP_KERNEL);
	sc->cc = kmalloc(sizeof(br_ssl_client_context), GFP_KERNEL);
	sc->xc = kmalloc(sizeof(br_x509_minimal_context), GFP_KERNEL);
	sc->ioc = kmalloc(sizeof(br_sslio_context), GFP_KERNEL);
	sc->iobuf = kmalloc(BR_SSL_BUFSIZE_BIDI, GFP_KERNEL);
	return sc;
}

static void free_ssl_socket_context(ssl_socket_context *sc)
{
	if (sc)
	{
		printk("free_ssl_socket_context: shutting down ssl io context: %p", sc->ioc);
		// TODO we should call br_sslio_close here, but that hangs in non-typed socket mode
		br_ssl_engine_close(sc->ioc->engine); 
		// if (br_sslio_close(sc->ioc))
		// {
		// 	pr_err("br_sslio_close returned an error");
		// }
		kfree(sc->ioc);
		kfree(sc->iobuf);
		kfree(sc);
	}
}

static int send_msg(struct sock *sock, void *msg, size_t len)
{
	printk("send_msg -> buf %p size %d bytes, sock: %p", msg, len, sock);
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = msg, .iov_len = len};

	iov_iter_kvec(&hdr.msg_iter, WRITE, &iov, 1, len);

	int sent = tcp_sendmsg(sock, &hdr, len);

	printk("send_msg -> sent %d bytes, sock: %p", sent, sock);

	return sent;
}

static int recv_msg(struct sock *sock, char *buf, size_t size)
{
	printk("recv_msg -> buf %p size %d bytes, sock: %p", buf, size, sock);
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = buf, .iov_len = size};
	int addr_len = 0;

	iov_iter_kvec(&hdr.msg_iter, READ, &iov, 1, size);

    int received = tcp_recvmsg(sock, &hdr, size, 0, &addr_len);

	printk("recv_msg -> received %d bytes, sock: %p", received, sock);

	return received;
}

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
    for (;;)
    {
        ssize_t rlen;

        rlen = recv_msg((struct sock *)ctx, buf, len);
        if (rlen <= 0)
        {
            if (rlen < 0)
            {
                continue;
            }
            return -1;
        }
        return (int)rlen;
    }
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
    for (;;)
    {
        ssize_t wlen;

        wlen = send_msg((struct sock *)ctx, buf, len);
        if (wlen <= 0)
        {
            if (wlen < 0)
            {
                continue;
            }
            return -1;
        }
        return (int)wlen;
    }
}

/* This is a copy of inet_listen, but uses SOCK_WASM instead of SOCK_STREAM
   This allows us to listen on SOCK_WASM sockets.
*/
int inet_wasm_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_WASM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN)
	{
		err = inet_csk_listen_start(sk);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}

int inet_wasm_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
{
	int ret = inet_accept(sock, newsock, flags, kern);

	// printk("inet_wasm_accept %d", ret);

	if (ret == 0)
	{
		ssl_socket_context *sc = new_server_ssl_socket_context();

		/*
		* Initialise the context with the cipher suites and
		* algorithms. This depends on the server key type
		* (and, for EC keys, the signature algorithm used by
		* the CA to sign the server's certificate).
		*
		* Depending on the defined macros, we may select one of
		* the "minimal" profiles. Key exchange algorithm depends
		* on the key type:
		*   RSA key: RSA or ECDHE_RSA
		*   EC key, cert signed with ECDSA: ECDH_ECDSA or ECDHE_ECDSA
		*   EC key, cert signed with RSA: ECDH_RSA or ECDHE_ECDSA
		*/
#if !RSA_OR_EC
		br_ssl_server_init_full_rsa(sc->sc, CHAIN, CHAIN_LEN, &RSA);
#elif
		br_ssl_server_init_full_ec(sc->sc, CHAIN, CHAIN_LEN, BR_KEYTYPE_EC, &EC);
#endif

		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc->sc->eng, sc->iobuf, BR_SSL_BUFSIZE_BIDI, true);

		/*
		 * Reset the server context, for a new handshake.
		 */
		br_ssl_server_reset(sc->sc);

		/*
		 * Initialise the simplified I/O wrapper context.
		 */
		br_sslio_init(sc->ioc, &sc->sc->eng, sock_read, newsock->sk, sock_write, newsock->sk);

		// We should save the ssl context here to the socket
		newsock->sk->sk_user_data = sc;

		if (br_sslio_flush(sc->ioc) == 0)
		{	
			printk("inet_wasm_accept: TLS handshake done");
		}
	}

	return ret;
}

int inet_wasm_connect(struct socket *sock,
				      struct sockaddr *vaddr,
				      int sockaddr_len, int flags)
{
	int ret = inet_stream_connect(sock, vaddr, sockaddr_len, flags);

	if (ret == 0)
	{
		const char *server_name = NULL; // TODO, this needs to be sourced down here

		ssl_socket_context *sc = new_client_ssl_socket_context();

		/*
		* Initialise the context with the cipher suites and
		* algorithms. This depends on the server key type
		* (and, for EC keys, the signature algorithm used by
		* the CA to sign the server's certificate).
		*
		* Depending on the defined macros, we may select one of
		* the "minimal" profiles. Key exchange algorithm depends
		* on the key type:
		*   RSA key: RSA or ECDHE_RSA
		*   EC key, cert signed with ECDSA: ECDH_ECDSA or ECDHE_ECDSA
		*   EC key, cert signed with RSA: ECDH_RSA or ECDHE_ECDSA
		*/
		br_ssl_client_init_full(sc->cc, sc->xc, TAs, TAs_NUM);

		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc->cc->eng, sc->iobuf, BR_SSL_BUFSIZE_BIDI, true);

		/*
		 * Reset the client context, for a new handshake. We provide the
		 * target host name: it will be used for the SNI extension. The
		 * last parameter is 0: we are not trying to resume a session.
		 */
		if (br_ssl_client_reset(sc->cc, server_name, 0) != 1)
		{
			pr_err("br_ssl_client_reset returned an error");
		}

		/*
		* Initialise the simplified I/O wrapper context, to use our
		* SSL client context, and the two callbacks for socket I/O.
		*/
		br_sslio_init(sc->ioc, &sc->cc->eng, sock_read, sock->sk, sock_write, sock->sk);

		// We should save the ssl context here to the socket
		sock->sk->sk_user_data = sc;

		if (br_sslio_flush(sc->ioc) != 0)
		{
			pr_err("br_sslio_flush returned an error: %d", br_ssl_engine_last_error(&sc->cc->eng));
		}

		printk("inet_wasm_connect: TLS handshake done");
	}

	return ret;
}

int inet_wasm_shutdown(struct socket *sock, int how)
{
	ssl_socket_context *c = sock->sk->sk_user_data;
	free_ssl_socket_context(c);
	sock->sk->sk_user_data = NULL;
	return inet_shutdown(sock, how);
}

void dump_msghdr(struct msghdr *msg)
{
	char data[1024];
	size_t len, nr_segs, iovlen;
	int npages;

	printk(KERN_INFO "msg_name = %p\n", msg->msg_name);
	printk(KERN_INFO "msg_namelen = %u\n", msg->msg_namelen);
	printk(KERN_INFO "msg_iter.type = %u\n", msg->msg_iter.iter_type);
	printk(KERN_INFO "msg_iter.count = %zd\n", msg->msg_iter.count);

	printk(KERN_INFO "iovoffset = %zd", msg->msg_iter.iov_offset);
	msg->msg_iter.iov_offset = 0;
	// iov_iter_zero(2, &msg->msg_iter);
	printk(KERN_INFO "iovoffset = %zd", msg->msg_iter.iov_offset);

	nr_segs = iov_iter_single_seg_count(&msg->msg_iter);
	printk(KERN_INFO "iovsegcount = %zd", nr_segs);

	npages = iov_iter_npages(&msg->msg_iter, 16384);
	printk(KERN_INFO "npages = %d", npages);

	iovlen = iov_length(msg->msg_iter.iov, npages);
	printk(KERN_INFO "iovlen = %zd", iovlen);

	len = copy_from_iter(data, iovlen - msg->msg_iter.count, &msg->msg_iter);
	printk(KERN_INFO "copylen = %zd\n", len);
	printk(KERN_INFO "msg = [%.*s]\n", len, data);
	printk(KERN_INFO "iovoffset = %zd\n", msg->msg_iter.iov_offset);
}

int wasm_recvmsg(struct sock *sock, struct msghdr *msg, size_t size,
					  int flags, int *addr_len)
{
	int ret, len;
	char data[8192];
	// void *data = kmalloc(size, GFP_KERNEL);

	ssl_socket_context *sc = sock->sk_user_data;

	ret = br_sslio_read(sc->ioc, data, min(size, sizeof(data)));

	if (ret <= 0)
	{
		const br_ssl_engine_context *ec = sc->sc ? &sc->sc->eng : &sc->cc->eng;
		if (br_ssl_engine_last_error(ec) == 0)
			ret = 0;
		goto bail;
	}

	// ret = br_sslio_read(sc->cc, msg->msg_iter.iov->iov_base, min(msg->msg_iter.iov->iov_len, size));

	// printk(KERN_INFO "inet_wasm_recvmsg -> br_sslio_read: %d bytes -> %.*s\n", ret, ret, dst);

	len = copy_to_iter(data, ret, &msg->msg_iter);
	if (len != ret)
	{
		return -ENOBUFS;
	}

bail:
	// kfree(data);

	return ret;
}

int inet_wasm_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
					  int flags)
{
	return wasm_recvmsg(sock->sk, msg, size, flags, 0);
}

int wasm_sendmsg(struct sock *sock, struct msghdr *msg, size_t size)
{
	int ret, len;
	char data[8192];
	ssl_socket_context *sc = sock->sk_user_data;

	// dump_msghdr(msg);

	len = copy_from_iter(data, min(size, sizeof(data)), &msg->msg_iter);
	// printk("inet_wasm_sendmsg data %.*s len = %d", size, data, len);

	ret = br_sslio_write_all(sc->ioc, data, len);
	if (ret < 0)
	{
		pr_err("br_sslio_write_all returned an error");
		return ret;
	}

	ret = br_sslio_flush(sc->ioc);
	if (ret < 0)
	{
		pr_err("br_sslio_flush returned an error");
		return ret;
	}

	return size;
}

int inet_wasm_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	return wasm_sendmsg(sock->sk, msg, size);
}

void wasm_shutdown(struct sock *sk, int how)
{
	printk("wasm_shutdown is running for sk %p", sk);
	ssl_socket_context *c = sk->sk_user_data;
	free_ssl_socket_context(c);
	sk->sk_user_data = NULL;
	printk("wasm_shutdown -> tcp_shutdown is running for sk %p", sk);
	tcp_shutdown(sk, how);
	printk("wasm_shutdown -> tcp_shutdown is done for sk %p", sk);
}

bool eval_connection(u16 port)
{
	return port == 8000 || port == 8080;
}

struct sock* (*accept)(struct sock *sk, int flags, int *err, bool kern);

int	         (*connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);

struct sock* wasm_accept(struct sock *sk, int flags, int *err, bool kern)
{
	u16 port = (u16)(sk->sk_portpair >> 16);
	printk("wasm_accept on port: %d", port);

	struct sock *client = accept(sk, flags, err, kern);

	if (client && eval_connection(port))
	{
		ssl_socket_context *sc = new_server_ssl_socket_context();

		/*
		* Initialise the context with the cipher suites and
		* algorithms. This depends on the server key type
		* (and, for EC keys, the signature algorithm used by
		* the CA to sign the server's certificate).
		*
		* Depending on the defined macros, we may select one of
		* the "minimal" profiles. Key exchange algorithm depends
		* on the key type:
		*   RSA key: RSA or ECDHE_RSA
		*   EC key, cert signed with ECDSA: ECDH_ECDSA or ECDHE_ECDSA
		*   EC key, cert signed with RSA: ECDH_RSA or ECDHE_ECDSA
		*/
#if !RSA_OR_EC
		br_ssl_server_init_full_rsa(sc->sc, CHAIN, CHAIN_LEN, &RSA);
#elif
		br_ssl_server_init_full_ec(sc->sc, CHAIN, CHAIN_LEN, BR_KEYTYPE_EC, &EC);
#endif

		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc->sc->eng, sc->iobuf, BR_SSL_BUFSIZE_BIDI, true);

		/*
		 * Reset the server context, for a new handshake.
		 */
		br_ssl_server_reset(sc->sc);

		/*
		 * Initialise the simplified I/O wrapper context.
		 */
		br_sslio_init(sc->ioc, &sc->sc->eng, sock_read, client, sock_write, client);

		// // We should save the ssl context here to the socket
		client->sk_user_data = sc;
		client->sk_prot = &wasm_prot;
	}

	return client;
}

int wasm_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	u16 port = ntohs(usin->sin_port);
	printk("wasm_connect to port: %d", port);

	int ret = connect(sk, uaddr, addr_len);

	if (ret == 0 && eval_connection(port))
	{
		const char *server_name = NULL; // TODO, this needs to be sourced down here

		ssl_socket_context *sc = new_client_ssl_socket_context();

		/*
		* Initialise the context with the cipher suites and
		* algorithms. This depends on the server key type
		* (and, for EC keys, the signature algorithm used by
		* the CA to sign the server's certificate).
		*
		* Depending on the defined macros, we may select one of
		* the "minimal" profiles. Key exchange algorithm depends
		* on the key type:
		*   RSA key: RSA or ECDHE_RSA
		*   EC key, cert signed with ECDSA: ECDH_ECDSA or ECDHE_ECDSA
		*   EC key, cert signed with RSA: ECDH_RSA or ECDHE_ECDSA
		*/
		br_ssl_client_init_full(sc->cc, sc->xc, TAs, TAs_NUM);

		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc->cc->eng, sc->iobuf, BR_SSL_BUFSIZE_BIDI, true);

		/*
		 * Reset the client context, for a new handshake. We provide the
		 * target host name: it will be used for the SNI extension. The
		 * last parameter is 0: we are not trying to resume a session.
		 */
		if (br_ssl_client_reset(sc->cc, server_name, 0) != 1)
		{
			pr_err("br_ssl_client_reset returned an error");
		}

		/*
		* Initialise the simplified I/O wrapper context, to use our
		* SSL client context, and the two callbacks for socket I/O.
		*/
		br_sslio_init(sc->ioc, &sc->cc->eng, sock_read, sk, sock_write, sk);

		// We should save the ssl context here to the socket
		sk->sk_user_data = sc;
		sk->sk_prot = &wasm_prot;
	}

	return ret;
}

int wasm_socket_init(void)
{
	int rc = -EINVAL;

	/* functions for a listening socket of type SOCK_WASM */
	memcpy(&inet_wasm_ops, &inet_stream_ops, sizeof(inet_wasm_ops));
	inet_wasm_ops.listen = inet_wasm_listen;
	inet_wasm_ops.accept = inet_wasm_accept;
	inet_wasm_ops.connect = inet_wasm_connect;
	inet_wasm_ops.recvmsg = inet_wasm_recvmsg;
	inet_wasm_ops.sendmsg = inet_wasm_sendmsg;
	inet_wasm_ops.shutdown = inet_wasm_shutdown;

	/* Not all tcp_prot's members were exported from the kernel,
	   so we use this hack to grab them from the exported tcp_prot struct,
	   and fill in our own.
	*/
	memcpy(&inet_wasm_prot, &tcp_prot, sizeof(inet_wasm_prot));
	strncpy(inet_wasm_prot.name, "WASM", sizeof(inet_wasm_prot.name));
	inet_wasm_prot.owner = THIS_MODULE;

	/* proto_register will only alloc twsk_prot and rsk_prot if they are
	   null no sense in allocing more space - we can just use TCP's, since
	   we are effecitvely just a TCP socket
	  (though it will alloc .slab even if non-null - we let it).
	*/
	rc = proto_register(&inet_wasm_prot, 1);
	if (rc)
	{
		printk(KERN_CRIT "wasm_init: Cannot register protocol"
						 "(already loaded?)\n");
		return rc;
	}

	inet_register_protosw(&wasm_sw);

	// let's overwrite tcp_port with our own implementation
	accept = tcp_prot.accept;
	connect = tcp_prot.connect;

	tcp_prot.accept = wasm_accept;
	tcp_prot.connect = wasm_connect;

	memcpy(&wasm_prot, &tcp_prot, sizeof(wasm_prot));
	wasm_prot.recvmsg = wasm_recvmsg;
	wasm_prot.sendmsg = wasm_sendmsg;
	wasm_prot.shutdown = wasm_shutdown;

	printk(KERN_INFO "WASM socket support loaded.");

	return 0;
}

void wasm_socket_exit(void)
{
	/* Currently, we're pointing to tcp_prot's twsk_prot and rsk_prot
	   and a call to proto_unregister will free these if non-null.
	   (We did allocate our own slab though, so proto_unregister will free
		that for us)
	*/
	inet_wasm_prot.rsk_prot = NULL;
	inet_wasm_prot.twsk_prot = NULL;

	inet_unregister_protosw(&wasm_sw);
	proto_unregister(&inet_wasm_prot);

	tcp_prot.accept = accept;
	tcp_prot.connect = connect;

	printk(KERN_INFO "WASM socket support unloaded.");
}
