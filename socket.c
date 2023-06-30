/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/protocol.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/uaccess.h>

#include "bearssl.h"
#include "device_driver.h"
#include "proxywasm.h"
#include "socket.h"

#define RSA_OR_EC 0

#if !RSA_OR_EC
#include "certificate_rsa.h"
#elif
#include "certificate_ec.h"
#endif

const char *ALPNs[] = {
	"istio-peer-exchange",
	"istio",
};

const size_t ALPNs_NUM = sizeof(ALPNs) / sizeof(ALPNs[0]);

static struct proto wasm_prot;

typedef struct
{
	union
	{
		br_ssl_server_context *sc;
		br_ssl_client_context *cc;
	};

	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_sslio_context ioc;
	br_x509_minimal_context xc;

	proxywasm_context *pc;
	proxywasm *p;
	i64 direction;
	char *protocol;
} wasm_socket_context;

static char *get_direction(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return "server";
	}
	else
	{
		return "client";
	}
}

static char *get_read_buffer(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_downstream_buffer(c->pc);
	}
	else
	{
		return pw_get_upstream_buffer(c->pc);
	}
}

static char *get_read_buffer_for_read(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_downstream_buffer(c->pc) + pw_get_downstream_buffer_size(c->pc);
	}
	else
	{
		return pw_get_upstream_buffer(c->pc) + pw_get_upstream_buffer_size(c->pc);
	}
}

static int get_read_buffer_capacity(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_downstream_buffer_capacity(c->pc) - pw_get_downstream_buffer_size(c->pc);
	}
	else
	{
		return pw_get_upstream_buffer_capacity(c->pc) - pw_get_upstream_buffer_size(c->pc);
	}
}

static int get_read_buffer_size(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_downstream_buffer_size(c->pc);
	}
	else
	{
		return pw_get_upstream_buffer_size(c->pc);
	}
}

static void set_read_buffer_size(wasm_socket_context *c, int size)
{
	if (c->direction == ListenerDirectionInbound)
	{
		pw_set_downstream_buffer_size(c->pc, size);
	}
	else
	{
		pw_set_upstream_buffer_size(c->pc, size);
	}
}

static char *get_write_buffer(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_upstream_buffer(c->pc);
	}
	else
	{
		return pw_get_downstream_buffer(c->pc);
	}
}

static char *get_write_buffer_for_write(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_upstream_buffer(c->pc) + pw_get_upstream_buffer_size(c->pc);
	}
	else
	{
		return pw_get_downstream_buffer(c->pc) + pw_get_downstream_buffer_size(c->pc);
	}
}

static int get_write_buffer_capacity(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_upstream_buffer_capacity(c->pc) - pw_get_upstream_buffer_size(c->pc);
	}
	else
	{
		return pw_get_downstream_buffer_capacity(c->pc) - pw_get_downstream_buffer_size(c->pc);
	}
}

static int get_write_buffer_size(wasm_socket_context *c)
{
	if (c->direction == ListenerDirectionInbound)
	{
		return pw_get_upstream_buffer_size(c->pc);
	}
	else
	{
		return pw_get_downstream_buffer_size(c->pc);
	}
}

static void set_write_buffer_size(wasm_socket_context *c, int size)
{
	if (c->direction == ListenerDirectionInbound)
	{
		pw_set_upstream_buffer_size(c->pc, size);
	}
	else
	{
		pw_set_downstream_buffer_size(c->pc, size);
	}
}

static wasm_socket_context *new_server_wasm_socket_context(proxywasm *p)
{
	wasm_socket_context *c = kzalloc(sizeof(wasm_socket_context), GFP_KERNEL);
	c->sc = kmalloc(sizeof(br_ssl_server_context), GFP_KERNEL);
	wasm_vm_result res = proxywasm_create_context(p);
	if (res.err)
	{
		pr_err("new_server_wasm_socket_context: failed to create context: %s", res.err);
		return NULL;
	}
	c->pc = proxywasm_get_context(p);
	c->p = p;
	c->direction = ListenerDirectionInbound;
	set_property_v(c->pc, "listener_direction", (char *)&c->direction, sizeof(c->direction));
	return c;
}

static wasm_socket_context *new_client_wasm_socket_context(proxywasm *p)
{
	wasm_socket_context *c = kzalloc(sizeof(wasm_socket_context), GFP_KERNEL);
	c->cc = kmalloc(sizeof(br_ssl_client_context), GFP_KERNEL);
	wasm_vm_result res = proxywasm_create_context(p);
	if (res.err)
	{
		pr_err("new_client_wasm_socket_context: failed to create context: %s", res.err);
		return NULL;
	}
	c->pc = proxywasm_get_context(p);
	c->p = p;
	c->direction = ListenerDirectionOutbound;
	set_property_v(c->pc, "listener_direction", (char *)&c->direction, sizeof(c->direction));
	return c;
}

static void free_wasm_socket_context(wasm_socket_context *sc)
{
	if (sc)
	{
		printk("free_wasm_socket_context: shutting down wasm_socket_context of context id: %p", sc->pc);

		proxywasm_destroy_context(sc->p);

		// TODO we should call br_sslio_close here, but that hangs in non-typed socket mode
		br_ssl_engine_close(sc->ioc.engine);
		// if (br_sslio_close(sc->ioc))
		// {
		// 	pr_err("br_sslio_close returned an error");
		// }
		if (sc->direction == ListenerDirectionInbound)
			kfree(sc->sc);
		else
			kfree(sc->cc);

		// TODO free the proxywasm context

		kfree(sc);
	}
}

static int send_msg(struct sock *sock, void *msg, size_t len)
{
	// printk("send_msg -> buf %p size %d bytes, sock: %p", msg, len, sock);
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = msg, .iov_len = len};

	iov_iter_kvec(&hdr.msg_iter, WRITE, &iov, 1, len);

	int sent = tcp_sendmsg(sock, &hdr, len);

	// printk("send_msg -> sent %d bytes, sock: %p", sent, sock);

	return sent;
}

static int recv_msg(struct sock *sock, char *buf, size_t size)
{
	// printk("recv_msg -> buf %p size %d bytes, sock: %p", buf, size, sock);
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = buf, .iov_len = size};
	int addr_len = 0;

	iov_iter_kvec(&hdr.msg_iter, READ, &iov, 1, size);

	int received = tcp_recvmsg(sock, &hdr, size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
							   0,
#endif
							   0, &addr_len);

	// printk("recv_msg -> received %d bytes, sock: %p", received, sock);

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

int wasm_recvmsg(struct sock *sock,
				 struct msghdr *msg,
				 size_t size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
				 int noblock,
#endif
				 int flags,
				 int *addr_len)
{
	int ret, len;

	wasm_socket_context *c = sock->sk_user_data;

	if (c->protocol == NULL)
	{
		if (br_sslio_flush(&c->ioc) == 0)
		{
			printk("wasm_recvmsg: TLS handshake done");
		}
		else
		{
			pr_err("wasm_recvmsg: %s TLS handshake error %d", get_direction(c), br_ssl_engine_last_error(&c->sc->eng));
		}

		c->protocol = br_ssl_engine_get_selected_protocol(&c->sc->eng);

		printk("wasm_recvmsg: %s protocol name: %s", get_direction(c), c->protocol);

		set_property_v(c->pc, "upstream.negotiated_protocol", c->protocol, strlen(c->protocol));
	}

	len = min(size, get_read_buffer_capacity(c));
	// printk("wasm_recvmsg: %s br_sslio_read trying to read %d bytes", get_direction(c), len);
	ret = br_sslio_read(&c->ioc, get_read_buffer_for_read(c), len);

	if (ret <= 0)
	{
		const br_ssl_engine_context *ec = c->sc ? &c->sc->eng : &c->cc->eng;
		if (br_ssl_engine_last_error(ec) == 0)
			ret = 0;
		pr_err("wasm_recvmsg: %s br_sslio_read error %d", get_direction(c), br_ssl_engine_last_error(ec));
		goto bail;
	}

	// printk("wasm_recvmsg: br_sslio_read read %d bytes", ret);

	set_read_buffer_size(c, get_read_buffer_size(c) + ret);

	proxywasm_lock(c->p);
	proxywasm_set_context(c->p, c->pc);
	wasm_vm_result result;
	switch (c->direction)
	{
	case ListenerDirectionOutbound:
		result = proxy_on_upstream_data(c->p, ret, 0);
		break;
	case ListenerDirectionInbound:
	case ListenerDirectionUnspecified:
		result = proxy_on_downstream_data(c->p, ret, 0);
		break;
	}
	proxywasm_unlock(c->p);

	if (result.err)
	{
		pr_err("wasm_recvmsg: proxy_on_upstream/downstream_data returned an error: %s", result.err);
		return -1;
	}

	int read_buffer_size = get_read_buffer_size(c);

	len = copy_to_iter(get_read_buffer(c), read_buffer_size, &msg->msg_iter);
	if (len < read_buffer_size)
	{
		pr_warn("wasm_recvmsg: copy_to_iter copied less than requested");
	}

	set_read_buffer_size(c, read_buffer_size - len);

	ret = len;

bail:

	return ret;
}

int wasm_sendmsg(struct sock *sock, struct msghdr *msg, size_t size)
{
	int ret, len;

	wasm_socket_context *c = sock->sk_user_data;

	// dump_msghdr(msg);

	if (c->protocol == NULL)
	{
		if (br_sslio_flush(&c->ioc) == 0)
		{
			printk("wasm_sendmsg: TLS handshake done");
		}
		else
		{
			pr_err("wasm_sendmsg: %s TLS handshake error %d", get_direction(c), br_ssl_engine_last_error(&c->sc->eng));
		}

		c->protocol = br_ssl_engine_get_selected_protocol(&c->sc->eng);

		printk("wasm_sendmsg: %s protocol name: %s", get_direction(c), c->protocol);

		set_property_v(c->pc, "upstream.negotiated_protocol", c->protocol, strlen(c->protocol));
	}

	// get the cipher suite from the context
	// const br_ssl_session_parameters *params = &c->sc->eng.session;
	// printk("wasm_sendmsg cipher suite: %d version: %d", params->cipher_suite, params->version);

	// // get the key from the context
	// const br_x509_certificate *chain = br_ssl_engine_get_chain(&sc->sc->eng);
	// const br_x509_pkey *pk = &chain->pkey;

	// // get iv from the context
	// const unsigned char *iv = br_ssl_engine_get_server_iv(&sc->sc->eng);

	// // get the salt from the context
	// const unsigned char *salt = br_ssl_engine_get_client_random(&sc->sc->eng);

	//	len = copy_from_iter(data, min(size, sizeof(data)), &msg->msg_iter);
	len = copy_from_iter(get_write_buffer_for_write(c), min(size, get_write_buffer_capacity(c)), &msg->msg_iter);

	set_write_buffer_size(c, get_write_buffer_size(c) + len);

	proxywasm_lock(c->p);
	proxywasm_set_context(c->p, c->pc);
	wasm_vm_result result;
	switch (c->direction)
	{
	case ListenerDirectionOutbound:
		result = proxy_on_downstream_data(c->p, len, 0);
		break;
	default:
		result = proxy_on_upstream_data(c->p, len, 0);
		break;
	}
	proxywasm_unlock(c->p);

	if (result.err)
	{
		pr_err("wasm_sendmsg: proxy_on_upstream/downstream_data returned an error: %s", result.err);
		ret = -1;
		goto bail;
	}

	// printk("wasm_sendmsg: %s br_sslio_write_all get_write_buffer_size = %d", get_direction(c), get_write_buffer_size(c));

	ret = br_sslio_write_all(&c->ioc, get_write_buffer(c), get_write_buffer_size(c));
	if (ret < 0)
	{
		const br_ssl_engine_context *ec = c->sc ? &c->sc->eng : &c->cc->eng;
		pr_err("wasm_sendmsg: %s br_sslio_write_all error %d", get_direction(c), br_ssl_engine_last_error(ec));
		return ret;
	}

	// printk("wasm_sendmsg: finished %s br_sslio_write_all wrote = %d bytes", get_direction(c), get_write_buffer_size(c));

	set_write_buffer_size(c, 0);

	ret = br_sslio_flush(&c->ioc);
	if (ret < 0)
	{
		pr_err("wasm_sendmsg: br_sslio_flush returned an error");
		goto bail;
	}

	ret = size;

bail:

	return ret;
}

void wasm_shutdown(struct sock *sk, int how)
{
	printk("wasm_shutdown: running for sk %p", sk);
	wasm_socket_context *c = sk->sk_user_data;
	free_wasm_socket_context(c);
	sk->sk_user_data = NULL;
	printk("wasm_shutdown: tcp_shutdown is running for sk %p", sk);
	tcp_shutdown(sk, how);
	printk("wasm_shutdown: tcp_shutdown is done for sk %p", sk);
}

void wasm_destroy(struct sock *sk)
{
	printk("wasm_destroy: running for sk %p", sk);
	wasm_socket_context *c = sk->sk_user_data;
	free_wasm_socket_context(c);
	sk->sk_user_data = NULL;
	tcp_v4_destroy_sock(sk);
}

// an enum for the direction
typedef enum
{
	INPUT,
	OUTPUT
} direction;

// a function to evaluate the connection if it should be intercepted
bool eval_connection(u16 port, direction direction, const char *comm)
{
	return (port == 8000 || port == 8080); //&& direction == INPUT && strcmp(comm, "python3") == 0;
}

struct sock *(*accept)(struct sock *sk, int flags, int *err, bool kern);

int (*connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);

struct sock *wasm_accept(struct sock *sk, int flags, int *err, bool kern)
{
	u16 port = (u16)(sk->sk_portpair >> 16);
	printk("wasm_accept: app: %s on port: %d", current->comm, port);

	struct sock *client = accept(sk, flags, err, kern);

	if (client && eval_connection(port, INPUT, current->comm))
	{
		proxywasm *p = this_cpu_proxywasm();
		proxywasm_lock(p);

		wasm_socket_context *sc = new_server_wasm_socket_context(p);

		wasm_vm_result res = proxy_on_new_connection(p);
		if (res.err)
		{
			pr_err("new_server_wasm_socket_context: failed to create context: %s", res.err);
		}

		proxywasm_unlock(p);

		// Sample how to send a command to the userspace agent
		const char *data = "{\"port\": \"8000\"}";
		command_answer *answer = send_command("accept", data);

		if (answer->error)
		{
			pr_err("wasm_accept: failed to send command: %s", answer->error);
		}
		else
		{
			pr_info("wasm_accept: command answer: %s", answer->answer);
		}

		free_command_answer(answer);

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

		br_x509_minimal_init_full(&sc->xc, TAs, TAs_NUM);
		br_ssl_engine_set_x509(&sc->sc->eng, &sc->xc.vtable);
		br_ssl_engine_set_default_rsavrfy(&sc->sc->eng);
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
		br_ssl_engine_set_buffer(&sc->sc->eng, &sc->iobuf, BR_SSL_BUFSIZE_BIDI, true);

		br_ssl_engine_set_protocol_names(&sc->sc->eng, ALPNs, ALPNs_NUM);

		br_ssl_server_set_trust_anchor_names_alt(sc->sc, TAs, TAs_NUM);

		/*
		 * Reset the server context, for a new handshake.
		 */
		br_ssl_server_reset(sc->sc);

		/*
		 * Initialise the simplified I/O wrapper context.
		 */
		br_sslio_init(&sc->ioc, &sc->sc->eng, sock_read, client, sock_write, client);

		// // We should save the ssl context here to the socket
		client->sk_user_data = sc;

		// and overwrite the socket protocol with our own
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

	if (ret == 0 && eval_connection(port, OUTPUT, current->comm))
	{
		const char *server_name = NULL; // TODO, this needs to be sourced down here

		proxywasm *p = this_cpu_proxywasm();
		proxywasm_lock(p);

		wasm_socket_context *sc = new_client_wasm_socket_context(p);

		wasm_vm_result res = proxy_on_new_connection(p);
		if (res.err)
		{
			pr_err("new_client_wasm_socket_context: failed to create context: %s", res.err);
		}

		proxywasm_unlock(p);

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
		br_ssl_client_init_full(sc->cc, &sc->xc, TAs, TAs_NUM);

		// br_x509_minimal_init_full(sc->xc, TAs, TAs_NUM);
		// br_ssl_engine_set_x509(&sc->cc->eng, &sc->xc->vtable);

		br_ssl_client_set_single_rsa(sc->cc, CHAIN, CHAIN_LEN, &RSA, br_rsa_pkcs1_sign_get_default());

		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc->cc->eng, &sc->iobuf, BR_SSL_BUFSIZE_BIDI, true);

		br_ssl_engine_set_protocol_names(&sc->cc->eng, ALPNs, ALPNs_NUM);

		/*
		 * Reset the client context, for a new handshake. We provide the
		 * target host name: it will be used for the SNI extension. The
		 * last parameter is 0: we are not trying to resume a session.
		 */
		if (br_ssl_client_reset(sc->cc, server_name, false) != 1)
		{
			pr_err("br_ssl_client_reset returned an error");
		}

		/*
		 * Initialise the simplified I/O wrapper context, to use our
		 * SSL client context, and the two callbacks for socket I/O.
		 */
		br_sslio_init(&sc->ioc, &sc->cc->eng, sock_read, sk, sock_write, sk);

		// We should save the ssl context here to the socket
		sk->sk_user_data = sc;
		sk->sk_prot = &wasm_prot;
	}

	return ret;
}

int wasm_socket_init(void)
{
	// let's overwrite tcp_port with our own implementation
	accept = tcp_prot.accept;
	connect = tcp_prot.connect;

	tcp_prot.accept = wasm_accept;
	tcp_prot.connect = wasm_connect;

	memcpy(&wasm_prot, &tcp_prot, sizeof(wasm_prot));
	wasm_prot.recvmsg = wasm_recvmsg;
	wasm_prot.sendmsg = wasm_sendmsg;
	wasm_prot.shutdown = wasm_shutdown;
	wasm_prot.destroy = wasm_destroy;

	br_hmac_drbg_context ctx;
	br_hmac_drbg_init(&ctx, &br_sha256_vtable, "RSA keygen seed", 15);


	br_rsa_keygen rsa_keygen = br_rsa_keygen_get_default();

	br_rsa_private_key rsa_priv;
	unsigned char raw_priv_key[BR_RSA_KBUF_PRIV_SIZE(2048)];

	br_rsa_public_key rsa_pub;
	unsigned char raw_pub_key[BR_RSA_KBUF_PUB_SIZE(2048)];


	uint32_t result = rsa_keygen(&ctx.vtable, &rsa_priv, raw_priv_key, &rsa_pub, raw_pub_key, 2048, 3);
	if (result == 1) {
		printk("RSA keys are successfully generated.");
	}

	printk("Generating private exponent");
 	br_rsa_compute_privexp rsa_priv_exp_comp = br_rsa_compute_privexp_get_default();
 	unsigned char priv_exponent[256];
 	size_t priv_exponent_size = rsa_priv_exp_comp(priv_exponent, &rsa_priv, 3);
 	if (rsa_pub.nlen != priv_exponent_size) {
 		printk("Error happened during priv_exponent generation");
 	}

	size_t len = br_encode_rsa_raw_der(NULL, &rsa_priv, &rsa_pub, priv_exponent, priv_exponent_size);

	unsigned char* encoded_rsa = kmalloc(len, GFP_KERNEL);
	br_encode_rsa_raw_der(encoded_rsa, &rsa_priv, &rsa_pub, priv_exponent, priv_exponent_size);


	size_t pem_len = br_pem_encode(NULL, NULL, len, "RSA PRIVATE KEY", 0);

	unsigned char *pem = kmalloc(pem_len+1, GFP_KERNEL);
	br_pem_encode(pem, encoded_rsa, len, "RSA PRIVATE KEY", 0);

	printk("%s", pem);

	printk(KERN_INFO "WASM socket support loaded.");

	return 0;
}

void wasm_socket_exit(void)
{
	tcp_prot.accept = accept;
	tcp_prot.connect = connect;

	printk(KERN_INFO "WASM socket support unloaded.");
}
