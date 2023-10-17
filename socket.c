/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/tls.h>
#include <net/sock.h>
#include <net/ip.h>

#include "bearssl.h"
#include "commands.h"
#include "csr.h"
#include "device_driver.h"
#include "opa.h"
#include "proxywasm.h"
#include "rsa_tools.h"
#include "socket.h"
#include "tls.h"
#include "string.h"

const char *ALPNs[] = {
	"istio-peer-exchange",
	"istio",
};

const size_t ALPNs_NUM = sizeof(ALPNs) / sizeof(ALPNs[0]);

static struct proto nasp_prot;
static struct proto nasp_ktls_prot;
static struct proto nasp_v6_prot;
static struct proto nasp_v6_ktls_prot;

static const br_rsa_private_key *rsa_priv;
static const br_rsa_public_key *rsa_pub;

typedef struct
{
	union
	{
		br_ssl_server_context *sc;
		br_ssl_client_context *cc;
	};

	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_sslio_context ioc;
	br_x509_nasp_context xc;
	br_x509_class validator;

	br_rsa_private_key *rsa_priv;
	br_rsa_public_key *rsa_pub;
	br_x509_certificate *cert;
	csr_parameters *parameters;

	br_x509_certificate *chain;
	size_t chain_len;
	br_x509_trust_anchor *trust_anchors;
	size_t trust_anchors_len;

	proxywasm *p;
	proxywasm_context *pc;
	i64 direction;
	char *protocol;

	buffer_t *read_buffer;
	buffer_t *write_buffer;

	struct sock *sock;

	opa_socket_context opa_socket_ctx;

	int (*ktls_recvmsg)(struct sock *sock,
						struct msghdr *msg,
						size_t size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
						int noblock,
#endif
						int flags,
						int *addr_len);

	int (*ktls_sendmsg)(struct sock *sock,
						struct msghdr *msg,
						size_t size);

} nasp_socket;

static int ktls_send_msg(nasp_socket *s, void *msg, size_t len)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = msg, .iov_len = len};

	iov_iter_kvec(&hdr.msg_iter, WRITE, &iov, 1, len);

	return s->ktls_sendmsg(s->sock, &hdr, len);
}

static int ktls_recv_msg(nasp_socket *s, void *buf, size_t buf_len, size_t size)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = buf, .iov_len = buf_len};
	int addr_len = 0;

	iov_iter_kvec(&hdr.msg_iter, READ, &iov, 1, buf_len);

	return s->ktls_recvmsg(s->sock, &hdr, size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
						   0,
#endif
						   0, &addr_len);
}

static int send_msg(struct sock *sock, void *msg, size_t len)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = msg, .iov_len = len};

	iov_iter_kvec(&hdr.msg_iter, WRITE, &iov, 1, len);

	return tcp_sendmsg(sock, &hdr, len);
}

static int recv_msg(struct sock *sock, void *buf, size_t size)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = buf, .iov_len = size};
	int addr_len = 0;

	iov_iter_kvec(&hdr.msg_iter, READ, &iov, 1, size);

	return tcp_recvmsg(sock, &hdr, size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
					   0,
#endif
					   0, &addr_len);
}

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int sock_read(void *ctx, unsigned char *buf, size_t len)
{
	return recv_msg((struct sock *)ctx, buf, len);
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	return send_msg((struct sock *)ctx, buf, len);
}

static char *get_direction(nasp_socket *s)
{
	if (s->direction == ListenerDirectionInbound)
	{
		return "server";
	}
	else
	{
		return "client";
	}
}

static br_ssl_engine_context *get_ssl_engine_context(nasp_socket *s)
{
	return s->direction == ListenerDirectionInbound ? &s->sc->eng : &s->cc->eng;
}

static int get_read_buffer_capacity(nasp_socket *s);

static int nasp_socket_read(nasp_socket *s, void *dst, size_t len)
{
	if (s->ktls_recvmsg)
	{
		return ktls_recv_msg(s, dst, get_read_buffer_capacity(s), len);
	}
	else
	{
		int ret = br_sslio_read(&s->ioc, dst, len);
		if (ret < 0)
		{
			const br_ssl_engine_context *ec = get_ssl_engine_context(s);
			int last_error = br_ssl_engine_last_error(ec);
			if (last_error == 0)
				return 0;
			pr_err("nasp_socket_read: %s br_sslio_read error %d", get_direction(s), last_error);
		}
		return ret;
	}
}

static int nasp_socket_write(nasp_socket *s, void *src, size_t len)
{
	if (s->ktls_sendmsg)
	{
		return ktls_send_msg(s, src, len); // TODO not sure if this is a write all!
	}
	else
	{
		int ret = br_sslio_write_all(&s->ioc, src, len);
		if (ret < 0)
		{
			const br_ssl_engine_context *ec = get_ssl_engine_context(s);
			pr_err("nasp: socket_write: %s br_sslio_write_all error %d", get_direction(s), br_ssl_engine_last_error(ec));
			return ret;
		}

		ret = br_sslio_flush(&s->ioc);
		if (ret != 0)
		{
			pr_err("nasp: socket_write: br_sslio_flush returned an error %d", ret);
		}
		return ret;
	}
}

static char *get_read_buffer(nasp_socket *s)
{
	return s->read_buffer->data;
}

static char *get_read_buffer_for_read(nasp_socket *s, int len)
{
	return buffer_access(s->read_buffer, len);
}

static int get_read_buffer_capacity(nasp_socket *s)
{
	return s->read_buffer->capacity - s->read_buffer->size;
}

static int get_read_buffer_size(nasp_socket *s)
{
	return s->read_buffer->size;
}

static void set_read_buffer_size(nasp_socket *s, int size)
{
	s->read_buffer->size = size;
}

static char *get_write_buffer(nasp_socket *s)
{
	return s->write_buffer->data;
}

static char *get_write_buffer_for_write(nasp_socket *s, int len)
{
	return buffer_access(s->write_buffer, len);
}

static int get_write_buffer_size(nasp_socket *s)
{
	return s->write_buffer->size;
}

static void set_write_buffer_size(nasp_socket *s, int size)
{
	s->write_buffer->size = size;
}

static void nasp_socket_free(nasp_socket *s)
{
	if (s)
	{
		printk("nasp: freeing nasp_socket of %s", current->comm);

		if (s->p)
		{
			proxywasm_lock(s->p, s->pc);
			proxywasm_destroy_context(s->p);
			proxywasm_unlock(s->p);
		}

		if (s->protocol && !s->ktls_sendmsg)
		{
			// This call runs the SSL closure protocol (sending a close_notify, receiving the response close_notify).
			if (!br_sslio_close(&s->ioc))
			{
				const br_ssl_engine_context *ec = get_ssl_engine_context(s);
				pr_err("nasp: %s br_sslio_close returned an error: %d", current->comm, br_ssl_engine_last_error(ec));
			}
			else
			{
				printk("nasp: %s br_sslio SSL closed", current->comm);
			}
		}

		if (s->direction == ListenerDirectionInbound)
		{
			kfree(s->sc);
		}
		else
		{
			kfree(s->cc);
		}

		br_x509_nasp_free(&s->xc);

		opa_socket_context_free(s->opa_socket_ctx);

		// if (c->rsa_priv != NULL)
		// {
		// 	kfree(c->rsa_priv->p);
		// }
		// if (c->rsa_pub != NULL)
		// {
		// 	kfree(c->rsa_pub->n);
		// }

		buffer_free(s->read_buffer);
		buffer_free(s->write_buffer);

		kfree(s->rsa_priv);
		kfree(s->rsa_pub);
		kfree(s->cert);
		kfree(s->parameters);
		kfree(s);
	}
}

int proxywasm_attach(proxywasm *p, nasp_socket *s, ListenerDirection direction, buffer_t *upstream_buffer, buffer_t *downstream_buffer)
{
	wasm_vm_result res = proxywasm_create_context(p, upstream_buffer, downstream_buffer);
	if (res.err)
	{
		pr_err("nasp: proxywasm_attach failed to create context: %s", res.err);
		return -1;
	}

	s->pc = proxywasm_get_context(p);
	s->p = p;
	s->direction = direction;
	set_property_v(s->pc, "listener_direction", (char *)&s->direction, sizeof(s->direction));

	proxywasm_set_context(p, s->pc);

	res = proxy_on_new_connection(p);
	if (res.err)
	{
		pr_err("nasp: proxywasm_attach failed to create connection: %s", res.err);
		return -1;
	}

	return 0;
}

static nasp_socket *nasp_socket_accept(struct sock *sock)
{
	nasp_socket *s = kzalloc(sizeof(nasp_socket), GFP_KERNEL);
	s->sc = kzalloc(sizeof(br_ssl_server_context), GFP_KERNEL);
	s->rsa_priv = kzalloc(sizeof(br_rsa_private_key), GFP_KERNEL);
	s->rsa_pub = kzalloc(sizeof(br_rsa_public_key), GFP_KERNEL);
	s->cert = kzalloc(sizeof(br_x509_certificate), GFP_KERNEL);
	s->chain = kzalloc(sizeof(br_x509_certificate), GFP_KERNEL);
	s->trust_anchors = kzalloc(sizeof(br_x509_trust_anchor), GFP_KERNEL);
	s->parameters = kzalloc(sizeof(csr_parameters), GFP_KERNEL);
	s->read_buffer = buffer_new(16 * 1024);
	s->write_buffer = buffer_new(16 * 1024);

	s->sock = sock;

	proxywasm *p = this_cpu_proxywasm();

	if (p)
	{
		proxywasm_lock(p, NULL);
		int err = proxywasm_attach(p, s, ListenerDirectionInbound, s->write_buffer, s->read_buffer);
		proxywasm_unlock(p);

		if (err != 0)
		{
			nasp_socket_free(s);
			return NULL;
		}
	}

	return s;
}

static nasp_socket *nasp_socket_connect(struct sock *sock)
{
	nasp_socket *s = kzalloc(sizeof(nasp_socket), GFP_KERNEL);
	s->cc = kzalloc(sizeof(br_ssl_client_context), GFP_KERNEL);
	s->rsa_priv = kzalloc(sizeof(br_rsa_private_key), GFP_KERNEL);
	s->rsa_pub = kzalloc(sizeof(br_rsa_public_key), GFP_KERNEL);
	s->cert = kzalloc(sizeof(br_x509_certificate), GFP_KERNEL);
	s->parameters = kzalloc(sizeof(csr_parameters), GFP_KERNEL);
	s->read_buffer = buffer_new(16 * 1024);
	s->write_buffer = buffer_new(16 * 1024);

	s->sock = sock;

	proxywasm *p = this_cpu_proxywasm();

	if (p)
	{
		proxywasm_lock(p, NULL);
		int err = proxywasm_attach(p, s, ListenerDirectionOutbound, s->read_buffer, s->write_buffer);
		proxywasm_unlock(p);

		if (err != 0)
		{
			nasp_socket_free(s);
			return NULL;
		}
	}

	return s;
}

void dump_array(unsigned char array[], size_t len)
{
	size_t u;
	for (u = 0; u < len; u++)
	{
		pr_cont("%x, ", array[u]);
	}
}

void dump_msghdr(struct msghdr *msg)
{
	char data[1024];
	size_t len, nr_segs, iovlen;
	int npages;

	pr_info("msg_name = %p\n", msg->msg_name);
	pr_info("msg_namelen = %u\n", msg->msg_namelen);
	pr_info("msg_iter.type = %u\n", msg->msg_iter.iter_type);
	pr_info("msg_iter.count = %zd\n", msg->msg_iter.count);

	pr_info("iovoffset = %zd", msg->msg_iter.iov_offset);
	msg->msg_iter.iov_offset = 0;
	// iov_iter_zero(2, &msg->msg_iter);
	pr_info("iovoffset = %zd", msg->msg_iter.iov_offset);

	nr_segs = iov_iter_single_seg_count(&msg->msg_iter);
	pr_info("iovsegcount = %zd", nr_segs);

	npages = iov_iter_npages(&msg->msg_iter, 16384);
	pr_info("npages = %d", npages);

	struct iovec *iov;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	iov = msg->msg_iter.iov;
#else
	iov = iter_iov(&msg->msg_iter);
#endif

	iovlen = iov_length(iov, npages);
	pr_info("iovlen = %zd", iovlen);

	len = copy_from_iter(data, iovlen - msg->msg_iter.count, &msg->msg_iter);
	pr_info("copylen = %zd\n", len);
	pr_info("msg = [%.*s]\n", (int)len, data);
	pr_info("iovoffset = %zd\n", msg->msg_iter.iov_offset);
}

static int configure_ktls_sock(nasp_socket *s);

static bool nasp_socket_proxywasm_enabled(nasp_socket *s)
{
	return s->pc != NULL;
}

static int ensure_tls_handshake(nasp_socket *s)
{
	int ret = 0;
	char *protocol = READ_ONCE(s->protocol);

	if (protocol == NULL)
	{
		ret = br_sslio_flush(&s->ioc);
		if (ret == 0)
		{
			printk("nasp: %s %s TLS handshake done, sk: %p", current->comm, get_direction(s), s->sock);
		}
		else
		{
			const br_ssl_engine_context *ec = get_ssl_engine_context(s);
			pr_err("nasp: %s TLS handshake error %d", current->comm, br_ssl_engine_last_error(ec));
			return ret;
		}

		protocol = br_ssl_engine_get_selected_protocol(&s->sc->eng);

		if (protocol)
		{
			printk("nasp: %s protocol name: %s", current->comm, protocol);
			if (nasp_socket_proxywasm_enabled(s))
				set_property_v(s->pc, "upstream.negotiated_protocol", protocol, strlen(protocol));
		}
		else
			protocol = "no-mtls";

		WRITE_ONCE(s->protocol, protocol);

		ret = configure_ktls_sock(s);
		if (ret != 0)
		{
			pr_err("naspp socket %s configure_ktls_sock failed %d", current->comm, ret);
			return ret;
		}
	}

	return ret;
}

// returns continue (0), pause (1) or error (-1)
static int nasp_socket_proxywasm_on_data(nasp_socket *s, int data_size, bool end_of_stream, bool send)
{
	int action = Pause;
	proxywasm_lock(s->p, s->pc);
	wasm_vm_result result = (send ? s->direction == ListenerDirectionOutbound : s->direction != ListenerDirectionOutbound)
								? proxy_on_downstream_data(s->p, data_size, end_of_stream)
								: proxy_on_upstream_data(s->p, data_size, end_of_stream);
	proxywasm_unlock(s->p);

	if (result.err)
	{
		pr_err("nasp: proxy_on_upstream/downstream_data returned an error: %s", result.err);
		action = -1;
		goto bail;
	}

	if (result.data->i32 == Continue || end_of_stream)
	{
		action = Continue;
	}

bail:
	return action;
}

int nasp_recvmsg(struct sock *sock,
				 struct msghdr *msg,
				 size_t size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
				 int noblock,
#endif
				 int flags,
				 int *addr_len)
{
	int ret, len;

	nasp_socket *s = sock->sk_user_data;

	ret = ensure_tls_handshake(s);
	if (ret != 0)
	{
		goto bail;
	}

	len = size;
	if (len == 0)
	{
		ret = 0;
		goto bail;
	}

	bool end_of_stream = false;
	int action = Pause;

	while (action != Continue)
	{
		ret = nasp_socket_read(s, get_read_buffer_for_read(s, len), len);
		if (ret < 0)
		{
			pr_err("nasp: recvmsg %s nasp_socket_read error %d", get_direction(s), ret);
			goto bail;
		}
		else if (ret == 0)
		{
			end_of_stream = true;
		}

		set_read_buffer_size(s, get_read_buffer_size(s) + ret);

		if (nasp_socket_proxywasm_enabled(s))
		{
			action = nasp_socket_proxywasm_on_data(s, ret, end_of_stream, false);
			if (action < 0)
			{
				ret = -1;
				goto bail;
			}
		}
		else
		{
			action = Continue;
		}
	}

	int read_buffer_size = get_read_buffer_size(s);

	len = copy_to_iter(get_read_buffer(s), read_buffer_size, &msg->msg_iter);
	if (len < read_buffer_size)
	{
		pr_warn("nasp: recvmsg copy_to_iter copied less than requested");
	}

	set_read_buffer_size(s, read_buffer_size - len);

	ret = len;

bail:
	return ret;
}

int nasp_sendmsg(struct sock *sock, struct msghdr *msg, size_t size)
{
	int ret, len;

	nasp_socket *s = sock->sk_user_data;

	ret = ensure_tls_handshake(s);
	if (ret != 0)
	{
		goto bail;
	}

	len = copy_from_iter(get_write_buffer_for_write(s, size), size, &msg->msg_iter);

	set_write_buffer_size(s, get_write_buffer_size(s) + len);

	if (nasp_socket_proxywasm_enabled(s))
	{
		ret = nasp_socket_proxywasm_on_data(s, len, false, true);
		if (ret < 0)
		{
			goto bail;
		}

		if (ret == Pause)
		{
			ret = len;
			goto bail;
		}
	}

	ret = nasp_socket_write(s, get_write_buffer(s), get_write_buffer_size(s));
	if (ret < 0)
	{
		goto bail;
	}

	set_write_buffer_size(s, get_write_buffer_size(s) - ret);

	ret = size;

bail:
	return ret;
}

void nasp_close(struct sock *sk, long timeout)
{
	nasp_socket *s = READ_ONCE(sk->sk_user_data);
	if (s)
	{
		printk("nasp: close %s running for sk %p ", current->comm, sk);
		nasp_socket_free(s);
		WRITE_ONCE(sk->sk_user_data, NULL);
	}
	tcp_close(sk, timeout);
}

// analyze tls_main.c to find out what we need to implement: check build_protos()
void ensure_nasp_ktls_prot(struct sock *sock, struct proto *nasp_ktls_prot)
{
	void (*close)(struct sock *sk, long timeout) = READ_ONCE(nasp_ktls_prot->close);

	if (close == NULL)
	{
		close = sock->sk_prot->close;

		int (*setsockopt)(struct sock *sk, int level,
						  int optname, sockptr_t optval,
						  unsigned int optlen);
		setsockopt = sock->sk_prot->setsockopt;

		int (*getsockopt)(struct sock *sk, int level,
						  int optname, char __user *optval,
						  int __user *option);
		getsockopt = sock->sk_prot->getsockopt;

		bool (*sock_is_readable)(struct sock *sk);
		sock_is_readable = sock->sk_prot->sock_is_readable;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
		int (*sendpage)(struct sock *sk, struct page *page,
						int offset, size_t size, int flags);
		sendpage = sock->sk_prot->sendpage;

		nasp_ktls_prot->sendpage = sendpage;
#endif
		nasp_ktls_prot->setsockopt = setsockopt;
		nasp_ktls_prot->getsockopt = getsockopt;
		nasp_ktls_prot->sock_is_readable = sock_is_readable;
		WRITE_ONCE(nasp_ktls_prot->close, close);
	}
}

static int configure_ktls_sock(nasp_socket *s)
{
	int ret;

	br_ssl_engine_context *eng = get_ssl_engine_context(s);
	br_ssl_session_parameters *params = &eng->session;

	if (params->cipher_suite != BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
	{
		pr_warn("nasp: configure_ktls: only ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite is supported, got %x", params->cipher_suite);
		return 0;
	}

	printk("nasp: configure_ktls for %s cipher suite: %x version: %x, iv: %.*s", current->comm, params->cipher_suite, params->version, 12, eng->out.chapol.iv);
	printk("nasp: configure_ktls for %s cipher suite: %x version: %x, iv: %.*s", current->comm, params->cipher_suite, params->version, 12, eng->in.chapol.iv);

	struct tls12_crypto_info_chacha20_poly1305 crypto_info_tx;
	crypto_info_tx.info.version = TLS_1_2_VERSION;
	crypto_info_tx.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
	memcpy(crypto_info_tx.iv, eng->out.chapol.iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
	memcpy(crypto_info_tx.key, eng->out.chapol.key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
	memcpy(crypto_info_tx.rec_seq, &eng->out.chapol.seq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
	// memcpy(crypto_info.salt, eng->out.chapol.salt, TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE);

	struct tls12_crypto_info_chacha20_poly1305 crypto_info_rx;
	crypto_info_rx.info.version = TLS_1_2_VERSION;
	crypto_info_rx.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
	memcpy(crypto_info_rx.iv, eng->in.chapol.iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
	memcpy(crypto_info_rx.key, eng->in.chapol.key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
	memcpy(crypto_info_rx.rec_seq, &eng->in.chapol.seq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
	// memcpy(crypto_info.salt, eng->out.chapol.salt, TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE);

	ret = s->sock->sk_prot->setsockopt(s->sock, SOL_TCP, TCP_ULP, KERNEL_SOCKPTR("tls"), sizeof("tls"));
	if (ret != 0)
	{
		pr_err("nasp: %s setsockopt TCP_ULP ret: %d", current->comm, ret);
		return ret;
	}

	ret = s->sock->sk_prot->setsockopt(s->sock, SOL_TLS, TLS_TX, KERNEL_SOCKPTR(&crypto_info_tx), sizeof(crypto_info_tx));
	if (ret != 0)
	{
		pr_err("nasp: %s setsockopt TLS_TX ret: %d", current->comm, ret);
		return ret;
	}

	// unsigned int yes = 1;
	// ret = c->sock->sk_prot->setsockopt(c->sock, SOL_TLS, TLS_TX_ZEROCOPY_RO, KERNEL_SOCKPTR(&yes), sizeof(yes));
	// if (ret != 0)
	// {
	// 	pr_err("nasp: %s setsockopt TLS_TX_ZEROCOPY_RO ret: %d", current->comm, ret);
	// 	return ret;
	// }

	ret = s->sock->sk_prot->setsockopt(s->sock, SOL_TLS, TLS_RX, KERNEL_SOCKPTR(&crypto_info_rx), sizeof(crypto_info_rx));
	if (ret != 0)
	{
		pr_err("nasp: %s setsockopt TLS_RX ret: %d", current->comm, ret);
		return ret;
	}

	// We have to save the proto here because the setsockopt calls override the TCP protocol.
	// later those methods set by ktls has to be used to read and write data, but first we
	// need to put back our read and write methods.
	s->ktls_recvmsg = s->sock->sk_prot->recvmsg;
	s->ktls_sendmsg = s->sock->sk_prot->sendmsg;

	struct proto *ktls_prot;
	if (s->sock->sk_family == AF_INET)
	{
		ktls_prot = &nasp_ktls_prot;
	}
	else
	{
		ktls_prot = &nasp_v6_ktls_prot;
	}

	ensure_nasp_ktls_prot(s->sock, ktls_prot);

	WRITE_ONCE(s->sock->sk_prot, ktls_prot);

	return 0;
}

// a function to evaluate the connection if it should be intercepted, now with opa
static opa_socket_context socket_eval(const char *input)
{
	return this_cpu_opa_socket_eval(input);
}

struct sock *(*accept)(struct sock *sk, int flags, int *err, bool kern);
int (*connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);

struct sock *(*accept_v6)(struct sock *sk, int flags, int *err, bool kern);
int (*connect_v6)(struct sock *sk, struct sockaddr *uaddr, int addr_len);

static int handle_cert_gen(nasp_socket *sc)
{
	// We should not only check for empty cert but we must check the certs validity
	// TODO must set the certificate to avoid new cert generation every time
	if (sc->chain_len == 0)
	{
		// generating certificate signing request
		if (sc->rsa_priv->plen == 0 || sc->rsa_pub->elen == 0)
		{
			u_int32_t result = generate_rsa_keys(sc->rsa_priv, sc->rsa_pub);
			if (result == 0)
			{
				pr_err("nasp: generate_csr error generating rsa keys");
				return -1;
			}
		}

		int len = encode_rsa_priv_key_to_der(NULL, sc->rsa_priv, sc->rsa_pub);
		if (len <= 0)
		{
			pr_err("nasp: generate_csr error during rsa private der key length calculation");
			return -1;
		}

		unsigned char *csr_ptr;

		csr_module *csr = this_cpu_csr();
		csr_lock(csr);
		{
			// Allocate memory inside the wasm vm since this data must be available inside the module
			wasm_vm_result malloc_result = csr_malloc(csr, len);
			if (malloc_result.err)
			{
				pr_err("nasp: generate_csr wasm_vm_csr_malloc error: %s", malloc_result.err);
				csr_unlock(csr);
				return -1;
			}

			uint8_t *mem = wasm_vm_memory(get_csr_module(csr));
			i32 addr = malloc_result.data->i32;

			unsigned char *der = mem + addr;

			int error = encode_rsa_priv_key_to_der(der, sc->rsa_priv, sc->rsa_pub);
			if (error <= 0)
			{
				pr_err("nasp: generate_csr error during rsa private key der encoding");
				csr_unlock(csr);
				return -1;
			}

			sc->parameters->subject = "CN=nasp-protected-workload";
			sc->parameters->dns = sc->opa_socket_ctx.dns;
			sc->parameters->uri = sc->opa_socket_ctx.uri;
			sc->parameters->email = "nasp@outshift.cisco.com";
			sc->parameters->ip = "127.0.0.1";

			csr_result generated_csr = csr_gen(csr, addr, len, sc->parameters);
			if (generated_csr.err)
			{
				pr_err("nasp: generate_csr wasm_vm_csr_gen error: %s", generated_csr.err);
				csr_unlock(csr);
				return -1;
			}

			wasm_vm_result free_result = csr_free(csr, addr);
			if (free_result.err)
			{
				pr_err("nasp: generate_csr wasm_vm_csr_free error: %s", free_result.err);
				csr_unlock(csr);
				return -1;
			}

			csr_ptr = strndup(generated_csr.csr_ptr + mem, generated_csr.csr_len);
			free_result = csr_free(csr, generated_csr.csr_ptr);
			if (free_result.err)
			{
				pr_err("nasp: generate_csr wasm_vm_csr_free error: %s", free_result.err);
				csr_unlock(csr);
				return -1;
			}
		}
		csr_unlock(csr);

		csr_sign_answer *csr_sign_answer;
		csr_sign_answer = send_csrsign_command(csr_ptr);
		if (csr_sign_answer->error)
		{
			pr_err("nasp: generate_csr csr sign answer error: %s", csr_sign_answer->error);
			kfree(csr_sign_answer->error);
			kfree(csr_sign_answer);
			return -1;
		}
		else
		{
			sc->trust_anchors = csr_sign_answer->trust_anchors;
			sc->trust_anchors_len = csr_sign_answer->trust_anchors_len;
			sc->chain = csr_sign_answer->chain;
			sc->chain_len = csr_sign_answer->chain_len;
		}

		kfree(csr_sign_answer);
	}
	return 0;
}

struct sock *nasp_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sock *client = NULL;
	struct proto *prot;
	nasp_socket *sc = NULL;

	if (sk->sk_family == AF_INET)
	{
		client = accept(sk, flags, err, kern);
		prot = &nasp_prot;
	}
	else
	{
		client = accept_v6(sk, flags, err, kern);
		prot = &nasp_v6_prot;
	}

	u16 port = (u16)(sk->sk_portpair >> 16);

	sc = nasp_socket_accept(client);
	if (!sc)
	{
		pr_err("nasp: nasp_socket_accept failed to create nasp_socket");
		goto error;
	}

	// send attest command
	command_answer *answer = send_attest_command(INPUT, client, port);

	if (answer->error)
	{
		pr_err("nasp: accept failed to send attest command: %s", answer->error);
		goto error;
	}
	else
	{
		pr_info("nasp: accept attest command answer: %s", answer->answer);
	}

	sc->opa_socket_ctx = socket_eval(answer->answer);
	free_command_answer(answer);

	if (client && sc->opa_socket_ctx.allowed)
	{
		u16 client_port = (u16)(client->sk_portpair);
		printk("nasp_accept: uid: %d app: %s on ports: %d <- %d", current_uid().val, current->comm, port, client_port);

		memcpy(sc->rsa_priv, rsa_priv, sizeof *sc->rsa_priv);
		memcpy(sc->rsa_pub, rsa_pub, sizeof *sc->rsa_pub);

		int result = handle_cert_gen(sc);
		if (result == -1)
		{
			goto error;
		}
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
		pr_info("nasp: accept use cert from agent");
		br_ssl_server_init_full_rsa(sc->sc, sc->chain, sc->chain_len, sc->rsa_priv);

		// mTLS enablement
		if (sc->opa_socket_ctx.mtls)
		{
			br_x509_minimal_init_full(&sc->xc.ctx, sc->trust_anchors, sc->trust_anchors_len);
			br_ssl_server_set_trust_anchor_names_alt(sc->sc, sc->trust_anchors, sc->trust_anchors_len);

			br_x509_nasp_init(&sc->xc, &sc->sc->eng, &sc->opa_socket_ctx);
			br_ssl_engine_set_default_rsavrfy(&sc->sc->eng);
		}

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
		client->sk_prot = prot;
	}

	return client;

error:
	nasp_socket_free(sc);
	if (client)
		client->sk_prot->close(client, 0);

	pr_err("nasp: [%s] accept error, socket closed", current->comm);

	return NULL;
}

int nasp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	u16 port = ntohs(usin->sin_port);

	int err;
	struct proto *prot;

	if (sk->sk_family == AF_INET)
	{
		err = connect(sk, uaddr, addr_len);
		prot = &nasp_prot;
	}
	else
	{
		err = connect_v6(sk, uaddr, addr_len);
		prot = &nasp_v6_prot;
	}

	printk("nasp: nasp_connect uid: %d app: %s to port: %d", current_uid().val, current->comm, port);

	nasp_socket *sc = nasp_socket_connect(sk);
	if (!sc)
	{
		pr_err("nasp: nasp_socket_connect failed to create nasp_socket");
		goto error;
	}

	// send attest command
	command_answer *answer = send_attest_command(OUTPUT, sk, port);

	if (answer->error)
	{
		pr_err("nasp: connect failed to send attest command: %s", answer->error);
		goto error;
	}
	else
	{
		pr_info("nasp: connect attest command answer: %s", answer->answer);
	}

	sc->opa_socket_ctx = socket_eval(answer->answer);
	free_command_answer(answer);

	if (err == 0 && sc->opa_socket_ctx.allowed)
	{
		const char *server_name = NULL; // TODO, this needs to be sourced down here

		memcpy(sc->rsa_priv, rsa_priv, sizeof *sc->rsa_priv);
		memcpy(sc->rsa_pub, rsa_pub, sizeof *sc->rsa_pub);

		int result = handle_cert_gen(sc);
		if (result == -1)
		{
			goto error;
		}

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
		pr_info("nasp: connect use cert from agent");
		br_ssl_client_init_full(sc->cc, &sc->xc.ctx, sc->trust_anchors, sc->trust_anchors_len);

		br_x509_nasp_init(&sc->xc, &sc->cc->eng, &sc->opa_socket_ctx);

		// mTLS enablement
		if (sc->opa_socket_ctx.mtls)
		{
			br_ssl_client_set_single_rsa(sc->cc, sc->chain, sc->chain_len, sc->rsa_priv, br_rsa_pkcs1_sign_get_default());
		}

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
			pr_err("nasp: connect br_ssl_client_reset returned an error");
		}

		/*
		 * Initialise the simplified I/O wrapper context, to use our
		 * SSL client context, and the two callbacks for socket I/O.
		 */
		br_sslio_init(&sc->ioc, &sc->cc->eng, sock_read, sk, sock_write, sk);

		// We should save the ssl context here to the socket
		sk->sk_user_data = sc;
		sk->sk_prot = prot;
	}

	return err;

error:
	nasp_socket_free(sc);

	release_sock(sk);
	sk->sk_prot->close(sk, 0);
	lock_sock(sk);

	pr_err("nasp: [%s] connect error, socket closed", current->comm);

	return -1;
}

int socket_init(void)
{
	// Initialize BearSSL random number generator
	int err = init_rnd_gen();
	if (err == -1)
	{
		return err;
	}

	// let's overwrite tcp_prot with our own implementation
	accept = tcp_prot.accept;
	connect = tcp_prot.connect;

	// let's overwrite tcp_prot with our own implementation
	accept_v6 = tcpv6_prot.accept;
	connect_v6 = tcpv6_prot.connect;

	tcp_prot.accept = nasp_accept;
	tcp_prot.connect = nasp_connect;

	tcpv6_prot.accept = nasp_accept;
	tcpv6_prot.connect = nasp_connect;

	memcpy(&nasp_prot, &tcp_prot, sizeof(nasp_prot));
	nasp_prot.recvmsg = nasp_recvmsg;
	nasp_prot.sendmsg = nasp_sendmsg;
	nasp_prot.close = nasp_close;

	memcpy(&nasp_ktls_prot, &nasp_prot, sizeof(nasp_prot));
	nasp_ktls_prot.close = NULL; // mark it as uninitialized

	memcpy(&nasp_v6_prot, &tcpv6_prot, sizeof(nasp_v6_prot));
	nasp_v6_prot.recvmsg = nasp_recvmsg;
	nasp_v6_prot.sendmsg = nasp_sendmsg;
	nasp_v6_prot.close = nasp_close;

	memcpy(&nasp_v6_ktls_prot, &nasp_v6_prot, sizeof(nasp_v6_prot));
	nasp_v6_ktls_prot.close = NULL; // mark it as uninitialized

	//- generate global tls key
	rsa_priv = kzalloc(sizeof(br_rsa_private_key), GFP_KERNEL);
	rsa_pub = kzalloc(sizeof(br_rsa_public_key), GFP_KERNEL);
	u_int32_t result = generate_rsa_keys(rsa_priv, rsa_pub);
	if (result == 0)
	{
		pr_err("nasp: socket_init error generating rsa keys");
		return -1;
	}

	printk(KERN_INFO "nasp: socket support loaded.");

	return 0;
}

void socket_exit(void)
{
	tcp_prot.accept = accept;
	tcp_prot.connect = connect;

	tcpv6_prot.accept = accept_v6;
	tcpv6_prot.connect = connect_v6;

	//- free global tls key
	kfree(rsa_priv);
	kfree(rsa_pub);

	printk(KERN_INFO "nasp: socket support unloaded.");
}
