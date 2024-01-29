/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

#define pr_fmt(fmt) "%s: " fmt, KBUILD_MODNAME

#include <linux/tcp.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/tls.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/inet.h>

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
#include "cert_tools.h"
#include "augmentation.h"
#include "json.h"
#include "sd.h"
#include "camblet.h"
#include "trace.h"

const char *ALPNs[] = {
	"http/1.1",
	"camblet",
};

const size_t ALPNs_NUM = sizeof(ALPNs) / sizeof(ALPNs[0]);

extern bool ktls_available;

static struct proto camblet_prot;
static struct proto camblet_ktls_prot;
static struct proto camblet_v6_prot;
static struct proto camblet_v6_ktls_prot;

static br_rsa_private_key *rsa_priv;
static br_rsa_public_key *rsa_pub;

struct camblet_socket;
typedef struct camblet_socket camblet_socket;

typedef int(camblet_send_msg)(camblet_socket *s, void *msg, size_t len);
typedef int(camblet_recv_msg)(camblet_socket *s, void *buf, size_t len, int flags);

struct camblet_socket
{
	union
	{
		br_ssl_server_context *sc;
		br_ssl_client_context *cc;
	};

	unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
	br_sslio_context ioc;
	br_x509_camblet_context xc;
	br_x509_class validator;

	br_rsa_private_key *rsa_priv;
	br_rsa_public_key *rsa_pub;
	csr_parameters *parameters;

	x509_certificate *cert;

	char *hostname;

	proxywasm *p;
	proxywasm_context *pc;
	i64 direction;
	char *protocol;
	struct mutex lock;

	buffer_t *read_buffer;
	buffer_t *write_buffer;

	struct sock *sock;
	bool sock_closed;

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

	void (*ktls_close)(struct sock *sk, long timeout);

	camblet_send_msg *send_msg;
	camblet_recv_msg *recv_msg;

	const tcp_connection_context *conn_ctx;
};

static int get_read_buffer_capacity(camblet_socket *s);

static br_ssl_engine_context *get_ssl_engine_context(camblet_socket *s)
{
	return s->direction == ListenerDirectionInbound ? &s->sc->eng : &s->cc->eng;
}

static int ktls_send_msg(camblet_socket *s, void *msg, size_t len)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = msg, .iov_len = len};

	iov_iter_kvec(&hdr.msg_iter, WRITE, &iov, 1, len);

	return s->ktls_sendmsg(s->sock, &hdr, len);
}

static int ktls_recv_msg(camblet_socket *s, void *buf, size_t size, int flags)
{
	int buf_len = get_read_buffer_capacity(s);
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = buf, .iov_len = buf_len};
	int addr_len = 0;

	iov_iter_kvec(&hdr.msg_iter, READ, &iov, 1, buf_len);

	return s->ktls_recvmsg(s->sock, &hdr, size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
						   0,
#endif
						   flags, &addr_len);
}

static int bearssl_send_msg(camblet_socket *s, void *src, size_t len)
{
	int err = br_sslio_write_all(&s->ioc, src, len);
	if (err < 0)
	{
		const br_ssl_engine_context *ec = get_ssl_engine_context(s);
		pr_err("br_sslio_write_all error # command[%s] br_last_err[%d]", current->comm, br_ssl_engine_last_error(ec));
		return err;
	}

	err = br_sslio_flush(&s->ioc);
	if (err < 0)
	{
		pr_err("br_sslio_flush error # command[%s] err[%d]", current->comm, err);
		return err;
	}

	return len;
}

static int
br_sslio_read_with_flags(br_sslio_context *ctx, void *dst, size_t len, int flags)
{
	unsigned char *buf;
	size_t alen;
	bool is_peek = flags & MSG_PEEK;

	if (len == 0)
	{
		return 0;
	}
	if (br_sslio_run_until(ctx, BR_SSL_RECVAPP) < 0)
	{
		return -1;
	}
	buf = br_ssl_engine_recvapp_buf(ctx->engine, &alen);
	if (alen > len)
	{
		alen = len;
	}
	memcpy(dst, buf, alen);
	if (!is_peek)
		br_ssl_engine_recvapp_ack(ctx->engine, alen);
	return (int)alen;
}

static int bearssl_recv_msg(camblet_socket *s, void *dst, size_t len, int flags)
{
	int ret = br_sslio_read_with_flags(&s->ioc, dst, len, flags);
	if (ret < 0)
	{
		const br_ssl_engine_context *ec = get_ssl_engine_context(s);
		int last_error = br_ssl_engine_last_error(ec);
		if (last_error == 0)
			return 0;
		if (last_error == BR_ERR_IO && s->sock_closed)
			return 0;
		if (last_error == BR_ERR_IO)
			return -EIO;
		pr_err("br_sslio_read error # command[%s] err[%d]", current->comm, last_error);
	}
	return ret;
}

static int plain_send_msg(camblet_socket *s, void *msg, size_t len)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = msg, .iov_len = len};

	iov_iter_kvec(&hdr.msg_iter, WRITE, &iov, 1, len);

	return tcp_sendmsg(s->sock, &hdr, len);
}

static int plain_recv_msg(camblet_socket *s, void *buf, size_t size, int flags)
{
	struct msghdr hdr = {0};
	struct kvec iov = {.iov_base = buf, .iov_len = size};
	int addr_len = 0;

	iov_iter_kvec(&hdr.msg_iter, READ, &iov, 1, size);

	return tcp_recvmsg(s->sock, &hdr, size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
					   0,
#endif
					   flags, &addr_len);
}

static int camblet_socket_read(camblet_socket *s, void *dst, size_t len, int flags)
{
	return s->recv_msg(s, dst, len, flags);
}
static int camblet_socket_write(camblet_socket *s, void *src, size_t len)
{
	return s->send_msg(s, src, len);
}

static char *get_read_buffer(camblet_socket *s)
{
	return s->read_buffer->data;
}

static char *get_read_buffer_for_read(camblet_socket *s, int len)
{
	return buffer_access(s->read_buffer, len);
}

static int get_read_buffer_capacity(camblet_socket *s)
{
	return s->read_buffer->capacity - s->read_buffer->size;
}

static int get_read_buffer_size(camblet_socket *s)
{
	return s->read_buffer->size;
}

static void set_read_buffer_size(camblet_socket *s, int size)
{
	s->read_buffer->size = size;
}

static char *get_write_buffer(camblet_socket *s)
{
	return s->write_buffer->data;
}

static char *get_write_buffer_for_write(camblet_socket *s, int len)
{
	return buffer_access(s->write_buffer, len);
}

static int get_write_buffer_size(camblet_socket *s)
{
	return s->write_buffer->size;
}

static void set_write_buffer_size(camblet_socket *s, int size)
{
	s->write_buffer->size = size;
}

static void camblet_socket_free(camblet_socket *s)
{
	if (s)
	{
		pr_debug("free camblet socket # command[%s]", current->comm);

		if (s->p)
		{
			proxywasm_lock(s->p, s->pc);
			proxywasm_destroy_context(s->p);
			proxywasm_unlock(s->p);
		}

		if (s->protocol && !s->ktls_sendmsg && !s->opa_socket_ctx.passthrough)
		{
			// This call runs the SSL closure protocol (sending a close_notify, receiving the response close_notify).
			if (br_sslio_close(&s->ioc) != BR_ERR_OK)
			{
				const br_ssl_engine_context *ec = get_ssl_engine_context(s);
				int err = br_ssl_engine_last_error(ec);
				if (err != 0 && err != BR_ERR_IO)
					pr_err("br_sslio_close error # command[%s] err[%d]", current->comm, err);
			}
			else
			{
				pr_debug("br_sslio SSL closed # command[%s]", current->comm);
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

		if (s->hostname)
		{
			kfree(s->hostname);
		}

		br_x509_camblet_free(&s->xc);

		opa_socket_context_free(s->opa_socket_ctx);
		buffer_free(s->read_buffer);
		buffer_free(s->write_buffer);

		kfree(s->rsa_priv);
		kfree(s->rsa_pub);
		x509_certificate_put(s->cert);

		kfree(s->parameters);
		kfree(s->conn_ctx);
		kfree(s);
	}
}

int proxywasm_attach(proxywasm *p, camblet_socket *s, ListenerDirection direction, buffer_t *upstream_buffer, buffer_t *downstream_buffer)
{
	wasm_vm_result res = proxywasm_create_context(p, upstream_buffer, downstream_buffer);
	if (res.err)
	{
		pr_err("could not create proxywasm context # err[%s]", res.err);
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
		pr_err("error during proxy_on_new_connection # err[%s]", res.err);
		return -1;
	}

	return 0;
}

static camblet_socket *camblet_new_server_socket(struct sock *sock, opa_socket_context opa_socket_ctx, const tcp_connection_context *conn_ctx)
{
	camblet_socket *s = kzalloc(sizeof(camblet_socket), GFP_KERNEL);
	s->sc = kzalloc(sizeof(br_ssl_server_context), GFP_KERNEL);
	s->rsa_priv = kzalloc(sizeof(br_rsa_private_key), GFP_KERNEL);
	s->rsa_pub = kzalloc(sizeof(br_rsa_public_key), GFP_KERNEL);
	s->parameters = kzalloc(sizeof(csr_parameters), GFP_KERNEL);
	s->read_buffer = buffer_new(16 * 1024);
	s->write_buffer = buffer_new(16 * 1024);

	s->sock = sock;
	s->opa_socket_ctx = opa_socket_ctx;

	s->conn_ctx = conn_ctx;

	mutex_init(&s->lock);

	proxywasm *p = this_cpu_proxywasm();

	if (p)
	{
		proxywasm_lock(p, NULL);
		int err = proxywasm_attach(p, s, ListenerDirectionInbound, s->write_buffer, s->read_buffer);
		proxywasm_unlock(p);

		if (err != 0)
		{
			camblet_socket_free(s);
			return NULL;
		}
	}

	return s;
}

static camblet_socket *camblet_new_client_socket(struct sock *sock, opa_socket_context opa_socket_ctx, const tcp_connection_context *conn_ctx)
{
	camblet_socket *s = kzalloc(sizeof(camblet_socket), GFP_KERNEL);
	s->cc = kzalloc(sizeof(br_ssl_client_context), GFP_KERNEL);
	s->rsa_priv = kzalloc(sizeof(br_rsa_private_key), GFP_KERNEL);
	s->rsa_pub = kzalloc(sizeof(br_rsa_public_key), GFP_KERNEL);
	s->parameters = kzalloc(sizeof(csr_parameters), GFP_KERNEL);
	s->read_buffer = buffer_new(16 * 1024);
	s->write_buffer = buffer_new(16 * 1024);

	s->sock = sock;
	s->opa_socket_ctx = opa_socket_ctx;

	s->conn_ctx = conn_ctx;

	mutex_init(&s->lock);

	proxywasm *p = this_cpu_proxywasm();

	if (p)
	{
		proxywasm_lock(p, NULL);
		int err = proxywasm_attach(p, s, ListenerDirectionOutbound, s->read_buffer, s->write_buffer);
		proxywasm_unlock(p);

		if (err != 0)
		{
			camblet_socket_free(s);
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

static int configure_ktls_sock(camblet_socket *s);

static bool camblet_socket_proxywasm_enabled(camblet_socket *s)
{
	return s->pc != NULL;
}

static int ensure_tls_handshake(camblet_socket *s)
{
	int ret = 0;
	char *protocol = READ_ONCE(s->protocol);
	const tcp_connection_context *conn_ctx = s->conn_ctx;

	if (protocol != NULL)
	{
		return ret;
	}

	mutex_lock(&s->lock);

	protocol = READ_ONCE(s->protocol);

	if (protocol == NULL)
	{
		ret = br_sslio_flush(&s->ioc);
		if (ret == 0)
		{
			pr_debug("TLS handshake done # command[%s] sk[%p]", current->comm, s->sock);
			trace_msg(conn_ctx, "TLS handshake done", 0);
		}
		else
		{
			const br_ssl_engine_context *ec = get_ssl_engine_context(s);
			int last_err = br_ssl_engine_last_error(ec);
			pr_err("TLS handshake error # command[%s] err[%d]", current->comm, last_err);
			char last_err_str[8];
			snprintf(last_err_str, 8, "%d", last_err);
			trace_err(conn_ctx, "TLS handshake error", 2, "error_code", last_err_str);
			goto bail;
		}

		protocol = br_ssl_engine_get_selected_protocol(&s->sc->eng);

		if (protocol)
		{
			trace_debug(conn_ctx, "ALPN selected", 2, "alpn", protocol);
			if (camblet_socket_proxywasm_enabled(s))
				set_property_v(s->pc, "upstream.negotiated_protocol", protocol, strlen(protocol));
		}
		else
			protocol = "no-mtls";

		if (s->opa_socket_ctx.passthrough)
		{
			trace_debug(conn_ctx, "passthrough enabled", 0);
			s->send_msg = plain_send_msg;
			s->recv_msg = plain_recv_msg;
		}
		else
		{
			ret = configure_ktls_sock(s);
			if (ret != 0)
			{
				pr_err("configure_ktls_sock failed # command[%s] err[%d]", current->comm, ret);
				trace_err(conn_ctx, "kTLS configuration failed", 0);
				goto bail;
			}
		}

		WRITE_ONCE(s->protocol, protocol);
	}

bail:
	mutex_unlock(&s->lock);

	return ret;
}

// returns continue (0), pause (1) or error (-1)
static int camblet_socket_proxywasm_on_data(camblet_socket *s, int data_size, bool end_of_stream, bool send)
{
	int action = Pause;
	proxywasm_lock(s->p, s->pc);
	wasm_vm_result result = (send ? s->direction == ListenerDirectionOutbound : s->direction != ListenerDirectionOutbound)
								? proxy_on_downstream_data(s->p, data_size, end_of_stream)
								: proxy_on_upstream_data(s->p, data_size, end_of_stream);
	proxywasm_unlock(s->p);

	if (result.err)
	{
		pr_err("proxy_on_upstream/downstream_data returned an error # err[%s]", result.err);
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

int camblet_recvmsg(struct sock *sock,
					struct msghdr *msg,
					size_t size,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
					int noblock,
#endif
					int flags,
					int *addr_len)
{
	int ret, len;

	camblet_socket *s = sock->sk_user_data;

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
		ret = camblet_socket_read(s, get_read_buffer_for_read(s, len), len, flags);
		if (ret < 0)
		{
			if (ret == -ERESTARTSYS)
				ret = -EINTR;

			goto bail;
		}
		else if (ret == 0)
		{
			end_of_stream = true;
		}

		set_read_buffer_size(s, get_read_buffer_size(s) + ret);

		if (camblet_socket_proxywasm_enabled(s))
		{
			action = camblet_socket_proxywasm_on_data(s, ret, end_of_stream, false);
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
		pr_warn("recvmsg copy_to_iter copied less than requested");
	}

	set_read_buffer_size(s, read_buffer_size - len);

	ret = len;

bail:
	return ret;
}

int camblet_sendmsg(struct sock *sock, struct msghdr *msg, size_t size)
{
	int ret, len;

	camblet_socket *s = sock->sk_user_data;

	ret = ensure_tls_handshake(s);
	if (ret != 0)
	{
		goto bail;
	}

	len = copy_from_iter(get_write_buffer_for_write(s, size), size, &msg->msg_iter);

	set_write_buffer_size(s, get_write_buffer_size(s) + len);

	if (camblet_socket_proxywasm_enabled(s))
	{
		ret = camblet_socket_proxywasm_on_data(s, len, false, true);
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

	ret = camblet_socket_write(s, get_write_buffer(s), get_write_buffer_size(s));
	if (ret < 0)
	{
		goto bail;
	}

	set_write_buffer_size(s, get_write_buffer_size(s) - ret);

	ret = size;

bail:
	return ret;
}

void camblet_close(struct sock *sk, long timeout)
{
	void (*close)(struct sock *sk, long timeout) = tcp_close;
	camblet_socket *s = READ_ONCE(sk->sk_user_data);

	if (s)
	{
		if (s->ktls_close)
		{
			close = READ_ONCE(s->ktls_close);
		}

		pr_debug("free camblet socket # command[%s] sk[%p]", current->comm, sk);
		camblet_socket_free(s);
		WRITE_ONCE(sk->sk_user_data, NULL);
	}

	close(sk, timeout);
}

// analyze tls_main.c to find out what we need to implement: check build_protos()
void ensure_camblet_ktls_prot(struct sock *sock, struct proto *camblet_ktls_prot)
{
	void (*close)(struct sock *sk, long timeout) = READ_ONCE(camblet_ktls_prot->close);

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

		camblet_ktls_prot->sendpage = sendpage;
#endif
		camblet_ktls_prot->setsockopt = setsockopt;
		camblet_ktls_prot->getsockopt = getsockopt;
		camblet_ktls_prot->sock_is_readable = sock_is_readable;

		camblet_ktls_prot->recvmsg = camblet_recvmsg;
		camblet_ktls_prot->sendmsg = camblet_sendmsg;

		WRITE_ONCE(camblet_ktls_prot->close, camblet_close);
	}
}

static int configure_ktls_sock(camblet_socket *s)
{
	int ret;

	br_ssl_engine_context *eng = get_ssl_engine_context(s);
	br_ssl_session_parameters *params = &eng->session;

	if (params->cipher_suite != BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 || !ktls_available)
	{
		if (!ktls_available)
			pr_warn("configure kTLS error: kTLS is not available on this system # command[%s]", current->comm);
		else
			pr_warn("configure kTLS error: only ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite is supported # requested_suite[%x]", params->cipher_suite);

		s->send_msg = bearssl_send_msg;
		s->recv_msg = bearssl_recv_msg;

		return 0;
	}

	pr_debug("configure kTLS for output # command[%s] cipher_suite[%x] version[%x] iv[%.*s]", current->comm, params->cipher_suite, params->version, 12, eng->out.chapol.iv);
	pr_debug("configure kTLS for input # command[%s] cipher_suite[%x] version[%x] iv[%.*s]", current->comm, params->cipher_suite, params->version, 12, eng->in.chapol.iv);

	struct tls12_crypto_info_chacha20_poly1305 crypto_info_tx = {.info = {.version = TLS_1_2_VERSION,
																		  .cipher_type = TLS_CIPHER_CHACHA20_POLY1305}};
	memcpy(crypto_info_tx.iv, eng->out.chapol.iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
	memcpy(crypto_info_tx.key, eng->out.chapol.key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
	uint64_t outseq = m3_bswap64(eng->out.chapol.seq);
	memcpy(crypto_info_tx.rec_seq, &outseq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
	//  memcpy(crypto_info.salt, eng->out.chapol.salt, TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE);

	struct tls12_crypto_info_chacha20_poly1305 crypto_info_rx = {.info = {.version = TLS_1_2_VERSION,
																		  .cipher_type = TLS_CIPHER_CHACHA20_POLY1305}};
	memcpy(crypto_info_rx.iv, eng->in.chapol.iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
	memcpy(crypto_info_rx.key, eng->in.chapol.key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
	uint64_t inseq = m3_bswap64(eng->in.chapol.seq);
	memcpy(crypto_info_rx.rec_seq, &inseq, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);
	// memcpy(crypto_info.salt, eng->out.chapol.salt, TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE);

	// We have to set the protocol to the original here because the kTLS proto gets created from the sockets original protocol,
	// so if it contains the camblet protocol parts it will spread to places where kTLS is used but camblet is not.
	s->sock->sk_prot = s->sock->sk_family == AF_INET6 ? &tcpv6_prot : &tcp_prot;

	ret = s->sock->sk_prot->setsockopt(s->sock, SOL_TCP, TCP_ULP, KERNEL_SOCKPTR("tls"), sizeof("tls"));
	if (ret != 0)
	{
		pr_err("could not set sockopt TCP_ULP # command[%s] err[%d]", current->comm, ret);
		return ret;
	}

	ret = s->sock->sk_prot->setsockopt(s->sock, SOL_TLS, TLS_TX, KERNEL_SOCKPTR(&crypto_info_tx), sizeof(crypto_info_tx));
	if (ret != 0)
	{
		pr_err("could not set sockopt TLS_TX # command[%s] err[%d]", current->comm, ret);
		return ret;
	}

	ret = s->sock->sk_prot->setsockopt(s->sock, SOL_TLS, TLS_RX, KERNEL_SOCKPTR(&crypto_info_rx), sizeof(crypto_info_rx));
	if (ret != 0)
	{
		pr_err("could not set sockopt TLS_RX # command[%s] err[%d]", current->comm, ret);
		return ret;
	}

	// unsigned int yes = 1;
	// ret = c->sock->sk_prot->setsockopt(c->sock, SOL_TLS, TLS_TX_ZEROCOPY_RO, KERNEL_SOCKPTR(&yes), sizeof(yes));
	// if (ret != 0)
	// {
	// 	pr_err("could not set sockopt TLS_TX_ZEROCOPY_RO # command[%s] err[%d]", current->comm, ret);
	// 	return ret;
	// }

	// We have to save the proto here because the setsockopt calls override the TCP protocol.
	// later those methods set by ktls has to be used to read and write data, but first we
	// need to put back our read and write methods.
	s->ktls_recvmsg = s->sock->sk_prot->recvmsg;
	s->ktls_sendmsg = s->sock->sk_prot->sendmsg;
	s->ktls_close = s->sock->sk_prot->close;

	struct proto *ktls_prot;
	if (s->sock->sk_family == AF_INET)
	{
		ktls_prot = &camblet_ktls_prot;
	}
	else
	{
		ktls_prot = &camblet_v6_ktls_prot;
	}

	ensure_camblet_ktls_prot(s->sock, ktls_prot);

	WRITE_ONCE(s->sock->sk_prot, ktls_prot);

	s->send_msg = ktls_send_msg;
	s->recv_msg = ktls_recv_msg;

	trace_debug(s->conn_ctx, "kTLS configured", 0);

	return 0;
}

bool sockptr_is_camblet(sockptr_t sp)
{
	char value[4];
	copy_from_sockptr(value, sp, 4);
	return strncmp(value, "camblet", 4) == 0;
}

// Let's intercept this call to set the socket options for setting up a simple TLS connection.
//
// TODO:
// We should put this method back to the proto after kTLS is configured, because kTLS will override this method.
int camblet_setsockopt(struct sock *sk, int level,
					   int optname, sockptr_t optval,
					   unsigned int optlen)
{
	if (level == SOL_TCP && optname == TCP_ULP)
	{
		// check if optval is "camblet"
		if (optlen == sizeof("camblet") && sockptr_is_camblet(optval))
		{
			opa_socket_context opa_socket_ctx = {.allowed = true, .passthrough = false, .mtls = false};
			tcp_connection_context conn_ctx = {.direction = OUTPUT};
			camblet_socket *s = camblet_new_client_socket(sk, opa_socket_ctx, &conn_ctx);

			sk->sk_user_data = s;

			return 0;
		}
	}
	else if (level == SOL_CAMBLET)
	{
		if (optname == CAMBLET_HOSTNAME)
		{
			camblet_socket *s = sk->sk_user_data;
			if (!s)
			{
				pr_err("camblet_setsockopt error: sk_user_data is NULL # command[%s]", current->comm);
				return -1;
			}

			s->hostname = kzalloc(optlen, GFP_KERNEL);
			copy_from_sockptr(s->hostname, optval, optlen);
			return 0;
		}
	}

	return tcp_setsockopt(sk, level, optname, optval, optlen);
}

// a function to evaluate the connection if it should be intercepted, now with opa
static opa_socket_context socket_eval(const tcp_connection_context *conn_ctx, const char *input)
{
	opa_socket_context ctx = this_cpu_opa_socket_eval(input);

	if (ctx.matched_policy_json)
	{
		trace_msg(conn_ctx, "policy match found", 2, "match", ctx.matched_policy_json);
	}
	else
	{
		trace_msg(conn_ctx, "policy match not found", 0);
	}

	char is_mtls_enabled[] = "false";
	if (ctx.mtls)
		strcpy(is_mtls_enabled, "true");

	char is_camblet_enabled[] = "false";
	if (ctx.allowed)
		strcpy(is_camblet_enabled, "true");

	trace_debug(conn_ctx, "policy evaluation result", 10, "id", ctx.id, "uri", ctx.uri, "ttl", ctx.ttl, "mtls", is_mtls_enabled, "camblet_enabled", is_camblet_enabled);

	return ctx;
}

struct sock *(*accept)(struct sock *sk, int flags, int *err, bool kern);
int (*connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*setsockopt)(struct sock *sk, int level,
				  int optname, sockptr_t optval,
				  unsigned int optlen);

struct sock *(*accept_v6)(struct sock *sk, int flags, int *err, bool kern);
int (*connect_v6)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int (*setsockopt_v6)(struct sock *sk, int level,
					 int optname, sockptr_t optval,
					 unsigned int optlen);

// lock cert generation
static DEFINE_MUTEX(cert_gen_lock);

static int handle_cert_gen_locked(camblet_socket *sc)
{
	// Generating certificate signing request
	if (sc->rsa_priv->plen == 0 || sc->rsa_pub->elen == 0)
	{
		u_int32_t result = generate_rsa_keys(sc->rsa_priv, sc->rsa_pub);
		if (result == 0)
		{
			pr_err("could not generate rsa keys");
			return -1;
		}
	}

	int len = encode_rsa_priv_key_to_der(NULL, sc->rsa_priv, sc->rsa_pub);
	if (len <= 0)
	{
		pr_err("could not encode RSA private key to DER");
		return -1;
	}

	unsigned char *csr_ptr;

	csr_module *csr = this_cpu_csr();
	csr_lock(csr);
	// Allocate memory inside the wasm vm since this data must be available inside the module
	wasm_vm_result malloc_result = csr_malloc(csr, len);
	if (malloc_result.err)
	{
		pr_err("wasm CSR malloc error # err[%s]", malloc_result.err);
		csr_unlock(csr);
		return -1;
	}

	uint8_t *mem = wasm_vm_memory(get_csr_module(csr));
	i32 addr = malloc_result.data->i32;

	unsigned char *der = mem + addr;

	int error = encode_rsa_priv_key_to_der(der, sc->rsa_priv, sc->rsa_pub);
	if (error <= 0)
	{
		pr_err("could not encode RSA private key to DER");
		csr_unlock(csr);
		return -1;
	}

	sc->parameters->subject = "CN=camblet-protected-workload";

	if (sc->opa_socket_ctx.dns)
	{
		sc->parameters->dns = sc->opa_socket_ctx.dns;
	}
	if (sc->opa_socket_ctx.uri)
	{
		sc->parameters->uri = sc->opa_socket_ctx.uri;
	}

	csr_result generated_csr = csr_gen(csr, addr, len, sc->parameters);
	if (generated_csr.err)
	{
		pr_err("wasm CSR gen error # err[%s]", generated_csr.err);
		csr_unlock(csr);
		return -1;
	}

	wasm_vm_result free_result = csr_free(csr, addr);
	if (free_result.err)
	{
		pr_err("wasm free error # err[%s]", free_result.err);
		csr_unlock(csr);
		return -1;
	}

	csr_ptr = strndup(generated_csr.csr_ptr + mem, generated_csr.csr_len);
	free_result = csr_free(csr, generated_csr.csr_ptr);
	if (free_result.err)
	{
		pr_err("wasm free error # err[%s]", free_result.err);
		csr_unlock(csr);
		return -1;
	}
	csr_unlock(csr);

	csr_sign_answer *csr_sign_answer;
	csr_sign_answer = send_csrsign_command(csr_ptr, sc->opa_socket_ctx.ttl);
	if (csr_sign_answer->error)
	{
		pr_err("error during CSR signing # err[%s]", csr_sign_answer->error);
		kfree(csr_sign_answer->error);
		kfree(csr_sign_answer);
		return -1;
	}
	else
	{
		x509_certificate_get(csr_sign_answer->cert);
		sc->cert = csr_sign_answer->cert;
	}
	kfree(csr_sign_answer);
	return 0;
}

static int handle_cert_gen(camblet_socket *sc)
{
	mutex_lock(&cert_gen_lock);
	int ret = handle_cert_gen_locked(sc);
	mutex_unlock(&cert_gen_lock);

	return ret;
}

static int cache_and_validate_cert(camblet_socket *sc, char *key)
{
	// Check if cert gen is required or we already have a cached certificate for this socket.
	u16 cert_validation_err_no = 0;
	int err;

	cert_with_key *cached_cert_bundle = find_cert_from_cache(key);
	if (!cached_cert_bundle)
	{
	regen_cert:
		err = handle_cert_gen(sc);
		if (err == -1)
		{
			return -1;
		}
		add_cert_to_cache(key, sc->cert);
	}
	// Cert found in the cache use that
	else
	{
		sc->cert = cached_cert_bundle->cert;
	}
	// Validate the cached or the generated cert
	if (!validate_cert(sc->cert->validity))
	{
		pr_debug("remove invalid certificate from cache");
		x509_certificate_put(sc->cert);
		remove_cert_from_cache(cached_cert_bundle);
		cert_validation_err_no++;
		if (cert_validation_err_no == 1)
		{
			goto regen_cert;
		}
		else if (cert_validation_err_no == 2)
		{
			return -1;
		}
	}
	return 0;
}

static tcp_connection_context *tcp_connection_context_init(direction direction, struct sock *s, u16 port)
{
	tcp_connection_context *ctx = kzalloc(sizeof(tcp_connection_context), GFP_KERNEL);

	ctx->direction = direction;
	ctx->id = s;

	const char *ipformat = "%pI4";

	if (s->sk_family == AF_INET6)
	{
		ipformat = "%pI6";
	}

	if (direction == INPUT)
	{
		if (s->sk_family == AF_INET6)
		{
			struct in6_addr *ipv6_saddr = &inet6_sk(s)->saddr;
			struct in6_addr *ipv6_daddr = &s->sk_v6_daddr;
			snprintf(ctx->source_ip, INET6_ADDRSTRLEN, ipformat, ipv6_daddr);
			snprintf(ctx->destination_ip, INET6_ADDRSTRLEN, ipformat, ipv6_saddr);
		}
		else
		{
			snprintf(ctx->source_ip, INET6_ADDRSTRLEN, ipformat, &s->sk_daddr);
			snprintf(ctx->destination_ip, INET6_ADDRSTRLEN, ipformat, &s->sk_rcv_saddr);
		}

		ctx->source_port = s->sk_dport;
		ctx->destination_port = s->sk_num;
	}
	else
	{
		if (s->sk_family == AF_INET6)
		{
			struct in6_addr *ipv6_saddr = &inet6_sk(s)->saddr;
			struct in6_addr *ipv6_daddr = &s->sk_v6_daddr;
			snprintf(ctx->source_ip, INET6_ADDRSTRLEN, ipformat, ipv6_saddr);
			snprintf(ctx->destination_ip, INET6_ADDRSTRLEN, ipformat, ipv6_daddr);
		}
		else
		{
			snprintf(ctx->source_ip, INET6_ADDRSTRLEN, ipformat, &s->sk_rcv_saddr);
			snprintf(ctx->destination_ip, INET6_ADDRSTRLEN, ipformat, &s->sk_daddr);
		}

		ctx->source_port = s->sk_num;
		ctx->destination_port = port;
	}

	snprintf(ctx->source_address, INET6_ADDRSTRLEN + 5, "%s:%d", ctx->source_ip, ctx->source_port);
	snprintf(ctx->destination_address, INET6_ADDRSTRLEN + 5, "%s:%d", ctx->destination_ip, ctx->destination_port);

	return ctx;
}

void add_sd_entry_labels_to_json(service_discovery_entry *sd_entry, JSON_Value *json)
{
	if (!json)
	{
		return;
	}

	if (!sd_entry)
	{
		return;
	}

	JSON_Object *root = json_value_get_object(json);

	JSON_Value *remote_value = json_value_init_object();
	JSON_Object *remote = json_object(remote_value);

	JSON_Value *labels_value = json_value_init_object();
	JSON_Object *labels = json_object(labels_value);

	size_t i;
	for (i = 0; i < sd_entry->labels_len; i++)
	{
		json_object_set_boolean(labels, sd_entry->labels[i], true);
	}

	json_object_set_value(remote, "labels", labels_value);
	json_object_set_value(root, "remote", remote_value);
}

void add_net_conn_info_to_json(const tcp_connection_context *conn_ctx, JSON_Object *json_object)
{
	if (!json_object)
	{
		return;
	}

	if (conn_ctx->direction == INPUT)
		json_object_set_boolean(json_object, "direction:input", true);
	else
		json_object_set_boolean(json_object, "direction:output", true);

	char buff[256];

	snprintf(buff, sizeof(buff), "source:ip:%s", conn_ctx->source_ip);
	json_object_set_boolean(json_object, buff, true);
	snprintf(buff, sizeof(buff), "source:port:%d", conn_ctx->source_port);
	json_object_set_boolean(json_object, buff, true);

	snprintf(buff, sizeof(buff), "destination:ip:%s", conn_ctx->destination_ip);
	json_object_set_boolean(json_object, buff, true);
	snprintf(buff, sizeof(buff), "destination:port:%d", conn_ctx->destination_port);
	json_object_set_boolean(json_object, buff, true);
}

static command_answer *prepare_opa_input(const tcp_connection_context *conn_ctx, service_discovery_entry *sd_entry, char *augmentation_response_json)
{
	if (!augmentation_response_json)
	{
		return answer_with_error("nil augmentation response json");
	}

	command_answer *answer = NULL;

	JSON_Value *json = json_parse_string(augmentation_response_json);
	if (!json)
	{
		return answer_with_error("could not parse json");
	}

	JSON_Object *root = json_value_get_object(json);
	if (!root)
	{
		answer = answer_with_error("could not get root object");
		goto cleanup;
	}

	JSON_Object *labels = json_object_get_object(root, "labels");
	if (!labels)
	{
		answer = answer_with_error("could not find labels in json");
		goto cleanup;
	}

	add_net_conn_info_to_json(conn_ctx, labels);
	if (sd_entry)
	{
		add_sd_entry_labels_to_json(sd_entry, json);
	}

	answer = kzalloc(sizeof(struct command_answer), GFP_KERNEL);
	answer->answer = json_serialize_to_string(json);

cleanup:
	json_value_free(json);

	return answer;
}

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int br_low_read(void *ctx, unsigned char *buf, size_t len)
{
	camblet_socket *s = (camblet_socket *)ctx;
	int ret = plain_recv_msg(s, buf, len, 0);
	// BearSSL doesn't like 0 return value, but it's not an error
	// so we return -1 instead and set sock_closed to true to
	// indicate that the socket is closed without errors.
	if (ret == 0)
	{
		s->sock_closed = true;
		ret = -1;
	}
	return ret;
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int br_low_write(void *ctx, const unsigned char *buf, size_t len)
{
	return plain_send_msg((camblet_socket *)ctx, buf, len);
}

opa_socket_context enriched_socket_eval(const tcp_connection_context *conn_ctx, direction direction, struct sock *sk, int port)
{
	// we take a shortcut if the socket is already augmented for example through setsockopt
	if (sk->sk_user_data)
	{
		return ((camblet_socket *)sk->sk_user_data)->opa_socket_ctx;
	}

	service_discovery_entry *sd_entry = NULL;
	opa_socket_context opa_socket_ctx = {0};

	if (direction == OUTPUT)
	{
		pr_debug("look for sd entry # command[%s] address[%s]", current->comm, conn_ctx->destination_ip);
		sd_entry = sd_table_entry_get(conn_ctx->destination_ip);
		if (sd_entry == NULL)
		{
			char *address = strnprintf("%s:%d", conn_ctx->destination_ip, conn_ctx->destination_port);
			pr_debug("look for sd entry # command[%s] address[%s:%d]", current->comm, conn_ctx->destination_ip, conn_ctx->destination_port);
			sd_entry = sd_table_entry_get(address);
			kfree(address);
		}
		if (!sd_entry)
		{
			trace_debug(conn_ctx, "sd entry not found", 4, "command", current->comm, "address", conn_ctx->destination_address);

			return opa_socket_ctx;
		}

		trace_debug(conn_ctx, "outgoing connection", 4, "command", current->comm, "address", conn_ctx->destination_address);
	}
	else
	{
		trace_debug(conn_ctx, "incoming connection", 4, "command", current->comm, "address", conn_ctx->source_address);
	}

	// augmenting process connection
	augmentation_response *response = augment_workload();
	if (response->error)
	{
		trace_err(conn_ctx, "could not augment process connection", 2, "error", response->error);
		augmentation_response_put(response);
	}
	else
	{
		command_answer *answer = prepare_opa_input(conn_ctx, sd_entry, response->response);
		if (answer->error)
		{
			trace_err(conn_ctx, "could not prepare opa input", 2, "error", answer->error);
		}
		else
		{
			trace_debug(conn_ctx, "augmentation response", 2, "response", answer->answer);
			opa_socket_ctx = socket_eval(conn_ctx, answer->answer);
		}
		free_command_answer(answer);
		augmentation_response_put(response);
	}

	return opa_socket_ctx;
}

void camblet_configure_server_tls(camblet_socket *sc)
{
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
	br_ssl_server_init_full_rsa(sc->sc, sc->cert->chain, sc->cert->chain_len, sc->rsa_priv);

	// mTLS enablement
	if (sc->opa_socket_ctx.mtls)
	{
		br_x509_minimal_init_full(&sc->xc.ctx, sc->cert->trust_anchors, sc->cert->trust_anchors_len);
		br_ssl_server_set_trust_anchor_names_alt(sc->sc, sc->cert->trust_anchors, sc->cert->trust_anchors_len);

		bool insecure;
		br_x509_camblet_init(&sc->xc, &sc->sc->eng, &sc->opa_socket_ctx, sc->conn_ctx, insecure = false);
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
	br_sslio_init(&sc->ioc, &sc->sc->eng, br_low_read, sc, br_low_write, sc);
}

void camblet_configure_client_tls(camblet_socket *sc)
{
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
	int trust_anchors_len = 0;
	br_x509_trust_anchor *trust_anchors = NULL;

	if (sc->cert && sc->cert->trust_anchors)
	{
		trust_anchors_len = sc->cert->trust_anchors_len;
		trust_anchors = sc->cert->trust_anchors;
	}

	br_ssl_client_init_full(sc->cc, &sc->xc.ctx, trust_anchors, trust_anchors_len);

	// Currently we need to enforce our one and only cipher suite,
	// from where we can extract kTLS paramaters.
	static const uint16_t suites[] = {
		BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	};

	br_ssl_engine_set_suites(&sc->cc->eng, suites,
							 (sizeof suites) / (sizeof suites[0]));

	bool insecure;
	br_x509_camblet_init(&sc->xc, &sc->cc->eng, &sc->opa_socket_ctx, sc->conn_ctx, insecure = trust_anchors_len == 0);

	// mTLS enablement
	if (sc->opa_socket_ctx.mtls)
	{
		br_ssl_client_set_single_rsa(sc->cc, sc->cert->chain, sc->cert->chain_len, sc->rsa_priv, br_rsa_pkcs1_sign_get_default());
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
	if (br_ssl_client_reset(sc->cc, sc->hostname, false) != 1)
	{
		pr_err("br_ssl_client_reset error");
	}

	/*
	 * Initialise the simplified I/O wrapper context, to use our
	 * SSL client context, and the two callbacks for socket I/O.
	 */
	br_sslio_init(&sc->ioc, &sc->cc->eng, br_low_read, sc, br_low_write, sc);
}

struct sock *camblet_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sock *client_sk = NULL;
	struct proto *prot;
	camblet_socket *sc = NULL;

	if (sk->sk_family == AF_INET)
	{
		client_sk = accept(sk, flags, err, kern);
		prot = &camblet_prot;
	}
	else
	{
		client_sk = accept_v6(sk, flags, err, kern);
		prot = &camblet_v6_prot;
	}

	if (!client_sk && *err != 0)
	{
		goto error;
	}

	// return if the agent is not running
	if (atomic_read(&already_open) == CDEV_NOT_USED)
	{
		return client_sk;
	}

	u16 port = (u16)(sk->sk_portpair >> 16);

	const tcp_connection_context *conn_ctx = tcp_connection_context_init(INPUT, client_sk, port);

	opa_socket_context opa_socket_ctx = enriched_socket_eval(conn_ctx, INPUT, client_sk, port);

	if (opa_socket_ctx.allowed)
	{
		sc = camblet_new_server_socket(client_sk, opa_socket_ctx, conn_ctx);
		if (!sc)
		{
			pr_err("could not create camblet socket");
			goto error;
		}

		memcpy(sc->rsa_priv, rsa_priv, sizeof *sc->rsa_priv);
		memcpy(sc->rsa_pub, rsa_pub, sizeof *sc->rsa_pub);

		int result = cache_and_validate_cert(sc, sc->opa_socket_ctx.id);
		if (result == -1)
		{
			goto error;
		}

		camblet_configure_server_tls(sc);

		// We should save the ssl context here to the socket
		// and overwrite the socket protocol with our own
		client_sk->sk_user_data = sc;
		WRITE_ONCE(client_sk->sk_prot, prot);
	}

	return client_sk;

error:
	camblet_socket_free(sc);
	if (client_sk)
		client_sk->sk_prot->close(client_sk, 0);

	return NULL;
}

int camblet_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	u16 port = ntohs(usin->sin_port);
	camblet_socket *sc = sk->sk_user_data;

	int err;
	struct proto *prot;

	if (sk->sk_family == AF_INET)
	{
		err = connect(sk, uaddr, addr_len);
		prot = &camblet_prot;
	}
	else
	{
		err = connect_v6(sk, uaddr, addr_len);
		prot = &camblet_v6_prot;
	}

	if (err != 0)
	{
		goto error;
	}

	// return if the agent is not running, and we don't have a socket context attached to the socket
	if (sc == NULL && atomic_read(&already_open) == CDEV_NOT_USED)
	{
		return err;
	}

	const tcp_connection_context *conn_ctx = tcp_connection_context_init(OUTPUT, sk, port);

	opa_socket_context opa_socket_ctx = enriched_socket_eval(conn_ctx, OUTPUT, sk, port);

	if (opa_socket_ctx.allowed)
	{
		if (!sc)
		{
			sc = camblet_new_client_socket(sk, opa_socket_ctx, conn_ctx);
			if (!sc)
			{
				pr_err("could not create camblet socket");
				goto error;
			}
		}

		memcpy(sc->rsa_priv, rsa_priv, sizeof *sc->rsa_priv);
		memcpy(sc->rsa_pub, rsa_pub, sizeof *sc->rsa_pub);

		if (sc->opa_socket_ctx.mtls)
		{
			int result = cache_and_validate_cert(sc, sc->opa_socket_ctx.id);
			if (result == -1)
			{
				goto error;
			}
		}

		camblet_configure_client_tls(sc);

		// We should save the ssl context here to the socket
		// and overwrite the socket protocol with our own
		sk->sk_user_data = sc;
		WRITE_ONCE(sk->sk_prot, prot);
	}

	return err;

error:
	camblet_socket_free(sc);

	lock_sock(sk);
	sk->sk_prot->close(sk, 0);
	release_sock(sk);

	return err;
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

	// save original tcp_prot methods first
	accept = tcp_prot.accept;
	connect = tcp_prot.connect;
	setsockopt = tcp_prot.setsockopt;

	accept_v6 = tcpv6_prot.accept;
	connect_v6 = tcpv6_prot.connect;
	setsockopt_v6 = tcpv6_prot.setsockopt;

	// overwrite tcp_prot with our methods
	tcp_prot.accept = camblet_accept;
	tcp_prot.connect = camblet_connect;
	tcp_prot.setsockopt = camblet_setsockopt;

	tcpv6_prot.accept = camblet_accept;
	tcpv6_prot.connect = camblet_connect;
	tcpv6_prot.setsockopt = camblet_setsockopt;

	memcpy(&camblet_prot, &tcp_prot, sizeof(camblet_prot));
	camblet_prot.recvmsg = camblet_recvmsg;
	camblet_prot.sendmsg = camblet_sendmsg;
	camblet_prot.close = camblet_close;

	memcpy(&camblet_ktls_prot, &camblet_prot, sizeof(camblet_prot));
	camblet_ktls_prot.close = NULL; // mark it as uninitialized

	memcpy(&camblet_v6_prot, &tcpv6_prot, sizeof(camblet_v6_prot));
	camblet_v6_prot.recvmsg = camblet_recvmsg;
	camblet_v6_prot.sendmsg = camblet_sendmsg;
	camblet_v6_prot.close = camblet_close;

	memcpy(&camblet_v6_ktls_prot, &camblet_v6_prot, sizeof(camblet_v6_prot));
	camblet_v6_ktls_prot.close = NULL; // mark it as uninitialized

	//- generate global tls key
	rsa_priv = kzalloc(sizeof(br_rsa_private_key), GFP_KERNEL);
	rsa_pub = kzalloc(sizeof(br_rsa_public_key), GFP_KERNEL);
	u_int32_t result = generate_rsa_keys(rsa_priv, rsa_pub);
	if (result == 0)
	{
		pr_err("could not generate rsa keys");
		return -1;
	}

	pr_info("socket support loaded");

	return 0;
}

void socket_exit(void)
{
	tcp_prot.accept = accept;
	tcp_prot.connect = connect;
	tcp_prot.setsockopt = setsockopt;

	tcpv6_prot.accept = accept_v6;
	tcpv6_prot.connect = connect_v6;
	tcpv6_prot.setsockopt = setsockopt_v6;

	//- free global tls key
	free_rsa_private_key(rsa_priv);
	free_rsa_public_key(rsa_pub);

	pr_info("socket support unloaded");
}
