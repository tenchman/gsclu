#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <polarssl/ssl.h>
#include <polarssl/base64.h>
#include <polarssl/havege.h>
#include <polarssl/error.h>
#include <polarssl/net.h>
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "tio.h"

#define CAFILE  "/etc/ssl/certs/ca-bundle.crt"
static char tio_buf[1024];

/* ssl data */
typedef struct {
  ssl_context ssl;
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  x509_cert cacert;
  x509_cert clicert;
  rsa_context rsa;
} _ssl_ctx_t;


static ssize_t tio_std_recv(io_ctx_t *ctx, char *buf, size_t len)
{
  return recv(ctx->fd, buf, len, 0);
}

static ssize_t tio_std_send(io_ctx_t *ctx, char *buf, size_t len)
{
  return send(ctx->fd, buf, len, 0);
}

static ssize_t tio_tls_recv(io_ctx_t *ctx, char *buf, size_t len)
{
  int ret;
  _ssl_ctx_t *sslctx = (_ssl_ctx_t *)ctx->ssl_ctx;
  while (0 >= (ret = ssl_read(&sslctx->ssl, (unsigned char *)buf, len))) {
    if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE) {
      ret = -1;
      break;
    }
  }
  return ret;
}

static ssize_t tio_tls_send(io_ctx_t *ctx, char *buf, size_t len)
{
  int ret = 0;
  _ssl_ctx_t *sslctx = (_ssl_ctx_t *)ctx->ssl_ctx;
  while (len && 0 >= (ret = ssl_write(&sslctx->ssl, (const unsigned char *)buf, len))) {
    if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE) {
      ret = -1;
      break;
    }
  }
  return ret;
}

io_ctx_t *tio_init(void)
{
  io_ctx_t *io;
  if (NULL == (io = calloc(1, sizeof(io_ctx_t)))) {
    /* */
  } else {
    io->recv = tio_std_recv;
    io->send = tio_std_send;
    io->ibuf.pos = io->ibuf.start = io->ibuf.buf;
  }
  return io;
}

void tio_shutdown(io_ctx_t *io)
{
  _ssl_ctx_t *sslctx = (_ssl_ctx_t *)io->ssl_ctx;
  if (io->fd > 0) {
    shutdown(io->fd, SHUT_RDWR);
    net_close(io->fd);
  }

  /* cleanup all SSL related stuff */
  if (sslctx) {
    x509_free(&sslctx->cacert);
    x509_free(&sslctx->clicert);
    rsa_free(&sslctx->rsa);
    ssl_free(&sslctx->ssl);
    free(sslctx);
  }

  free(io);
}

int tio_recv(io_ctx_t *io, char *buf, size_t len)
{
  return io->recv(io, buf, len);
}

int tio_send(io_ctx_t *io, char *buf, size_t len)
{
  return io->send(io, buf, len);
}

static char *tio_tls_error(int ret)
{
  memset(tio_buf, 0, sizeof(tio_buf));
  error_strerror(ret, (char *) tio_buf, sizeof(tio_buf));
  return tio_buf;
}

int tio_tls_handshake(io_ctx_t *ctx)
{
  int ret;
  _ssl_ctx_t *sslctx = (_ssl_ctx_t *)ctx->ssl_ctx;

  while (0 != (ret = ssl_handshake(&sslctx->ssl)))
  {
    if (POLARSSL_ERR_NET_WANT_READ != ret && POLARSSL_ERR_NET_WANT_WRITE != ret)
    {
      fprintf(stderr, "SSL/TLS handshake failed! %s\n", tio_tls_error(ret));
      return -1;
    }
  }

  if (0 != (ret = ssl_get_verify_result(&sslctx->ssl))) {
    fprintf(stderr, "Verifying peer X.509 certificate failed.\n" );
    if ((ret & BADCERT_EXPIRED) != 0)
      fprintf(stderr, " server certificate has expired\n");
    if ((ret & BADCERT_REVOKED) != 0)
      fprintf(stderr, " server certificate has been revoked\n");
    if ((ret & BADCERT_CN_MISMATCH) != 0)
      fprintf(stderr, " CN mismatch\n");
    if ((ret & BADCERT_NOT_TRUSTED) != 0)
      fprintf(stderr, " self-signed or not signed by a trusted CA\n");
  }
  
  ctx->recv = tio_tls_recv;
  ctx->send = tio_tls_send;
  return 0;
}

int tio_tls_init(io_ctx_t *ctx, const unsigned char *pers, const char *server)
{
  _ssl_ctx_t *ssl;
  int ret = -1;

  if (NULL == (ssl = malloc(sizeof(_ssl_ctx_t)))) {
    fprintf(stderr, "%s: out of memory\n", __func__);
    return -1;
  }

  entropy_init(&ssl->entropy);

  if (0 != (ret = ctr_drbg_init(&ssl->ctr_drbg, entropy_func, &ssl->entropy, pers, strlen((char *)pers)))) {
    fprintf(stderr, "Seeding the random number generator failed\n");
  } else if (0 > (ret = x509parse_crtfile(&ssl->cacert, CAFILE))) {
    // fprintf(stderr, "Loading the CA root certificate failed: %s\n", sv_tls_error(ret));
  } else if (0 != (ret = ssl_init(&ssl->ssl))) {
    /* */
  } else {
    ssl_set_endpoint(&ssl->ssl, SSL_IS_CLIENT);
    ssl_set_authmode(&ssl->ssl, SSL_VERIFY_OPTIONAL);
    ssl_set_ca_chain(&ssl->ssl, &ssl->cacert, NULL, server);

    ssl_set_rng(&ssl->ssl, ctr_drbg_random, &ssl->ctr_drbg );
    ssl_set_bio(&ssl->ssl, net_recv, &ctx->fd, net_send, &ctx->fd);
    ssl_set_hostname(&ssl->ssl, server);

    ctx->ssl_ctx = (ssl_ctx_t *)ssl;
  }
  return ret ? -1 : 0;
}

char *tio_gets(io_ctx_t *io, char *buf, size_t len)
{
  char *lbr, *ret = NULL;
  size_t n;

  while (1) {
    if (NULL != (lbr = strchr(io->ibuf.pos, '\n'))) {
      n = (lbr - io->ibuf.pos) + 1;
      if (len <= n) {
	/* Oh, no. Buffer too small! */
      } else {
	memcpy(buf, io->ibuf.pos, n);
	io->ibuf.pos += n;
	buf[n] = '\0';
	ret = buf;
      }
      break;  
    } else if (-1 == io->recv(io, io->ibuf.buf, sizeof(io->ibuf.buf))) {
      break;
    }
  }
  return ret;
}
