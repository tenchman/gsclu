#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <mbedtls/ssl.h>
#include <mbedtls/base64.h>
#include <mbedtls/havege.h>
#include <mbedtls/error.h>
#include <mbedtls/net.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "tio.h"

#define CAFILE  "/etc/ssl/certs/ca-bundle.crt"
static char tio_buf[1024];

/* ssl data */
typedef struct {
  mbedtls_ssl_context ssl;
  mbedtls_entropy_context entropy;
  mbedtls_ssl_config conf;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
  mbedtls_rsa_context rsa;
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
  while (0 >= (ret = mbedtls_ssl_read(&sslctx->ssl, (unsigned char *)buf, len))) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
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
  while (len && 0 >= (ret = mbedtls_ssl_write(&sslctx->ssl, (const unsigned char *)buf, len))) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
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
    io->ibuf.pos = io->ibuf.buf;
  }
  return io;
}

void tio_shutdown(io_ctx_t *io)
{
  _ssl_ctx_t *sslctx = (_ssl_ctx_t *)io->ssl_ctx;
  if (io->fd > 0) {
    shutdown(io->fd, SHUT_RDWR);
  }

  /* cleanup all SSL related stuff */
  if (sslctx) {
    mbedtls_x509_crt_free(&sslctx->cacert);
    mbedtls_x509_crt_free(&sslctx->clicert);
    mbedtls_rsa_free(&sslctx->rsa);
    mbedtls_ssl_free(&sslctx->ssl);
    mbedtls_entropy_free(&sslctx->entropy);
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
  mbedtls_strerror(ret, (char *) tio_buf, sizeof(tio_buf));
  return tio_buf;
}

int tio_tls_handshake(io_ctx_t *ctx)
{
  int ret;
  _ssl_ctx_t *sslctx = (_ssl_ctx_t *)ctx->ssl_ctx;

  while (0 != (ret = mbedtls_ssl_handshake(&sslctx->ssl)))
  {
    if (MBEDTLS_ERR_SSL_WANT_READ != ret && MBEDTLS_ERR_SSL_WANT_WRITE != ret)
    {
      fprintf(stderr, "SSL/TLS handshake failed! %s\n", tio_tls_error(ret));
      return -1;
    }
  }

  if (0 != (ret = mbedtls_ssl_get_verify_result(&sslctx->ssl))) {
    fprintf(stderr, "Verifying peer X.509 certificate failed.\n" );
    if ((ret & MBEDTLS_X509_BADCERT_EXPIRED) != 0)
      fprintf(stderr, " * server certificate has expired\n");
    if ((ret & MBEDTLS_X509_BADCERT_REVOKED) != 0)
      fprintf(stderr, " * server certificate has been revoked\n");
    if ((ret & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0)
      fprintf(stderr, " * CN mismatch\n");
    if ((ret & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0)
      fprintf(stderr, " * self-signed or not signed by a trusted CA\n");
  }

  ctx->recv = tio_tls_recv;
  ctx->send = tio_tls_send;
  return 0;
}

static void tio_tls_config(_ssl_ctx_t *ssl, int verify)
{

  mbedtls_ssl_config_init(&ssl->conf);
  mbedtls_ssl_config_defaults(&ssl->conf,
      MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  switch (verify) {
    case 0:
      mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_NONE);
      break;
    case 1:
      mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
      break;
    default:
      mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
      break;
  }
  mbedtls_ssl_conf_ca_chain(&ssl->conf, &ssl->cacert, NULL);
  mbedtls_ssl_conf_rng(&ssl->conf, mbedtls_ctr_drbg_random, &ssl->ctr_drbg);
}

int tio_tls_init(io_ctx_t *ctx, const unsigned char *pers, const char *server, int verify)
{
  _ssl_ctx_t *ssl;
  int ret = -1;

  if (NULL == (ssl = malloc(sizeof(_ssl_ctx_t)))) {
    fprintf(stderr, "%s: out of memory\n", __func__);
    return -1;
  }

  mbedtls_entropy_init(&ssl->entropy);
  mbedtls_ssl_init(&ssl->ssl);
  tio_tls_config(ssl, verify);
  if (0 != mbedtls_ctr_drbg_seed(&ssl->ctr_drbg, mbedtls_entropy_func, &ssl->entropy, pers, strlen((char *)pers))) {
    fprintf(stderr, "Seeding the random number generator failed");
  } else if (0 > (ret = mbedtls_x509_crt_parse_file(&ssl->cacert, CAFILE))) {
    fprintf(stderr, "Loading the CA root certificate failed: %s\n", tio_tls_error(ret));
  } else if (0 > (ret = mbedtls_ssl_setup(&ssl->ssl, &ssl->conf))) {
    fprintf(stderr, "Set up the SSL context failed: %s\n", tio_tls_error(ret));
  } else {
    mbedtls_ssl_set_bio(&ssl->ssl, &ctx->fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    mbedtls_ssl_set_hostname(&ssl->ssl, server);
    ctx->ssl_ctx = (ssl_ctx_t *)ssl;
  }
  return ret ? -1 : 0;
}

char *tio_gets(io_ctx_t *io, char *buf, size_t len)
{
  char *lbr, *ret = NULL;
  size_t n, rem;

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
    } else if (0 < (rem = io->ibuf.total - (io->ibuf.pos - io->ibuf.buf))) {
      memmove(io->ibuf.buf, io->ibuf.pos, rem);
      if (-1 == (int)(n = io->recv(io, io->ibuf.buf + rem, sizeof(io->ibuf.buf) - rem))) {
	break;
      }
      io->ibuf.pos = io->ibuf.buf;
      io->ibuf.total = rem + n;
    } else if (-1 == (int)(io->ibuf.total = io->recv(io, io->ibuf.buf, sizeof(io->ibuf.buf)))) {
      break;
    }
  }
  return ret;
}
int tio_connect(int *fd, const char *server, int port)
{
  int ret = -1;
  char sport[16];
  snprintf(sport, sizeof(sport), "%d", port);
  mbedtls_net_context ctx = {};
  if (0 == (ret = mbedtls_net_connect(&ctx, server, sport, MBEDTLS_NET_PROTO_TCP)))
    *fd = ctx.fd;
  return ret;
}
