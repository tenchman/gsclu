#ifndef _TIO_H
#define _TIO_H 1

typedef int (*tio_errfunc)(char *str, size_t size, const char *format, va_list ap);

/* ssl data */
typedef struct {
  ssl_context ssl;
  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  x509_cert cacert;
  x509_cert clicert;
  rsa_context rsa;
} ssl_ctx_t;

typedef struct tio_buf_s {
  char buf[8100];
  char *start;
  char *pos;
} tio_buf_t;

/* io_ctx_t */
typedef struct io_ctx io_ctx_t;
struct io_ctx {
  int fd;
  ssl_context *ssl;
  ssl_ctx_t *ssl_ctx;
  ssize_t (*recv) (io_ctx_t *, char *, size_t);
  ssize_t (*send) (io_ctx_t *, char *, size_t);
  tio_buf_t ibuf;
};

io_ctx_t *tio_init(void);
void tio_shutdown(io_ctx_t *io);
int tio_recv(io_ctx_t *io, char *buf, size_t len);
int tio_send(io_ctx_t *io, char *buf, size_t len);
char *tio_gets(io_ctx_t *io, char *buf, size_t len);
int tio_tls_handshake(io_ctx_t *io);
int tio_tls_init(io_ctx_t *ctx, const unsigned char *pers, const char *server);

#endif
