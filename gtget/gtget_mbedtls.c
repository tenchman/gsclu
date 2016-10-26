/* $Id$

  gtget is Copyright (c) 2004 - XXXX Gernot Tenchio

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include "strbuf.h"
#include "gtget.h"

extern int timedout;

typedef struct sslparam_t {
  mbedtls_ssl_context ssl;
  mbedtls_ssl_session ssn;
  mbedtls_ssl_config conf;
  mbedtls_pk_context pk;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
} sslparam_t;

static void print_ssl_error(int e)
{
  char buf[256];
  mbedtls_strerror(e, buf, sizeof(buf));
  write2f("%s\n", buf);
}

ssize_t gtget_ssl_write(connection_t * c, char *buf, size_t n)
{
  int r = 0, s;
  sslparam_t *ssl = (sslparam_t *) c->ssl;

  if (timedout)
    return -1;
  alarm(c->timeout);
  while (n > 0 && r >= 0) {
    s = n < SSL_MAX_PLAINTEXT_LEN ? n : SSL_MAX_PLAINTEXT_LEN;
    while ((r = mbedtls_ssl_write(&ssl->ssl, (unsigned char *)buf, n)) <= 0) {
      if (MBEDTLS_ERR_SSL_WANT_WRITE == r) {
	/* */
      } else if (MBEDTLS_ERR_SSL_WANT_READ == r) {
	/* */
      } else {
	break;
      }
    }
    if (r < 0)
      return -1;
    n -= s;
    buf += s;
  }
  alarm(0);
  return r;
}

ssize_t gtget_ssl_read(connection_t * c, char *buf, size_t n)
{
  int r = 0;
  sslparam_t *ssl = (sslparam_t *) c->ssl;

  if (timedout)
    return -1;
  alarm(c->timeout);
  while ((r = mbedtls_ssl_read(&ssl->ssl, (unsigned char *)buf, n)) <= 0) {
    if (MBEDTLS_ERR_SSL_WANT_WRITE == r) {
      /* */
    } else if (MBEDTLS_ERR_SSL_WANT_READ == r) {
      /* */
    } else {
      break;
    }
  }
  alarm(0);
  if (r == MBEDTLS_ERR_NET_CONN_RESET)
    return 0;
  return r;
}

static int verify_cb(void *arg, mbedtls_x509_crt * crt, int depth, uint32_t *flags)
{
  connection_t *conn = (connection_t *) arg;
  int cnlen = strlen(conn->remote->host);
  mbedtls_x509_name *name;
  name = &crt->subject;
  while (name != NULL) {
    if (memcmp(name->oid.p, "\x55\x04\x03", 3) == 0) {
      int len = (int) name->oid.p[4];
      if (len == cnlen && memcmp(name->val.p, conn->remote->host, cnlen) == 0)
	return 0;
    }
    name = name->next;
  }
  write2f("%s: MBEDTLS_ERR_X509_CERT_VERIFY_FAILED\n", __func__);
  return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
}

REGPARM(1)
void gtget_ssl_init(connection_t * conn)
{
  char *clientcert = NULL;
  char *clientkey = NULL;
  const char *pers = "gtget";
  sslparam_t *ssl = calloc(1, sizeof(sslparam_t));
  
  if (!(conn->flags & GTGET_FLAG_INSECURE)) {
    char *cacertfile = alloca(strlen(conn->remote->host) + 5);
    char *servercert = NULL;

    strcpy(cacertfile, conn->remote->host);
    strcat(cacertfile, ".pem");

    if (!(servercert = tryopen_alt(conn, conn->caFile, cacertfile)))
      servercert = tryopen("cacerts.pem");
    if (!(servercert))
      die(conn, "can't open cacert", NULL);
    if (mbedtls_x509_crt_parse_file(&ssl->cacert, servercert))
      die(conn, "error reading cacert", servercert);
  }

  /* read and parse the client certificate if provided */
  if ((clientcert = tryopen_alt(conn, conn->ccFile, "clientcert.pem"))) {
    if (!(clientkey = tryopen_alt(conn, conn->ckFile, "clientkey.pem")))
      clientkey = clientcert;

    if (mbedtls_x509_crt_parse_file(&ssl->clicert, clientcert)) {
      die(conn, "error reading client certificate", clientcert);
      if (clientkey && mbedtls_pk_parse_public_keyfile(&ssl->pk, clientkey))
        die(conn, "error reading client key", clientkey);

    }
    write2f("using client cert: %s\n", clientcert);
    write2f("using client key:  %s\n", clientkey);
  }

  mbedtls_entropy_init(&ssl->entropy);
  if (0 != (mbedtls_ctr_drbg_seed(&ssl->ctr_drbg, mbedtls_entropy_func, &ssl->entropy,
	  (const unsigned char *)pers, strlen(pers))))
    die(conn, "Seeding the random number generator failed", NULL);


  mbedtls_ssl_init(&ssl->ssl);
  mbedtls_ssl_config_init(&ssl->conf);
  mbedtls_ssl_config_defaults(&ssl->conf,
      MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  mbedtls_ssl_conf_ca_chain(&ssl->conf, &ssl->cacert, NULL);
  mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_verify(&ssl->conf, verify_cb, conn);
  mbedtls_ssl_conf_ciphersuites(&ssl->conf, mbedtls_ssl_list_ciphersuites());
  mbedtls_ssl_conf_rng(&ssl->conf, mbedtls_ctr_drbg_random, &ssl->ctr_drbg);
  mbedtls_ssl_setup(&ssl->ssl, &ssl->conf);
  mbedtls_ssl_set_hostname(&ssl->ssl, conn->remote->host);
  mbedtls_ssl_set_session(&ssl->ssl, &ssl->ssn);
  if ((conn->flags & GTGET_FLAG_INSECURE)) {
    mbedtls_ssl_conf_authmode(&ssl->conf, MBEDTLS_SSL_VERIFY_NONE);
  }
  conn->ssl = ssl;
}

REGPARM(1)
void gtget_ssl_connect(connection_t * conn)
{
  int ret;
  sslparam_t *ssl = (sslparam_t *) conn->ssl;

  if (conn->proxy->host)
    proxy_connect(conn);

  mbedtls_ssl_set_bio(&ssl->ssl, &conn->sockfd, mbedtls_net_send, mbedtls_net_recv, NULL );

  while ((ret = mbedtls_ssl_handshake(&ssl->ssl))) {
    if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ)
      break;
  }

  if (ret) {
    if (conn->verbosity >= 1) {
      write2f("ssl_handshake() @ %d returned %d, ", conn->sockfd, -ret);
      print_ssl_error(ret);
    }
    die(conn, "ssl_handshake() failed", NULL);
  }

  if (conn->verbosity >= 1)
    write2f(" => ssl_handshake OK. %s\n", mbedtls_ssl_get_ciphersuite(&ssl->ssl));

  conn->read = gtget_ssl_read;
  conn->write = gtget_ssl_write;
}

REGPARM(1)
void gtget_ssl_close(connection_t * conn)
{
  if (conn->ssl) {
    sslparam_t *ssl = (sslparam_t *) conn->ssl;
    mbedtls_ssl_close_notify(&ssl->ssl);
  }
}
