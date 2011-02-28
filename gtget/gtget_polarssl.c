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
#include <polarssl/ssl.h>
#include <polarssl/net.h>
#include <polarssl/havege.h>
#include "strbuf.h"
#include "gtget.h"

extern int timedout;

typedef struct sslparam_t {
  ssl_context ssl;
  ssl_session ssn;
  havege_state hs;
  x509_cert cacert;
  x509_cert clicert;
  rsa_context rsa;
} sslparam_t;

ssize_t gtget_ssl_write(connection_t * c, char *buf, size_t n)
{
  int r = 0, s;
  sslparam_t *ssl = (sslparam_t *) c->ssl;

  if (timedout)
    return -1;
  alarm(c->timeout);
  while (n > 0 && r >= 0) {
    s = n < SSL_MAX_PLAINTEXT_LEN ? n : SSL_MAX_PLAINTEXT_LEN;
    while ((r = ssl_write(&ssl->ssl, (unsigned char *)buf, n)) <= 0
	   && r == POLARSSL_ERR_NET_TRY_AGAIN);
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
  while ((r = ssl_read(&ssl->ssl, (unsigned char *)buf, n)) <= 0
	 && r == POLARSSL_ERR_NET_TRY_AGAIN);
  alarm(0);
  if (r == POLARSSL_ERR_NET_CONN_RESET)
    return 0;
  return r;
}

static int verify_cb(x509_cert * crt, int status, void *arg)
{
  connection_t *conn = (connection_t *) arg;
  int cnlen = strlen(conn->remote->host);
  x509_name *name;
  name = &crt->subject;
  while (name != NULL) {
    if (memcmp(name->oid.p, "\x55\x04\x03", 3) == 0) {
      int len = (int) name->oid.p[4];
      if (len == cnlen && memcmp(name->val.p, conn->remote->host, cnlen) == 0)
	return 0;
    }
    name = name->next;
  }
  write2f("%s: POLARSSL_ERR_X509_CERT_VERIFY_FAILED\n", __func__);
  return POLARSSL_ERR_X509_CERT_VERIFY_FAILED;
}

REGPARM(1)
void gtget_ssl_init(connection_t * conn)
{
  char *clientcert = NULL;
  char *clientkey = NULL;
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
    if (x509parse_crtfile(&ssl->cacert, servercert))
      die(conn, "error reading cacert", servercert);
  }

  /* read and parse the client certificate if provided */
  if ((clientcert = tryopen_alt(conn, conn->ccFile, "clientcert.pem"))) {
    if (!(clientkey = tryopen_alt(conn, conn->ckFile, "clientkey.pem")))
      clientkey = clientcert;

    if (x509parse_crtfile(&ssl->clicert, clientcert)) {
      die(conn, "error reading client certificate", clientcert);
      if (clientkey && x509parse_keyfile(&ssl->rsa, clientkey, NULL))
	die(conn, "error reading client key", clientkey);
    }
    write2f("using client cert: %s\n", clientcert);
    write2f("using client key:  %s\n", clientkey);
  }

  havege_init(&ssl->hs);

  if (ssl_init(&ssl->ssl))
    die(conn, "error initializing SSL", NULL);

  ssl_set_endpoint(&ssl->ssl, SSL_IS_CLIENT);
  if ((conn->flags & GTGET_FLAG_INSECURE)) {
    ssl_set_authmode(&ssl->ssl, SSL_VERIFY_NONE);
  }
  ssl_set_ca_chain(&ssl->ssl, &ssl->cacert, NULL, conn->remote->host);
  ssl_set_authmode(&ssl->ssl, SSL_VERIFY_OPTIONAL);
  ssl_set_validator(&ssl->ssl, verify_cb, conn);
  ssl_set_ciphers(&ssl->ssl, ssl_default_ciphers);
  ssl_set_session(&ssl->ssl, 1, 600, &ssl->ssn);
  ssl_set_rng(&ssl->ssl, havege_rand, &ssl->hs);
  conn->ssl = ssl;
}

REGPARM(1)
void gtget_ssl_connect(connection_t * conn)
{
  int ret;
  sslparam_t *ssl = (sslparam_t *) conn->ssl;

  if (conn->proxy->host)
    proxy_connect(conn);

  ssl_set_bio(&ssl->ssl, net_recv, &conn->sockfd, net_send, &conn->sockfd);

  while ((ret = ssl_handshake(&ssl->ssl)) == POLARSSL_ERR_NET_TRY_AGAIN);

  if (ret) {
    if (conn->verbosity >= 1)
      write2f("ssl_handshake() returned %d\n", -ret);
    die(conn, "ssl_handshake() failed", NULL);
  }

  if (conn->verbosity >= 1)
    write2f(" => ssl_handshake OK. %s\n", ssl_get_cipher(&ssl->ssl));

  conn->read = gtget_ssl_read;
  conn->write = gtget_ssl_write;
}

REGPARM(1)
void gtget_ssl_close(connection_t * conn)
{
  sslparam_t *ssl = (sslparam_t *) conn->ssl;
  ssl_close_notify(&ssl->ssl);
}
