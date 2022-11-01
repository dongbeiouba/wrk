#ifndef SSL_H
#define SSL_H

#include "net.h"

#if defined(TONGSUO_VERSION_NUMBER) || defined(BABASSL_VERSION_NUMBER)
# define HAVE_NTLS
#endif

SSL_CTX *ssl_init(config *);

status ssl_connect(connection *, char *);
status ssl_close(connection *);
status ssl_read(connection *, size_t *);
status ssl_write(connection *, char *, size_t, size_t *);
size_t ssl_readable(connection *);

#endif /* SSL_H */
