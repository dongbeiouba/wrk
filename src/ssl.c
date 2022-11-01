// Copyright (C) 2013 - Will Glozer.  All rights reserved.

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl.h"

SSL_CTX *ssl_init(config *cfg) {
    SSL_CTX *ctx = NULL;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

#ifdef HAVE_NTLS
    if (cfg->ntls)
        ctx = SSL_CTX_new(NTLS_client_method());
    else
#endif
    ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx != NULL) {
#ifdef HAVE_NTLS
        int ret = 1;

        if (cfg->ntls)
            SSL_CTX_enable_ntls(ctx);

        if (cfg->cipher)
            ret &= SSL_CTX_set_cipher_list(ctx, cfg->cipher);

        if (cfg->sign_cert)
            ret &= SSL_CTX_use_sign_certificate_file(ctx,
                                                     cfg->sign_cert,
                                                     SSL_FILETYPE_PEM);
        if (cfg->sign_key)
            ret &= SSL_CTX_use_sign_PrivateKey_file(ctx,
                                                    cfg->sign_key,
                                                    SSL_FILETYPE_PEM);
        if (cfg->enc_cert)
            ret &= SSL_CTX_use_enc_certificate_file(ctx,
                                                    cfg->enc_cert,
                                                    SSL_FILETYPE_PEM);
        if (cfg->enc_key)
            ret &= SSL_CTX_use_enc_PrivateKey_file(ctx,
                                                   cfg->enc_key,
                                                   SSL_FILETYPE_PEM);
        if (ret != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
#endif
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_verify_depth(ctx, 0);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    }

    return ctx;
}

status ssl_connect(connection *c, char *host) {
    int r;
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, host);
    if ((r = SSL_connect(c->ssl)) != 1) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    return OK;
}

status ssl_close(connection *c) {
    SSL_shutdown(c->ssl);
    SSL_clear(c->ssl);
    return OK;
}

status ssl_read(connection *c, size_t *n) {
    int r;
    if ((r = SSL_read(c->ssl, c->buf, sizeof(c->buf))) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

status ssl_write(connection *c, char *buf, size_t len, size_t *n) {
    int r;
    if ((r = SSL_write(c->ssl, buf, len)) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

size_t ssl_readable(connection *c) {
    return SSL_pending(c->ssl);
}
