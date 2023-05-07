#ifndef MBEDTLS_SUPPORT_HEADER_INCLUDED
#define MBEDTLS_SUPPORT_HEADER_INCLUDED

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"

#include <iomanip>



#define SSL_ERROR_NONE            0
#define SSL_ERROR_SSL             1
#define SSL_ERROR_WANT_READ       2
#define SSL_ERROR_WANT_WRITE      3
#define SSL_ERROR_WANT_X509_LOOKUP 4
#define SSL_ERROR_SYSCALL         5
#define SSL_ERROR_ZERO_RETURN     6
#define SSL_ERROR_WANT_CONNECT    7
#define SSL_ERROR_WANT_ACCEPT     8

#define SSL_VERIFY_NONE             0x00
#define SSL_VERIFY_PEER             0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE      0x04
#define SSL_VERIFY_PEER_STRICT      0x08
#define SSL_VERIFY_CRL_CHECK_ALL    0x20
#define SSL_VERIFY_CRL_CHECK        0x40
#define SSL_VERIFY_X509_STRICT      0x80
#define SSL_VERIFY_ANY              (SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
#define SSL_VERIFY_NONE_IF_NO_PEER_CERT 0x100
#define SSL_VERIFY_CLIENT_POST_HANDSHAKE 0x200
#define SSL_VERIFY_TRUSTED_FIRST    0x400
#define SSL_VERIFY_REQUIRED         SSL_VERIFY_PEER_STRICT


#define SSL_FILETYPE_PEM                1


#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002U
#define SSL_MODE_AUTO_RETRY                 0x00000004U

#define X509_V_OK 0

typedef struct ssl_method {
  int endpoint_type;
  int ssl_maj_ver;
  int ssl_min_ver;
} SSL_METHOD;

typedef struct mbedtls_ssl_ctx {
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* Own cert & private key */
    mbedtls_x509_crt cert;  // client certification
    mbedtls_pk_context pk;  // client private key
    /* CA certs */
    mbedtls_x509_crt CA_cert;
    /* SSL_VERIFY_REQUIRED in this implementation */
    int authmode;
    /* endpoint details */
    SSL_METHOD* method;
} SSL_CTX;

typedef struct mbedtls_bio {
    mbedtls_net_context net;
} BIO;

typedef struct mbedtls_ssl {
    mbedtls_ssl_context ctx;
    mbedtls_net_context net;

    BIO *bio;
    int fd;
    /* last SSL error. see SSL_get_error implementation. */
    int last_error;
} SSL;




SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_peek(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_shutdown(SSL* ssl);
int SSL_pending(const SSL* ssl);
int SSL_get_error(const SSL *ssl, int ret);
int SSL_connect(SSL *ssl);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_accept(SSL *ssl);
int SSL_clear_mode(SSL* ssl, int mode);
void SSL_set_verify(SSL *ssl, int mode, void* reserved);
long SSL_get_verify_result(SSL *ssl);

int SSL_set_tlsext_host_name(SSL* ssl, const char* name);

SSL_METHOD* SSLv23_client_method();
SSL_METHOD* SSLv23_server_method();
SSL_METHOD* TLS_client_method();
SSL_METHOD* TLS_server_method();


typedef struct mbedtls_x509_store {
    mbedtls_x509_crt cert;
    int fd;
} X509_STORE;

typedef struct mbedtls_x509 {
    int fd;
} X509;

typedef mbedtls_pk_context EVP_PKEY;


SSL_CTX *SSL_CTX_new(SSL_METHOD* method);
void SSL_CTX_free(SSL_CTX *ctx);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void* reserved);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath);
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *cert);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *private_key);
long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);




#define BIO_NOCLOSE 0x00

BIO *BIO_new_socket(int sock, int close_flag);
int BIO_read(BIO *bio, void *buf, int len);
int BIO_write(BIO *bio, const void *buf, int len);
void BIO_set_nbio(BIO *bio, int flag);
void BIO_free(BIO *bio);
void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio);



#endif
