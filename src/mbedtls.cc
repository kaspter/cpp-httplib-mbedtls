#include "mbedtls.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md5.h>

#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/sockios.h>

int get_custom_data(char *buf, int len) {
  int sock, offset = 0;
  struct ifconf conf;
  char ifconfbuf[128 * sizeof(struct ifreq)];
  struct ifreq *ifr;
  unsigned char *ptr;
  memset(buf, 0, len);
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == 0) {
    return 0;
  }

  memset(ifconfbuf, 0, sizeof(ifconfbuf));
  conf.ifc_buf = ifconfbuf;
  conf.ifc_len = sizeof(ifconfbuf);
  if (ioctl(sock, SIOCGIFCONF, &conf ) != 0) {
    return 0;
  }

  for (ifr = conf.ifc_req;
       (unsigned char *)ifr < (unsigned char *)conf.ifc_req + conf.ifc_len &&
       offset < len; ifr++ ) {
    if (ioctl(sock, SIOCGIFFLAGS, ifr) != 0
        || ioctl(sock, SIOCGIFHWADDR, ifr) != 0) {
      continue;
    }

    ptr = (unsigned char *)&ifr->ifr_addr.sa_data;
    offset += snprintf(buf + offset, len - offset,
                       "%02x:%02x:%02x:%02x:%02x:%02x\n",
                       *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3),
                       *(ptr + 4), *(ptr + 5));
  }

  close(sock);
  buf[len - 1] = 0;

  return strlen(buf);
}

int my_entropy_func(void *data, unsigned char *output, size_t len, size_t *olen) {
    char buf[1024];
    int ret = get_custom_data(buf, sizeof(buf));
    if (ret <= 0) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    // mbedtls_entropy_update((mbedtls_entropy_context *)data, (const unsigned char *)buf, strlen(buf));
    mbedtls_entropy_func(data, output, len);
    *olen = len;
    return 0;
}

/* CTX functions */

SSL_METHOD* SSLv23_client_method()
{
  static SSL_METHOD SSLv23_client = {
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_MAJOR_VERSION_3,
    MBEDTLS_SSL_MINOR_VERSION_1
  };

  return &SSLv23_client;
}

SSL_METHOD* SSLv23_server_method()
{
  static SSL_METHOD SSLv23_server = {
      MBEDTLS_SSL_IS_SERVER,
      MBEDTLS_SSL_MAJOR_VERSION_3,
      MBEDTLS_SSL_MINOR_VERSION_1
  };

  return &SSLv23_server;
}

/* SSLv3 is deprecated, set minimum to TLS 1.0 */
SSL_METHOD* TLS_server_method()
{
  static SSL_METHOD tls_server = {
    MBEDTLS_SSL_IS_SERVER,
    MBEDTLS_SSL_MAJOR_VERSION_3,
    MBEDTLS_SSL_MINOR_VERSION_1
  };

  return &tls_server;
}

SSL_METHOD* TLS_client_method()
{
  static SSL_METHOD tls_client = {
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_MAJOR_VERSION_3,
    MBEDTLS_SSL_MINOR_VERSION_1
  };

  return &tls_client;
}

SSL_CTX *SSL_CTX_new(SSL_METHOD* method) {
    SSL_CTX *ctx = (SSL_CTX *)calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    mbedtls_ssl_config_init(&(ctx->conf));
    mbedtls_entropy_init(&(ctx->entropy));
    mbedtls_ctr_drbg_init(&(ctx->ctr_drbg));
    mbedtls_x509_crt_init(&(ctx->cert));
    mbedtls_pk_init(&(ctx->pk));
    mbedtls_x509_crt_init(&(ctx->CA_cert));

    ctx->authmode = SSL_VERIFY_NONE; //SSL_VERIFY_REQUIRED;
    ctx->method = method;

    // Set the default entropy functions.
    // mbedtls_entropy_add_source(&(ctx->entropy), my_entropy_func, &(ctx->ctr_drbg), 128, MBEDTLS_ENTROPY_SOURCE_STRONG);

    const char *pers = "mbedtls-openssl-compat";
    mbedtls_ctr_drbg_seed(&(ctx->ctr_drbg), mbedtls_entropy_func, &(ctx->entropy), (const unsigned char *)pers, strlen(pers));

    return ctx;
}

void SSL_CTX_free(SSL_CTX *ctx)
{
    mbedtls_ssl_config_free(&(ctx->conf));
    mbedtls_entropy_free(&(ctx->entropy));
    mbedtls_ctr_drbg_free(&(ctx->ctr_drbg));
    mbedtls_x509_crt_free(&(ctx->cert));
    mbedtls_pk_free(&(ctx->pk));
    mbedtls_x509_crt_free(&(ctx->CA_cert));
    free(ctx);
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void* reserved) {
    // Reserved argument is not used.
    (void)reserved;

    if (mode & SSL_VERIFY_PEER) {
        ctx->authmode = SSL_VERIFY_REQUIRED;
    } else {
        ctx->authmode = SSL_VERIFY_NONE;
    }
}

long SSL_CTX_set_mode(SSL_CTX *ctx, long mode)
{
    // mbedtls_ssl_conf_ciphersuites(&(ctx->conf), NULL); // necessary to update the mode flags
    // mbedtls_ssl_conf_mode(&(ctx->conf), mode);

    return mode;
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
    int ret;
    if (type != SSL_FILETYPE_PEM) {
        fprintf(stderr, "Unsupported certificate file type %d\n", type);
        return 0;
    }

    ret = mbedtls_x509_crt_parse_file(&(ctx->cert), file);
    if (ret != 0) {
        fprintf(stderr, "SSL_CTX_use_certificate_file");
        return 0;
    }

    return 1;
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *cert)
{
    return 1;
}


int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file) {
    /*
    * MbedTLS uses the same function for parsing
    * certificate and certificates chain.
    */
    return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
    int ret;

    if (type != SSL_FILETYPE_PEM) {
        fprintf(stderr, "Unsupported private key file type %d\n", type);
        return 0;
    }

    ret = mbedtls_pk_parse_keyfile(&(ctx->pk), file, NULL);
    if (ret != 0) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file");
        return 0;
    }

    return 1;
}

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *private_key)
{
    return 1;
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CApath)
{
    int ret;
    if (CApath == NULL && CAfile == NULL) {
        return 0;
    }

    if (CAfile != NULL) {
        ret = mbedtls_x509_crt_parse_file(&(ctx->CA_cert), CAfile);
        if (ret != 0) {
            fprintf(stderr, "SSL_CTX_load_verify_locations");
            return 0;
        }
    }

    if (CApath != NULL) {
        ret = mbedtls_x509_crt_parse_path(&(ctx->CA_cert), CApath);
        if (ret != 0) {
            fprintf(stderr, "SSL_CTX_load_verify_locations");
            return 0;
        }
    }

    return 1;
}

/* SSL functions */

SSL *SSL_new(SSL_CTX *ctx)
{
    SSL_METHOD *method = ctx->method;

    SSL* ssl = (SSL*)malloc(sizeof(SSL));
    if (ssl == NULL) {
        return NULL;
    }
    ssl->last_error = SSL_ERROR_NONE;

    mbedtls_ssl_init(&(ssl->ctx));
    mbedtls_net_init(&(ssl->net));

    int ret = mbedtls_ssl_config_defaults(&(ctx->conf),
                                        method->endpoint_type,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
        printf("mbedtls_ssl_config_defaults() returned %d\n", ret);
        return NULL;
    }

    mbedtls_ssl_conf_rng(&(ctx->conf), mbedtls_ctr_drbg_random, &(ctx->ctr_drbg));

    mbedtls_ssl_conf_min_version(&(ctx->conf), method->ssl_maj_ver, method->ssl_min_ver);

    mbedtls_ssl_conf_ca_chain(&(ctx->conf), &ctx->CA_cert, NULL);
    mbedtls_ssl_conf_own_cert(&(ctx->conf), &(ctx->cert), &(ctx->pk));

    mbedtls_ssl_conf_authmode(&(ctx->conf), ctx->authmode);

    ret = mbedtls_ssl_setup(&(ssl->ctx), &(ctx->conf));
    if (ret != 0) {
        printf("mbedtls_ssl_setup returned -0x%x\n", -ret);
        mbedtls_net_free(&(ssl->net));
        mbedtls_ssl_free(&(ssl->ctx));
        free(ssl);
        return NULL;
    }


    // ssl->ssl_ctx = ctx;

    return ssl;
}

void SSL_free(SSL *ssl) {
    mbedtls_net_free(&(ssl->net));
    mbedtls_ssl_free(&(ssl->ctx));
    if (ssl->bio)
        BIO_free(ssl->bio);
    free(ssl);
}

int SSL_get_error(const SSL* ssl, int ret_code) {
    switch (ssl->last_error) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        return ssl->last_error;
    case SSL_ERROR_SSL:
        if (ret_code == 0) {
            return SSL_ERROR_ZERO_RETURN;
        }
        return SSL_ERROR_SSL;
    default:
        return SSL_ERROR_NONE;
    }
}

int SSL_set_fd(SSL *ssl, int fd) {
  ssl->fd = fd;
  ssl->last_error = 0;
  return 1;
}

/* MbedTLS read/write functions work as OpenSSL analogues */
int SSL_read(SSL *ssl, void *buf, int num)
{
    int ret = mbedtls_ssl_read(&ssl->ctx, (unsigned char*)buf, num);
    if (ret <= 0) {
        switch (ret) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            ssl->last_error = SSL_ERROR_WANT_READ;
            break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            ssl->last_error = SSL_ERROR_WANT_WRITE;
            break;
        case MBEDTLS_ERR_SSL_TIMEOUT:
            ssl->last_error = SSL_ERROR_WANT_READ;
            break;
        default:
            ssl->last_error = SSL_ERROR_SSL;
            break;
        }
        return -1;
    }

    return ret;
}

int SSL_peek(SSL *ssl, void *buf, int num)
{
#if 0
    int ret = mbedtls_ssl_read(&ssl->ctx, (unsigned char *)buf, num);
    printf("%s %d %d\n", __func__, __LINE__, ret);
    return ret;
#else
    return 1;
#endif
}

//返回值 > 0: 表示成功发送的字节数。
//返回值 = 0: 表示 SSL/TLS 连接已经关闭，不能再进行数据发送。
//返回值 < 0: 表示发送错误，具体错误码可以使用 SSL_get_error() 函数获取。常见的错误码包括：
//SSL_ERROR_WANT_READ: 表示需要等待读取数据后才能进行发送。
//SSL_ERROR_WANT_WRITE: 表示需要等待写入数据后才能进行发送。
//SSL_ERROR_SYSCALL: 表示发生了系统调用错误，可以通过 errno 获取具体错误码。
//SSL_ERROR_SSL: 表示发生了 SSL/TLS 协议错误，可以通过 ERR_get_error() 获取具体错误码。

int SSL_write(SSL *ssl, const void *buf, int num)
{
    int ret = mbedtls_ssl_write(&ssl->ctx, (unsigned char *)buf, num);
    if (ret <= 0) {
        switch (ret) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            ssl->last_error = SSL_ERROR_WANT_READ;
            break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            ssl->last_error = SSL_ERROR_WANT_WRITE;
            break;
        case MBEDTLS_ERR_SSL_TIMEOUT:
            ssl->last_error = SSL_ERROR_WANT_READ;
            break;
        default:
            ssl->last_error = SSL_ERROR_SSL;
            break;
        }
        return -1;
    }

    return ret;
}

int SSL_connect(SSL *ssl) {

    int ret = mbedtls_ssl_handshake(&ssl->ctx);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != 0) {
        printf("%s:%d %s()...mbedtls handshake failed returned 0x%04x\n", __FILE__, __LINE__, __FUNCTION__, (ret < 0 )? -ret : ret);
        if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
            printf("%s:%d %s()...unable to verify the server's certificate\n", __FILE__, __LINE__, __FUNCTION__);
        }
    }

    if (ret != 0) {
        switch (ret) {
        case MBEDTLS_ERR_SSL_WANT_READ:
            ssl->last_error = SSL_ERROR_WANT_READ;
            break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            ssl->last_error = SSL_ERROR_WANT_WRITE;
            break;
        case MBEDTLS_ERR_SSL_TIMEOUT:
            ssl->last_error = SSL_ERROR_WANT_READ;
            break;
        default:
            ssl->last_error = SSL_ERROR_SSL;
            break;
        }
        return -1;
    }

  return 1;
}

int SSL_accept(SSL *ssl) {
  return SSL_connect(ssl);
}

int SSL_shutdown(SSL* ssl) {
    int ret = mbedtls_ssl_close_notify(&(ssl->ctx));
    if (ret != 0) {
        return -1;
    }
    return 1;
}

int SSL_pending(const SSL* ssl)
{
    return mbedtls_ssl_get_bytes_avail(&(ssl->ctx));
}


int SSL_clear_mode(SSL* ssl, int mode)
{
    return 0;
}

void SSL_set_verify(SSL *ssl, int mode, void* reserved)
{
    return;
}

long SSL_get_verify_result(SSL *ssl)
{
    // mbedtls_ssl_get_verify_result
    return 0;
}

int SSL_set_tlsext_host_name(SSL* ssl, const char* name)
{
    int ret = mbedtls_ssl_set_hostname(&(ssl->ctx), name);
    return 1;
}

//
BIO *BIO_new_socket(int sock, int close_flag)
{
    BIO* bio = (BIO*)malloc(sizeof(BIO));
    if (bio == NULL) {
        return NULL;
    }

    mbedtls_net_init(&(bio->net));
    bio->net.fd = sock;
    return bio;
}

int BIO_read(BIO *bio, void *buf, int len)
{
    return len;
}

int BIO_write(BIO *bio, const void *buf, int len)
{
    return len;
}

void BIO_set_nbio(BIO *bio, int flag)
{
    return;
}

void BIO_free(BIO *bio)
{
    if (bio) {
        mbedtls_net_free(&(bio->net));
        free(bio);
    }
    return;
}

void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio)
{
    // mbedtls_ssl_set_bio(&(ssl->ctx), (void*)(intptr_t)(rbio->fd), __mbedtls_net_send, __mbedtls_net_recv, NULL);
    mbedtls_ssl_set_bio(&(ssl->ctx), &rbio->net, mbedtls_net_send, mbedtls_net_recv, NULL);
    ssl->bio = rbio;
}
