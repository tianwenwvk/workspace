/*
 * opensslbase.cpp
 *
 *  Created on: 11 Jul 2016
 *      Author: vicky
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "opensslbase.h"
#define SERVER_CERT_PATH "/var/certs/servers/server.pem"
#define SERVER_KEY_PATH  "/var/certs/servers/server.key"
#define CAFILE "/var/certs/server/ca.pem"
#define CLIENT_CERT_PATH "/var/certs/clients/client.pem"
#define CLIENT_KEY_PATH  "/var/certs/clients/client.key"
#define CLIENT_CAFILE "/var/certs/clients/ca.pem"

void init_openssl()
{
    SSL_load_error_strings();
    //registers the available SSL/TLS ciphers and digests
    SSL_library_init();
    //OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_SSL_CTX()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}
//ssl handshake, verfy cert, res=1
static int verify_cb(int res, X509_STORE_CTX *xs)
{
    printf("SSL VERIFY RESULT :%d\n",res);
    switch (xs->error)
    {
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            printf(" NOT GET CRL!\n");
            return 1;
        default :
            break;
    }
    return res;
}

void configure_SSL_CTX(SSL_CTX *ctx)
{
   // SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
	SSL_CTX_set_verify_depth(ctx, 10);
	SSL_CTX_load_verify_locations(ctx,CAFILE, NULL);
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_PATH, SSL_FILETYPE_PEM) < 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_PATH, SSL_FILETYPE_PEM) < 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx))
      {
        printf("Check private key failed!\n");
    	ERR_print_errors_fp(stdout);
        exit(1);
      }

      SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAFILE));
}
int sslsock_handle_nbio (SSL* ssl, int ret, timeval* totv)
{
//	 void            *ssl;           /* -> the SSL info                      */
//	 int             ret;            /* the SSL I/O function return value    */
//	 struct timeval  *totv;          /* -> timeout info, or NULL             */

	int     sfd, i;
    fd_set  rset, wset;

    sfd = SSL_get_fd (ssl);
    i = SSL_get_error (ssl, ret);

    if (i == SSL_ERROR_WANT_READ) {
    do {
        FD_ZERO (&rset);
        FD_SET (sfd, &rset);
        i = select (sfd + 1, &rset, NULL, NULL, totv);
    } while ((i < 0) && (errno == EINTR));
    if (i == 0) {
        /* the select() timed out */
        ret = -2;
        errno = ETIMEDOUT;
    } else {
        /* either an error, or it's readable */
        ret = i;
    }
    } else if (i == SSL_ERROR_WANT_WRITE) {
    do {
        FD_ZERO (&wset);
        FD_SET (sfd, &wset);
        i = select (sfd + 1, NULL, &wset, NULL, totv);
    } while ((i < 0) && (errno == EINTR));
    if (i == 0) {
        /* the select() timed out */
        ret = -2;
        errno = ETIMEDOUT;
    } else {
        /* either an error, or it's writable */
        ret = i;
    }
    }
    /* else, leave "ret" alone, and return it as-is */

    return (ret);
}

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX* opensslbase::sslctx_s_init()
{
	SSL_CTX *ctx = NULL;
	const SSL_METHOD *method;
	//init_openssl();
	SSL_load_error_strings();
	//registers the available SSL/TLS ciphers and digests
	SSL_library_init();
	//OpenSSL_add_ssl_algorithms();

	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}
	//configure_SSL_CTX(ctx);
	// SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
	SSL_CTX_set_verify_depth(ctx, 10);
	SSL_CTX_load_verify_locations(ctx, CAFILE, NULL);
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_PATH, SSL_FILETYPE_PEM)< 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_PATH, SSL_FILETYPE_PEM)< 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Check private key failed!\n");
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAFILE));

	return ctx;
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    ctx = sslctx_s_init();

    sock = create_socket(7838);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

SSL_CTX* opensslbase::sslctx_c_init()
{
#if 0
    BIO *bio = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    EVP_PKEY *pkey =NULL;
    PKCS12* p12 = NULL;
    X509_STORE *store =NULL;
    int error_code =0;
#endif

    SSL_CTX *g_sslctx = NULL;
    int ret =0;
    //print_client_cert(CERT_PATH);
    //registers the libssl error strings
    SSL_load_error_strings();

    //registers the available SSL/TLS ciphers and digests
    SSL_library_init();

    //creates a new SSL_CTX object as framework to establish TLS/SSL
    g_sslctx = SSL_CTX_new(SSLv23_client_method());
    if(g_sslctx == NULL){
        ret = -1;
        return NULL;
    }

    //passwd is supplied to protect the private key,when you want to read key
    //SSL_CTX_set_default_passwd_cb_userdata(g_sslctx,"900820");

    //set cipher ,when handshake client will send the cipher list to server
    SSL_CTX_set_cipher_list(g_sslctx,"HIGH:MEDIA:LOW:!DH");
    //SSL_CTX_set_cipher_list(g_sslctx,"AES128-SHA");

    //set verify ,when recive the server certificate and verify it and verify_cb function will deal the result of verification
    SSL_CTX_set_verify(g_sslctx, SSL_VERIFY_PEER, verify_cb);

    //sets the maximum depth for the certificate chain verification that shall be allowed for ctx
    SSL_CTX_set_verify_depth(g_sslctx, 10);

    //load the certificate for verify server certificate, CA file usually load
    SSL_CTX_load_verify_locations(g_sslctx,CLIENT_CAFILE, NULL);

    //load user certificate,this cert will be send to server for server verify
    if(SSL_CTX_use_certificate_file(g_sslctx,CLIENT_CERT_PATH,SSL_FILETYPE_PEM) <= 0){
        printf("certificate file error!\n");
        ret = -1;
        return NULL;
    }
    //load user private key
    if(SSL_CTX_use_PrivateKey_file(g_sslctx,CLIENT_KEY_PATH,SSL_FILETYPE_PEM) <= 0){
        printf("privatekey file error!\n");
        ret = -1;
        return NULL;
    }
    if(!SSL_CTX_check_private_key(g_sslctx)){
        printf("Check private key failed!\n");
        ret = -1;
        return NULL;
    }

    return g_sslctx;
}

