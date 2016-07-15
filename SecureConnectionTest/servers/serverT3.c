#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024
#define SERVER_CERT_PATH "./server.pem"
#define SERVER_KEY_PATH  "./server.key"
#define CAFILE "./ca.pem"

void ShowCerts(SSL * ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    printf("Digital certificate information:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Certificate: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  }
  else
    printf("No certificate information！\n");
}
void print_peer_certificate(SSL *ssl)
{
    X509* cert= NULL;
    char buf[8192]={0};
    BIO *bio_cert = NULL;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
		printf("Digital certificate information:\n");
		X509_NAME_oneline(X509_get_subject_name(cert),buf,8191);
		printf("Verified Peer Name:%s\n",buf);
		memset(buf,0,sizeof(buf));
		X509_NAME_oneline(X509_get_issuer_name(cert), buf, 8191);
        printf("Issuer: %s\n", buf);
		memset(buf,0,sizeof(buf));
		bio_cert = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(bio_cert, cert);
		BIO_read( bio_cert, buf, 8191);
	   
		printf("CLIENT CERT:\n%s\n",buf);
		if(bio_cert)BIO_free(bio_cert);
		if(cert)X509_free(cert);
  }
  else
    printf("No certificate information！\n");
}

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

int main(int argc, char **argv)
{
  int sockfd, new_fd, fd;
  socklen_t len;
  struct sockaddr_in my_addr, their_addr;
  unsigned int myport, lisnum;
  char buf[MAXBUF + 1];
  SSL_CTX *ctx;
  mode_t mode;
  char pwd[100];
  char* temp;


  if (argv[1])
    myport = atoi(argv[1]);
  else
  {
    myport = 7838;
    argv[2]=argv[3]=NULL;
  }

  if (argv[2])
    lisnum = atoi(argv[2]);
  else
  {
    lisnum = 2;
    argv[3]=NULL;
  }

  SSL_library_init();

  OpenSSL_add_all_algorithms();

  SSL_load_error_strings();

  ctx = SSL_CTX_new(SSLv23_server_method());

  if (ctx == NULL)
  {
    ERR_print_errors_fp(stdout);
    exit(1);
  }
  
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
  SSL_CTX_set_verify_depth(ctx, 10);
  SSL_CTX_load_verify_locations(ctx,CAFILE, NULL);
  
  /* load certificate */
  getcwd(pwd,100);
  if(strlen(pwd)==1)
    pwd[0]='\0';
  if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_PATH, SSL_FILETYPE_PEM) <= 0)
  {
    printf("certificate file error!\n");
	ERR_print_errors_fp(stdout);
    exit(1);
  }
  /* load private key */
  getcwd(pwd,100);
  if(strlen(pwd)==1)
    pwd[0]='\0';
  if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_PATH, SSL_FILETYPE_PEM) <= 0)
  {
    printf("privatekey file error!\n");
	ERR_print_errors_fp(stdout);
    exit(1);
  }

  if (!SSL_CTX_check_private_key(ctx))
  {
    printf("Check private key failed!\n");
	ERR_print_errors_fp(stdout);
    exit(1);
  }

  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAFILE)); 
	
  if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("socket");
    exit(1);
  }
  else
    printf("socket created\n");

  bzero(&my_addr, sizeof(my_addr));
  my_addr.sin_family = PF_INET;
  my_addr.sin_port = htons(myport);
  if (argv[3])
    my_addr.sin_addr.s_addr = inet_addr(argv[3]);
  else
    my_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1)
  {
    perror("bind");
    exit(1);
  }
  else
    printf("binded\n");

  if (listen(sockfd, lisnum) == -1)
  {
    perror("listen");
    exit(1);
  }
  else
    printf("begin listen\n");

  while (1)
  {
    SSL *ssl;
    len = sizeof(struct sockaddr);
    /* connection from clients */
    if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1)
    {
      perror("accept");
      exit(errno);
    }
    else
    {
		printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), new_fd);
        
	}
    ssl = SSL_new(ctx);

    SSL_set_fd(ssl, new_fd);

	SSL_CTX_set_verify(SSL_get_SSL_CTX(ssl), SSL_VERIFY_PEER, NULL);
	
    if (SSL_accept(ssl) == -1)
    {
      perror("accept");
      close(new_fd);
      break;
    }

	print_peer_certificate(ssl);
    while(1)
    {
      bzero(buf, MAXBUF + 1);
      len = SSL_read(ssl, buf, MAXBUF);
      if(len == 0)
      {
        printf("Receive Complete !\n");
        break;
      }
      else if(len < 0)
      {
        printf("Failure to receive message ! Error code is %d，Error messages are '%s'\n", errno, strerror(errno));
        exit(1);
      }
	
	printf("Received: %s \n",buf);
	SSL_write(ssl, buf, strlen(buf));
    }


    close(fd);

    SSL_shutdown(ssl);

    SSL_free(ssl);

    close(new_fd);
  }


  close(sockfd);
  SSL_CTX_free(ctx);
  
  return 0;
}


