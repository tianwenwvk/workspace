/*
 * opensslbase.h
 *
 *  Created on: 13 Jul, 2016
 *      Author: vicky
 */

#ifndef OPENSSLBASE_H_
#define OPENSSLBASE_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

class opensslbase {
	public:
	SSL_CTX* sslctx_s_init();
	SSL_CTX* sslctx_c_init();
};

#endif /* OPENSSLBASE_H_ */
