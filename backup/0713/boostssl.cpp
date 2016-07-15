/*
 * boostssl.cpp
 *
 *  Created on: 8 Jul 2016
 *      Author: root
 */

#include "netbase.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
using namespace boost::asio;

class ssl_socket {
	ssl_socket(const CService &addrConnect, int af, int style, int protocol) : socket(af, style, protocol){
		//using namespace boost::asio;
		    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;
		    boost::asio::io_service service;
		    std::string host = addrConnect.ToStringIP();
		    std::string port = addrConnect.GetPort();

		    boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
		    ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::single_dh_use);
		    ctx.set_verify_mode(boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert);
		    ctx.load_verify_file("./certs/server.crt");
		    ctx.use_certificate_chain_file("./client_certs/client.crt");
		    ctx.use_private_key_file("./client_certs/client.key", boost::asio::ssl::context::pem);
		    ctx.use_tmp_dh_file("./client_certs/dh1024.pem");

		    ssl_socket ssl_sk(service, ctx);
		    boost::asio::ip::tcp::resolver resolver(service);
		    boost::asio::ip::tcp::resolver::query query(host, port);
		    connect(ssl_sk.lowest_layer(), resolver.resolve(query));
		    std::cout << "Connected: " << ssl_sk.lowest_layer().remote_endpoint() << "\n";

		    // SSL handshake
		    ssl_sk.set_verify_mode(boost::asio::ssl::verify_none);
		    ssl_sk.set_verify_callback(boost::asio::ssl::rfc2818_verification(host));
		    ssl_sk.handshake(ssl_socket::client);

	}
};

int main(int argc, char* argv[]) {

	typedef ssl::stream<ip::tcp::socket> ssl_socket;

	ssl::context ctx(ssl::context::sslv23);
	//ctx.set_default_verify_paths();
	ctx.set_options(boost::asio::ssl::context::default_workarounds
	                   | boost::asio::ssl::context::no_sslv2
	                   | boost::asio::ssl::context::single_dh_use);
	ctx.set_verify_mode(boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert);
	ctx.load_verify_file("/var/certs/server_certs/server.crt");
	ctx.use_certificate_chain_file("/var/certs/client_certs/client.crt");
	ctx.use_private_key_file("/var/certs/client_certs/client.key", boost::asio::ssl::context::pem);
	ctx.use_tmp_dh_file("/var/certs/client_certs/dh1024.pem");

    io_service service;
    ssl_socket sock(service, ctx);
    ip::tcp::resolver resolver(service);
    std::string host = "127.0.0.1";
    ip::tcp::resolver::query query(host, "18880");
    connect(sock.lowest_layer(), resolver.resolve(query));
    // SSL handshake
    sock.set_verify_mode(ssl::verify_none);
    sock.set_verify_callback(ssl::rfc2818_verification(host));
    sock.handshake(ssl_socket::client);

    std::string req = "hello. this is from boost ssl client";
    //"GET /index.html HTTP/1.0\r\nHost: " + host + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    write(sock, buffer(req.c_str(), req.length()));
    char buff[512];
    boost::system::error_code ec;
    while ( !ec) {
        int bytes = read(sock, buffer(buff), ec);
        std::cout << std::string(buff, bytes);
    }
}

