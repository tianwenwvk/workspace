/*
 * boostssl.cpp
 *
 *  Created on: 8 Jul 2016
 *      Author: root
 */


#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
using namespace boost::asio;

using namespace boost::asio;
io_service service;
int main(int argc, char* argv[]) {

	typedef ssl::stream<ip::tcp::socket> ssl_socket;

	ssl::context ctx(ssl::context::sslv23);
    ctx.set_default_verify_paths();
    io_service service;
    ssl_socket sock(service, ctx);
    ip::tcp::resolver resolver(service);
    std::string host = "127.0.0.1";
    ip::tcp::resolver::query query(host, 18880);
    connect(sock.lowest_layer(), resolver.resolve(query));
    // SSL handshake
    sock.set_verify_mode(ssl::verify_none);
    sock.set_verify_callback(ssl::rfc2818_verification(host));
    sock.handshake(ssl_socket::client);

    std::string req = "GET /index.html HTTP/1.0\r\nHost: " + host + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    write(sock, buffer(req.c_str(), req.length()));
    char buff[512];
    boost::system::error_code ec;
    while ( !ec) {
        int bytes = read(sock, buffer(buff), ec);
        std::cout << std::string(buff, bytes);
    }
}

