#include <algorithm>
#include <iostream>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

const std::string PORT = "1965";
const std::string GEMINI_PREFIX = "gemini://";

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <URL>" << std::endl;
        std::cout << "ERROR: expected gemini URL" << std::endl;
        return 1;
    }

    std::string url = argv[1];
    if (!url.starts_with(GEMINI_PREFIX)) {
        std::cout << "ERROR: Invalid URL: Does not start with " << GEMINI_PREFIX << std::endl;
        return 1;
    }

    std::string HOST = url;
    std::size_t protocol = HOST.find_first_of(":");
    HOST = HOST.substr(protocol + 3);
    std::size_t slash = HOST.find_first_of("/");
    HOST = HOST.substr(0, slash);

    struct addrinfo hints {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res;
    int status;
    if ((status = getaddrinfo(HOST.c_str(), PORT.c_str(), &hints, &res)) != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return 1;
    }

    int sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    for (struct addrinfo *addr = res; addr != nullptr; addr = addr->ai_next) {
        sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

        if (sd == -1) break;
        if (connect(sd, addr->ai_addr, addr->ai_addrlen) == 0) break;

        close(sd);
        sd = -1;
    }
    if (sd == -1) {
        std::cerr << "Socket error: " << strerror(errno) << std::endl;
        return 1;
    }

    struct sockaddr_in *addr_in = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    std::cout << "Created connection to " << inet_ntoa(addr_in->sin_addr)
        << ":" << ntohs(addr_in->sin_port) << std::endl;

    freeaddrinfo(res);

    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        std::cerr << "ERROR: SSL context error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == nullptr) {
        std::cerr << "ERROR: SSL new error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        return 1;
    }

    SSL_set_tlsext_host_name(ssl, HOST.c_str());

    SSL_set_fd(ssl, sd);
    if (SSL_connect(ssl) < 0) {
        std::cerr << "ERROR: SSL error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;;
        return 1;
    }

    url += "\r\n";

    char buf[1024];
    SSL_write(ssl, url.c_str(), url.size());

    ssize_t n = SSL_read(ssl, buf, sizeof(buf));
    while (n > 0) {
        char s[n + 1];
        for (int i = 0; i < n; i++) {
            s[i] = buf[i];
        }
        s[n] = '\0';

        printf("%s\n", s);

        n = SSL_read(ssl, buf, sizeof(buf));
    }

    SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
