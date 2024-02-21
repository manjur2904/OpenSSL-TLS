#include <iostream>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/md5.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
using namespace std;

int main(){
    cout<<"Manjur\n";
    // Create a socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        std::cerr << "Error creating socket\n";
        return 1;
    }

    // Bind the socket to the address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8080);
    if (bind(server_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Bind failed\n";
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 5) < 0) {
        std::cerr << "Listen failed\n";
        return 1;
    }

    // Accept a client connection
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_address, &client_address_len);
    if (client_fd < 0) {
        std::cerr << "Accept failed\n";
        return 1;
    }
    cout<<"Accept a client connection\n";

    // Initialize SSL library and register algorithms
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL_CTX object as framework for TLS/SSL enabled functions.
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_use_certificate_file(ctx, "server_cert.pem", SSL_FILETYPE_PEM)) {
        std::cerr << "Error loading server certificate\n";
        return 1;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "server_key.pem", SSL_FILETYPE_PEM)) {
        std::cerr << "Error loading server private key\n";
        return 1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the certificate\n";
        return 1;
    }

    // Create new SSL connection state object
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Error creating SSL object\n";
        return 1;
    }

    // Attach the SSL session to the socket descriptor
    SSL_set_fd(ssl, client_fd);

    // Try to SSL-accept here, returns 1 for success
    if (SSL_accept(ssl) != 1) {
        std::cerr << "Error accepting SSL connection\n";
        SSL_free(ssl);
        return 1;
    }

    // Read data from the client
    char buffer[1024];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
        // Handle error
        int err = SSL_get_error(ssl, bytes_read);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // The operation did not complete; try again later
        } else {
            // Other error; handle appropriately
            fprintf(stderr, "SSL_read error: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        }
    } else {
        // Data read successfully
        buffer[bytes_read] = '\0'; // Null-terminate the buffer
        printf("Received %d bytes: %s\n", bytes_read, buffer);
    }


    /*
    // Verify the client's certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "Error getting client certificate\n";
        SSL_free(ssl);
        return 1;
    }

    X509_STORE* store = X509_STORE_new();
    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, cert, NULL);

    if (X509_verify_cert(store_ctx) != 1) {
        std::cerr << "Error verifying client certificate\n";
        X509_STORE_CTX_free(store_ctx);
        X509_STORE_free(store);
        SSL_free(ssl);
        return 1;
    }

    std::cout << "Client certificate verified successfully\n";

    // Cleanup
    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    */
    return 0;
}
