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
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == -1) {
        std::cerr << "Error creating socket\n";
        return 1;
    }

    // Connect to the server
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
        std::cerr << "Invalid address\n";
        return 1;
    }

    if (connect(client_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Connection failed\n";
        return 1;
    }

    // Receive data from the server
    // char buffer[1024] = {0};
    // read(client_fd, buffer, 1024);
    // std::cout << "Message from server: " << buffer << "\n";

    SSL_CTX* ctx = NULL;
	SSL *ssl = NULL;
    // Initialize SSL library and register algorithms
	SSL_library_init();

	// Adds all algorithms to the table (digests and ciphers)
	OpenSSL_add_all_algorithms();

	// Registers the error strings for all libcrypto and libssl error strings.
	SSL_load_error_strings();

	// Create a new SSL_CTX object as framework for TLS/SSL enabled functions.
	ctx = SSL_CTX_new(TLS_client_method());

	if(!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) // Set the minimum protocol versions to TLS1_3_VERSION.
	{
		cout<<( "Unable to set minimum supported protocol 'TLS1_3_VERSION' for the CTX. Please check parameters.\n");
		return 0;
	}

	if(!SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) // Set the maximum protocol versions to TLS1_3_VERSION.
	{
		cout<<("Unable to set maximum supported protocol 'TLS1_3_VERSION' for the CTX. Please check parameters.\n");
		return 0;
	}
    // Create new SSL connection state object
	ssl = SSL_new(ctx);

	// Attach or bind the SSL session to the socket descriptor.
	SSL_set_fd(ssl, client_fd);

	// Try to SSL-connect here, returns 1 for success
	int SSL_ret = SSL_connect(ssl);
	if ( SSL_ret != 1 )
	{
		cout<<"SSL_ret = " <<SSL_ret<<endl;
		cout<<("Error: Could not build a SSL session ... Program Terminated.\n");
		close(client_fd);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		return 0;
	}
	else
	{
		cout<<("Successfully enabled SSL/TLS session ...\n");
	}


	const char *msg = "Hello, server!";
    int msg_len = strlen(msg);

    // Send data over the SSL connection
    int bytes_written = SSL_write(ssl, msg, msg_len);
    if (bytes_written <= 0) {
        // Handle error
        int err = SSL_get_error(ssl, bytes_written);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // The operation did not complete; try again later
        } else {
            // Other error; handle appropriately
            fprintf(stderr, "SSL_write error: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        }
    } else {
        // Data sent successfully
        printf("Sent %d bytes: %s\n", bytes_written, msg);
    }



	/*
    // char  *CACertificatefile = (char*)calloc(64,sizeof(char));
    const char *CACertificatefile = "gr_cafo_cert3.pem";
    X509 *cert;
	X509_STORE     *xs = NULL;
	X509_STORE_CTX *xsc = NULL;
	int ret = 0;
	// char* ca_filepath = "configurations/gr_cacom_cert3.pem";

	cert = SSL_get_peer_certificate(ssl); // Get the GR server's certificate.
	//unsigned long err = ERR_get_error();
	//PRINT("SSL_get_peer_certificate Error code: "<<err);
	if(cert == NULL)
	{
		cout<<("Error: Could not get a certificate from NSE Server \n");
		return false;
	}
	else
	{
		// Process and use the peer certificate as needed
		// For example, print information about the certificate
		X509_NAME *subject = X509_get_subject_name(cert);
		char *subject_name = X509_NAME_oneline(subject, NULL, 0);
		cout<<"Peer Certificate Subject:" << subject_name<<endl;
		//OPENSSL_free(subject_name);
		// Don't forget to free the certificate when you're done with it
		//X509_free(peer_cert);
	}

	cout<<("X509_STORE_CTX \n");
	if((xs = X509_STORE_new()) == NULL) // This function returns a new X509_STORE.
	{
		cout << "Error creating X509_STORE_CTX object." <<endl;
		return false;
	}
	int err = ERR_get_error();
	cout<<"X509_STORE_new Error code: "<<err<<endl;
	cout<<("X509_STORE_CTX NEW\n");
	// Create the context structure for the validation operation.
	xsc = X509_STORE_CTX_new(); // This function returns a newly initialised X509_STORE_CTX.
	err = ERR_get_error();
	cout<<"X509_STORE_CTX_new Error code: "<<err<<endl;

	cout<<("X509_STORE_load\n");
	ret = X509_STORE_load_locations(xs, CACertificatefile, NULL); // Configure files and directories used by a certificate store.
		// The path of CA certificate (gr_ca_cert1.pem) will be used in this function.
		// The CA certificate (gr_ca_cert1.pem) will be provided by the Exchange for validation of Gateway Router certificate.
	err = ERR_get_error();
	cout<<"X509_STORE_load_locations Error code: "<<err<<endl;
	if(ret != 1)
	{
		cout << "Error loading CA cert or chain file." <<endl;
		return false;
	}
    cout<<("Manjur-1\n");
    SSL_CTX_set_cert_store(ctx, xs);
	cout<<("X509_STORE_init\n");
	ret = X509_STORE_CTX_init(xsc, xs, cert, NULL); // This function returns a newly initialised X509_STORE_CTX structure.
	err = ERR_get_error();
	cout<<"X509_STORE_CTX_init Error code: "<<err<<endl;
	if(ret != 1){
		cout<<"X509_STORE_CTX_init, ret = "<<ret<<endl;
		return 0;
	}
    cout<<("Manjur0\n");
        //SSL_CTX_set_cert_store(ctx, xs);
        cout<<("Manjur1\n");
	ret = X509_verify_cert(xsc); // This function builds and verify X509 certificate chain.
        cout<<("Manjur2\n");
	err = ERR_get_error();
	cout<<"X509_verify_cert Error code: "<<err<<endl;
	if(ret != 1){
		cout<<"Failed to X509_verify_cert, ret = "<<ret<<endl;
		return 0;
	}
	cout<<("Gateway router server certification successful\n");
	*/
    return 0;
}