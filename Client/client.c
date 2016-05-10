/* client.c -- stream socket 
** Ele Leung (21149831) 2/05/16 
*/

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define SERVERPORT "3434" // the port client will be connecting to

#define BUFSIZE 1024 // max no. of bytes we can get at once

#define RED 	"\033[31m" 
#define RESET 	"\033[0m"
#define GREEN 	"\033[32m" 

// void debug_print(char *function, char *message)

// get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Function to connect socket
int connect_socket(const char *host, const char *port) {
	int x, sockfd;
	struct addrinfo hints, *addr, *p;
	char s[INET6_ADDRSTRLEN]; 

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((x = getaddrinfo(host, port, &hints, &addr)) != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(x));
		return -1;
	}

	// Step through linked list of results and connect to first possible
	for (p = addr; p != NULL; p = p->ai_next) {
		
		if ((sockfd = socket(p->ai_family, p->ai_socktype, 
			p->ai_protocol)) == -1) {
			perror(RED "Error: Opening socket\n" RESET);
			continue;
		}
		
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			shutdown(sockfd, SHUT_RDWR);
			close(sockfd);
			perror(RED "Error" RESET);
			continue;
		}
		
		break;
	}

	if (p == NULL) {
		fprintf(stderr, RED "Error: Client failed to connect\n" RESET);
		return -1;
	}

	// convert IP address to readable form
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s,
		sizeof(s));

	// check connection
	printf(GREEN "Client connected to %s\n" RESET, s);

	freeaddrinfo(addr);
	return(sockfd);
}

// Send file to server - change so you read to buffer then SSL_WRITE
int write_file_to_server(int sockfd, const char filenm[]) {
	char buffer[BUFSIZE];
	int nbytes;

	// Check you can open file
	printf("Client sending %s to the Server...\n", filenm);
	FILE *fp = fopen(filenm, "r");
	if (fp == NULL) {
		fprintf(stderr, RED "File %s not found\n" RESET, filenm);
		return EXIT_FAILURE;
	}

	bzero(buffer, BUFSIZE); // or memset?
	while ((nbytes = fread(buffer, sizeof(char), BUFSIZE, fp)) > 0) {
		if ((send(sockfd, buffer, nbytes, 0)) < 0) {
			fprintf(stderr, RED "Error: failed to send file\n" RESET);
			return EXIT_FAILURE;
		}
	}
	printf("File sent...\n");
	return EXIT_SUCCESS;
}

// Read file from server
int read_file_from_server(int sockfd, const char filenm[]) {
	char buffer[BUFSIZE];

	printf("Client receiving %s from the Server...\n", filenm);
	FILE *fp = fopen(filenm, "a"); // a or w?
	if (fp == NULL) {
		fprintf(stderr, RED "File %s can't be opened\n" RESET, filenm);
		return EXIT_SUCCESS;
	}
	bzero(buffer, BUFSIZE);
	int nbytes;
	while ((nbytes = recv(sockfd, buffer, BUFSIZE, 0)) > 0) {
		int writebytes = fwrite(buffer, sizeof(char), nbytes, fp);
		if (writebytes < nbytes) {
			fprintf(stderr, RED "File write failed\n" RESET);
		}
		// bzero(buffer, BUFSIZE);
		if (nbytes == 0) {
			break;
		}
	}
	if (nbytes < 0) {
		fprintf(stderr, RED "Can't read from socket\n" RESET);
		fclose(fp);
		return EXIT_FAILURE;
	}
	printf(GREEN "File successfully received\n" RESET);
	fclose(fp);

	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
	return EXIT_SUCCESS;
}

// Initialise OpenSSL
SSL_CTX * init_cert(void) {
	SSL_CTX *ctx;

	SSL_load_error_strings(); // load the error strings for good error reporting
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    
    // initilise SSL context and load keys
    ctx = SSL_CTX_new(SSLv3_method());
    if (ctx == NULL) {
        fprintf(stderr, RED "Failure getting SSL context" RESET);
    }
    return ctx;
}

// load certificate and keys
void loadCert(SSL_CTX * ctx, char * cert, char * key) {
	// load local cert 
	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
	}
	// or SSL_CTX_use_PrivateKey_file
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
    {
        ERR_print_errors_fp(stderr);
    }
    // check private key
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        ERR_print_errors_fp(stderr);
    }
}

// show certs?

int main(int argc, char * argv[]) {
	int sockfd;
	unsigned char msg;
	char buf[BUFSIZE];
	char menu[BUFSIZE];
	SSL_CTX *ctx;
	SSL *ssl;

	// Initialise OpenSSL and cert
	SSL_library_init(); // load SSL encrpytion & hash algorithms
	ctx = init_cert();
	loadCert(ctx, "clientcert.pem", "clientkey.pem");

	if (argc != 2) {
		fprintf(stderr, RED "Usage: server hostname\n" RESET);
		return EXIT_FAILURE;
	}

	// call to create and connect socket
	if ((sockfd = connect_socket(argv[1], SERVERPORT)) < 0) {
		//perror("Error: Connection!!!\n"); // change to if == 0, 
		return EXIT_FAILURE;
	}

	// create new SSL connection state
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if (SSL_connect(ssl) == -1) { 	
		ERR_print_errors_fp(stderr);
	}

	// read_file_from_server(ssl, sockfd, "bookcpy.txt");
	printf(GREEN "Connected with %s encryption\n" RESET, SSL_get_cipher(ssl));
	// ShowCerts(ssl);
	write_file_to_server(sockfd, "insta.jpg"); 

	SSL_free(ssl); 

	// get message line from user
	printf("Please enter msg: ");
	memset(buf, '\0', BUFSIZE);
	fgets(buf, BUFSIZE, stdin);

	// send message line to the server - rmv newline char?
	msg = SSL_write(ssl, buf, strlen(buf));
	if (msg < 0) {
		perror(RED "Error: Writing to socket\n" RESET);
	}

	// print server's reply
	memset(buf, '\0', BUFSIZE);
	msg = SSL_read(ssl, buf, BUFSIZE);
	if (msg < 0) {
		perror(RED "Error: Reading from socket\n" RESET);
	}
	printf("\nEcho from server: %s\n", buf);
	
	// shut down socket
	shutdown(sockfd, SHUT_RDWR);
	// close connection
	close(sockfd);
	SSL_CTX_free(ctx);

	return EXIT_SUCCESS;
}


