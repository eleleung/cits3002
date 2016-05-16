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
#include <getopt.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define SERVERPORT 	"3434" // the port client will be connecting to

#define BUFSIZE 1024 // max no. of bytes we can get at once

#define RED 		"\033[31m" 
#define RESET 		"\033[0m"
#define GREEN 		"\033[32m" 
#define MAGENTA 	"\x1b[35m"
#define CYAN    	"\x1b[36m"
#define BLUE 		"\x1b[34m"

// global variables
extern int optopt, optind;

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
	printf(GREEN "Client connected to %s%s\n", s, RESET);

	freeaddrinfo(addr);
	return(sockfd);
}

// Send file to server
int write_file_to_server(SSL *ssl, const char filenm[]) {
	char buffer[BUFSIZE];
	int nbytes;

	// Check you can open file
	FILE *fp = fopen(filenm, "rb");
	if (fp == NULL) {
		fprintf(stderr, RED "File %s not found\n" RESET, filenm);
		return EXIT_FAILURE;
	}

	// send file name
	printf(BLUE "Client sending %s to the Server...%s\n", filenm, RESET);
	SSL_write(ssl, filenm, strlen(filenm));

	bzero(buffer, BUFSIZE);
	while ((nbytes = fread(buffer, sizeof(char), BUFSIZE, fp)) > 0) {
		if ((SSL_write(ssl, buffer, nbytes)) < 0) {
			fprintf(stderr, RED "Error: failed to send file\n" RESET);
			return EXIT_FAILURE;
		}
	}
	fclose(fp);
	printf(BLUE "File sent...%s\n", RESET);
	return EXIT_SUCCESS;
}

// Read file from server
int read_file_from_server(SSL *ssl, const char filenm[]) {
	char buffer[BUFSIZE];

	// receiving file name
	printf(BLUE "Client receiving %s from the Server...%s\n", RESET, filenm);
	SSL_write(ssl, filenm, strlen(filenm));

	FILE *fp = fopen(filenm, "a"); // a or w?
	if (fp == NULL) {
		fprintf(stderr, RED "File %s can't be opened\n" RESET, filenm);
		return EXIT_SUCCESS;
	}

	bzero(buffer, BUFSIZE);
	int nbytes;
	while ((nbytes = SSL_read(ssl, buffer, BUFSIZE)) > 0) {
		int writebytes = fwrite(buffer, sizeof(char), nbytes, fp);
		if (writebytes < nbytes) {
			fprintf(stderr, RED "File write failed\n" RESET);
		}
		bzero(buffer, BUFSIZE);
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
void load_cert(SSL_CTX * ctx, char * cert, char * key) {
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

int main(int argc, char * argv[]) {
	int sockfd, opt = 0;
	char buf[BUFSIZE];
	char verify[100], veri[100], host[255]; // or char *host = malloc(strlen(host)+1);
	SSL_CTX *ctx;
	SSL *ssl;
	
	while ((opt = getopt(argc, argv, "a:c:f:h:ln:u:v:")) != -1) {
		switch(opt) {
			case 'a': 
				printf(CYAN "%s %s\n", optarg, RESET);
				break;
			case 'c':
				printf(CYAN "%s %s\n", optarg, RESET);
				break;
			case 'f':
				printf(CYAN "%s %s\n", optarg, RESET);
				break;
			case 'h':
				strcpy(host, optarg);
				printf(CYAN "%s %s\n", optarg, RESET);
				break;
			case 'l':
				printf(CYAN "list all files %s \n", RESET);
				break;
			case 'n':
				printf(CYAN "%s %s\n", optarg, RESET);
				break;
			case 'u':
				printf(CYAN "%s %s\n", optarg, RESET);
				break;
			case 'v':
				strcpy(verify, optarg);
				if (optind < argc && *argv[optind] != '-') {
					strcpy(veri, argv[optind]);
					optind++;
				}
				else {
					fprintf(stderr, "-v command requires two arguments\n");
				}
				printf(CYAN "%s %s %s\n", verify, veri, RESET);
				break;
			default:
				printf(MAGENTA "Usage: %s\n", RESET);
		}
	}

	// Initialise OpenSSL and cert
	SSL_library_init(); // load SSL encrpytion & hash algorithms
	ctx = init_cert();
	load_cert(ctx, "clientcert.pem", "clientkey.pem");

	// call to create and connect socket
	if ((sockfd = connect_socket(host, SERVERPORT)) < 0) {
		return EXIT_FAILURE;
	}
	
	// create new SSL connection state
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if (SSL_connect(ssl) == -1) { 	
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	// read_file_from_server(ssl, sockfd, "bookcpy.txt");
	printf(GREEN "Connected with %sencryption %s\n", RESET, SSL_get_cipher(ssl));
	// ShowCerts(ssl);
	write_file_to_server(ssl, "test.txt"); 
	
	// shut down socket
	shutdown(sockfd, SHUT_RDWR);

	// close connection
	close(sockfd);
	SSL_CTX_free(ctx);
	SSL_free(ssl); 
	
	return EXIT_SUCCESS;
}
