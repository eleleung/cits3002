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

#define SERVERPORT 	"1234" // the port client will be connecting to

#define BUFSIZE 1024 // max no. of bytes we can get at once
#define MAXSTR 20 
#define MAXLEN 1024

#define RED 		"\033[31m" 
#define RESET 		"\033[0m"
#define GREEN 		"\033[32m" 
#define MAGENTA 	"\x1b[35m"
#define CYAN    	"\x1b[36m"
#define BLUE 		"\x1b[34m"

// global variables
extern int optopt, optind;

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
			fprintf(stderr, RED "Error: Socket is not connected%s\n", RESET);
			//perror(RED "Error" RESET);
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

	// read file into buffer and send buffer to server
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
	int nbytes;

	// receiving file name
	printf(BLUE "Client receiving %s from the Server...%s\n", RESET, filenm);
	SSL_write(ssl, filenm, strlen(filenm));

	FILE *fp = fopen(filenm, "w"); // a or w?
	if (fp == NULL) {
		fprintf(stderr, RED "File %s can't be opened\n" RESET, filenm);
		return EXIT_SUCCESS;
	}

	bzero(buffer, BUFSIZE);
	// read file from server and write to file
	while ((nbytes = SSL_read(ssl, buffer, BUFSIZE)) > 0) {
		// fetch to stdout
		fprintf(stdout, BLUE "%s%s", buffer, RESET);
		// if 0 then 
		int writebytes = fwrite(buffer, sizeof(char), nbytes, fp);
		if (writebytes < nbytes) {
			fprintf(stderr, RED "File write failed\n" RESET);
		}
		bzero(buffer, BUFSIZE);
		if (nbytes == 0) {
			fprintf(stderr, RED "No file found\n" RESET);
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
void load_cert(SSL_CTX *ctx, char *cert, char *key) {
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

// debugging print
void print_bytes(const void *object, size_t size)
{
  const unsigned char * const bytes = object;

  printf("[ ");
  int count = 0;
  while(bytes[count])
  {
    printf("%02x ", bytes[count]);
    count++;
  }
  printf("]\n");
}

int evp_sign(SSL *ssl, char *rsa_pkey, char *filename) {
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	FILE *file = fopen(filename, "rb");
	FILE *rsa_pkey_file = fopen(rsa_pkey, "rb");

	EVP_PKEY * pkey = PEM_read_PrivateKey(rsa_pkey_file, NULL, NULL, NULL);
	if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}
	
	unsigned char *sign = malloc(EVP_PKEY_size(pkey));
	unsigned int sign_len = EVP_PKEY_size(pkey);
	if (!sign) {
		fprintf(stderr, RED "Error: Couldn't malloc memory%s\n", RESET);
		EVP_PKEY_free(pkey);
		return EXIT_FAILURE;
	}

	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (!EVP_SignInit(md_ctx, EVP_sha256())) {
		fprintf(stderr, "Error: EVP_SignInit failed%s\n", RESET);
		EVP_PKEY_free(pkey);
		return EXIT_FAILURE;
	}

	// read in data in sizes of BUFSIZE to generate signature
	unsigned char *data = malloc(BUFSIZE);
	int data_len = fread(data, sizeof(char), BUFSIZE, file);
	if (!data) {
		fprintf(stderr, RED "Error: Couldn't malloc memory%s\n", RESET);
		EVP_PKEY_free(pkey);
		return EXIT_FAILURE;
	}	

	// update signature 
	while (data_len > 0) {
		if (!EVP_SignUpdate(md_ctx, data, data_len)) {
			fprintf(stderr, "Error: EVP_SignUpdate failed%s\n", RESET);
			EVP_PKEY_free(pkey);
			return EXIT_FAILURE;
		}
		data_len = fread(data, sizeof(char), BUFSIZE, file);
	}

	// finalise signing operation
	if (!EVP_SignFinal(md_ctx, sign, &sign_len, pkey)) {
		fprintf(stderr, "Error: EVP_SignFinal failed%s\n", RESET);
		EVP_PKEY_free(pkey);
		return EXIT_FAILURE;
	}
	print_bytes(sign, sizeof(sign));

	// send signature to server
	if ((SSL_write(ssl, sign, (int)sign_len)) < 0) {
		fprintf(stderr, RED "Error: failed to send signature\n" RESET);
		return EXIT_FAILURE;
	}

	EVP_MD_CTX_destroy(md_ctx);
	free(sign);
	free(data);

	return EXIT_SUCCESS;
}

char * concat(char *command, char *filename) {
	char *cmd_and_file;
	int length = strlen(command)+strlen(filename)+1;

	if ((cmd_and_file = malloc(length)) != NULL) {
		bzero(cmd_and_file, (length));
		strcat(cmd_and_file, command);
		strcat(cmd_and_file, filename);
	}
	else {
		fprintf(stderr, RED "Malloc Failed %s\n", RESET);
		free(cmd_and_file);
		return "Error\n";
	}
	return cmd_and_file;
}

void expect_confirm(SSL *ssl) {
	char confirm[BUFSIZE];
	bzero(confirm, BUFSIZE);
	int nbytes;

	while ((nbytes = SSL_read(ssl, confirm, BUFSIZE)) > 0) {
		fprintf(stdout, MAGENTA "%s%s", confirm, RESET);
	}
	if (nbytes <= 0) {
		fprintf(stderr, RED "Nothing from server%s\n", RESET);
	}
}

int add_or_replace(SSL *ssl, char *command, char *rsa_pkey, char *filename) {
	printf(CYAN "%s %s\n", filename, RESET);

	// concat. command and filename
	char *cmd_and_file = concat(command, filename);
	int length = strlen(cmd_and_file)+1;

	// send command+filename to server
	if ((SSL_write(ssl, cmd_and_file, length)) < 0) {
		fprintf(stderr, RED "Error: failed to send file\n" RESET);
		free(cmd_and_file);
		return EXIT_FAILURE;
	}

	// debug print
	printf(MAGENTA "Command and filename successfully sent!%s\n", RESET);

	// receive confirmation from server
	expect_confirm(ssl);

	// sign file - need strlen of file to be sent
	if ((evp_sign(ssl, rsa_pkey, filename)) != 0) {
		fprintf(stderr, RED "Error: Failed to sign file%s\n", RESET);
		free(cmd_and_file);
		return EXIT_FAILURE;
	}

	// write file to server
	write_file_to_server(ssl, filename);

	free(cmd_and_file);
	return EXIT_SUCCESS;
}

int fetch(SSL *ssl, char *command, char *filename, char *circleNum, char *vouchName) {
	printf(CYAN "%s %s\n", filename, RESET);

	// concat. command and filename
	char *string1 = concat(command, filename);
	char *string2 = concat(string1, " -c ");
	char *string3 = concat(string2, circleNum);
	char *string4 = concat(string3, " -n ");
	char *cmd_and_file = concat(string4, vouchName);

	printf("%s\n",cmd_and_file);
	
	int length = strlen(cmd_and_file)+1;

	// send command+filename to server
	if ((SSL_write(ssl, cmd_and_file, length)) < 0) {
		fprintf(stderr, RED "Error: failed to send file\n" RESET);
		free(cmd_and_file);
		return EXIT_FAILURE;
	}

	// debug print
	printf(MAGENTA "Command and filename successfully sent!%s\n", RESET);

	// receive confirmation from server
	expect_confirm(ssl);

	// need to change to stdout
	read_file_from_server(ssl, filename);
	
	free(string1);
	free(string2);
	free(string3);
	free(string4);
	free(cmd_and_file);
	return EXIT_SUCCESS;
}

int list(SSL *ssl, char *command) {
	printf(CYAN "list all files %s \n", RESET);
	int length = strlen(command)+1;

	// send to server
	if ((SSL_write(ssl, command, length)) < 0) {
		fprintf(stderr, RED "Error: failed to send command\n" RESET);
		return EXIT_FAILURE;
	}

	// receive confirmation from server - not restricted to 1024
	expect_confirm(ssl);

	free(command);
	return EXIT_SUCCESS;
}

int upload_cert(SSL *ssl, char *command, char *cert) {
	printf(CYAN "%s %s\n", cert, RESET);

	// concat. command and filename
	char *cmd_and_cert = concat(command, cert);
	int length = strlen(cmd_and_cert)+1;

	// send command+filename to server
	if ((SSL_write(ssl, cmd_and_cert, length)) < 0) {
		fprintf(stderr, RED "Error: failed to send file\n" RESET);
		free(cmd_and_cert);
		return EXIT_FAILURE;
	}

	// debug print
	printf(MAGENTA "Command and cert successfully sent!%s\n", RESET);

	// receive confirmation from server
	expect_confirm(ssl);

	// write cert to server
	write_file_to_server(ssl, cert);

	free(cmd_and_cert);
	return EXIT_SUCCESS;
}

// fetch and then send signature
int vouch_file(SSL *ssl, char *command, char *filename, char *rsa_pkey, char *cert) {
	printf(CYAN "%s %s %s\n", filename, cert, RESET);

	// send concat-ed string
	// snprintf(prefix, sizeof(prefix), "%s: %s: %s", argv[0], cmd_argv[0], cmd_argv[1]);
	char *cmd_and_file;
	int length = strlen(command)+strlen(filename)+strlen(cert)+1;

	if ((cmd_and_file = malloc(length)) != NULL) {
		bzero(cmd_and_file, (length));
		strcat(cmd_and_file, command);
		strcat(cmd_and_file, filename);
		strcat(cmd_and_file, " ");
		strcat(cmd_and_file, cert);
	}
	else {
		fprintf(stderr, RED "Malloc Failed %s\n", RESET);
		free(cmd_and_file);
		// exit
	}

	// send to server
	if ((SSL_write(ssl, cmd_and_file, length)) < 0) {
		fprintf(stderr, RED "Error: failed to send command\n" RESET);
		free(cmd_and_file);
		return EXIT_FAILURE;
	}

	// debug print
	printf(MAGENTA "Command and filename successfully sent!%s\n", RESET);

	read_file_from_server(ssl, filename);

	// call -u and upload cert
	//SSL_write(ssl, "-u", strlen("-u")+1);
	//write_file_to_server(ssl, cert);

	// sign file - need strlen of file to be sent
	//BOOLEAN flag = TRUE;
	if ((evp_sign(ssl, rsa_pkey, filename)) != 0) {
		fprintf(stderr, RED "Error: Failed to sign file%s\n", RESET);
		free(cmd_and_file);
		return EXIT_FAILURE;
	}

	// receive confirmation from server
	expect_confirm(ssl);

	free(cmd_and_file);
	return EXIT_SUCCESS;
}

int main(int argc, char * argv[]) {
	int sockfd, opt = 0, count = 0;
	char filename[100], cert[100], host[255]; // or char *host = malloc(strlen(host)+1);
	char command[MAXSTR][2];
	char paramValue[MAXSTR][MAXLEN] = {{0}};
	char circleNum[MAXSTR][MAXLEN] = {{0}};
	char vouchName[MAXSTR][MAXLEN] = {{0}};
	
	// Initialise OpenSSL and cert
	SSL_CTX *ctx;
	SSL *ssl;
	SSL_library_init(); // load SSL encrpytion & hash algorithms
	ctx = init_cert();
	load_cert(ctx, "mycert.pem", "mykey.pem");

	while ((opt = getopt(argc, argv, "a:c:f:h:ln:s:u:v:")) != -1) {
		switch(opt) {
			case 'a': 
				if ((add_or_replace(ssl, "-a ", "mykey.pem", optarg)) != 0) {
					fprintf(stderr, RED "-a command failed %s\n", RESET);
					break;
				}
				printf(CYAN "-a successful%s\n", RESET);
				break;
			case 'c':
				strcpy(circleNum[count], "0");
				strcpy(circleNum[count], optarg);
				break;
			case 'f':
				count++;
				command[count][0] = opt;
				strcpy(paramValue[count], optarg);
				break;
			case 'h': // flaw because it needs to be first thing sent
				strcpy(host, optarg);
				printf(CYAN "%s %s\n", host, RESET);
				
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
				printf(GREEN "Connected with %s encryption %s\n", SSL_get_cipher(ssl), RESET);
				break;
			case 'l':
				if ((list(ssl, "l")) != 0) {
					fprintf(stderr, RED "-l command failed %s\n", RESET);
					break;
				}
				printf(CYAN "-l successful%s\n", RESET);
				break;
			case 'n':
				strcpy(vouchName[count], "");
				strcpy(vouchName[count], optarg);
				break;
			case 'u':
				if ((upload_cert(ssl, "-u ", optarg)) != 0) {
					fprintf(stderr, RED "-u command failed %s\n", RESET);
					break;
				}
				printf(CYAN "-u successful%s\n", RESET);				
				break;
			case 'v':
				strcpy(filename, optarg);
				// make getopt search for 2 args for -v
				if (optind < argc && *argv[optind] != '-') {
					strcpy(cert, argv[optind]);
					optind++;
				}
				else {
					fprintf(stderr, "-v command requires two arguments\n");
					break;
				}
				if ((vouch_file(ssl, "-v", filename, "clientkey.pem", cert)) != 0) {
					fprintf(stderr, RED "-v command failed %s\n", RESET);
					break;
				}
				printf(CYAN "-v successful%s\n", RESET);
				break;
			default:
				printf(CYAN "Usage: %s\n", RESET);
		}
	}
	for (int i = 0; i <= count; i++) {
		switch(command[i][0]) {
			case 'f':
			 	if ((fetch(ssl, "-f ", paramValue[i], circleNum[i], vouchName[i])) != 0) {
					fprintf(stderr, RED "-f command failed %s\n", RESET);
					break;
				}
				printf(CYAN "-f successful %s\n", RESET);
				break;
		}
	}

	// shut down socket
	shutdown(sockfd, SHUT_RDWR);

	// close connection
	close(sockfd);
	SSL_CTX_free(ctx);
	SSL_free(ssl); 

	return EXIT_SUCCESS;
}
