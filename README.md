# cits3002

## A Secure File Server

This project needs to create a file server/client pair that uses ssl for encryption. 

The following commands need to be implemented:
* -a filename 		: add or replace a file on the oldtrusty server
* -c number 		: provide the required circumference (length) of a circle of trust
* -f filename 		: fetch an existing file from the oldtrusty server (simply sent to stdout)
* -h hostname:port 	: provide the remote address hosting the oldtrusty server
* -l 			: list all stored files and how they are protected
* -n name 		: require a circle of trust to involve the named person (i.e. their certificate)
* -u certificate 	: upload a certificate to the oldtrusty server
*-v filename certificate: vouch for the authenticity of an existing file in the oldtrusty server using the indicated certificate
