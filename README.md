# cits3002

## A Secure File Server

The following commands are valid inputs:
* -a filename 		: add or replace a file on the oldtrusty server
* -c number 		: provide the required circumference (length) of a circle of trust
* -f filename 		: fetch an existing file from the oldtrusty server (simply sent to stdout)
* -h hostname:port 	: provide the remote address hosting the oldtrusty server
* -l 			: list all stored files and how they are protected
* -n name 		: require a circle of trust to involve the named person (i.e. their certificate)
* -u certificate 	: upload a certificate to the oldtrusty server
* -v filename certificate: vouch for the authenticity of an existing file in the oldtrusty server using the indicated certificate

## The Python Server

For the python server some dependencies have to be met:
* Python 3.x.x must be installed
* pip3 must be installed (most pkg-managers refer to this as python3-pip)
* OpenSSL must be installed with the header packages

Before the first run of the server run setup.py in the /Server/ subdirectory, this will install pyOpenSSL in an external_modules folder for those without root access.

The server is started by running server.py from the /Server/ subdirectory
