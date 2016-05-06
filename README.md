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
* -v filename certificate: vouch for the authenticity of an existing file in the oldtrusty server using the indicated certificate

## The Circle Of Trust Model

A circle of certificates are generated much the same as a chain of certificates. The main difference is instead of forming a heirarchy the initial certificate that was self signed is replaced by a certificate signed by the last member of the chain hence forming a circle. 

Files are verified by a member of a circle of trust vouching for that file. If one member vouches for it then, given that everyone in the circle trusts everyone else, the file is considered verfied by a circle with a circumference equal to the number of members in the circle. 

This provides us with two metrics; one is the total number of people who have vouched for the file, and the second is the circumference of the circle of people who indirectly trust that file. 

Considerations for trust:
* How to associate a given client with an already uploaded certificate?
* Should only members of the circle be allowed to donload files? 
 

