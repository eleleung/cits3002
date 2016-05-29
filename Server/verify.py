######################################
#   CITS3002 PROJECT PARTICIPANTS:   #
#------------------------------------#
# Eleanor Leung   |	    21149831     #
# Aiden Ziegelaar |     21333223     #
# Matthew Cooper  |     20933403     #
######################################

import os
import socket
import config
import OpenSSL
from OpenSSL import crypto
import os
import fileOperations
import SSLOperations

# workaround for untrusted certs
def checkcerts(connection, x509, errnum, errdepth, ok):
    if not ok:
        return True
    else:
        return True

# verify a signature
def verify(filename, cert, signature):
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    try:
        result = crypto.verify(cert, signature, dataFile.read(), config.digest)
    except OpenSSL.crypto.Error:
        result = True
    dataFile.close()
    if result == None:
        return True
    else:
        return False

# sign a file
def sign(filename):
    with open(os.path.join(config.root, 'server.pkey')) as certFile:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, certFile.read())
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    data = dataFile.read()
    print(data)
    signature = crypto.sign(pkey, dataFile.read(), config.digest)
    print(data)
    with open("sig.txt", "wb+") as sig:
        sig.write(signature)
    dataFile.close()
    with open(os.path.join(config.root, 'server.cert')) as certFile:
        print(verify(filename, crypto.load_certificate(crypto.FILETYPE_PEM, certFile.read()), signature))
    return signature
