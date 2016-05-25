import socket
import config
import sys
from OpenSSL import crypto
import os
import fileOperations
import SSLOperations

def checkcerts(connection, x509, errnum, errdepth, ok):
    if not ok:
        print(config.pcolours.WARNING + "Certificate not in trusted certs")
        return True
    else:
        return True

def verify(filename, cert, signature):
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    result = crypto.verify(cert, signature, dataFile.read(), config.digest)
    dataFile.close()
    return result

def sign(filename):
    with open(os.path.join(config.root, 'server.pkey')) as certFile:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, certFile.read(), "cits3002")
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    signature = crypto.sign(pkey, dataFile.read(), config.digest)
    dataFile.close()
    return signature
