import os
import socket
import config
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
    try:
        result = crypto.verify(cert, signature, dataFile.read(), config.digest)
    except OpenSSL.crypto.Error:
        result = True
    dataFile.close()
    print(result)
    if result == None:
        return True
    else:
        return False

def sign(filename):
    with open(os.path.join(config.root, 'server.pkey')) as certFile:
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, certFile.read())
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    signature = crypto.sign(pkey, dataFile.read(), config.digest)
    with open("sig.txt", "wb+") as sig:
        sig.write(signature)
    dataFile.close()
    with open(os.path.join(config.root, 'server.cert')) as certFile:
        print(verify(filename, crypto.load_certificate(crypto.FILETYPE_PEM, certFile.read()), signature))
    return signature
