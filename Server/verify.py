import socket
import config
import sys
from OpenSSL import crypto
import os
import fileOperations
import SSLOperations

def checkcerts(connection, x509, errnum, errdepth, ok):
    if not ok:
        return False
    else:
        return True


def verify(filename, cert, signature):
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    result = crypto.verify(cert, signature, dataFile.read(), config.digest)
    dataFile.close()
    return result

def sign(filename, pkey):
    filePath = os.path.join(config.storage, filename)
    dataFile = open(filePath.strip("\x00"), "rb")
    signature = crypto.verify(cert, signature, dataFile.read(), config.digest)
    return signature
