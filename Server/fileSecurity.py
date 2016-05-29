######################################
#   CITS3002 PROJECT PARTICIPANTS:   #
#------------------------------------#
# Eleanor Leung   |	    21149831     #
# Aiden Ziegelaar |     21333223     #
# Matthew Cooper  |     20933403     #
######################################

import os
import verify
import config
import pickle
import OpenSSL

# verify one certificate with another
def verifyCertificate(cert, issuerCert):
    # set issuer to self to make certificate psudo CA
    issuerCert.set_issuer(issuerCert.get_subject())
    # create store and context
    tempTrustStore = OpenSSL.crypto.X509Store()
    tempTrustStore.add_cert(issuerCert)
    context = OpenSSL.crypto.X509StoreContext(tempTrustStore, cert)
    context.set_store(tempTrustStore)
    # verify the certificate in the context with the specified trusted store containing the psudo CA
    if context.verify_certificate() == None:
        return True
    else:
        return False

# get the name of the issuer of a cert
def getIssuerName(cert):
    for pair in cert.get_issuer().get_components():
            if pair[0] == b"CN":
                return pair[1].decode()

# get the issuer of a cert, returns the cert of the issuer
def getNextCert(name):
    # open cert by name
    with open(os.path.join(config.certs, name + ".crt"), "r") as certFile:
        certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile.read())
        # open cert by issuer name
        with open(os.path.join(config.certs, getIssuerName(certObject) + ".crt"), "r") as nextCertFile:
            nextCertObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, nextCertFile.read())
            # verify the issuer signs the cert
            if verifyCertificate(certObject, nextCertObject):
                # return the name of the issuer
                return getIssuerName(nextCertObject)
            else:
                return None
# make a list of names of certificates that verify each other
def makeCircle(name):
    circle = []
    currentCertObject = []
    with open(os.path.join(config.certs, name + ".crt"), "r") as certFile:
        firstCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile.read())
        firstIssuer = getIssuerName(firstCert)
    i = 1
    circle.append(firstIssuer)
    cert = getNextCert(firstIssuer)
    # while unique certs in loop append name to circle
    while cert != firstIssuer:
        if cert != None:
            circle.append(cert)
        else:
            circle = None
            break
        cert = getNextCert(cert)
    return circle

# generate a list of circles, returns list
def genCircles(filename, minCircleSize):
    if minCircleSize == "-n":
        minCircleSize = 0
    vouches = checkVouches(filename)
    circles = []
    for vouch in vouches:
        circle = makeCircle(vouch[0])
        if circle != None:
            if len(circle) >= int(minCircleSize):
                circles.append(circle)
    return circles

# vouch for a file on the server
def applySignature(filename, signature, cert):
    previousVouches = []
    result = verify.verify(filename, cert, signature)
    if result:
        previousVouches = checkVouches(filename)
        for pair in cert.get_subject().get_components():
            if b'CN' == pair[0]:
                previousVouches.append([pair[1].decode(), signature])
        with open(os.path.join(config.certs, filename + ".pickle"), "wb+") as vouchFile:
            pickle.dump(previousVouches, vouchFile)
    else:
        print(config.pcolours.FAIL + "File has changed since signing")
        return -1
    return 0

# check for previous vouches on a file in the server
def checkVouches(filename):
    if os.path.exists(os.path.join(config.certs, filename + ".pickle")):
        with open(os.path.join(config.certs, filename + ".pickle"), "rb") as vouchFile:
            vouchList = list(pickle.load(vouchFile))
            print(vouchList)
            for vouch in vouchList:
                with open(os.path.join(config.certs, vouch[0] + ".crt"), "r") as certFile:
                    certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile.read())
                    validity = verify.verify(filename, certObject, vouch[1])
                    if validity == False:
                        vouchList.remove(vouch)
            if vouchList == None:
                vouchList = []
            return vouchList
    else:
            return []
