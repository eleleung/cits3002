import os
import verify
import config
import pickle
import OpenSSL

def getIssuerName(cert):
    for pair in cert.get_issuer().get_subject():
            if pair[0] == "CN":
                return pair[0]

def getNextCert(name):
    with open(os.path.join(config.certs, name + ".cert"), "r") as certFile:
        certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)
        with open(os.path.join(config.certs, getIssuerName() + ".crt"), "r") as nextCertFile:
            nextCertObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)
            #crypto.verify(nextCertObject,certObject.gety_si certObject.get_name_hash(),
        return getIssuerName(nextCertObject)

def makeCircle(name):
    circle = []
    currentCertObject = []
    with open(os.path.join(config.certs, name + ".cert"), "r") as certFile:
        firstCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)
        issuer = getIssuerName(firstCert)
    i = 1
    circle.append(issuer)
    cert = getNextCert(issuer)
    while cert != firstCertName:
        cert = getNextCert(cert)
        circle.append(cert)
    return circle

def genCircles(filename, minCircleSize):
    vouches = checkVouches(filename)
    circles = []
    return[[1,1,1,1,1,1]]
    for vouch in vouches:
        circles.append(makeCircle(vouch[0]))

def applySignature(filename, signature, cert):
    previousVouches = []
    result = verify.verify(filename, cert, signature)
    if result:
        previousVouches = checkVouches(filename)
        for pair in cert.get_subject().get_components():
            if b'CN' == pair[0]:
                previousVouches.append([pair[1].decode(), signature])
            print(pair)
        with open(os.path.join(config.certs, filename + ".pickle"), "wb+") as vouchFile:
            pickle.dump(previousVouches, vouchFile)
    else:
        print(config.pcolours.FAIL + "File has changed since signing")

def checkVouches(filename):
    if os.path.exists(os.path.join(config.certs, filename + ".pickle")):
        with open(os.path.join(config.certs, filename + ".pickle"), "rb") as vouchFile:
            vouchList = pickle.load(vouchFile)
            for vouch in vouchList:
                with open(os.path.join(config.certs, vouch[0] + ".crt"), "r") as certFile:
                    certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile.read())
                    validity = verify.verify(filename, certObject, vouch[1])
                    if validity == False:
                        vouchList = vouchList.remove(vouch)
            print(vouchList)
            return vouchList
    else:
            return []
