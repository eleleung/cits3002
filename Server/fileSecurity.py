import os
import verify
import config
import pickle
import OpenSSL

def verifyCertificate(cert, issuerCert):
    issuerCert.set_issuer(issuerCert.get_subject())
    tempTrustStore = OpenSSL.crypto.X509Store()
    tempTrustStore.add_cert(issuerCert)
    print(tempTrustStore)
    context = OpenSSL.crypto.X509StoreContext(tempTrustStore, cert)
    context.set_store(tempTrustStore)
    if context.verify_certificate() == None:
        return True
    else:
        return False

def getIssuerName(cert):
    for pair in cert.get_issuer().get_components():
            if pair[0] == b"CN":
                return pair[1].decode()

def getNextCert(name):
    with open(os.path.join(config.certs, name + ".crt"), "r") as certFile:
        certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile.read())
        with open(os.path.join(config.certs, getIssuerName(certObject) + ".crt"), "r") as nextCertFile:
            nextCertObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, nextCertFile.read())
            if verifyCertificate(certObject, nextCertObject):
                return getIssuerName(nextCertObject)
            else:
                return None

def makeCircle(name):
    circle = []
    currentCertObject = []
    with open(os.path.join(config.certs, name + ".crt"), "r") as certFile:
        firstCert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile.read())
        firstIssuer = getIssuerName(firstCert)
    i = 1
    circle.append(firstIssuer)
    cert = getNextCert(firstIssuer)
    while cert != firstIssuer:
        if cert != None:
            circle.append(cert)
        else:
            circle = None
            break
        cert = getNextCert(cert)

    print(circle)
    return circle

def genCircles(filename, minCircleSize):
    vouches = checkVouches(filename)
    circles = []
    for vouch in vouches:
        circle = makeCircle(vouch[0])
        if circle != None:
            circles.append(circle)
    return circles

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
