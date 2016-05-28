import os
import verify
import config
import pickle
import OpenSSL

def makeCircle(name):

    currentCertObject = []
    with open(os.path.join(config.certs, name + ".cert"), "r") as certFile:
        firstCertObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)
        firstIssuer = "test"
    while firstCertObject != currentCertObject:
        with open(os.path.join(config.certs,  + ".cert"), "r") as certFile:
            certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)
            for pair in certObject.get_issuer().get_subject():
                    if pair[0] == "CN":
                        with open(os.path.join(config.certs, vouch[0] + ".crt"), "r") as nextCertFile:
                            nextCertObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)

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
            if pair[0] == "CN":
                previousVouches.append([pair[0], signature])
        with open(filename + ".pickle", "wb+") as vouchFile:
            pickle.dump(previousVouches)
    else:
        print(config.pcolours.FAIL + "File has changed since signing")

def checkVouches(filename):
    if os.path.exists(os.path.join(config.certs, filename + ".pickle")):
        with open(filename + ".pickle", "rb") as vouchFile:
            vouchList = pickle.load(nameList)
            for vouch in vouchList:
                with open(os.path.join(config.certs, vouch[0] + ".crt"), "r") as certFile:
                    certObject = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certFile)
                    vailidity = verify.verify(filename, certObject, vouch[1])
                    if validity == False:
                        vouchList = vouchList.remove(vouch)
            return vouchList
    else:
            return []
