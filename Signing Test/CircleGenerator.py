from OpenSSL import crypto
import random
import os
import pickle

def create(numberOfCerts):
    with open("FirstNames.csv", "r") as csvFile:
        firstNames = csvFile.read().split("\n")
    with open("FirstNames.csv", "r") as csvFile:
        lastNames = csvFile.read().split("\n")
    i = 1
    if os.path.exists(os.path.join(os.getcwd(), "takenNames.pickle")):
        print("Previous list of names found")
        with open("takenNames.pickle", "rb") as nameList:
            takenNames = pickle.load(nameList)
    else:
        takenNames = []
    firstName = genName(firstNames, lastNames, takenNames)
    takenNames.append(firstName)
    firstKey = genKey(firstName)
    firstCert = genCert(firstName, firstKey, firstKey, "self", i)
    previous = {"Cert" : firstCert, "Key" : firstKey}
    while i <= numberOfCerts:
        currentName = genName(firstNames, lastNames, takenNames)
        currentKey = genKey(currentName)
        currentCert = genCert(currentName, currentKey, previous["Key"], previous["Cert"].get_subject(), i)
        previous["Cert"] = currentCert
        previous["Key"] = currentKey
        i = i + 1
        takenNames.append(currentName)
    firstCert = genCert(firstName, firstKey, currentKey, currentCert.get_subject(), 1)
    with open("takenNames.pickle", "wb+") as nameList:
        pickle.dump(takenNames, nameList)
    print(str(i - 1) + " certificates generated")
    return 0

def genKey(name):
    KEY_FILE = name + ".key"
    # Create a key pair
    k = crypto.PKey()
    # Generate Pkey with 1024bit RSA type encryption.
    k.generate_key(crypto.TYPE_RSA, 1024)
    # Write key to file
    with open(KEY_FILE, "wb+") as keyFile:
        keyFile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    return k


def genCert(name, certKey, issuerKey, issuer, i):
    CERT_FILE = name + ".crt"
    # create a signed cert
    cert = crypto.X509()
    #Filling in Certificate information.
    #countryName – The country of the entity.
    cert.get_subject().C = "AU"
    #stateOrProvinceName – The state or province of the entity.
    cert.get_subject().ST = "WA"
    #localityName – The locality of the entity.
    cert.get_subject().L = "Perth"
    #organizationName – The organization name of the entity.
    cert.get_subject().O = "UWA"
    #organizationalUnitName – The organizational unit of the entity.
    cert.get_subject().OU = "CITS3002"
    #commonName – The common name of the entity.
    cert.get_subject().CN = name
    cert.set_pubkey(certKey)

    #Setting the serial number of the certificate
    cert.set_serial_number(100 + 1 + i)

    #Set expiration date of Certificate to be in 10 years time.
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    if issuer == "self":
        cert.set_issuer(cert.get_subject())
    else:
        cert.set_issuer(issuer)
    cert.set_pubkey(certKey)
    cert.sign(issuerKey, "sha256")
    with open(CERT_FILE, "wb+") as certFile:
        certFile.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    return cert

def genName(firstNames, lastNames, takenNames):
    fullname = firstNames[random.randint(0, len(firstNames)-1)] + lastNames[random.randint(0, len(lastNames)-1)]
    if fullname in takenNames:
        fullname = genName(takenNames)
    return fullname
