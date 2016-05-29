import os
import socket
import config
from OpenSSL import SSL, crypto
import verify
import fileSecurity

def receive_cert(client):
    certString = ""
    try:
        data = client.recv(config.payload_size).decode()
    except SSL.SysCallError:
        data = ""
    while data != "":
        certString = certString + data
        try:
            data = client.recv(config.payload_size).decode()
        except SSL.SysCallError:
            data = ""
    print(certString)
    return crypto.load_certificate(crypto.FILETYPE_PEM, certString)

def send_file(client, filename, largestCircle):
    filePath = os.path.join(config.storage, filename)
    print(config.pcolours.OKBLUE + "filename is :" + filePath)
    sent_file = open(filePath.strip("\x00"), "rb")
    #data = "Circle of circumference " + str(largestCircle) + "\nContaining all requested names"
    #data.ljust(1024, " ")
    #client.send(data)
    data = verify.sign(filename)
    print(data)
    while data:
        try:
            client.send(data)
        except OpenSSL.SSL.SysCallError as e:
            print("Client closed connection")
        data = sent_file.read(config.payload_size)
    sent_file.close()
    print(config.pcolours.OKGREEN +"File sent")

def receive_file(client, filename, root, size):
    filePath = os.path.join(root, filename)
    print(config.pcolours.OKBLUE + "Filename is :" + filePath)
    recv_file = open(filePath.strip("\x00"), "wb+")
    # write data to file
    try:
        signature = client.recv(config.payload_size)
    except SSL.SysCallError as msg:
        print(config.pcolours.WARNING +"First frame is end of file ssl error:" + str(msg))
        return(-1)
    print(signature)
    clientCertObject = client.get_peer_certificate()
    try:
        data = client.recv(config.payload_size)
    except SSL.SysCallError:
        data = ""
    while data != "":
        recv_file.write(data)
        try:
            data = client.recv(config.payload_size)
        except SSL.SysCallError:
            data = ""
    recv_file.close()
    if verify.verify(filename, clientCertObject, signature) == True:
        print(config.pcolours.OKGREEN + "File is verified")
    else:
        print(config.pcolours.WARNING + "File could not be verified")
    fileSecurity.applySignature(filename, signature, clientCertObject)
    print(config.pcolours.OKGREEN +"File received")

def listFiles(client):
    rootDir = config.storage
    string = ""
    for dirName, subdirList, fileList in os.walk(rootDir):
        for fname in fileList:
            circles  = fileSecurity.genCircles(fname, "0")
            for circle in circles:
                circles[circles.index(circle)] = len(circle)
            circles.sort()
            if circles == []:
                circles = [0]
            string = string + '    ++    %s' % fname + "\t\t\t++    Circumference:" + str(circles[0]) + "\n"
    client.send(string)
