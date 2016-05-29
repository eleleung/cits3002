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
from OpenSSL import SSL, crypto
import verify
import fileSecurity

# receive a string from the client and load it as a cert, returns the x509 object
def receive_cert(client):
    certString = ""
    # try to read from the socket, exit if client has closed socket
    try:
        data = client.recv(config.payload_size).decode()
    except SSL.SysCallError:
        data = ""
    # read socket data while socket is open by client, exit when socket closed
    while data != "":
        certString = certString + data
        try:
            data = client.recv(config.payload_size).decode()
        except SSL.SysCallError:
            data = ""
    # return x509 object
    return crypto.load_certificate(crypto.FILETYPE_PEM, certString)

# send a file to the client
def send_file(client, filename, largestCircle):
    # open file to send
    filePath = os.path.join(config.storage, filename)
    print(config.pcolours.OKBLUE + "filename is :" + filePath)
    sent_file = open(filePath.strip("\x00"), "rb")
    # sign file to send to be verified at the other end
    data = verify.sign(filename)
    # while there is data to send; send data, error if client closes prematurely
    while data:
        try:
            client.send(data)
        except OpenSSL.SSL.SysCallError as e:
            print("Client closed connection")
            return -1
        data = sent_file.read(config.payload_size)
    # close file once it has been fully sent
    sent_file.close()
    print(config.pcolours.OKGREEN +"File sent")
    return 0

# receive a file from the client
def receive_file(client, filename, root, size):
    # create/replace file to be received
    filePath = os.path.join(root, filename)
    print(config.pcolours.OKBLUE + "Filename is :" + filePath)
    recv_file = open(filePath.strip("\x00"), "wb+")
    # receive the signature
    try:
        signature = client.recv(config.payload_size)
    except SSL.SysCallError as msg:
        print(config.pcolours.WARNING +"First frame is end of file ssl error:" + str(msg))
        return(-1)
    # get the cert of the client 
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
