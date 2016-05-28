import os
import socket
import config
from OpenSSL import SSL, crypto
import verify

def ByteToHex( byteStr ):
    hex = []
    for aChar in byteStr:
        hex.append( "%02X " % ord( aChar ) )
    return ''.join( hex ).strip()

def send_file(client, filename, largestCircle, size):
    filePath = os.path.join(config.storage, filename)
    print(config.pcolours.OKBLUE + "filename is :" + filePath)
    sent_file = open(filePath.strip("\x00"), "rb")
    #data = "Circle of circumference " + str(largestCircle) + "\nContaining all requested names"
    #data.ljust(1024, " ")
    #client.send(data)
    data = verify.sign(filename)
    while data:
        client.send(data)
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
        print(ByteToHex(signature))
    except SSL.SysCallError as msg:
        print(config.pcolours.WARNING +"First frame is end of file ssl error:" + str(msg))
        return(-1)
    clientCertObject = client.get_peer_certificate()
    readData = 0
    while readData < size:
        readData = readData + len(data)
        try:
            data = client.recv(config.payload_size)
        except SSL.SysCallError as msg:
            data = ""
        recv_file.write(data)
    recv_file.close()
    if verify.verify(filename, clientCertObject, signature) == True:
        print(config.pcolours.OKGREEN + "File is verified")
    else:
        print(config.pcolours.WARNING + "File could not be verified")
    print(config.pcolours.OKGREEN +"File received")

def listFiles(client):
    rootDir = "./root"
    for dirName, subdirList, fileList in os.walk(rootDir):
        print(dirName)
        for fname in fileList:
            client.send('    ++    %s' % fname + "\t\t\t++    Circumference:" + "\n")
