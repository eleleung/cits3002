import socket
import config
import sys
from OpenSSL import SSL
import os
from eventlet import Timeout
import verify

def send_file(conn, filename):
    filePath = os.path.join(config.storage, filename)
    print("filename is :" + filePath)
    sent_file = open(filePath.strip("\x00"), "wb+")
    data = verify.sign(filename)
    while data:
        try:
            client.send(data)
        except SSL.SysCallError as msg:
            data = ""
        data = sent_file.read(config.payload_size)
    sent_file.close()
    print("file received")
    client.close()
    print("client disconnected")

def receive_file(client, filename):
    filePath = os.path.join(config.storage, filename)
    print("filename is :" + filePath)
    recv_file = open(filePath.strip("\x00"), "wb+")
    # write data to file
    try:
        signature = client.recv(config.payload_size)
    except SSL.SysCallError as msg:
        print("first frame is end of file ssl error:" + str(msg))
        return(-1)
    clientCert = client.get_peer_certificate()
    print(clientCert)
    try:
        data = client.recv(config.payload_size)
    except SSL.SysCallError as msg:
        data = ""
    while data:
        recv_file.write(data)
        try:
            data = client.recv(config.payload_size)
        except SSL.SysCallError as msg:
            data = ""
    if verify.verify(filename, clientCert, signature):
        print("File is verified")
    else:
        print("File could not be verified")
    recv_file.close()
    print("file received")
    client.close()
    print("client disconnected")
