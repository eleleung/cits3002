import socket
import config
import sys
from OpenSSL import SSL, crypto
import os
from eventlet import Timeout
import verify
import config

def send_file(conn, filename):
    filePath = os.path.join(config.storage, filename)
    print(config.pcolours.OKBLUE + "filename is :" + filePath)
    sent_file = open(filePath.strip("\x00"), "wb+")
    data = verify.sign(filename)
    while data:
        try:
            client.send(data)
        except SSL.SysCallError as msg:
            data = ""
        data = sent_file.read(config.payload_size)
    sent_file.close()
    print(config.pcolours.OKGREEN +"File received")
    client.close()
    print(config.pcolours.OKBLUE +"Client disconnected")

def receive_file(client, filename):
    filePath = os.path.join(config.storage, filename)
    print(config.pcolours.OKBLUE + "Filename is :" + filePath)
    recv_file = open(filePath.strip("\x00"), "wb+")
    # write data to file
    try:
        signature = client.recv(config.payload_size)
        print(signature)
    except SSL.SysCallError as msg:
        print(config.pcolours.WARNING +"First frame is end of file ssl error:" + str(msg))
        return(-1)
    clientCertObject = client.get_peer_certificate()
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
    recv_file.close()
    if verify.verify(filename, clientCertObject, signature):
        print(config.pcolours.OKGREEN + "File is verified")
    else:
        print(config.pcolours.WARNING + "File could not be verified")
    print(config.pcolours.OKGREEN +"File received")
    client.close()
    print(config.pcolours.OKBLUE +"Client disconnected")
