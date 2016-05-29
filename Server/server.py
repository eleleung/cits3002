import os
import sys
sys.path.append(os.path.join(os.getcwd(), "external_modules"))
sys.path.append(os.path.join(os.getcwd(), "external_modules","OpenSSL"))
import socket
import config
from OpenSSL import SSL
import os
import fileOperations
import SSLOperations
import networkOperations
import shlex
import verify
import control

def runserver():
    # create globals
    config.init()
    ctx = SSLOperations.create_context()
    # connect socket
    socketSSL = networkOperations.createSSL(ctx)
    while True:
        acceptIncoming(socketSSL)

def acceptIncoming(conn):
    # connect to client
    client, addr = conn.accept()
    print(config.pcolours.OKGREEN +"Accepting connection")
    try:
        command = client.recv(config.payload_size).decode()
    except SSL.SysCallError as msg:
        print("No command received, ssl error:" + str(msg))
        return(-1)
    command = shlex.split(command)
    control.parse(command, client)

runserver()
