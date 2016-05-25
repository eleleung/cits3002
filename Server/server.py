import socket
import config
import sys
from OpenSSL import SSL
import os
import fileOperations
import SSLOperations
import shlex
import verify

def runserver(port):
    # create globals
    config.init()
    ctx = SSLOperations.create_context()
    # connect socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # wrap socket
    encrypted_conn = SSL.Connection(ctx, conn)
    encrypted_conn.set_accept_state()
    # set up the sockets
    host = socket.gethostname()
    try:
        encrypted_conn.bind(("192.168.43.70", int(port)))
    except socket.error as msg:
        print('Bind failed, socket error message: ' + str(msg))
        sys.exit()
    encrypted_conn.listen(config.backlog)

    # courtesy statement
    print("Server running on: \nHost: " + host + "\nPort: " + port)
    while 1==1:
        acceptIncoming(encrypted_conn)

def acceptIncoming(conn):
    # connect to client
    print("accepting connection")
    client, addr = conn.accept()
    client.do_handshake()
    try:
        command = client.recv(config.payload_size).decode()
    except SSL.SysCallError as msg:
        print("No command received, ssl error:" + str(msg))
        return(-1)
    client.send("Confirm".ljust(1024))
    command = shlex.split(command)
    filename = command[(command.index("-a") + 1)]
    print(filename)
    fileOperations.receive_file(client, filename)

runserver(sys.argv[1])
