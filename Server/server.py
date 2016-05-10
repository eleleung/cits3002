import socket
import config
import sys
from OpenSSL import SSL
import os

def create_context():
    ctx     = SSL.Context(SSL.TLSv1_2_METHOD)
    try:
        ctx.use_privatekey_file(os.path.join(config.root, 'server.pkey'))
    except SSL.Error as error:
        print('server.pkey could not be found \nPlace in directory: ' + str(config.root) + "\n", file=sys.stderr)
        try:
            ctx.use_certificate_file(os.path.join(config.root, 'server.cert'))
        except SSL.Error as error:
            print('server.cert could not be found \nPlace in directory: ' + str(config.root) + "\n", file=sys.stderr)
            sys.exit()
    try:
        ctx.use_certificate_file(os.path.join(config.root, 'server.cert'))
    except SSL.Error as error:
        print('server.cert could not be found \nPlace in directory: ' + str(config.root) + "\n", file=sys.stderr)
        sys.exit()
    return ctx

# connect socket
def runserver(port, file):
    config.init()
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctx = create_context()
    encrypted_conn = SSL.Connection(ctx, conn)
    host = socket.gethostname()
    try:
        encrypted_conn.bind(("", int(port)))
    except socket.error as msg:
        print('Bind failed, socket error message: ' + str(msg))
        sys.exit()
    conn.listen(config.backlog)
    print("Server running on: \nHost: " + host + "\nPort: " + port)
    receive(encrypted_conn, file)

def send_file(conn, file):
    client, addr = conn.accept()
    conn.do_handshake()
    filename = client.recv(config.payload_size).decode()
    send_file = open(filename, "r")
    data = send_file.read(config.payload_size)
    while data:
        client.send(data)
        data = send_file.read(config.payload_size)
    sendfile.close()

def receive_file(conn):
    client, addr = conn.accept()
    conn.do_handshake()
    filename = client.recv(config.payload_size).decode()
    recv_file = open(filename, "w+")
    data = client.recv(config.payload_size)
    while data:
        recv_file.write(data)
        data = client.recv(config.payload_size)
    recv_file.close()


# send data
def receive(conn, data):
    while 1==1:
        client, addr = conn.accept()
        conn.do_handshake()
        payload = client.recv(config.payload_size).decode()
        if payload:
            print(str(payload))
        client.send(bytes(data, "UTF-8"))
        client.close()

runserver(sys.argv[1], sys.argv[2])
