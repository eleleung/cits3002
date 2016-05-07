import socket
import config
import sys
from OpenSSL import SSL
import os

# connect socket
def runserver(port, data):
    config.init()

    root    = os.getcwd()
    ctx     = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.use_privatekey_file(os.path.join(root, 'server.pkey'))
    ctx.use_certificate_file(os.path.join(root, 'server.cert'))

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    encrypted_conn = SSL.Connection(ctx, conn)
    host = socket.gethostname()
    try:
        encrypted_conn.bind(("", int(port)))
    except socket.error as msg:
        print('Bind failed.')
        sys.exit()
    conn.listen(config.backlog)
    print("Server running on: \nHost: " + host + "\nPort: " + port)
    receive(encrypted_conn, data)

# send data
def receive(conn, data):
    while 1==1:
        client, addr = conn.accept()
        conn.do_handshake()
        payload = client.recv(config.payload_size).decode()
        if payload:
            print(str(payload).strip())
        client.send(bytes(data, "UTF-8"))
        client.close()

runserver(sys.argv[1], sys.argv[2])
