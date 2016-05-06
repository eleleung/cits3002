import socket
import config
import sys

# connect socket
def runserver(port, data):
    config.init()
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    try:
        conn.bind(("192.168.43.70", int(port)))
    except socket.error as msg:
        print('Bind failed.')
        sys.exit()
    conn.listen(config.backlog)
    print("Server running on: \nHost: " + host + "\nPort: " + port)
    receive(conn, data)

# send data
def receive(conn, data):
    while 1==1:
        client, addr = conn.accept()
        payload = client.recv(config.payload_size).decode()
        if payload:
            print(str(payload).strip())
        client.send(bytes(data, "UTF-8"))
        client.close()

runserver(sys.argv[1], sys.argv[2])
