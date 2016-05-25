import os
def init():
    global backlog
    backlog = 5
    global payload_size
    payload_size = 1024
    global root
    root = os.getcwd()
    global storage
    storage = os.path.join(os.getcwd(), "data_storage")
    global certs
    certs = os.path.join(os.getcwd(), "cert_storage")
    global digest
    digest = "sha256"
