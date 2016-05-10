import os
def init():
    global backlog
    backlog = 5
    global payload_size
    payload_size = 1024
    global root
    root = os.getcwd()
