######################################
#   CITS3002 PROJECT PARTICIPANTS:   #
#------------------------------------#
# Eleanor Leung   |	    21149831     #
# Aiden Ziegelaar |     21333223     #
# Matthew Cooper  |     20933403     #
######################################

import os
import sys

def init():
    global backlog
    backlog = 5
    global payload_size
    payload_size = 1024
    global root
    root = os.getcwd()
    global storage
    storage = os.path.join(os.getcwd(), "root")
    global certs
    certs = os.path.join(os.getcwd(), "cert_storage")
    global digest
    digest = "sha256"
    global ERROR
    ERROR = "\x00"
    global defaultCircumference
    defaultCircumference = 0
    global port
    port = 3434


class pcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
