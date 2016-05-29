import os
import fileOperations
import socket
import OpenSSL
import config
import fileSecurity

def parse(command, client):
    # search for -a flag and prepare to receive a file from the client
    if "-a" in command:
        client.send(config.pcolours.OKBLUE + "Confirm")
        fileOperations.receive_file(client, command[(command.index("-a") + 1)], config.storage, command[len(command) - 1])
    # search for -f flag and verify the file meets the clients requirements then send the file to the client
    if "-f" in command:
        # check the requested file exists
        if not os.path.exists(os.path.join(os.getcwd(), config.storage, command[(command.index("-f") + 1)])):
            client.send(config.pcolours.FAIL + "ERROR: File not found")
            client.close()
        else:
            # generate the circles which satisfy all requirements
            names = []
            # get all circles which are greater or equal to the minimum size.
            if "-c" in command:
                circles = fileSecurity.genCircles(command[(command.index("-f") + 1)], command[(command.index("-c") + 1)])
            else:
                circles = fileSecurity.genCircles(command[(command.index("-f") + 1)], config.defaultCircumference)
            # \x00 is a workaround both here and in other functions, it was simply easier to fix in python than in c
            # check all requested names and append to a list
            for i, j in enumerate(command):
                if j == "-n":
                    names.append(command[i + 1])
            # Remove any circles which do not contain the specified names
            print(circles)
            print(names)
            for circle in circles:
                for name in names:
                    if name != '\x00':
                        if name.strip("\x00") not in circle:
                            circles.remove(circle)
            largestCircle = 0
            # find the largest circle and send the file to the client, if no circle large enough exists; send error ande close socket
            print(circles)
            if circles != []:
                for circle in circles:
                    if len(circle) > largestCircle:
                        largestCircle = len(circle)
                fileOperations.send_file(client, command[(command.index("-f") + 1)], largestCircle)
            else:
                client.send(config.pcolours.FAIL + "ERROR: Circle of insufficient size")
                client.close()
    # search for -l flag and generate a file list to send to the client
    if "-l\x00" in command:
        fileOperations.listFiles(client)
    # search for -u flag and prepare to receive a certificate from the client any uploaded file is vouched for by the uploader
    if "-u" in command:
        fileOperations.receive_file(client, command[(command.index("-u") + 1)], config.certs)
    # search for -v flag and send file to the client
    if "-v" in command:
        if not os.path.exists(os.path.join(os.getcwd() + command[(command.index("-v") + 1)].strip("\x00"))):
            client.send(config.pcolours.FAIL + "ERROR: File not found")
            client.close()
        else:
            fileOperations.send_file(client, command[(command.index("-v") + 1)], largestCircle)
    client.close()
    print(config.pcolours.OKBLUE + "Client disconnected")
