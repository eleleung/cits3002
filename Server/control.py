import os
import fileOperations
import socket
import OpenSSL
import config
import fileSecurity

def parse(command, client):
    if "-a" in command:
        client.send(config.pcolours.OKBLUE + "Confirm")
        fileOperations.receive_file(client, command[(command.index("-a") + 1)], config.storage)
    if "-f" in command:
        if not os.path.exists(os.path.join(os.getcwd(), config.storage, command[(command.index("-f") + 1)])):
            client.send(config.pcolours.FAIL + "ERROR: File not found")
            client.close()
        else:
            names = []
            if "-c" in command:
                circles = fileSecurity.genCircles(command[(command.index("-f") + 1)], command[(command.index("-c") + 1)])
            else:
                circles = fileSecurity.genCircles(command[(command.index("-f") + 1)], config.defaultCircumference)
            for i, j in enumerate(command):
                if j == "-n":
                    names.append(command[i + 1])
            for circle in circles:
                for name in names:
                    if name not in circle:
                        circles.remove(circle)
            largestCircle = 0
            if circle != []:
                for circle in circles:
                    if len(circle) > largestCircle:
                        largestCircle = len(circle)
                fileOperations.send_file(client, command[(command.index("-f") + 1)], largestCircle, command[len(command) - 1])
            else:
                client.send(config.pcolours.FAIL + "ERROR: Circle of insufficient size")
                client.close()
    if "-l" in command:
        fileOperations.listFiles(command[(command.index("-l") + 1)])
    if "-u" in command:
        fileOperations.receive_file(client, command[(command.index("-u") + 1)], config.certs)
    if "-v" in command:
        if not os.path.exists(os.path.join(os.getcwd() + command[(command.index("-f") + 1)])):
            client.send(config.pcolours.ERROR + "ERROR: File not found")
            client.close()
        else:
            parse(["-f", command[(command.index("-v") + 1)]])
    if "-s" in command:
        clientCertObject = client.get_peer_certificate()
        fileSecurity.applySignature(command[(command.index("-s") + 1)], command[(command.index("-s") + 2), clientCertObject])
    client.close()
    print(config.pcolours.OKBLUE + "Client disconnected")
