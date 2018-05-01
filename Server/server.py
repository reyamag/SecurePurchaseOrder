from __future__ import print_function
import socket
import subprocess
import sys
import pickle  # for sending lists


# Server-wide variables
bufferSize = 4096
request_queue = 10
serverName = 'localhost'
codingMethod = 'UTF-8'
serverSource = 'server.py'

# Create a buffer that receives a specified number of bytes over
# a specified TCP socket
def recvAll(sock, numBytes):

    # The buffer
    recvBuff = ''

    # Keep receiving till all is received
    while len(recvBuff) < numBytes:

        # Attempt to receive bytes
        tmpBuff = sock.recv(numBytes).decode(codingMethod)

        # The other side has closed the socket
        if not tmpBuff:
            break

        # Add the received bytes to the buffer
        recvBuff += tmpBuff

    return recvBuff


# Function to connect to a temporary client socket
def connectTempSocket(client):

    # Create a temporary socket from which to find a 'random' port number
    # for an ephemeral data port
    tempSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to port 0
    try:
        tempSocket.bind(('', 0))
    except socket.error as msg:
        print('Bind failed. Error Code :', str(msg))
        return None

    # Let the ephemeral port number be the ID of the temporary socket
    tempPortNum = tempSocket.getsockname()[1]
    print('Ephemeral port # is', tempPortNum)

    # Send tempPortNum to client
    client.send(str(tempPortNum).encode(codingMethod))

    # Listen on tempSocket - allow only one connection
    tempSocket.listen(1)

    # Accept incoming connections to tempCliSock
    (tempCliSock, addr) = tempSocket.accept()

    # Close listening tempSocket
    tempSocket.close()
    
    return tempCliSock


# Function to accept a file from client
def receiveFileFromClient(fileName, tempSocket):

    # Receive the first 10 bytes indicating the
    # size of the file
    fileSizeBuff = recvAll(tempSocket, 10)

    # Get the file size
    if fileSizeBuff == '':
        print('Nothing received.')
        return 0
    else:
        fileSize = int(fileSizeBuff)

    print('The file size is', fileSize, 'bytes')

    # Get the file data
    fileData = recvAll(tempSocket, fileSize)

    # Open file to write to
    fileWriter = open(fileName, 'w+')

    # Write received data to file
    fileWriter.write(fileData)

    # Close the file
    fileWriter.close()


# Function to send a file to the client
def sendFileToClient(fileName, tempSocket):

    # Open file
    try:
        file_object = open(fileName, 'r')
    except OSError:
        print('Cannot open file:', fileName)
        tempSocket.close()
        return False

    print('Sending', fileName, 'to client')
    while True:
        # Read data
        fileData = file_object.read()

        # Make sure file is not empty by reading only EOF
        if fileData:

            # Get the size of the data read
            # and convert it to string
            dataSize = str(len(fileData))

            # Prepend 0's to the size string
            # until the size is 10 bytes
            while len(dataSize) < 10:
                dataSize = '0' + dataSize

            # Prepend the size of the data to the
            # file data.
            fileData = dataSize + fileData

            # The number of bytes sent
            numSent = 0

            # Send the data!
            while len(fileData) > numSent:
                numSent += tempSocket.send(fileData[numSent:].encode(codingMethod))

        # The file is completely empty
        else:
            break

        print('Sent', numSent, 'bytes.')

    # Close the socket and the file
    file_object.close()
    tempSocket.close()

    return True


# *******************************************************************
#                             MAIN PROGRAM
# *******************************************************************
def main():
    # Normally obtained from command line arguments
    # if command line has 3 args. For ex: python server.py 1234

    if len(sys.argv) < 2:
        print ('python3 ' + sys.argv[0] + '<port_number>')

    serverPort = int(sys.argv[1])

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')

    # bind socket to host and port
    try:
        serverSocket.bind((serverName, serverPort))
    except socket.error as msg:
        print('Bind failed. Error Code:', str(msg))

        serverSocket.close()
        return

    print('Socket bind complete')

    serverSocket.listen(request_queue)
    print('Socket now listening')

    # Listen forever
    while True:
        print('\nAwaiting connection...')

        # Block until connection is received
        (clientSocket, addr) = serverSocket.accept()
        print('Connected with client', addr, '@', serverPort)

        # 1. Ensure correct client authentication...
        authenticated = False

        while not authenticated:
            print("Waiting for authentication....")
            clientUser = clientSocket.recv(bufferSize).decode(codingMethod)
            clientPass = clientSocket.recv(bufferSize).decode(codingMethod)

            # Authenicate user
            print(clientUser, clientPass)

            if clientPass == "abc":
                print("Credentials match. Provide session ID")
                # Send session ID
                clientSocket.send('1234567'.encode(codingMethod))
                authenticated = True
            else:
                print("Credentials do not match. Report failure")
                # Failure.
                clientSocket.send('-1'.encode(codingMethod))

        while True:
            clientCommand = clientSocket.recv(bufferSize).decode(codingMethod)

            if not clientCommand:
                print('Client connection has unexpectedly terminated')
                break

            # Argument counting using spaces
            client_args = clientCommand.count(' ')

            if client_args == 1:
                (cmd, fileName) = clientCommand.split()
            elif client_args == 0:
                cmd = clientCommand

            if cmd == 'put' and client_args == 1:

                tempSock = connectTempSocket(clientSocket)

                # Receive the file from client
                print('Receive', fileName, 'from client...')
                success = receiveFileFromClient(fileName, tempSock)

                # Report success/failure to the client
                if success == 0:
                    print('Unable to receive', fileName)
                    clientSocket.send('0'.encode(codingMethod))
                else:
                    print('Successfully received', fileName)
                    clientSocket.send('1'.encode(codingMethod))

                # Close the temporary data socket
                tempSock.close()

            elif cmd == 'get' and client_args == 1:
                print('\nGet command received. Prepare to send', fileName)

                tempSock = connectTempSocket(clientSocket)

                print('Sending', fileName, 'to client')
                success = sendFileToClient(fileName, tempSock)

                if success:
                    print('Successfully sent', fileName)
                    # Receive success notification from client
                    receipt = clientSocket.recv(1).decode(codingMethod)
                    if receipt == '1':
                        print('Client successfully received', fileName)
                    else:
                        print('Client unable to receive', fileName)
                else:
                    print('Unable to upload', fileName)

                # Close the temporary data socket
                tempSock.close()

            elif cmd == 'quit':
                print('Quit command received. Closing socket now')
                clientSocket.close()
                break

            elif cmd == 'ls':
                print('ls command received')

                # Create ephemeral port and send to client
                tempSock = connectTempSocket(clientSocket)

                raw_data = []
                dir_files = []

                # Get raw directory data
                for line in subprocess.getstatusoutput(cmd):
                    raw_data.append(line)

                # Format into list
                dir_files = raw_data[1].split('\n')

                # Remove server's source code from the returned list
                index = 0
                for file in dir_files:
                    if file == serverSource:
                        del dir_files[index]
                    index += 1

                # Need 'pickle.dumps' in order to send through socket
                data = pickle.dumps(dir_files)

                #send directory data back to client
                tempSock.send(data)
                print('Successfully sent directory data')

                tempSock.close()

            else:
                print('Not a valid command')


if __name__ == "__main__":
    main()
