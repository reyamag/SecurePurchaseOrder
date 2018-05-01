from __future__ import print_function
import socket
import subprocess
import sys
import threading


# Server-wide variables
bufferSize = 4096
request_queue = 10
serverName = "localhost"
codingMethod = "UTF-8"
GLOBAL_threads = []

# Create a buffer that receives a specified number of bytes over
# a specified TCP socket
def recvAll(sock, numBytes):

    # The buffer
    recvBuff = ""

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

    # Create a temporary socket from which to find a "random" port number
    # for an ephemeral data port
    tempSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to port 0
    try:
        tempSocket.bind(("", 0))
    except socket.error as msg:
        print("Bind failed. Error Code :", str(msg))
        return None

    # Let the ephemeral port number be the ID of the temporary socket
    tempPortNum = tempSocket.getsockname()[1]
    print("Ephemeral port # is", tempPortNum)

    # Send tempPortNum to client
    client.send(str(tempPortNum).encode(codingMethod))

    # Listen on tempSocket - allow only one connection
    tempSocket.listen(1)

    # Accept incoming connections to tempCliSock
    (tempCliSock, addr) = tempSocket.accept()

    # Close listening tempSocket
    tempSocket.close()
    
    return tempCliSock

def getFirstAvailableThreadID():

    ctr = 1

    for ID in GLOBAL_threads:
        if ctr != ID:
            return ctr # We found a missing threadID. Use that one!
        ctr += 1
    
    # Every threadID from 1 -> n is used. Use n + 1
    return GLOBAL_threads[len(GLOBAL_threads)-1] + 1

# Thread stopping code used from:
#   https://stackoverflow.com/questions/323972/is-there-any-way-to-kill-a-thread-in-python
#   (Answer by "Phillipe F."")
# serverThread class source used from:
#   https://www.tutorialspoint.com/python/python_multithreading.htm
class serverThread(threading.Thread):
    def __init__(self, threadID, name, counter, sSocket, sPort, cSocket, _addr):   
        # Create thread & prepare for eventual termination.
        threading.Thread.__init__(self)
        self._stop_event = threading.Event()

        # Initialze variables necessary for socket communication.
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.serverSocket = sSocket
        self.serverPort = sPort
        self.clientSocket = cSocket
        self.addr = _addr

    # Run the main thread process
    def run(self):
        print("Starting " + self.name)
        mainClientProcess(self.name, self.serverSocket, self.serverPort, self.clientSocket, self.addr)
        print("Exiting " + self.name)
        self.stop() # Kill thread
        GLOBAL_threads.remove(self.threadID)

    # Methods to wait for thread to exit properly using join()
    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()


def mainClientProcess(threadName, serverSocket, serverPort, clientSocket, addr):
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
            clientSocket.send("1234567".encode(codingMethod))
            authenticated = True
        else:
            print("Credentials do not match. Report failure")
            # Failure.
            clientSocket.send("-1".encode(codingMethod))

    while True:
        clientCommand = clientSocket.recv(bufferSize).decode(codingMethod)

        if not clientCommand:
            print("Client connection has unexpectedly terminated")
            break

        if clientCommand == "test":
            print("Testing works!")
        elif clientCommand == "quit":
            print("Quit command received. Closing socket now")
            clientSocket.close()
            break
        else:
            print("Not a valid command")



# *******************************************************************
#                             MAIN PROGRAM
# *******************************************************************
def main():
    # Normally obtained from command line arguments
    # if command line has 3 args. For ex: python server.py 1234

    if len(sys.argv) < 2:
        print ("python3 " + sys.argv[0] + "<port_number>")

    serverPort = int(sys.argv[1])

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    # bind socket to host and port
    try:
        serverSocket.bind((serverName, serverPort))
    except socket.error as msg:
        print("Bind failed. Error Code:", str(msg))

        serverSocket.close()
        return

    print("Socket bind complete")

    serverSocket.listen(request_queue)
    print("Socket now listening")

    # Listen forever
    while True:
        print("\nAwaiting connection...")

        # Block until connection is received
        (clientSocket, addr) = serverSocket.accept()
        print("Connected with client", addr, "@", serverPort, "\n")

        # Create a unique thread for this connection and continue listening
        thrID = 1 if len(GLOBAL_threads) == 0 else getFirstAvailableThreadID()
        GLOBAL_threads.append(thrID)
        GLOBAL_threads.sort()
        thread = serverThread(thrID, "Thread-" + str(thrID), thrID, serverSocket, serverPort, clientSocket, addr)
        thread.start()
        


if __name__ == "__main__":
    main()
