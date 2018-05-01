from __future__ import print_function
import socket
import sys
import os.path
import getpass

bufferSize = 4096
serverName = "localhost"
codingMethod = "UTF-8"
idt = "    "  # Indent so that client feedback looks clean


# Receives a specified number of bytes over a TCP socket
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


# Function to create a socket using a provided port # and server
def createSocket(portNum):
	# Create a TCP socket
	connSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	# Connect to server
	connSock.connect((serverName, int(portNum)))
	print("Connected to port #", portNum)
	
	# Return the created socket
	return connSock


# *******************************************************************
#							MAIN PROGRAM
# *******************************************************************
def main():
	# if client command line has 3 args. for ex: python client.py localhost 1234
	if len(sys.argv) < 3:
		print("python3 " + sys.argv[0]+"<server_machine>"+"<server_port>")

	serverName = sys.argv[1]
	serverPort = int(sys.argv[2])

	primarySocket = createSocket(serverPort)
	authenticated = False
    
	while True:
		
		# Perform initial authentication process
		while not authenticated:
			userInput = input("$> user: ")
			passInput = getpass.getpass("$> password: ")
        
            # Hash password and send over TCP
			primarySocket.send(userInput.encode(codingMethod))
			primarySocket.send(passInput.encode(codingMethod))

			# Receive session ID from server (-1 if incorrect credentials)

			sessionID = primarySocket.recv(bufferSize).decode(codingMethod)
			if sessionID == "-1":
				print(idt, "Incorrect credentials. Try again")
			else:
				print(idt, "Session ID:", sessionID)
				authenticated = True

		ans = input("$> ")

		# Argument counting using spaces
		arg_count = ans.count(" ")

		if arg_count == 1:
			print(idt, "Currently only 1 word commands...")
		elif arg_count == 0:
			command = ans

		# Process input
		if command == "test":
			# Send the command to server
			primarySocket.send(ans.encode(codingMethod))
		elif command == "quit":
			print(idt, "Closing now")

			primarySocket.send(ans.encode(codingMethod))
			primarySocket.close()
			break
		else:
			print(idt, "Invalid command. Try: 'test' or 'quit'")


if __name__ == "__main__":
	main()
