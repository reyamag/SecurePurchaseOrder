from __future__ import print_function
import socket
import sys
import os.path
import getpass
from Crypto.Hash import SHA512

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
	sessionID = -1
    
	while True:
		
		# Perform initial authentication process
		while sessionID == -1:
			userInput = input("$> \nUsername: ")
			passInput = getpass.getpass("$> \nPassword: ")
        
            # Hash password and send over TCP
			primarySocket.send(userInput.encode(codingMethod))
			primarySocket.send(passInput.encode(codingMethod))

			# Receive session ID from server (0/1 for success/failure)
			serverMsg = primarySocket.recv(bufferSize).decode(codingMethod)
			parsedMsg = serverMsg.split('::')
			
			if str(parsedMsg[0]) == "1":
				sessionID = int(parsedMsg[1])
				print(idt, "Authentication successful. Session ID:", sessionID)
			else:
				errorMsg = parsedMsg[1]
				print(idt, errorMsg)
				continue



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
		elif command == "pwd":
			# Update password

			# 1. Send command to server.
			primarySocket.send(ans.encode(codingMethod))

			# 2. Prompt for current password
			oldPassword = getpass.getpass("$> \nEnter old password: ")
			oldPassword = SHA512.new(oldPassword.encode(codingMethod)).hexdigest()

			# 3. Send to server for verification
			storedPassword = primarySocket.send(oldPassword.encode(codingMethod))
			passwordIsCorrect = primarySocket.recv(bufferSize).decode(codingMethod)

			# 4. If password match, continue. Else, notify server that command is terminated
			if passwordIsCorrect != "1":
				print(idt, "Old password incorrect!")
				continue
			
			toSendMsg = ""
			
			# Prompt for new password/confirmation.
			newPassword1 = getpass.getpass("Enter new password: ")
			newPassword2 = getpass.getpass("Confirm new password: ")
			if newPassword1 != newPassword2:
				print(idt, "New passwords do not match!")
				toSendMsg = "0::"
			else:
				# Prepare to send server new password hash
				toSendMsg = "1::" + SHA512.new(newPassword1.encode(codingMethod)).hexdigest()
	
			primarySocket.send(toSendMsg.encode(codingMethod))

			# 5. Receive success msg if we attempted to update
			if toSendMsg[0] == "1":
				flag = primarySocket.recv(bufferSize).decode(codingMethod)
				if str(flag) != "1":
					print(idt, "Issue updating password")
				else:
					print(idt, "Password updated successfully!")

		elif command == "quit":
			print(idt, "Closing now")

			primarySocket.send(ans.encode(codingMethod))
			primarySocket.close()
			break
		else:
			print(idt, "Invalid command. Try: 'test' or 'quit'")


if __name__ == "__main__":
	main()
