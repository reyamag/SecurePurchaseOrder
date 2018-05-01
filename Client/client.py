from __future__ import print_function
import socket
import sys
import pickle  # for receiving list data
import os.path
import getpass

bufferSize = 4096
serverName = "localhost"
codingMethod = "UTF-8"
idt = "    "  # Indent so that client feedback looks clean


# Receives a specified number of bytes over a TCP socket
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


# Function to create a socket using a provided port # and server
def createSocket(portNum):
	# Create a TCP socket
	connSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	# Connect to server
	connSock.connect((serverName, int(portNum)))
	print('Connected to port #', portNum)
	
	# Return the created socket
	return connSock


# Function to upload a file to the server over an ephemeral port #
def uploadFileToServer(fileName, portNum):

	# Generate an ephemeral port
	print(idt, end=' ')
	tempSocket = createSocket(portNum)

	# Open file
	try:
		file_object = open(fileName, 'r')
	except OSError:
		print(idt, 'Cannot open file: ' + fileName)
		tempSocket.close()
		return False

	#file_object = Path(fileName)
	
	#if file_object.is_file():
	#	return True
	#else:
	#	print(idt, 'Cannot open file: ' + fileName)
	#	tempSocket.close()
	#	return False

	print(idt, 'Uploading ' + fileName + ' to server')
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

		print(idt, 'Sent', numSent, 'bytes.')
	
	# Close the socket and the file
	file_object.close()
	tempSocket.close()

	return True


# Function to download a file from the server over an ephemeral port #
def downloadFileFromServer(fileName, portNum):

	# Generate an ephemeral port
	print(idt, end=' ')
	tempSocket = createSocket(portNum)

	# Receive the first 10 bytes indicating the
	# size of the file
	fileSizeBuff = recvAll(tempSocket, 10)

	# Get the file size
	if fileSizeBuff == '':
		print(idt, 'Nothing received.')
		return False
	else:
		fileSize = int(fileSizeBuff)

	print(idt, 'The file size is', fileSize, 'bytes')

	# Get the file data
	fileData = recvAll(tempSocket, fileSize)

	# Open file to write to
	fileWriter = open(fileName, 'w+')

	# Write received data to file
	fileWriter.write(fileData)

	# Close file
	fileWriter.close()

	return True


# *******************************************************************
#							MAIN PROGRAM
# *******************************************************************
def main():
	# if client command line has 3 args. for ex: python client.py localhost 1234
	if len(sys.argv) < 3:
		print('python3 ' + sys.argv[0]+'<server_machine>'+'<server_port>')

	serverName = sys.argv[1]
	serverPort=int (sys.argv[2])

	primarySocket = createSocket(serverPort)
	authenticated = False
    
	while True:
		
		# Perform initial authentication process
		while not authenticated:
			userInput = input('$> user: ')
			passInput = getpass.getpass('$> password: ')
        
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

		ans = input('$> ')

		# Argument counting using spaces
		ftp_arg_count = ans.count(' ')

		if ftp_arg_count == 1:
			(command, fileName) = ans.split()
		elif ftp_arg_count == 0:
			command = ans

		# Process input
		if command == 'put' and ftp_arg_count == 1:
			# Send the entire command to server: put [file]
			primarySocket.send(ans.encode(codingMethod))

			# Receive an ephemeral port from server to upload the file over
			tempPort = primarySocket.recv(bufferSize).decode(codingMethod)

			print(idt, 'Received ephemeral port #', tempPort)
			success = uploadFileToServer(fileName, tempPort)

			if success:
				print(idt, 'Successfully uploaded file')
				# Get server report
				receipt = primarySocket.recv(1).decode(codingMethod)
				if receipt == '1':
					print(idt, 'Server successfully received file')
				else:
					print(idt, 'Server was unable to receive the file')
			else:
				print(idt, 'Unable to upload file')

		elif command == 'get' and ftp_arg_count == 1:
			# Send the entire command to server: get [file]
			primarySocket.send(ans.encode(codingMethod))

			# Receive an ephemeral port from server to download the file over
			tempPort = primarySocket.recv(bufferSize).decode(codingMethod)
			print(idt, 'Received ephemeral port #', tempPort)

			success = downloadFileFromServer(fileName, tempPort)

			# Send success/failure notification to server
			if success:
				print(idt, 'Successfully downloaded file')
				primarySocket.send('1'.encode(codingMethod))
			else:
				print(idt, 'Unable to download file')
				primarySocket.send('0'.encode(codingMethod))

		elif command == 'ls' and ftp_arg_count == 0:
			# Send the entire command to server: ls
			primarySocket.send(ans.encode(codingMethod))

			# Get ephemeral port generated by server
			tempPort = primarySocket.recv(bufferSize).decode(codingMethod)
			print(idt, 'Received ephemeral port #', tempPort)

			# Create ephemeral socket and wait for data
			print(idt, end=' ')
			eSocket = createSocket(tempPort)
			data = eSocket.recv(bufferSize)

			# Need 'pickle.loads' to extract list
			server_dir = pickle.loads(data)

			# Print out directory
			print('\n', idt + 'Files on server:')
			for line in server_dir:
				print(idt, line)

			eSocket.close()

		elif command == 'quit' and ftp_arg_count == 0:
			print(idt, 'Closing now')

			primarySocket.send(ans.encode(codingMethod))
			primarySocket.close()
			break

		else:
			print(idt, 'Invalid command. Try: put [file], get [file], ls, or quit')


if __name__ == "__main__":
	main()
