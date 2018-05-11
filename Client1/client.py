from __future__ import print_function
import socket
import sys
import os.path
import getpass
from Crypto.Hash import SHA512
from signingFunctions import *

bufferSize = 4096
serverName = ""
codingMethod = "UTF-8"
idt = "    "  # Indent so that client feedback looks clean


# Receive msg size before receving the message
# over a limited-size buffer
def recvMsg(sock):

    size = int(sock.recv(4096).decode(codingMethod))

    return recvAll(sock, size)


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

def sendMsg(sock, msg):

    if len(msg.encode(codingMethod)) > bufferSize:
        # User is trying to send a message that is greater than 2^bufferSize bytes.
        print(idt, "The message you are sending is too large to send over this socket.")
        return False

    # Ensure size message is exactly the size of the buffer
    size = str(len(msg.encode())).zfill(bufferSize)

    # Send message size and then the actual message.
    sock.send(size.encode(), bufferSize)
    sock.send(msg.encode())

    return True

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
    if len(sys.argv) != 3:
        print("\tUSAGE: $python3 " + sys.argv[0] + " <server_machine> " + " <server_port>")
        return 
    
    serverName = sys.argv[1]
    serverPort = int(sys.argv[2])

    primarySocket = createSocket(serverPort)

    authenticated = False
    userName = ""

    while True:
		
        # Perform initial authentication process
        while not authenticated:
            userInput = input("Username: ")
            userName = userInput
            passInput = getpass.getpass("Password: ")

            # Hash password and send over TCP
            sendMsg(primarySocket, userInput)
            sendMsg(primarySocket, passInput)

            # Receive authentication success/failure from server
            serverMsg = recvMsg(primarySocket)
            parsedMsg = serverMsg.split('::')

            if str(parsedMsg[0]) == "1":
                authenticated = True
                print(idt, "Authentication successful.")
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

        # Send the command to server
        sendMsg(primarySocket, ans)

        # Process input
        if command == "test":
            
            sendMsg(primarySocket, "test")
            print(idt, "Sent test message to server")
            recvMsg(primarySocket)
            print(idt, "Received test message from server")
            print(idt, "Connection test successful")

        elif command == "pwd":
            # Update password

            # 1. Prompt for current password
            oldPassword = getpass.getpass("Enter old password: ")
            oldPassword = SHA512.new(oldPassword.encode(codingMethod)).hexdigest()

            # 2. Send to server for verification
            sendMsg(primarySocket, oldPassword)
            passwordIsCorrect = recvMsg(primarySocket)

            # 3. If password match, continue. Else, notify server that command is terminated
            if passwordIsCorrect != "1":
                print(idt, "Old password incorrect!")
                continue

            # 4. Get new password information and send to server
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

            sendMsg(primarySocket, toSendMsg)

            # 5. Receive success msg if we attempted to update
            if toSendMsg[0] == "1":
                flag = recvMsg(primarySocket)

                if str(flag) != "1":
                    print(idt, "Issue updating password")
                else:
                    print(idt, "Password updated successfully!")

        elif command == "order":
            # Order protocol...
            # Get order information from the user
            # Send the order message to server
            # Receive order success/failure message from server
            
            orderDesc = input("\nWhat do you want to order? ")
            orderQty = int(input("How many? "))

            theOrder = Order(initList=[orderDesc, orderQty, int(float(datetime.utcnow().timestamp())), userName])

            ##################################################################
            ##################################################################
            ###############################TODO###############################
            ##################################################################
            ##################################################################
            # Need to sign the message and hash and whatnot.
            # Implement simple protocol to ensure everything checks out.
            # TODO
            # TODO
            myOrder = str(theOrder) # TEMP: TODO - Sign and hash this!!!!!
            # TODO
            # TODO
            ##################################################################
            ##################################################################
            ##################################################################
            ##################################################################
            ##################################################################

            sendMsg(primarySocket, myOrder)
            print(idt, "Sent order for", orderQty, "" + str(orderDesc) + str("'s" if (orderQty > 1) else ""))

            # Receive order confirmation/failure notice from server
            serverMsg = recvMsg(primarySocket)
            parsedMsg = serverMsg.split("::")
            
            print(idt, parsedMsg[1])

        # TODO: Add command: update public key

        elif command == "quit":
            print(idt, "Closing now")

            primarySocket.close()
            break
        else:
            print(idt, "Invalid command. Try: 'test', 'order', 'pwd', or 'quit'")


if __name__ == "__main__":
    main()
