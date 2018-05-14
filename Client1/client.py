from __future__ import print_function
import socket
import sys
import os.path
import getpass
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto import Random
from signingFunctions import *
from socketFunctions import *
import base64

bufferSize = 4096
serverName = ""
codingMethod = "UTF-8"
idt = "    "  # Indent so that client feedback looks clean

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
    # if client command line has 3 args. for ex: python client.py localhost 1234 privateKey.PEM
    if len(sys.argv) != 4:
        print("\tUSAGE: $python3 " + sys.argv[0] + " <server_machine> <server_port> <private_key_file>")
        return 
    
    serverName = sys.argv[1]
    serverPort = int(sys.argv[2])
    privKeyFile = sys.argv[3]

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
                print(idt, "Authentication successful.\n")
                print(idt, "Enter command choice:")
                print(idt, "test - test connection")
                print(idt, "pwd - change password")
                print(idt, "order - create an order")
                print(idt, "inventory - search for an item in inventory")
                print(idt, "quit - quit and close server")
            else:
                errorMsg = parsedMsg[1]
                print(idt, errorMsg)
            continue

        ans = input("$> ")

        # Argument counting using spaces
        arg_count = ans.count(" ")

        if arg_count == 1:
            print(idt, "Invalid command. Try: 'test', 'order', 'inventory', 'pwd', or 'quit'")
        elif arg_count == 0:
            command = ans

        # Send the command to server
        sendMsg(primarySocket, ans)

        # Process input
        if command == "test":

            testMsg = "Hello Server :)"

            sendMsg(primarySocket, testMsg)
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
            
            # Get the private key from the input parameters
            privKey = load_key(load_sig(privKeyFile))

            # Get the signature of the order
            orderSignature = getFileSig(str(theOrder), privKey, isFile=False)
            
            # Now, encrypt the order itself
            # First, generate an AES key and initialization vector for block-chain encryption.
            aesKey = os.urandom(16) # 16 random bytes
            iv = Random.new().read(AES.block_size) # Random IV
            myEncryptor = AESCipher(aesKey, iv)

            # Second, generate the encrypted text.
            encryptedOrder = myEncryptor.encrypt(str(theOrder))

            # Send a sequence of messages in this order:
            #   1. Digital signature
            #   2. AES key
            #   3. IV vector
            #   4. Encrypted order
            # Note: Messages 2-4 are byte-strings and cannot be encoded/decoded.

            sendMsg(primarySocket, orderSignature, encode=False)

            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            # TODO: Encrypt AES key & iv using RSA.

            sendMsg(primarySocket, aesKey, encode=False)
            sendMsg(primarySocket, iv, encode=False)

            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            ###################################################################
            sendMsg(primarySocket, encryptedOrder, encode=False)

            print("Order sent to server. Waiting for reply.....")

            # Receive order confirmation/failure notice from server
            serverMsg = recvMsg(primarySocket)
            print(idt, serverMsg.split("::")[1])

        elif command == "inventory":
            item = input("Which item are you looking for? ")
            sendMsg(primarySocket, item)

            response = recvMsg(primarySocket)
            print(idt, response.split("::")[1])

        elif command == "quit":
            print(idt, "Closing now")

            primarySocket.close()
            break
        else:
            print(idt, "Invalid command. Try: 'test', 'order', 'inventory', 'pwd', or 'quit'")


if __name__ == "__main__":
    main()
