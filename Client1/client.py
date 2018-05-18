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
privKeyFile = ""
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

def formatRSAPublicKey(pubKeyPEM):
    s = pubKeyPEM.decode()
    s = s.replace("-----BEGIN PUBLIC KEY-----\n","")
    s = s.replace("\n-----END PUBLIC KEY-----","")
    s = s.replace("\n", "")
    return s

# *******************************************************************
#							MAIN PROGRAM
# *******************************************************************
def main():
    # if client command line has 3 args. for ex: python client.py localhost 1234 privateKey.PEM
    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print("\tUSAGE: $python3 " + sys.argv[0] + " <server_machine> <server_port> [<private_key_file>]")
        return 
    
    serverName = sys.argv[1]
    serverPort = int(sys.argv[2])
    needsPrivKeyParam = True

    try:
        primarySocket = createSocket(serverPort)
    except ConnectionRefusedError:
        print("Server is currently not accepting requests. Try again later.")
        exit(0)

    # Welcome Screen Loop
    print(idt,idt, "\n\nWelcome to Order Processing!\n")
    try:
        while True:
            exists = input("Are you a returning user? (Y or N): ")

            if exists not in ['Y', 'y', 'N', 'n']:
                print(idt, "Please enter Y or N")
                continue
            
            if exists in ['Y', 'y']: # Go straight to login
                sendMsg(primarySocket, "0")
                break
            else:
                sendMsg(primarySocket, "1") # Notify server of new user setup
            
            print("\nTo setup a new user, please enter the following information:")
            usernameVerify = False
            while not usernameVerify:
                new_userName = input("Username: ")
                if not new_userName.isalnum():
                    print(idt, "Valid usernames must be alpha-numeric characters only. Try again.")
                    continue
                
                # Send username to server to check for availability
                sendMsg(primarySocket, new_userName)

                response = recvMsg(primarySocket)
                if response == "1":
                    usernameVerify = True
                else:
                    print(idt, "Username already exists! Try another one.")
            
            emailVerify = False
            while not emailVerify:
                new_email = input("Email: ")
                if "@" not in new_email:
                    print(idt, "Please input a valid email.")
                else:
                    emailVerify = True

            passwordsVerify = False
            while not passwordsVerify:
                new_password1 = getpass.getpass("Password: ")
                new_password2 = getpass.getpass("Confirm Password: ")
                if new_password1 != new_password2:
                    print(idt, "Passwords don't match! Please retry")
                else:
                    passwordsVerify = True
            
            print("\nFinally, the server needs a public key to identify you by.")

            newRSAKey = None
            keyVerify = False
            while not keyVerify:
                generate = input("Do you want the system to generate a public/private key pair for you? (Y or N): ")
                if generate in ['Y', 'y']:

                    # Generate a new key
                    newRSAKey = RSA.generate(1024)

                    # Save the private key to file
                    privKeyFile = str(new_userName + "_Private_Key.pem")
                    f = open(privKeyFile, "wb")
                    f.write(newRSAKey.exportKey('PEM'))
                    f.close()
                    needsPrivKeyParam = False

                    # We have all the information we need. Send to server.
                    keyVerify = True
                    break
                
                _privateKeyFile = input("Please input the '.pem' file containing your private key: ")
                if _privateKeyFile[-4:] != ".sl3" or not os.path.isfile(_privateKeyFile):
                    print("Private key file is invalid. Try again.")
                    continue
                else:
                    privKeyFile = _privateKeyFile
                    # Load the key info
                    newRSA = load_key(_privateKeyFile)

                    # We have all the information we need. Send to server.
                    keyVerify = True
                    break

            if passwordsVerify and keyVerify:
                # Send all the information to the server now.
                sendMsg(primarySocket, new_userName)
                sendMsg(primarySocket, SHA512.new(new_password1.encode(codingMethod)).hexdigest())
                sendMsg(primarySocket, new_email)
                keyFormatted = formatRSAPublicKey(newRSAKey.publickey().exportKey('PEM'))
                sendMsg(primarySocket, keyFormatted)

                print("Wonderful! You have been setup as a new user! Proceed to login")
                break
            
    except KeyboardInterrupt:
        print()
        exit(0)

    # The parameter is not needed when it was just created.
    if needsPrivKeyParam:
        if len(sys.argv) != 4:
            print("Private key file necessary for use of purchasing system!")
            print("USAGE: $python3 " + sys.argv[0] + " <server_machine> <server_port> [<private_key_file>]\n")
        else:
            privKeyFile = sys.argv[3]

    authenticated = False
    userName = ""

    print("\nPlease enter your credentials.")

    while True:

        try:
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
        except(ConnectionResetError, BrokenPipeError):
            print("Connection terminated by the server. Try again later.")
            exit(0)
        except KeyboardInterrupt:
            if authenticated:
                print("\r\rPlease use the 'quit' method instead of keyboard interrupt.")
            else:
                print()
                primarySocket.close()
                exit(0)


if __name__ == "__main__":
    main()
