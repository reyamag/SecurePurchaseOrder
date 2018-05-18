import socket
import subprocess
import sys
import threading
import sqlite3
from os.path import isfile
from Crypto.Hash import SHA512
import random
from signingFunctions import *
from socketFunctions import *
import os
import smtplib

# Server-wide variables
bufferSize = 4096
request_queue = 10

if len(sys.argv) < 3:
    print ("\tUSAGE: $python3 " + sys.argv[0] + " <server_name> <port_number> [<email_password>]")
    exit(-1)
serverName = sys.argv[1]
serverPort = int(sys.argv[2])
clientDB_file = "clientData.sl3"
inventoryDB_file = "inventory.sl3"
codingMethod = "UTF-8"
GLOBAL_threads = []
ALL_threads = []
TIMEOUT_WINDOW = 20 # 20 seconds


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

    __slots__ = ["threadID", "name", "counter", "serverSocket", "serverPort", "clientSocket", "addr"]

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

def getDBPath(db_file):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(BASE_DIR, db_file)

def getPasswordHash(userName):

    clientDB = sqlite3.connect(getDBPath(clientDB_file))
    cursor = clientDB.cursor()
    sqlStr = "SELECT Password_Hash FROM clients WHERE Client_Name='{}'".format(userName)
    result = cursor.execute(sqlStr).fetchone()

    cursor.close()
    clientDB.close()

    return "-1" if result == None else result[0]

def updatePassword(userName, newPassword):

    result = False

    clientDB = sqlite3.connect(getDBPath(clientDB_file))
    cursor = clientDB.cursor()
    sqlStr = "UPDATE clients SET Password_Hash='{}' WHERE Client_Name='{}'".format(newPassword, userName)
    cursor.execute(sqlStr)
    clientDB.commit()
    result = (cursor.rowcount == 1)
    cursor.close()
    clientDB.close()
    
    return result

def updateInventory(item, amountOrdered):
    
    currentStock = getItemStock(item)

    inventoryDB = sqlite3.connect(getDBPath(inventoryDB_file))
    cursor = inventoryDB.cursor()
    sqlStr = "UPDATE inventory SET InStock={} WHERE ItemDescription='{}'".format(currentStock-amountOrdered, item)
    cursor.execute(sqlStr)
    inventoryDB.commit()
    cursor.close()
    inventoryDB.close()

    return

def createNewUser(username, passwordHash, email, publicKey):

    clientDB = sqlite3.connect(getDBPath(clientDB_file))
    cursor = clientDB.cursor()
    sqlStr = "INSERT INTO clients (Client_Name, Password_Hash, Public_Key, Email) "
    sqlStr += "VALUES ('{}', '{}', '{}', '{}')".format(username, passwordHash, publicKey, email)
    cursor.execute(sqlStr)
    clientDB.commit()
    cursor.close()
    clientDB.close()

    return

def getItemStock(item):

    inventoryDB = sqlite3.connect(getDBPath(inventoryDB_file))
    cursor = inventoryDB.cursor()
    sqlStr = "SELECT InStock FROM Inventory WHERE ItemDescription='{}'".format(item)
    result = cursor.execute(sqlStr).fetchone()

    cursor.close()
    inventoryDB.close()

    return -1 if result == None else result[0]

def getClientPubKey(userName):

    clientDB = sqlite3.connect(getDBPath(clientDB_file))
    cursor = clientDB.cursor()
    sqlStr = "SELECT Public_Key FROM clients WHERE Client_Name='{}'".format(userName)
    result = cursor.execute(sqlStr).fetchone()

    cursor.close()
    clientDB.close()

    if result == None:
        return None
    
    keyRaw = result[0]
    
    return str("-----BEGIN PUBLIC KEY-----\n" + 
                keyRaw[:64] + "\n" +
                keyRaw[64:128] + "\n" +
                keyRaw[128:192] + "\n" +
                keyRaw[192:] + "\n" +
                "-----END PUBLIC KEY-----")


def getUserEmail(userName):

    clientDB = sqlite3.connect(getDBPath(clientDB_file))
    cursor = clientDB.cursor()
    sqlStr = "SELECT Email FROM clients WHERE Client_Name='{}'".format(userName)
    result = cursor.execute(sqlStr).fetchone()

    cursor.close()
    clientDB.close()

    return result[0]

# Function source largly used from online example:
# https://stackoverflow.com/questions/17332384/python-3-send-email-smtp-gmail-error-smtpexception
def sendMail(order, email_TO, recipientName, password):

    SUBJECT = "Order Confirmation from"
    TEXT = str("Hi " + recipientName + 
            "\nYour order for " + str(order._quantity) + " " + 
            str(order._description) + str("'s" if (order._quantity > 1) else "") +
            " has been successfully processed and is on it's way." + 
            "\n\nHave a wonderful day!"
            "\n\n\n(This message was sent to you by " + str(sys.argv[1]) + 
            " using Python3.6)")

    # Gmail Sign In
    gmail_sender = 'OrderConfirmation.cpsc452.sp18@gmail.com'

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.ehlo()
    server.starttls()
    try:
        server.login(gmail_sender, password)
    except:
        server.quit()
        print("Invalid credentials")
        return False

    BODY = '\r\n'.join(['To: %s' % email_TO,
                        'From: %s' % gmail_sender,
                        'Subject: %s' % SUBJECT,
                        '', TEXT])
    retVal = False
    try:
        server.sendmail(gmail_sender, [email_TO], BODY)
        print("Email sent successfully")
        retVal = True
    except:
        print("Issue sending email")

    server.quit()
    return retVal

def mainClientProcess(threadName, serverSocket, serverPort, clientSocket, addr):

    try:
        newUserSetup = recvMsg(clientSocket)
    
        if newUserSetup == "1":
            while True:
                print("Prepare to receive user - must validate if already exists!")
                newPotentialUser = recvMsg(clientSocket)
                
                # A retrieved password hash means this user exists!
                if getPasswordHash(newPotentialUser) != "-1":
                    print("Report that user exists")
                    sendMsg(clientSocket, "0")
                else:
                    print("Report that user is unique")
                    sendMsg(clientSocket, "1")
                    break
            
            # Wait to receive more....
            print("Wait to receive more...")
            newUser = recvMsg(clientSocket)
            newPasswordHash = recvMsg(clientSocket)
            newEmail = recvMsg(clientSocket)
            newPublicKey = recvMsg(clientSocket)

            createNewUser(newUser, newPasswordHash, newEmail, newPublicKey)

    except ValueError:
        print("User terminated during new user setup phase")
        clientSocket.close()
        return

    # 1. Ensure correct client authentication...
    authenticated = False
    clientUserName = ""
    emailEnabled = (len(sys.argv) == 6) # Server was started with the email password

    while not authenticated:
        print("Waiting for authentication....")
        try:
            clientUserName = recvMsg(clientSocket)
            clientPass = recvMsg(clientSocket)
        except ValueError:
            print("User terminated during credential authentication.")
            clientSocket.close()
            return

        # Hash input and compare to stored value for this client
        correctHash = getPasswordHash(clientUserName)
        enteredHash = SHA512.new(clientPass.encode(codingMethod)).hexdigest()

        # Client Msg - "<Flag>::<Msg>", where <Msg> may be nothing or ErrorMsg
        if correctHash == enteredHash:
            sendMsg(clientSocket, str("1"))
            authenticated = True
        elif correctHash == "-1":
            sendMsg(clientSocket, "0::User does not exist. Try again.")
        else:
            sendMsg(clientSocket, "0::Password is invalid. Try again.")
            print("Credentials do not match. Report failure")
    
    print("User successfully authenticated. Wait for command.")

    while True:
        clientCommand = ""
        
        try:
            clientCommand = recvMsg(clientSocket)
        except ValueError:
            print("Incorrect message format from user. Exiting thread.")
            clientSocket.close()
            return

        args = clientCommand.split(" ")

        if not clientCommand:
            print("Client connection has unexpectedly terminated")
            break

        if clientCommand == "test":
            # test protocol...
            # Receive test message from client
            # Send test message to client
            # Wait for another command.

            msg = recvMsg(clientSocket)
            print("Received test message from client")
            sendMsg(clientSocket, "Test")
            print("Sent test message to client")
            print("Connection test successful")

        elif clientCommand == "pwd":
            # pwd protocol...
            # Receives old password message from user
            # Sends password verfication message to user
            #   If verification failed, wait for another command.
            # Recieve new password message from user
            #   If message has 0 flag at msg start, wait for another command.
            # Send update success message to user

            print("Client wants to update password")

            # Receive current password from user, compare to database, and report success
            passwordFromUser = recvMsg(clientSocket)

            if passwordFromUser == getPasswordHash(clientUserName):
                # Notify user old password is correct. Wait for furthur input.
                sendMsg(clientSocket, "1")
            else:
                print("Passwords do not match")
                sendMsg(clientSocket, "0")
                continue # Wait for a new command since this one 'failed'

            clientMsg = recvMsg(clientSocket)
            parsedMsg = clientMsg.split("::")

            if parsedMsg[0] == "1":
                print("Updating password.")
                if updatePassword(clientUserName, parsedMsg[1]):
                    sendMsg(clientSocket, "1")
                else:
                    sendMsg(clientSocket, "0")
                    print("Password update unsucessful. Report to client")
            else:
                print("Client terminated 'pwd' command")

        elif clientCommand == "order":
            # Order protocol...
            # Receives order message from client
            # Sends response message to client
            #   Response contains success 1\0 flag at beginning of message

            print("Client wants to order")
            print("Received:")
            clientSignature = recvMsg(clientSocket, decode=False)
            print("\tClient Signature")
            aesKey = recvMsg(clientSocket, decode=False)
            print("\tAES key")
            iv = recvMsg(clientSocket, decode=False)
            print("\tAES IV Vector")
            encryptedMsg = recvMsg(clientSocket, decode=False)
            print("\tEncrypted message")


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
            # TODO: Decrypt AES & IV keys using RSA public key

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

            # 1. Decrypt the message using the AES key and IV vector.
            myDecryptor = AESCipher(aesKey, iv)
            plaintext_Order = myDecryptor.decrypt(encryptedMsg)

            # 2. Generate the hash of the data sent.
            hash_plaintext_Order = readAndHash(plaintext_Order, isFile=False)

            print("Verifying signature with public key against hash...")
            clientsPubKey = load_key(getClientPubKey(clientUserName))
            
            # 3. Verify signature of client AND integrity of the order.
            if not verify_sign(hash_plaintext_Order, clientSignature, clientsPubKey):
                sendMsg(clientSocket, "0::Signature is invalid. Order not processed.")
                continue

            print("Signature is valid and order data integrity verified. Proceed")

            # 4. Signature and data integrity confirmed. Generate order.
            order = Order(initString=plaintext_Order)

            # 5. Confirm order has a fresh timestamp.
            if datetime.utcnow().timestamp() - order._timeOrdered > TIMEOUT_WINDOW:
                print("Timestamp invalid.")
                sendMsg(clientSocket, "0::Order timeout. Please resubmit")
                continue
            
            # 6. Confirm product availability
            available = getItemStock(order._description)
            if available == -1:
                sendMsg(clientSocket, "0::Item does not exist in inventory")
                continue
            elif available - order._quantity < 0:
                sendMsg(clientSocket, ("0::Order exceeds available inventory. " + 
                                        "There are only " + str(available) + " left. " +
                                        "Please modify or redo your order."))
                continue

            # 7. Update the inventory to reflect the transaction.
            updateInventory(order._description, order._quantity)
            successMsg = "1::Order processed successfully."
            print(successMsg.split("::")[1])
            
            # If server was started without an email password, do not send email
            if emailEnabled and sendMail(order, getUserEmail(clientUserName), clientUserName, sys.argv[3]):
                successMsg += ("\n     Email confirmation sent successfully to: " +
                                str(getUserEmail(clientUserName)))
            else:
                successMsg += "\n     However, email confirmation was unable to be sent"

            sendMsg(clientSocket, successMsg)

        elif clientCommand == "inventory":
            print("Client is checking product availability")
            item = recvMsg(clientSocket)

            available = getItemStock(item)
            if available == -1:
                sendMsg(clientSocket, "0::'" + item + "' does not exist in inventory")
            else:
                s = str("1::There " + 
                        str("is " if available == 1 else "are ") + 
                        str(available) + " " +
                        item + str("'s " if available > 1 else " ") +
                        "left in stock.")
                sendMsg(clientSocket, s)
            
        elif clientCommand == "quit":
            # Quit protocol...
            # No messages to send/receive
            # Close connection with client and exit

            print("Quit command received. Closing socket now")
            clientSocket.close()
            break
        else:
            print("Not a valid command")



# *******************************************************************
#                             MAIN PROGRAM
# *******************************************************************
def main():

    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print ("\tUSAGE: $python3 " + sys.argv[0] + " <server_name> <port_number> [<email_password>]")
        return
    
    if not isfile(getDBPath('clientData.sl3')):
        print("clientData.sl3 doesn't exist on server! Please create")
        return

    if not isfile(getDBPath('inventory.sl3')):
        print("inventory.sl3 doesn't exist on server! Please create")
        return

    if len(sys.argv) < 4:
        print("WARNING: Email functionality not enabled due to no password input")

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
        try:
            (clientSocket, addr) = serverSocket.accept()
            print("Connected with client", addr, "@", serverPort, "\n")

            # Create a unique thread for this connection and continue listening
            thrID = 1 if len(GLOBAL_threads) == 0 else getFirstAvailableThreadID()
            GLOBAL_threads.append(thrID)
            GLOBAL_threads.sort()
            thread = serverThread(thrID, "Thread-" + str(thrID), thrID, serverSocket, serverPort, clientSocket, addr)
            ALL_threads.append(thread)
            thread.start()
        except KeyboardInterrupt:
            print("\rShutting off server.")
            os._exit(0)
        except ValueError:
            print("Incorrect value from user. Keep listening.")
        


if __name__ == "__main__":
    main()
