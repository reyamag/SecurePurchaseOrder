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
    print("\tUSAGE: $python3 " + sys.argv[0] + " <server_name> <port_number> [<email_password>]")
    exit(-1)
serverName = sys.argv[1]
serverPort = int(sys.argv[2])
clientDB_file = "clientData.sl3"
inventoryDB_file = "inventory.sl3"
serverPrivateKeyFile = "Server_Private_Key.pem"
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
        outputLog("Starting thread", self)
        mainClientProcess(self)
        outputLog("Exiting", self)
        self.stop() # Kill thread
        GLOBAL_threads.remove(self.threadID)

    # Methods to wait for thread to exit properly using join()
    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()


def outputLog(msg, thread=None):
    rightNow = int(datetime.utcnow().timestamp())

    if thread != None:
        print(thread.name + ", " + str(rightNow) + " -- " + msg)
    else:
        print("ROOT, " + str(rightNow) + " -- " + msg)



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
def sendMail(order, email_TO, recipientName, password, thread):

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
        outputLog("Invalid credentials", thread)
        return False

    BODY = '\r\n'.join(['To: %s' % email_TO,
                        'From: %s' % gmail_sender,
                        'Subject: %s' % SUBJECT,
                        '', TEXT])
    retVal = False
    try:
        server.sendmail(gmail_sender, [email_TO], BODY)
        outpuLog("Email sent successfully", thread)
        retVal = True
    except:
        outputLog("Issue sending email", thread)

    server.quit()
    return retVal

def mainClientProcess(managingthread):

    clientSocket = managingthread.clientSocket

    try:
        newUserSetup = recvMsg(clientSocket)
    
        if newUserSetup == "1":
            while True:
                outputLog("Prepare to receive user - must validate if already exists!", managingthread)
                newPotentialUser = recvMsg(clientSocket)
                
                # A retrieved password hash means this user exists!
                if getPasswordHash(newPotentialUser) != "-1":
                    outputLog("Report that user exists", managingthread)
                    sendMsg(clientSocket, "0")
                else:
                    outputLog("Report that user is unique", managingthread)
                    sendMsg(clientSocket, "1")
                    break
            
            # Wait to receive more....
            outputLog("Wait to receive more...", managingthread)
            newUser = recvMsg(clientSocket)
            newPasswordHash = recvMsg(clientSocket)
            newEmail = recvMsg(clientSocket)
            newPublicKey = recvMsg(clientSocket)

            createNewUser(newUser, newPasswordHash, newEmail, newPublicKey)

    except ValueError:
        outputLog("User terminated during new user setup phase", managingthread)
        clientSocket.close()
        return

    # 1. Ensure correct client authentication...
    authenticated = False
    clientUserName = ""
    emailEnabled = (len(sys.argv) == 6) # Server was started with the email password

    while not authenticated:
        outputLog("Waiting for authentication....", managingthread)
        try:
            clientUserName = recvMsg(clientSocket)
            clientPass = recvMsg(clientSocket)
        except ValueError:
            outputLog("User terminated during credential authentication.", managingthread)
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
            outputLog("Credentials do not match. Report failure", managingthread)
    
    outputLog("User successfully authenticated. Wait for command.", managingthread)

    while True:
        clientCommand = ""
        
        try:
            clientCommand = recvMsg(clientSocket)
        except ValueError:
            outputLog("Incorrect message format from user. Exiting thread.", managingthread)
            clientSocket.close()
            return

        args = clientCommand.split(" ")

        if not clientCommand:
            outputLog("Client connection has unexpectedly terminated", managingthread)
            break

        if clientCommand == "test":
            # test protocol...
            # Receive test message from client
            # Send test message to client
            # Wait for another command.

            msg = recvMsg(clientSocket)
            outputLog("Received test message from client", managingthread)
            sendMsg(clientSocket, "Test")
            outputLog("Sent test message to client", managingthread)
            outputLog("Connection test successful", managingthread)

        elif clientCommand == "pwd":
            # pwd protocol...
            # Receives old password message from user
            # Sends password verfication message to user
            #   If verification failed, wait for another command.
            # Recieve new password message from user
            #   If message has 0 flag at msg start, wait for another command.
            # Send update success message to user

            outputLog("Client wants to update password", managingthread)

            # Receive current password from user, compare to database, and report success
            passwordFromUser = recvMsg(clientSocket)

            if passwordFromUser == getPasswordHash(clientUserName):
                # Notify user old password is correct. Wait for furthur input.
                sendMsg(clientSocket, "1")
            else:
                outputLog("Passwords do not match", managingthread)
                sendMsg(clientSocket, "0")
                continue # Wait for a new command since this one 'failed'

            clientMsg = recvMsg(clientSocket)
            parsedMsg = clientMsg.split("::")

            if parsedMsg[0] == "1":
                outputLog("Updating password.", managingthread)
                if updatePassword(clientUserName, parsedMsg[1]):
                    sendMsg(clientSocket, "1")
                else:
                    sendMsg(clientSocket, "0")
                    outputLog("Password update unsucessful. Report to client", managingthread)
            else:
                outputLog("Client terminated 'pwd' command", managingthread)

        elif clientCommand == "order":
            # Order protocol...
            # Receives order message from client
            # Sends response message to client
            #   Response contains success 1\0 flag at beginning of message

            outputLog("Client wants to order", managingthread)
            outputLog("Received:", managingthread)
            clientSignature = recvMsg(clientSocket, decode=False)
            outputLog("\tClient Signature", managingthread)
            aesKey_encrypted = recvMsg(clientSocket, decode=False)
            outputLog("\tAES key (encrypted)", managingthread)
            iv_encrypted = recvMsg(clientSocket, decode=False)
            outputLog("\tAES IV Vector (encrypted)", managingthread)
            encryptedMsg = recvMsg(clientSocket, decode=False)
            outputLog("\tEncrypted message", managingthread)


            # Decrypt the session key information w/ server's private key
            serverPrivateKey = load_key(load_sig(serverPrivateKeyFile))
            aesKey = serverPrivateKey.decrypt(aesKey_encrypted)
            iv = serverPrivateKey.decrypt(iv_encrypted)
            outputLog("Decryption of session keys successful", managingthread)


            # 1. Decrypt the message using the AES key and IV vector.
            myDecryptor = AESCipher(aesKey, iv)
            plaintext_Order = myDecryptor.decrypt(encryptedMsg)

            # 2. Generate the hash of the data sent.
            hash_plaintext_Order = readAndHash(plaintext_Order, isFile=False)

            outputLog("Verifying signature with public key against hash...", managingthread)
            clientsPubKey = load_key(getClientPubKey(clientUserName))
            
            # 3. Verify signature of client AND integrity of the order.
            if not verify_sign(hash_plaintext_Order, clientSignature, clientsPubKey):
                sendMsg(clientSocket, "0::Signature is invalid. Order not processed.")
                continue

            outputLog("Signature is valid and order data integrity verified. Proceed", managingthread)

            # 4. Signature and data integrity confirmed. Generate order.
            order = Order(initString=plaintext_Order)

            # 5. Confirm order has a fresh timestamp.
            if datetime.utcnow().timestamp() - order._timeOrdered > TIMEOUT_WINDOW:
                outputLog("Timestamp invalid.", managingthread)
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
            outputLog(successMsg.split("::")[1])
            
            # If server was started without an email password, do not send email
            if emailEnabled and sendMail(order, getUserEmail(clientUserName), clientUserName, sys.argv[3], managingthread):
                successMsg += ("\n     Email confirmation sent successfully to: " +
                                str(getUserEmail(clientUserName)))
            else:
                successMsg += "\n     However, email confirmation was unable to be sent"

            sendMsg(clientSocket, successMsg)

        elif clientCommand == "inventory":
            outputLog("Client is checking product availability", managingthread)
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

            outputLog("Quit command received. Closing socket now", managingthread)
            clientSocket.close()
            break
        else:
            outputLog("Not a valid command", managingthread)



# *******************************************************************
#                             MAIN PROGRAM
# *******************************************************************
def main():

    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print("\tUSAGE: $python3 " + sys.argv[0] + " <server_name> <port_number> [<email_password>]")
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
    outputLog("Socket created")

    # bind socket to host and port
    try:
        serverSocket.bind((serverName, serverPort))
    except socket.error as msg:
        outputLog("Bind failed. Error Code:", str(msg))

        serverSocket.close()
        return

    outputLog("Socket bind complete")

    serverSocket.listen(request_queue)
    outputLog("Socket now listening")

    # Listen forever
    while True:
        outputLog("Awaiting connection...")

        # Block until connection is received
        try:
            (clientSocket, addr) = serverSocket.accept()
            outputLog(str("Connected with client ") + str(addr) + " @ " + str(serverPort))

            # Create a unique thread for this connection and continue listening
            thrID = 1 if len(GLOBAL_threads) == 0 else getFirstAvailableThreadID()
            GLOBAL_threads.append(thrID)
            GLOBAL_threads.sort()
            thread = serverThread(thrID, "Thread-" + str(thrID), thrID, serverSocket, serverPort, clientSocket, addr)
            ALL_threads.append(thread)
            thread.start()
        except KeyboardInterrupt:
            outputLog("\rShutting off server.")
            os._exit(0)
        except ValueError:
            outputLog("Incorrect value from user. Keep listening.")
        


if __name__ == "__main__":
    main()
