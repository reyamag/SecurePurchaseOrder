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
serverName = ""
codingMethod = "UTF-8"
GLOBAL_threads = []
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

def retrievePasswordHash(userName):

    clientDB = sqlite3.connect(getDBPath(sys.argv[3]))
    cursor = clientDB.cursor()
    sqlStr = "SELECT Password_Hash FROM clients WHERE Client_Name='{}'".format(userName)
    result = cursor.execute(sqlStr).fetchone()

    cursor.close()
    clientDB.close()

    return "-1" if result == None else result[0]

def updatePassword(userName, newPassword):

    result = False

    clientDB = sqlite3.connect(getDBPath(sys.argv[3]))
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

    inventoryDB = sqlite3.connect(getDBPath(sys.argv[4]))
    cursor = inventoryDB.cursor()
    sqlStr = "UPDATE inventory SET InStock={} WHERE ItemDescription='{}'".format(currentStock-amountOrdered, item)
    cursor.execute(sqlStr)
    inventoryDB.commit()
    cursor.close()
    inventoryDB.close()

    return

def getItemStock(item):

    inventoryDB = sqlite3.connect(getDBPath(sys.argv[4]))
    cursor = inventoryDB.cursor()
    sqlStr = "SELECT InStock FROM Inventory WHERE ItemDescription='{}'".format(item)
    result = cursor.execute(sqlStr).fetchone()

    cursor.close()
    inventoryDB.close()

    return -1 if result == None else result[0]

def getUserEmail(userName):

    clientDB = sqlite3.connect(getDBPath(sys.argv[3]))
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

    # 1. Ensure correct client authentication...
    authenticated = False
    clientUserName = ""
    emailEnabled = (len(sys.argv) == 6) # Server was started with the email password

    while not authenticated:
        print("Waiting for authentication....")
        clientUserName = recvMsg(clientSocket)
        clientPass = recvMsg(clientSocket)

        # Hash input and compare to stored value for this client
        correctHash = retrievePasswordHash(clientUserName)
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
        clientCommand = recvMsg(clientSocket)

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

            if passwordFromUser == retrievePasswordHash(clientUserName):
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
            clientOrder = recvMsg(clientSocket)
            
            ##################################################################
            ##################################################################
            ###############################TODO###############################
            ##################################################################
            ##################################################################
            # Need to verify signature and hash and whatnot from this message.
            # Implement simple protocol to ensure everything checks out.
            # Signature needs to be verified from the client database
            # TODO
            # TODO
            # TODO
            # TODO
            ##################################################################
            ##################################################################
            ##################################################################
            ##################################################################
            ##################################################################

            # Since the digital signature was legitamite, create order
            order = Order(initString=clientOrder)

            # Confirm order has a fresh timestamp.
            if datetime.utcnow().timestamp() - order._timeOrdered > TIMEOUT_WINDOW:
                sendMsg(clientSocket, "0::Order timeout. Please resubmit")
                continue
            
            # Confirm product availability
            available = getItemStock(order._description)
            if available == -1:
                sendMsg(clientSocket, "0::Item does not exist in inventory")
                continue
            elif available - order._quantity < 0:
                sendMsg(clientSocket, ("0::Order exceeds available inventory. " + 
                                        "Please modify or redo your order."))
                continue

            # Update the inventory to reflect the transaction.
            updateInventory(order._description, order._quantity)
            successMsg = "1::Order processed successfully."
            
            # If server was started without an email password, do not send email
            if emailEnabled and sendMail(order, getUserEmail(clientUserName), clientUserName, sys.argv[5]):
                successMsg += ("\n     Email confirmation sent successfully to: " +
                                str(getUserEmail(clientUserName)))
            else:
                successMsg += "\n     However, email confirmation was unable to be sent"

            sendMsg(clientSocket, successMsg)
            
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

    if len(sys.argv) < 5 or len(sys.argv) > 6:
        print ("\tUSAGE: $python3 " + sys.argv[0] + " <server_name> <port_number> <client_data> <inventory_dat> <email_password>")
        return

    serverName = sys.argv[1]
    serverPort = int(sys.argv[2])
    
    if sys.argv[3][-4:] != ".sl3" or not isfile(sys.argv[3]):
        print("Please import a valid sqlite3 (.sl3 extension) database file for clients")
        return

    if sys.argv[4][-4:] != ".sl3" or not isfile(sys.argv[4]):
        print("Please import a valid sqlite3 (.sl3 extension) database file for inventory")
        return

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
