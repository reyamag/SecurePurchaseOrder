import socket

codingMethod = "UTF-8"
bufferSize = 4096

# Receive msg size before receving the message
# over a limited-size buffer
def recvMsg(sock, decode=True):

    size = int(sock.recv(4096).decode(codingMethod))
    return recvAll(sock, size, decode)


# Create a buffer that receives a specified number of bytes over
# a specified TCP socket. Can receive as actual bytes or string
def recvAll(sock, numBytes, decode):

    # The buffer (bytes or string depending on param)
    recvBuff = "" if decode else b''

    # Keep receiving till all is received
    while len(recvBuff) < numBytes:

        # Attempt to receive bytes
        tmp = sock.recv(numBytes)
        tmpBuff = tmp.decode(codingMethod) if decode else tmp

        # The other side has closed the socket
        if not tmpBuff:
            break

        # Add the received bytes to the buffer
        recvBuff += tmpBuff

    return recvBuff

def sendMsg(sock, msg, encode=True):

    if len(msg.encode(codingMethod) if encode else msg) > bufferSize:
        # User is trying to send a message that is greater than 2^bufferSize bytes.
        print(idt, "The message you are sending is too large to send over this socket.")
        return False

    # Ensure size message is exactly the size of the buffer
    size = str(len(msg.encode() if encode else msg)).zfill(bufferSize)

    # Send message size and then the actual message.
    sock.send(size.encode(), bufferSize)
    sock.send(msg.encode() if encode else msg)

    return True


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