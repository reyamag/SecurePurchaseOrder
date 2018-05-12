# SecurePurchaseOrder
A simple secure purchase order program using Python's cryptographic libraries

# Authors
Charles Bucher: charles.abucher@gmail.com <br>
Reyniel Maglian: rrmaglian@csu.fullerton.edu

# Overview

To add.

# Instructions

Ensure python3 support for sqlite3, Crypto, sockets, and threading.

1: run `$make clean` and then `$make`

This step is vitally important. Both the Client and Server subfolders use the exact same socket/signing functions, but to reduce file length and duplicate files, those functions were placed into header files, and those master header files reside in the main directory, NOT the subfolders. `$make clean` clears out the old copies from the subfolders and `$make` copies the master header files to the respective subfolders.

**Failing to do this step will cause program failures**

2: start the server:<br>
     `$python3 server.py <SERVER_NAME> <PORT> <CLIENT_DATA> <INVENTORY_DATA> <EMAIL_PASS>`
  
Instructions Notes:<br>

     <SERVER_NAME>:
          - The name of the server's IP address (use 'localhost' for testing on local machine)
          
     <PORT>:
          - The port the server is listening on.
          
     <CLIENT_DATA>:
          - The sqlite3 (.sql3) file that contains ID, name, Password Hashes, public-keys, and emails for clients
          
     <INVENTORY_DATA>:
          - The sqlite3 file that contains the products the server has available to order
          
     <EMAIL_PASS>:
          - The gmail password for the emailer that the server uses to send email confirmations. 
            Not providing this means the server will not send confirmation emails.
    
3: Run various clients:<br>
     `$python3 client.py <SERVER_NAME> <PORT>`

Instructions Notes:<br>

     <SERVER_NAME>:
           - The server's IP address (use 'localhost' for testing on local machine)
     <PORT>:
           - The port to connect to the server over

4: Perform commands:<br>
     
     test:
          Tests the connection with the server
          
     pwd:
          Changes the user's password
          
     order:
          Sends an order request to the server
          
     quit:
          Terminates the connection
          
          



