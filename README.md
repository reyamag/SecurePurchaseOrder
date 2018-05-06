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

2: start the server:<br>
     `$python3 server.py <PORT> <CLIENT_DATA>`
  
     Notes:<br>
          <PORT>: the port the server is listening on.<br>
          <CLIENT_DATA>: the sqlite3 (.sql3) file that contains ID, name, Password Hashes, public-keys, and emails for clients<br>
    
3: Run various clients:<br>
     `$python3 client.py <SERVER_NAME> <PORT>`
     
     Notes:<br>
          <SERVER_NAME>: the server's IP address (use 'localhost' for testing on local machine')
          <PORT>: the port to connect to the server over

4: Perform commands:<br>
     
     test:
          Tests the connection with the server
          
     pwd:
          Changes the password
          
     send_order:
          Sends an order request to the server
          
     quit:
          Terminates the connection
          
          



