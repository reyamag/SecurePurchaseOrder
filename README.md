# SecurePurchaseOrder
A simple secure purchase order program using Python's cryptographic libraries

# Authors
Charles Bucher: charles.abucher@gmail.com <br>
Reyniel Maglian: rrmaglian@csu.fullerton.edu

# Overview

Secure Purchase Order is a Python based system that runs on a concurrent server. The system is a server/client model where you have a central server, the Order Processing Department (ODP), and n many clients it can serve at any given time. Those clients have a very specific purpose - to send orders to the server. When the server receives an order from a client, it ensures it has the required item in stock, and if so, processes the request and sends an order success email to the user. Throughout all of these server/client interactions there are necessary security precautions, ensuring data integrity, non-repudiation, authenticity, and confidentiality. <br>

The main service that the OPD (the server) provides is the secure exchanging of customer(s) orders. The OPD has to receive both the secure digital signature and the order of the customer to verify its authenticity. Other services that our system provides is being able to use AES security to help secure and authenticate the order and digital signature that the user will create when creating an order. Another main important service that our system provides is sending an email confirmation that the order has been created and notifies the user along with a timestamp. <br>


# Instructions

Ensure python3 support for sqlite3, Crypto, sockets, and threading.

1: run `$make clean` and then `$make`

This step is vitally important. Both the Client and Server subfolders use the exact same socket/signing functions, and so to reduce file length and duplicate files, those functions were placed in master header files. Those master header files reside in the main directory, NOT the subfolders. `$make clean` clears out the old copies from the subfolders and `$make` copies the master header files to the respective subfolders.

**Failing to do this step will most likely cause program failures**

2: start the server:<br>
     `$python3 server.py <SERVER_NAME> <PORT> [<EMAIL_PASS>]`
  
Instructions Notes:<br>

     <SERVER_NAME>:
          - The name of the server's IP address (use 'localhost' for testing on local machine)
          - Required
          
     <PORT>:
          - The port the server is listening on.
          - Required
          
     [<EMAIL_PASS>]:
          - The gmail password for the emailer that the server uses to send email confirmations.
          - Optional
            
    
3: Run various clients:<br>
     `$python3 client.py <SERVER_NAME> <PORT> [<PRIVATE_KEY_FILE>]`

Instructions Notes:<br>

     <SERVER_NAME>:
           - The server's IP address (use 'localhost' for testing on local machine)
           - Required
           
     <PORT>:
           - The port to connect to the server over
           - Required
     <PRIVATE_KEY_FILE>:
           - A file containing the private key file of the user
           - Optional as a command arg, but a file must be provided to the program before use

4: Perform commands:<br>
     
     test:
          Tests the connection with the server
          
     pwd:
          Changes the user's password
          
     order:
          Sends an order request to the server
          
     inventory:
          Search for an item in the inventory
          
     quit:
          Terminates the connection
          
5: Create users:<br>
     
     Before a user is authenticated, the system allows for the creation of a new user.
     This process requires a desired username, password, email, and public key be provided.
     System offers to generate public/private key pair if new user doesn't have one already.
          
          



