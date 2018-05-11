from Crypto.Cipher import DES 
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode 
from datetime import datetime

# Loads and returns the hash of some data
# Data can be in file or directly passed
def readAndHash(source, isFile):

    contents = ""

    # Read the input file
    if isFile:
        inFile = open(fileName, 'r')
        contents = inFile.read()
        inFile.close()
    else:
        contents = source

    # Compute SHA-512 hash on the contents
    return SHA512.new(contents.encode())


# Loads an RSA key object from the location specified
# Can be a file or directly passed
def load_key(keyData, isFile):

    rawKey = ""

    if isFile:
        rawKey = open(keyPath, 'r').read()
    else:
        rawKey = keyData

    decodedKey = b64decode(rawKey)
    rsaKey = RSA.importKey(decodedKey)

    return rsaKey


# Signs some data using an RSA private key
def sign_data(sigKey, data):

    signer = PKCS1_v1_5.new(sigKey) 

    sign = signer.sign(data) 
    return b64encode(sign)


# Saves the digital signature to a file
def save_sig(fileName, signature):

    # Signature is b-64 encoded, so binary writing is needed
    inFile = open(fileName, 'wb')
    inFile.write(signature)
    
    inFile.close()


# Loads a signature from a file
def load_sig(fileName):
	
    # Signature is b-64 encoded, so binary reading is needed
    inFile = open(fileName, "rb")
    signature = inFile.read()
    inFile.close()

    return signature


# Verifies a signature against a public key
def verify_sign(hashData, sig, veriKey):

    signer = PKCS1_v1_5.new(veriKey) 

    return signer.verify(hashData, b64decode(sig))


# Verifies the signature of the file
def verifyFileSig(fileName, pubKey, signature):
	
    # 1. Read the input file
    # 2. Compute an SHA-512 hash of the contents read
    hashedContents = readAndHash(fileName)

    # 3. Use the verifySig function you implemented in
    # order to verify the file signature
    return verifySig(hashedContents, signature, pubKey)


# Loads a signature from a data source.
# Can be a file or data passed directly 
def getFileSig(fileName, isFile, privKey):

    # 1. Read the input file
    # 2. Compute an SHA-512 hash of the contents read
    hashedContents = readAndHash(fileName, isFile)

    # Creating the signature for the input file with the 
    # hash using the digSig() function
    return digSig(privKey, hashedContents)

# Arbitrary Design on what an 'Order' is.
class Order:

    __slots__ = ["_description", "_quantity", "_timeOrdered", "_orderedBy"]

    # Create an order based on a list, or an initialization String
    def __init__(self, initList=None, initString=None):

        if initList == None and initString != None:
            parsed = str(initString).split("::")
            self._description = parsed[0]
            self._quantity = int(parsed[1])
            self._timeOrdered = int(parsed[2])
            self._orderedBy = parsed[3]
        elif initList != None and initString == None:
            self._description = str(initList[0])
            self._quantity = int(str(initList[1]))
            self._timeOrdered = int(str(initList[2]))
            self._orderedBy = str(initList[3])
        else:
            self._description = ""
            self._quantity = 0
            self._timeOrdered = 0
            self._orderedBy = ""

    def __str__(self):
        return self._description + "::" + str(self._quantity) + "::" + str(self._timeOrdered) + "::" + self._orderedBy
