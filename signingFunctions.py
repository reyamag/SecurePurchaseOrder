from Crypto import Random
from Crypto.Cipher import AES
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
        inFile = open(fileName, 'r').read()
    else:
        contents = source

    # Compute SHA-512 hash on the contents
    return SHA512.new(contents.encode())


# Loads an RSA key object
def load_key(keyData):

    rawKey = ""

    rawKey = keyData

    #decodedKey = b64decode(rawKey)
    rsaKey = RSA.importKey(rawKey)

    return rsaKey


# Signs some data using an RSA private key
def sign_data(sigKey, data):

    signer = PKCS1_v1_5.new(sigKey) 

    signedData = signer.sign(data) 

    return b64encode(signedData)


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
def verifyFileSig(source, pubKey, signature, isFile):

    hashedContents = readAndHash(source, isFile)

    return verify_sign(hashedContents, signature, pubKey)


# Creates a signature from a data source.
# Can be a file or data passed directly 
def getFileSig(source, privKey, isFile):

    # 1. Read the input file
    # 2. Compute an SHA-512 hash of the contents read
    hashedContents = readAndHash(source, isFile)

    # Creating the signature for the input file with the 
    # hash using the sign_data() function
    return sign_data(privKey, hashedContents)

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

# AES Block Encryption.
# Class design used from: https://gist.github.com/crmccreary/5610068

def pad(s):
    BLOCK_SIZE = 16
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def unpad(s):
    return s[0:-ord(s[-1])]

class AESCipher:

    __slots__ = ['key', 'init_vector']

    def __init__(self, key, iv):
        self.key = key
        self.init_vector = iv

    def encrypt(self, plaintext):

        plaintext = pad(plaintext) # Ensure padded data
        cipher = AES.new(self.key, AES.MODE_ECB, self.init_vector)

        return (self.init_vector + cipher.encrypt(plaintext))

    def decrypt(self, ciphertext):

        ciphertext = ciphertext
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB, self.init_vector)
        return unpad(cipher.decrypt(ciphertext).decode())