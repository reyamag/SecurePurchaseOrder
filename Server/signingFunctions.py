from Crypto.Cipher import DES 
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA512
from base64 import b64encode, b64decode 

##################################################
# Loads and returns the hash of a given file's contents
# @param fileName - the file
# @return - the hashed contents
##################################################
def readAndHash(fileName):

    # Read the input file
    inFile = open(fileName, 'r')
    contents = inFile.read()
    inFile.close()

    # Compute SHA-512 hash on the contents
    return SHA512.new(contents.encode())


##################################################
# Loads the RSA key object from the location
# @param keyPath - the path of the key
# @return - the RSA key object with the loaded key
##################################################
def loadKey(keyPath):

    rawKey = open(keyPath, 'r').read()
    decodedKey = b64decode(rawKey)
    rsaKey = RSA.importKey(decodedKey)

    return rsaKey


##################################################
# Signs the string using an RSA private key
# @param sigKey - the signature key
# @param data - the data to sign (encrypt)
# @return digSignature - the digital signature (encrypted data)
##################################################
def digSig(sigKey, data):

    signer = PKCS1_v1_5.new(sigKey) 

    sign = signer.sign(data) 
    return b64encode(sign)


############################################
# Saves the digital signature to a file
# @param fileName - the output file name
# @param signature - the signature to save
############################################
def saveSig(fileName, signature):

    # Signature is b-64 encoded, so binary writing is needed
    inFile = open(fileName, 'wb')
    inFile.write(signature)
    
    inFile.close()


###########################################
# Loads the signature and converts it into
# a tuple
# @param fileName - the file containing the
# signature
# @return - the signature
###########################################
def loadSig(fileName):
	
    # Signature is b-64 encoded, so binary reading is needed
    inFile = open(fileName, "rb")
    signature = inFile.read()
    inFile.close()

    return signature


#################################################
# Verifies the signature
# @param theHash - the hashed data 
# @param sig - the signature to check against
# @param veriKey - the verification key
# @return - True if the signature matched and
# false otherwise
#################################################
def verifySig(theHash, sig, veriKey):

    signer = PKCS1_v1_5.new(veriKey) 

    return signer.verify(theHash, b64decode(sig))


###########################################################
# Verifies the signature of the file
# @param fileName - the name of the file
# @param pubKey - the public key to use for verification
# @param signature - the signature of the file to verify
##########################################################
def verifyFileSig(fileName, pubKey, signature):
	
    # 1. Read the input file
    # 2. Compute an SHA-512 hash of the contents read
    hashedContents = readAndHash(fileName)

    # 3. Use the verifySig function you implemented in
    # order to verify the file signature
    result = verifySig(hashedContents, signature, pubKey)

    # 4. Return the result of the verification i.e.,
    # True if matches and False if it does not match
    if result == True: 
        print("Success! Signatures match.")
    elif result == False:
        print("Error! Signatures DO NOT match.")


##########################################################
# Returns the file signature
# @param fileName - the name of the file
# @param privKey - the private key to sign the file with
# @return fileSig - the file signature
##########################################################
def getFileSig(fileName, privKey):

    # 1. Read the input file
    # 2. Compute an SHA-512 hash of the contents read
    hashedContents = readAndHash(fileName)

    # Creating the signature for the input file with the 
    # hash using the digSig() function
    return digSig(privKey, hashedContents)