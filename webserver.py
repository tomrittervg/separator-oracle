#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from base64 import *

import tornado.ioloop
import tornado.web
import tornado.options


IV = u'12345678abcdefgh'
SECRET_KEY = u'a1b2c3d4e5f6g7h8a1b2c3d4e5f6g7h8'
NONCE = u'12345678'
SEGMENT_SIZE = 16
EXPECTED_DELIMITERS = 2
EXTRA_DELIMITERS_OKAY = False

plaintext='timestamp|username|accesslevel'
plaintext='a|b'

def printBytes(s):
    if type(s) == 'bytearray':
        s = str(s)
    str = ""
    for c in s:
        str += '%02X ' % ord(c)
    return str

class CTREncryptHandler(tornado.web.RequestHandler):
    def get(self, plaintext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=Counter.new(64, prefix=NONCE))
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = b64encode(ciphertext)
        self.write(ciphertext)
class CTRDecryptHandler(tornado.web.RequestHandler):
    def get(self, ciphertext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=Counter.new(64, prefix=NONCE))
        ciphertext = b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext)

        parts = plaintext.split("|")
        if EXTRA_DELIMITERS_OKAY and len(parts) < EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif EXTRA_DELIMITERS_OKAY and len(parts) >= EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) != EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) == EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")
            
class OFBEncryptHandler(tornado.web.RequestHandler):
    def get(self, plaintext):
        cipher = AES.new(SECRET_KEY, AES.MODE_OFB, IV)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = b64encode(ciphertext)
        self.write(ciphertext)
class OFBDecryptHandler(tornado.web.RequestHandler):
    def get(self, ciphertext):
        cipher = AES.new(SECRET_KEY, AES.MODE_OFB, IV)
        ciphertext = b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext)

        parts = plaintext.split("|")
        if EXTRA_DELIMITERS_OKAY and len(parts) < EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif EXTRA_DELIMITERS_OKAY and len(parts) >= EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) != EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) == EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")

def unpackageIV(str):
    a = str.split("|")
    if len(a) != 2:
        raise Exception("Invalid string to unpackage: " + str)
    return b64decode(a[0]), b64decode(a[1])
class CBCEncryptHandler(tornado.web.RequestHandler):
    def get(self, plaintext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = b64encode(ciphertext)
        self.write(ciphertext)
class CBCDecryptHandler(tornado.web.RequestHandler):
    def get(self, package):
        ciphertext, localIV = unpackageIV(package)
        
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, localIV)
        plaintext = cipher.decrypt(ciphertext)

        parts = plaintext.split("|")
        if EXTRA_DELIMITERS_OKAY and len(parts) < EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif EXTRA_DELIMITERS_OKAY and len(parts) >= EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) != EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) == EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")
        
class CFBEncryptHandler(tornado.web.RequestHandler):
    def get(self, plaintext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CFB, IV, segment_size=SEGMENT_SIZE*8)
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = b64encode(ciphertext)
        self.write(ciphertext)
class CFBDecryptHandler(tornado.web.RequestHandler):
    def get(self, ciphertext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CFB, IV, segment_size=SEGMENT_SIZE*8)
        ciphertext = b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext)

        parts = plaintext.split("|")
        if EXTRA_DELIMITERS_OKAY and len(parts) < EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif EXTRA_DELIMITERS_OKAY and len(parts) >= EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) != EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) == EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull")

class PlaintextEHandler(tornado.web.RequestHandler):
    def get(self, plaintext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=Counter.new(64, prefix=NONCE))
        ciphertext = cipher.encrypt(plaintext)
        ciphertext = b64encode(ciphertext)
        self.write(ciphertext)
class PlaintextDHandler(tornado.web.RequestHandler):
    def get(self, ciphertext):
        cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=Counter.new(64, prefix=NONCE))
        ciphertext = b64decode(ciphertext)
        plaintext = cipher.decrypt(ciphertext)

        parts = plaintext.split("|")
        if EXTRA_DELIMITERS_OKAY:
            raise Exception("Bad Scenario")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) != EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            self.write(" Invalid Code ")
        elif not EXTRA_DELIMITERS_OKAY and len(parts) == EXPECTED_DELIMITERS+1:
            self.write(printBytes(plaintext))
            #self.write(" " + plaintext + " ")
            self.write(" ------ ")
            self.write("Successfull: ")
            if parts[1] == "Admin":
                print "Administrator!"
            else:
                print "Peon."
            
application = tornado.web.Application([
    (r"/cbc/encrypt/(.*)", CBCEncryptHandler),
    (r"/cbc/decrypt/(.*)", CBCDecryptHandler),
    (r"/cfb/encrypt/(.*)", CFBEncryptHandler),
    (r"/cfb/decrypt/(.*)", CFBDecryptHandler),
    (r"/ofb/encrypt/(.*)", OFBEncryptHandler),
    (r"/ofb/decrypt/(.*)", OFBDecryptHandler),
    (r"/ctr/encrypt/(.*)", CTREncryptHandler),
    (r"/ctr/decrypt/(.*)", CTRDecryptHandler),
    (r"/plaintext/encrypt/(.*)", PlaintextEHandler),
    (r"/plaintext/decrypt/(.*)", PlaintextDHandler),
])
tornado.options.parse_command_line()

if __name__ == "__main__":
    application.listen(9999)
    tornado.ioloop.IOLoop.instance().start()
