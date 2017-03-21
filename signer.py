import socket
import argparse
import select
import sys
import random
import binascii
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

argsList =sys.argv

def mypad(somenum):
	return '0' * (4-len(str(somenum)))+str(somenum)


if argsList[1] == '--genkey':
	keys = RSA.generate(4096)

	privHandle = open('mypriv.pem','w')
	privHandle.write(keys.exportKey('PEM'))
	privHandle.close()

	pubHandle = open("mypubkey.pem",'w')
	pubHandle.write(keys.publickey().exportKey())
	pubHandle.close()

if argsList[1] == '--c':
	s = socket.socket()

	s.connect((argsList[2],9998))

	message = ""

	for i in range(4,len(argsList)):
		message = message+argsList[i] + " "
	message = message[:-1]

	lenOfMessage = mypad(len(message))




	#key = RSA.importKey(open('mypriv.pem','rb').read())
	#print(key)
	f = open('mypriv.pem','r')
	key = RSA.importKey(f.read())
	#print(key)
	h = SHA256.new(str(message))
	signer = PKCS1_v1_5.new(key)
	Signature = signer.sign(h)

	Signature_hex = binascii.hexlify(Signature)
	lenofSign = mypad(len(Signature_hex))

	sendM = str(lenOfMessage+message+lenofSign+Signature_hex)
	dataFile = open("data.dat",'w')
	dataFile.write(sendM)
	dataFile.close()

	s.send(sendM)
	s.close()
if argsList[1] == '--s':
	s=socket.socket()
	s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	s.bind(('',9998))
	s.listen(10)
	c,addr = s.accept()
	message = c.recv(1000)
	c.close()
	messageL = message[:4]
	message = message[4:]
	actualMessage = message[:int(messageL)]
	Signature = str(message[int(messageL)+4:])
	key = RSA.importKey(open('mypubkey.pem').read())
	h = SHA256.new(actualMessage)
	verifier = PKCS1_v1_5.new(key)
	if verifier.verify(h,Signature):
		print "signature is autenic"
	else:
		print"not"
