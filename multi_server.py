#CS544-Computer Networks
#Developer: Mruga Shah
#6/7/2019
#This file contains the server side programming that runs a virtual server that talks to the clients that connect to it.
#It is a concurrent server that can handle multiple connections. It is used to send out replies/verification/error out to the client.
#It ensures that the communication happens in a secure manner and the client is not an attacker.
#
from socket import *
import threading
import struct
import random
import pickle

#The clientThread function receives the client PDU's and analyzes them so as to read the correct message at the right stage(DFA state)
#It also unpacks each message and uses the information in each PDU to either validate the message and move on to next stage(DFA state)
#Or sets an error bit
def clientThread(conn):
    while True:
    	sentence=conn.recv(12000)  	#recieves the data sent by the client
    	if not sentence:
                break
    	rcvd = pickle.loads(sentence)
    	msglen = rcvd[0]		#first field receieved is length.it tells the server how much to read and what message it should expect
    	if msglen == 16 and rcvd[1]==0:		#If the message length is right
    	#SESSION ESTABLISHMENT MESSAGE
    		t = struct.unpack(b'6sii',rcvd[2]) #unpacks the PDU in the form of struct
    		sr = list(b'Server')

    		if t[2]==0 and t[0].decode('ascii')=='Client':  #verifies that the message is from the client using the "Client" string
    			comm = 1				#change the state
    			rand = random.randint(1,100)		#generate a random number to be sent to the client
    			reply = struct.pack(b'BBBBBBii',sr[0],sr[1],sr[2],sr[3],sr[4],sr[5],rand,comm)   #packs the data into a struct format
    			sid = rand*t[1]				#calculate the session id using the client_random_no*server_random_no
    			print("New client connected")
    			#print("sid",sid)
    			conn.send(reply)   			#sends the PDU with server values to the client
    		else:				#if the state/the client name is not verified
    			comm=0					#do not change state
    			reply = struct.pack(b'BBBBBBii',t[0][0],t[0][1],t[0][2],t[0][3],t[0][4],t[0][5],0,comm)   #packs the data into a struct format
    			conn.send(reply)			#create and send PDU to the server
    	elif msglen==16 and rcvd[1]==1:		#reads the message if the message length is correct and the state is correct
    	#VERSION NEGOTIATION MESSAGE
    		t = struct.unpack('iiii',rcvd[2])

    		if t[0]==sid and t[2]==1 and version == t[1]: 	#if the version id is verified and the state is correct and the versions match
    			comm1 = 2				#change the state
    			error_bit = 0				#no error
    			reply1 = struct.pack('iiii',sid,version,comm1,error_bit)
    			conn.send(reply1)			#create and send the PDU
    		else:						#if either the session id/version/state do not match
    			comm1=1					#dont change the state
    			error_bit = 1				#set the error bit
    			reply1 = struct.pack('iiii',sid,version,comm1,error_bit)
    			conn.send(reply1)			#create and send the PDU
    	elif msglen==12 and rcvd[1]==2:			#if the message length is correct and the state is correct
    	#AUTHENTICATION MESSAGE
    		t = struct.unpack('iii',rcvd[3])

    		if t[2]==2 and t[0]==sid and rcvd[2] == '21d1c8454d8bb0eb68f99c05ffe3f914add36d142d37a0f9e4b95ac8': #if the state is right and the hash matches the one sent by the client
    			comm2 = 3			#change the state
    			error_bit = 0			#no error
    			reply2 = struct.pack('iii',sid,error_bit,comm2)
    			conn.send(reply2)		#create and send the PDU
    		else:					#if the hash/session id/state is not correct
    			comm2 = 2			#dont change state
    			error_bit = 1			#set error bit
    			reply2 = struct.pack('iii',sid,error_bit,comm2)
    			conn.send(reply2)		#create and send PDU
    	elif msglen==24 and rcvd[1]==3:
    		#HASH ALGORITHM SELECTION MESSAGE
    		t = struct.unpack(b'i3si4sii',rcvd[2])

    		if t[5]==3 and t[0]==sid:		#if the session id is verified and the state is correct
    			comm3 = 4			#change the state
    			bool1 = 1			#select the first algorithm by setting the boolean value to 1
    			bool2 = 0
    			reply3 = struct.pack(b'iBBBiBBBBii',sid,t[1][0],t[1][1],t[1][2],bool1,t[3][0],t[3][1],t[3][2],t[3][3],bool2,comm3)
    			conn.send(reply3)		#create the reply PDU and send to client
    		else:					#if the sesssion is not verified or the state is incorrect
    			comm3 = 3			#dont change the state
    			bool1 = 0			#keep both the booleans 0 to indicate that no algorithm was selected
    			bool2 = 0
    			reply3 = struct.pack(b'iBBBiBBBBii',sid,t[1][0],t[1][1],t[1][2],bool1,t[3][0],t[3][1],t[3][2],t[3][3],bool2,comm3)
    			conn.send(reply3)	#create the reply PDU and send to client

    	else:
    		#TERMINATION MESSAGE
    		t = struct.unpack('iii',rcvd[2])

    		if t[0]==sid and t[1]==4: 				#if the session id is verified and the state is correct
    			comm4 = 5					#change the state
    			new_sid = 0					#new session id should be set to 0
    			reply4 = struct.pack('iii',sid,comm4,new_sid)  	#create the PDU
    			conn.send(reply4)				#send the reply
    		else:							#if the session is not verified and the state is incorrect
    			comm4 = 4					#don't change the state. This lets the client know there is error
    			new_sid = 0					#change the new session id to 0 since this is the last message
    			reply4 = struct.pack('iii',sid,comm4,new_sid)	#create the reply PDU
    			conn.send(reply4)				#send to client

#The following code ensures that the server makes the connection and is ready to listen to messages from multiple clients simultaneously
PORT = 13000				#server port number
server = socket(AF_INET, SOCK_STREAM)	#TCP connection
server.bind(('', PORT))
server.listen(1)			#listen for the incoming messages
sid = 0
version = 10
error_bit = 0

print("Server is ready to recieve")	#if the connection port is setup, let the user know that the server is ready to recieve messages
while 1:
    clientsock, clientAddress = server.accept()
    t = threading.Thread(target=clientThread(clientsock))  #Concurrent server: creates threads to talk to multiple clients simultaneously. Directs it to the clientThreead function, each time a client tries to connect to the server
    t.start()						   #start the thread
