#CS 544-Computer Networks
#Developer: Mruga Shah
#6/7/2019
#This file contains the client side programming of the protocol that sends messages to the server.
#It also talks to the user and gets details like hostname/IP and crededntials.
#
#STATEFUL

import random
import struct
import pickle
import hashlib
from socket import *
sid =0
bool1 =0
bool2=0

serverName = input("Connect to(Server Name/IP):")	#prompts the user to enter the name/IP of the machine they want to connect to
serverPort = 13000					#default server port
clientSocket = socket(AF_INET,SOCK_STREAM)		#TCP connection
clientSocket.connect((serverName,serverPort))		#connect to the server with the serverName provided by the user

#STATE: INITIAL CLIENT STATE (NO CONNECTION)

#The following code sends a random number to the server and recieves another random number from the server to
#calculate a session id that will be used throughout this session of communication between the client and the server.
#Session Id = server_random*client_random
random_int = random.randint(1,100) 	#3rd field containing the random number sent by the client
cl = list(b'Client') 			#2nd field containing the string "Client"
comms = 0 				#4th field that tells what stage (DFA state) is the system in 

var = struct.pack(b'BBBBBBii', cl[0], cl[1], cl[2], cl[3], cl[4], cl[5], random_int, comms) #create the PDU
msg = [len(var),0,var]				#add the 1st field that is the length of the data to the PDU
final_msg = pickle.dumps(msg)
clientSocket.send(final_msg) 			#send the message (PDU) to the server

mod_var = clientSocket.recv(12000) 		#recieve the reply from server

a = struct.unpack(b'6sii',mod_var)
if (a[2]==1 and a[0].decode('ascii')=='Server'):   #if the state changes to 1 on the server and the message is from the server, the session is established
	sid = random_int*a[1]			   #session id is calculated. It is equal to Client_Random_No*Server_Random_No
	#print("Session Established...",sid)
	comms = 1				   		#if everything went right change the state
else:
	print("No connection established,try again...")		#Else, throw error
	comms = 0						#No change in state

#STATE: SESSION ESTABLISHED

#The following code makes sure that the server side and the client side are using the same protocol version. 
#For our purposes, we have hardcoded the version number.
version = 10							#client protocol version
error_bit = 0
if comms ==1:
	var1 = struct.pack('iiii', sid, version, comms, error_bit)      #create PDU for sending out the client protocol version. Use sessiod id from above
	#print(len(var1),var[0],var[1],var[2],var[3])
	msg1 = [len(var1),1,var1]				#In PDU,add the first field as the length of the message
	final_msg1 = pickle.dumps(msg1)
	clientSocket.send(final_msg1)				#send PDU

	mod_var1 = clientSocket.recv(12000)			#recieve from server

	a1 = struct.unpack('iiii',mod_var1)
	if a1[2]==2 and error_bit==0:				#if the state changes to 2 in server and the error_bit is not 1 implies that the versio was negotiated correctly
		#print("Version Negotiated...")
		#print(sid)
		comms = 2					#if everything went right, change the state
	else:							#else,throw Version error
		print("Version Mismatch...")


#STATE: VERSION NEGOTIATED

#The following code gets from the user their credentials and sends across the hash of those credentils for verification by the server.
#If the credentials cannot be verified,it throws an error and terminates the session.
if comms==1:							#if the version did not change, terminate the session
	print("Session Terminated Abruptly!")
else:								#else, go on to authentication
	username = input('Please enter your username:')		#ask the user for their credentials
	pwd = input('Please enter the password:')
	cred = username+pwd					#combine username,password into a string
	m = hashlib.sha224(cred.encode('ascii')).hexdigest()	#calculate the hash
	var2 = struct.pack('iii', sid, error_bit,comms)		#create the PDU
	#print(len(var2))
	msg2 = [len(var2),2,m,var2]				#add the first field to the PDU i.e. the length of the message
	final_msg2 = pickle.dumps(msg2)
	clientSocket.send(final_msg2)				#send the PDU
	#print(m,len(m))

	mod_var2 = clientSocket.recv(12000)			#recieve reply from server

	a2 = struct.unpack('iii',mod_var2)
	if a2[2]==3 and error_bit==0:				#if the state changes to 3 on the server and the error bit is not set(there is no error)
		#print("Authenticated...")
		comms = 3					#change the state
	else:
		print("Authenciation Error...")			#else throw an error

#STATE: AUTHENTICATED

#The following code sends a list of algorithm names for the server to select from.
#It makes sure that the server selects one and only algorithm from the list.
if comms ==2:
	print("Session Terminated Abruptly!")			#if the user was not authenticated, terminate the session
else:
	md = list(b'MD5')
	sh = list(b'SHA1')
	var3 = struct.pack(b'iBBBiBBBBii', sid, md[0], md[1], md[2], bool1, sh[0], sh[1], sh[2], sh[3], bool2, comms)  #create the PDU
	#print(len(var3))
	msg3 = [len(var3),3,var3]				#add the first field, length
	final_msg3 = pickle.dumps(msg3)
	clientSocket.send(final_msg3)				#send the PDU

	mod_var3 = clientSocket.recv(12000)			#receive the reply from the PDU

	a3 = struct.unpack(b'i3si4sii',mod_var3)
	#print(a3[0],a3[2],a3[4],a3[5])
	if a3[5]==4 and a3[2]!=a3[4]:				#if the server changes the state, and the second condition is that one of the two algorithms is selected by the server
		#print("Algorithm Selected")
		print("Successful Negotiation...")
		comms = 4					#change the state
	else:
		print("Not negotiated correclty...")		#else, throw an error
		print("Session Terminated Abruptly!")

#STATE: HASH ALGORITHM SELECTED

#The folowing code sends a termination message to the server. It also makes sure that the new session id is set to 0 on the server side.
new_sid = sid							#initialize a new session id to the current session id. It should change to 0 by the end of the session
if comms == 3:
	print("Session Terminated Abruptly!")			#if the algorithm was selected incorreclty, terminate session
else:
	var4 = struct.pack('iii',sid,comms,new_sid)		#create PDU
	msg4 = [len(var4),4,var4]				#add first field, length
	final_msg4 = pickle.dumps(msg4)
	clientSocket.send(final_msg4)				#send the PDU

	mod_var4 = clientSocket.recv(12000)			#recieve reply from server

	a4 = struct.unpack('iii',mod_var4)
	if a4[1]==5 and a4[2]==0:				#if the server changes the state to 5 and the new session id is set to 0
		print("Session Terminated...")			#Session is terminated correctly
	else:
		print("Session Terminated Abruptly!")		#Else,terminated abruptly


clientSocket.close() 						#close the connection

#STATE: INITIAL CLIENT STATE(TERMINATED CONNECTION)
