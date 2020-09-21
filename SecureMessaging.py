"""
SecureMessaging.py

NAMES: Callie Schineller, Morgan Farrah

Run as client: python3 SecureMessaging.py [Server IP] [Server Port]
Run as server: python3 SecureMessaging.py [Server Port]

"""

import sys
import socket
import os
from threading import Thread

import Crypto
import pyDH

from Crypto.Cipher import AES


QUEUE_LENGTH = 1
SEND_BUFFER_SIZE = 2048
SERVER = 0

class SecureMessage:

    def __init__(self, server_ip=None, server_port=None):
        """Initialize SecureMessage object, create & connect socket,
           do key exchange, and start send & receive loops"""

        self.C_PUBKEY = 0
        self.S_PUBKEY = 0
        self.C_SHAREDKEY = 0
        self.S_SHAREDKEY = 0 

        # create IPv4 TCP socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # connect as client
        if server_ip and server_port:
            self.s.connect((server_ip, server_port))

        # connect as server
        elif server_port and not server_ip:
            self.s.bind(('', server_port))
            self.s.listen(QUEUE_LENGTH)
            self.s, _ = self.s.accept()

        # Run Diffie-Hellman key exchange
        self.key_exchange()

        # start send and receive loops
        self.recv_thread = Thread(target=self.recv_loop, args=())
        self.recv_thread.start()
        self.send_loop()

    def send_loop(self):
        """Loop to check for user input and send messages"""
        while True:
            try:
                user_input = input().encode()
                sys.stdout.flush()
                message = self.process_user_input(user_input)
                self.s.send(message[:SEND_BUFFER_SIZE])
            except EOFError:
                self.s.shutdown(socket.SHUT_RDWR)
                os._exit(0)

    def recv_loop(self):
        """Loop to receive and print messages"""
        while True:
            recv_msg = self.s.recv(SEND_BUFFER_SIZE).decode("ISO-8859-1")
            if recv_msg:
                message = self.process_received_message(recv_msg)
                sys.stdout.write("\t" + message + "\n")
                sys.stdout.flush()
            else:
                os._exit(0)

    def key_exchange(self):

        c = pyDH.DiffieHellman() #client
        s = pyDH.DiffieHellman() #server

        self.C_PUBKEY = c.gen_public_key() #global variable
        self.S_PUBKEY = s.gen_public_key() #global variable

        #client sends their public key to server
        self.s.send(str(self.C_PUBKEY).encode("ISO-8859-1"))
        c_pubkey = self.s.recv(SEND_BUFFER_SIZE)

        #server sends their public key to client
        self.s.send(str(self.S_PUBKEY).encode("ISO-8859-1"))
        s_pubkey = self.s.recv(SEND_BUFFER_SIZE)

        #generate shared keys using what they received from each other
        self.C_SHAREDKEY = c.gen_shared_key(int(s_pubkey.decode("ISO-8859-1")))
        self.S_SHAREDKEY = s.gen_shared_key(int(c_pubkey.decode("ISO-8859-1"))) 
        

    def process_user_input(self, user_input):
        
        #check if we're dealing with the server or the client to know which key to use
        if SERVER: 
            ciphertxt = AES.new(bytes(self.S_SHAREDKEY, encoding="ISO-8859-1")[:16], AES.MODE_EAX) 
        else:    
            ciphertxt = AES.new(bytes(self.C_SHAREDKEY, encoding="ISO-8859-1")[:16], AES.MODE_EAX)
            
        nonce = ciphertxt.nonce
        splitter = "splt".encode("ISO-8859-1")
        ciphertxt, tag = ciphertxt.encrypt_and_digest(user_input)

        return nonce+splitter+ciphertxt+splitter+tag

    def process_received_message(self, recv_msg):
        #split the message into its parts using the splitter
        splitter = "splt".encode("ISO-8859-1")
        array = recv_msg.split(splitter.decode("ISO-8859-1"))
        nonce = bytes(array[0], encoding="ISO-8859-1")
        ciphertxt = array[1]
        tag = array[2]

        if SERVER:
            cipher = AES.new(bytes(self.S_SHAREDKEY[:16], encoding="ISO-8859-1"), AES.MODE_EAX, nonce=nonce)
        else:
            cipher = AES.new(bytes(self.C_SHAREDKEY[:16], encoding="ISO-8859-1"), AES.MODE_EAX, nonce=nonce)


        #decrypt the ciphertxt using the cipher
        plaintxt = cipher.decrypt(bytes(ciphertxt, encoding="ISO-8859-1"))

        #check for integrity/authenticity
        try:
            cipher.verify(bytes(tag, encoding="ISO-8859-1"))

        except ValueError:
            raise ValueError("MessageModificationDetected")
            os._exit(0)

        return plaintxt.decode("ISO-8859-1")


def main():
    global SERVER
    """Parse command-line arguments and start client/server"""
    # too few arguments
    if len(sys.argv) < 2:
        sys.exit(
            "Usage: python3 SecureMessaging.py [Server IP (for client only)] [Server Port]")

    # arguments for server
    elif len(sys.argv) == 2:
        server_ip = None
        server_port = int(sys.argv[1])
        SERVER = True

    # arguments for client
    else:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        SERVER = False

    # create SecureMessage object
    secure_message = SecureMessage(
        server_ip=server_ip, server_port=server_port)


if __name__ == "__main__":
    main()
