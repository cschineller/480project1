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
C_PUBKEY = 0
S_PUBKEY = 0
C_SHAREDKEY = 0
S_SHAREDKEY = 0 
SERVER = 0


class SecureMessage:

    def __init__(self, server_ip=None, server_port=None):
        """Initialize SecureMessage object, create & connect socket,
           do key exchange, and start send & receive loops"""

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
            recv_msg = self.s.recv(SEND_BUFFER_SIZE).decode()
            if recv_msg:
                message = self.process_received_message(recv_msg)
                sys.stdout.write("\t" + message + "\n")
                sys.stdout.flush()
            else:
                os._exit(0)

    def key_exchange(self):

        c = pyDH.DiffieHellman() #client
        s = pyDH.DiffieHellman() #server

        C_PUBKEY = c.gen_public_key() #global variable
        S_PUBKEY = s.gen_public_key() #global variable

        #client sends their public key to server
        self.s.send((C_PUBKEY.to_bytes(SEND_BUFFER_SIZE, sys.byteorder)))
        c_pubkey = self.s.recv(SEND_BUFFER_SIZE)

        #server sends their public key to client
        self.s.send((C_PUBKEY.to_bytes(SEND_BUFFER_SIZE, sys.byteorder)))
        s_pubkey = self.s.recv(SEND_BUFFER_SIZE)

        #generate shared keys using what they received from each other
        C_SHAREDKEY = c.gen_shared_key(s_pubkey)
        S_SHAREDKEY = s.gen_shared_key(c_pubkey) 
        

    def process_user_input(self, user_input):
        
        #check if we're dealing with the server or the client to know which key to use
        if SERVER: 
            ciphertxt = AES.new(S_PUBKEY[:32], AES.MODE_EAX) 
        else:    
            ciphertxt = AES.new(C_PUBKEY[:32], AES.MODE_EAX)
            
        nonce = Crypto.nonce
        splitter = "splt".encode("ISO-8859-1")
        ciphertxt, tag = ciphertxt.encrypt_and_digest(user_input)

        return nonce+splitter+ciphertxt+splitter+tag

    def process_received_message(self, recv_msg):

        #split the message into its parts using the splitter
        array = recv_msg.split("splt".decode("ISO-8859-1"))
        nonce = array[0]
        ciphertxt = array[1]
        tag = array[2]

        if SERVER:
            cipher = AES.new(S_PUBKEY[:32], AES.MODE_EAX, nonce=nonce)
        else:
            cipher = AES.new(C_PUBKEY[:32], AES.MODE_EAX, nonce=nonce)

        #decrypt the ciphertxt using the cipher
        plaintxt = cipher.decrypt(ciphertxt)

        #check for integrity/authenticity
        try:
            cipher.verify(tag)

        except ValueError:
            print("Key incorrect or message corrupted")
            os._exit(0)

        return plaintxt


def main():
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
