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
import codecs


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
        """TODO: Diffie-Hellman key exchange"""

        # generate c and then send to s using the self.s.send thing and encode
        # s receives it as pubkey and decodes it back and then generates their shared key using that

        c = pyDH.DiffieHellman()
        s = pyDH.DiffieHellman()
        c_pubkey, C_PUBKEY = c.gen_public_key()
        self.s.send(c_pubkey.encode('ISO-8859-1'))
        s_pubkey, S_PUBKEY = self.s.recv(SEND_BUFFER_SIZE.decode('ISO-8859-1'))
        c_sharedkey, C_SHAREDKEY = c.gen_shared_key(s_pubkey)
        s_sharedkey, S_SHAREDKEY = s.gen_shared_key(c_pubkey) 
        

    def process_user_input(self, user_input):
        #use key of socket to encrypt the plain text
        #use the global variable
        """TODO: Add authentication and encryption"""
        
        if SERVER: 
            ciphertxt = AES.new( S_PUBKEY, AES.MODE_EAX)
            
        else:    
            ciphertxt = AES.new(C_PUBKEY, AES.MODE_EAX)

        nonce = Crypto.nonce
        splitter = "splt".encode("ISO-8859-1")
        
        ciphertxt, tag = ciphertxt.encrypt_and_digest(user_input)
        
        #generate ciphertext with the aes thing and you use the nonce and create a splitter according to what chase said
        #and you're returning the nonce+splitter....
        #


        
        return nonce+splitter+

    def process_received_message(self, recv_msg):
        """TODO: Check message integrity and decrypt"""
        #encode it again then array 

        return recv_msg


def main():
    """Parse command-line arguments and start client/server"""
    SERVER = True
    # too few arguments
    if len(sys.argv) < 2:
        sys.exit(
            "Usage: python3 SecureMessaging.py [Server IP (for client only)] [Server Port]")

    # arguments for server
    elif len(sys.argv) == 2:
        server_ip = None
        server_port = int(sys.argv[1])

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
