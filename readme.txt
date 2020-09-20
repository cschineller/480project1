COSC 480B Assignment #1: Secure Messaging

Due Date: TODO at 5:00pm ET

You may work with a partner on this assignment.
Only one person per partnership needs to submit. 

Reminder: You may NOT work with the same partner on multiple assignments.

____________________________________________________________________________________

BACKGROUND

Secure messaging applications allow sending and receiving messages
with guaranteed confidentiality and integrity. 

Confidentiality: Messages are not readable by unauthorized individuals
Integrity: Messages cannot be modified in an unauthorized or undetectable manner

Secure messaging is essential to trusting any Internet communications, but it
is not limited to commercial messaging apps or code written by professionals.

For this assignment, you will be using creating a secure
2-way messaging application using cryptographic primitives. 

At the end of the assignment, you will have a Python application that will enable you
to exchange secure messages with anyone else in the class. No one else will be able
to read these messages (not Colgate ITS, your ISP, other people on the same WiFi network,
tech companies, etc.), and you will able to detect any unauthorized message modifications. 

It is a bad idea to write your own cryptograhy primitives unless you are an expert 
("Don't roll your own crypto!"), so you will be using the publicly available
Python libraries PyCryptodome and pyDH. 

____________________________________________________________________________________

PROVIDED FILES

1) readme.txt: This file!


2) SecureMessaging.py: Starter code with a very simple 2-way INsecure messaging app. 
                       SecureMessaging.py uses the Python socket library to 
                       create a TCP connection between itself and another instance of 
                       the program. One instance of SecureMessaging.py must be
                       run as the "client" while the other is run as the "server."
                       Once the connection is made, either side can send and receive
                       string messages up to 2048 characters long.

                       Run SecureMessaging.py using these commands:

                       As client:    python3 SecureMessaging.py [Server IP] [Server Port]
                       As server:    python3 SecureMessaging.py [Server Port]

                       You may need to allow Python to accept incoming network connections

                       The server port should be a high unused port (I recommend
                       starting with 10000 and going up from there). 
                       If you get an "Address already in use" error, 
                       try a different port.

                       If you running the client and the server on the same computer,
                       use "127.0.0.1" as the server IP. 

                       If you are running the client and server on different machines,
                       (e.g. to send messages to your partner or classmates), the person
                       running the server can Google "What's my IP" to get their 
                       public IP address.

                       Once connected, you can send messages by typing them into the 
                       terminal and pressing <enter>.


3) TestMessaging.sh: Bash testing script to check whether your secure messaging application
                     has the right user interface and can send/receive messages between
                     two instances of itself running on the same machine.

                     This test sets the minimum bar for the assignment. All submitted
                     code should pass this test.

                     Note that the provided SecureMessaging.py starter code passes,
                     so TestMessaging.sh does NOT check whether authentication or
                     encryption has been properly implemented.

                     The first time you run TestMessaging.py you may need to make it 
                     executable using this command:

                     chmod 764 TestMessaging.sh

                     Run TestMessaging.sh using this command:

                     ./TestMessaging.sh [server-port]

      				 The server port should be a high unused port (I recommend
                     starting with 10000 and going up from there). 
                     If you get an "Address already in use" error, 
                     try a different port.

3) questions.txt: Written questions. Fill in your answers in this file and submit it
                  (see Deliverables #2 below).

_____________________________________________________________________________________

INSTRUCTIONS

1) Install python3 from python.org if you do not already have it on your computer.

2) Install the PyCrpytodome and pyDH libraries by running the command
   "pip3 install pycryptodome pyDH" from your terminal.

3) Review and try out SecureMessaging.py starter code, making sure you understand
   the difference between the "client" and "server" initialization and how messages
   are sent and received. If this is your first experience with socket programming, you
   may want to review the documentation at https://docs.python.org/3/library/socket.html.
   If you have additional questions about how the provided SecureMessaging.py works, 
   post a question on the Moodle general Q&A forum or email Prof. Apthorpe.

4) Negotiate protocol details with your classmates on Moodle. In order to communicate
   with everyone in the class, your secure messaging applications will need to use 
   consistent message formats and a communication protocol that answers the following 
   questions, as well as others that may arise during implementation:

       4a) What will be the format of Diffie-Hellman key exchange messages?

       4b) How will message authentication codes be included (and differentiated from)
           the content of messages?

       4c) In what order will MACs (for integrity) and encryption (for confidentiality)
           be applied to messages?

       4d) What settings options will you use for D-H key exchange and the AES cipher?

   While you must propose and discuss potential protocols and message formats with 
   your classmates, you MUST NOT share code specifics with anyone other than 
   your partner and Prof. Apthorpe. Imagine that you are startups creating 
   messaging apps: you need a standard protocol so your users can communicate across
   platforms, but you don't want to share source code with the competition. 

5) Modify SecureMessaging.py to include the following required features while adhering 
   to the protocol agreed upon with your classmates:

       5a) Use the PyCryptodome library to generate all needed random numbers. 
           ThePyCryptodome documentation is at 
           https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

       5b) Use the pyDH library to implement Diffie-Hellman key exchange upon
           client/server connection. Before any user messages are sent, 
           the client and server should have TWO SHARED KEYS, 
           one for sending messages in the client -> server direction and one for 
           the server -> client direction. The pyDH documentation is at 
           https://github.com/amiralis/pyDH

       5c) Use the PyCryptodome library to add authentication to messages with 
           HMAC-SHA256 and confidentiality to messages by encrypting with 
           an AES block cipher.

       5d) If you detect that a message has been modified in transit 
           (via the HMAC), you should raise a ValueError("MessageModificationDetected")

       5e) Your modifications must not change the user-facing behavior of SecureMessaging.py
           You should still be able to run SecureMessaging.py using the following commands 
           and send messages by typing them in to the terminal and pressing <enter>:

           As client:    python3 SecureMessaging.py [Server IP] [Server Port]
           As server:    python3 SecureMessaging.py [Server Port]

           SecureMessaging.py must not require any additonal input from the user to 
           provide authentication and encryption. 

6) Test your modified SecureMessaging.py 

       6a) With the provided TestMessaging.sh

       6b) By sending messages to your partner and to your classmates. Grading will be based 
           on whether your SecureMessaging.py can communicate with another instance of itself
           and that you correctly implemented the protocol agreed upon with your classmates 
           on Moodle. You do NOT need to be able to communicate with every one of your classmates' 
           implementations for full credit (as their implementations might be incorrect). 

        6c) [Optional] For a small amount of extra credit, try adding to the TestMessaging.sh file
            or writing your own testing code to verfiy that your SecureMessaging.py works as expected.

7) Answer the questions in questions.txt

____________________________________________________________________________________

DELIVERABLES

ONE PARTNER should submit the following files:

1) SecureMessaging.py with all modifications from Instruction #5

2) questions.txt completed with your CONCISE answers

3) [Optional] TestMessaging.sh OR NewMessagingTests.py with your custom 
              extra credit testing code