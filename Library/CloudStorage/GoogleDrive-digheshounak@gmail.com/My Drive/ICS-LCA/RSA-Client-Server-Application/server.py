# server.py
# By Shounak Dighe
import socket
import pickle
from util.RSA import RSA

class Server:

    def __init__(self):
        print("[STARTING] Server is starting...")
        self.PORT = 5050
        # Local IP Address of the host
        self.SERVER_IP = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER_IP, self.PORT)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.ADDR)

    def listen(self):
        print(f'[LISTENING] Server listening on {self.SERVER_IP}...')
        self.server_socket.listen()
        self.conn, self.addr = self.server_socket.accept()
        return self.conn, self.addr

    def inputKeyParameters(self):
        print("Enter the space separated key parameters p, q and e:")
        self.p, self.q, self.e = map(int, input().split())

    def generateServerKeys(self):
        self.private_key, self.public_key = RSA.generateKeys(
            self.p, self.q, self.e)

    def receiveMsg(self):
        msg = self.conn.recv(1024)
        msg = pickle.loads(msg)
        return msg

    def sendMsg(self, data):
        data = pickle.dumps(data)
        self.conn.send(data)

    def workFlow(self):
        # Receiving data sent by the client
        data = self.receiveMsg()
        client_public_key = data['client_public_key']
        ciphertext = data['ciphertext']

        # Decrypt message using server's private key
        plaintext = RSA.decrypt(self.private_key, ciphertext)
        print("Decrypted plaintext:", plaintext)

        self.server_socket.close()

server_obj = Server()
conn, add = server_obj.listen()
print("[Connected] Connection created with IP: {} on PORT: {}".format(add[0], add[1]))
print("\n--------------Code by Shounak Dighe (1032233107)--------------\n")

server_obj.inputKeyParameters()

# Now verify key parameters
is_verified = RSA.verifyParameters(server_obj.p, server_obj.q, server_obj.e)
if not is_verified:
    server_obj.inputKeyParameters()

# Generate public and private key
server_obj.generateServerKeys()

# Receiving client's request
msg = server_obj.receiveMsg()
if msg == 'Y':
    # Sending public key on client's request
    server_obj.sendMsg(server_obj.public_key)
    print(f'[Sending] Public key to {server_obj.ADDR} (Client)...')

    # Workflow
    server_obj.workFlow()

else:
    print("[Server] Closing the connection...")
    server_obj.server_socket.close()
