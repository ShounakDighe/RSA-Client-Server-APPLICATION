# client.py
# By Shounak Dighe
import socket
import pickle
from util.RSA import RSA

class Client:
    def __init__(self):
        print("[STARTING] Client is starting...")
        self.PORT = 5050
        # Local IP Address of the host
        self.SERVER_IP = socket.gethostbyname(socket.gethostname())
        self.ADDR = (self.SERVER_IP, self.PORT)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        print(f'[Connecting] Client trying to connect {self.SERVER_IP}...')
        self.client_socket.connect(self.ADDR)
        print(f'[Connected] Secure connection established with server.')

    def inputMessage(self):
        print("Enter your message to be sent to the server:")
        self.message = input()

    def inputKeyParameters(self):
        print("Enter the space-separated key parameters p, q and e:")
        self.p, self.q, self.e = map(int, input().split())

    def generateClientKeys(self):
        self.private_key, self.public_key = RSA.generateKeys(
            self.p, self.q, self.e)

    def receiveMsg(self):
        msg = self.client_socket.recv(1024)
        msg = pickle.loads(msg)
        return msg

    def sendMsg(self, data):
        data = pickle.dumps(data)
        self.client_socket.send(data)

    def workFlow(self):
        # Encrypting the message using the server's public key
        ciphertext = RSA.encrypt(self.server_public_key, self.message)
        print("\nEncrypted message (ciphertext):", RSA.printHexList(ciphertext))

        # Arranging data to be sent to the server
        data = {'ciphertext': ciphertext, 'client_public_key': self.public_key}

        # Sending data to server
        self.sendMsg(data)

        self.client_socket.close()

client_obj = Client()
client_obj.connect()
print("\n--------------Code by Shounak Dighe (1032233107)--------------\n")

client_obj.inputMessage()
client_obj.inputKeyParameters()

# Now verify key parameters
is_verified = RSA.verifyParameters(client_obj.p, client_obj.q, client_obj.e)
if not is_verified:
    client_obj.inputKeyParameters()

# Generate public and private keys
client_obj.generateClientKeys()

print("Do you want to request the server for its public key? Y or N")
res = input()
if res.lower() == 'y':
    # Requesting server for its public key
    print("[Requesting] Server's public key...")
    client_obj.sendMsg("Y")

    # Receiving server's public key
    client_obj.server_public_key = client_obj.receiveMsg()

    print("Server's public key received!")

    # Workflow
    client_obj.workFlow()

else:
    print("[Client] Closing the connection...")
    client_obj.client_socket.close()
