import hashlib
import socket
import sys
from scapy.layers.inet import IP, TCP, Ether
from Crypto.Cipher import PKCS1_OAEP
from scapy.packet import Raw
from Crypto.PublicKey import RSA


def send_data(socket_, p1, server_public_key):
    """
    Funcion que se encarga de convertir un paquete de scapy a bytes encryptarlo usando rsa y enviarlo al
    servidor para que este lo envie al otro cliente.
    """

    try:
        p = IP(dst=p1, chksum=0) / TCP() / Raw("Esto es una prueba!")
        p2 = p[IP]
        message = bytes(p2)
        encryptor = PKCS1_OAEP.new(server_public_key)
        encrypted = encryptor.encrypt(message)
        socket_.send(encrypted)
        print("[+] Request Sent!")
    except Exception as e:
        raise e

def receive_data(socket_, command):
    """
    Funcion que se encarga de recibir un paquete de scapy enviado por otro cliente y redireccionado
    por el servidor.
    """
    rdata = socket_.recv(8192)
    IP(rdata).show()

def cli(socket_):
    """
    Función que se encarga de recibir comandos a través de la línea de comandos y asignarlos a las funciones
    indicadas.
    """
    command = str(input("$ "))
    if command[:4] == 'send':
        send_data(socket_, command[5:],server_public_key)
    if command == 'receive':
        receive_data(socket_, command)


"""
Se establece la conexión con el servidor y se reciben la llaves publica del servidor para el cifrado.
"""
if __name__ == "__main__":
    '''
    Comprobación de argumentos
    '''
    argv = sys.argv
    if not ("-p" in argv) or not ('-h' in argv):
        print('Use: python3 Client.py -h host -p port')
        exit()

    '''
    Asignación de variables y constantes globales
    '''
    server = socket.socket()
    host = argv[2]
    port = int(argv[4])
    print(">>> Creating public and private key")
    print(">>> Connecting to host...")
    server.connect((host, port))
    print(">>> Connected.")
    try:
        # Tell server that connection is OK
        server.send("Client: OK".encode())
        # Receive public key string from server
        server_string = server.recv(1024)
        server_string = server_string.decode()
        # Convert string to key
        server_public_key = RSA.importKey(server_string)
        while True:
            cli(server)
    except KeyboardInterrupt:
        server.close()
