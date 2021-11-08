import hashlib
import socket
import sys
import time
import threading
from scapy.layers.inet import IP, TCP, Ether
from Crypto.Cipher import PKCS1_OAEP
from scapy.packet import Raw
from Crypto.PublicKey import RSA


def send_data(socket_, p1, server_public_key,message):
    """
    Funcion que se encarga de convertir un paquete de scapy a bytes encryptarlo usando rsa y enviarlo al
    servidor para que este lo envie al otro cliente.
    """

    try:
        p = IP(dst=p1, chksum=0) / TCP() / Raw(message)
        p2 = p[IP]
        message = bytes(p2)
        encryptor = PKCS1_OAEP.new(server_public_key)
        encrypted = encryptor.encrypt(message)
        socket_.send(encrypted)
        print("[+] Request Sent!")
    except Exception as e:
        raise e

def handle_server(socket_):
    """
    Esta funcion tiene como objetivo mantener una comunicacion con el bot irc y el server de red mesh.
    Con esto podemos mandar mensajes de un cliente a un canal de el servidor irc.
    """
    while True:
        try:
            packet = socket_.recv(2040)
        except socket.timeout as e:
            err = e.args[0]
            if err == 'timed out':
                time.sleep(1)
                continue
            else:
                print(e)
                sys.exit(1)
        except socket.error as e:
            print(e)
            sys.exit(1)
        else:
            print("Received message from server")
            IP(packet).show()


def cli(socket_):
    """
    Función que se encarga de recibir comandos a través de la línea de comandos y asignarlos a las funciones
    indicadas.
    """
    command = str(input("$ ")).split()
    if command[0] == 'send':
        send_data(socket_, command[1],server_public_key,command[2])
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

        h1 = threading.Thread(target=handle_server, args=(server,))
        h1.start()
        while True:
           cli(server)
    except KeyboardInterrupt:
        server.close()
