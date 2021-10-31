import ast
import sys
import socket
from concurrent.futures import ThreadPoolExecutor
import logging
import random
from scapy.layers.inet import IP
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

logging.basicConfig(level=logging.DEBUG, format='%(threadName)s : %(message)s \n')

'''
Comprobación de argumentos
'''
argv = sys.argv
if '-n' in argv and '-p' in argv and len(argv) == 6:
    print('Use: python3  Server.py −p [ puerto ] −n [ numero_hilos ]')

'''
Asignación de variables y constantes globales
'''
nodes = {}  # Diccionario donde se guarda la dirección IP del nodo y su llave pública
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = int(argv[2])
socket.bind(('', port))
thread_n = int(argv[4])
socket.listen()

connections = {}


'''
Se generan las llaves publicas y privadas para el cifrado
'''
random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

def convert_list_to_string(org_list, split=' '):
    """
    Funcion tiene como objetivo retornar un string que contiene todos los elementos
    de la lista separados por un espacio.
    """
    return split.join(org_list)


def routing(source, destine):
    """
    Funcion que tiene como objetivo obtener la ruta que se sigue en la red mesh.
    """
    logging.info(">>> Routing", source, destine)
    if not nodes.get(destine):
        return "Destine is not register"
    MAX = 2
    MIN = 2
    keys = []
    hops = random.randint(MIN, MAX)
    hops_list = list(nodes.items())
    hops_count = (len(hops_list) - 2)
    last_hops = None
    while hops and hops < hops_count:
        address, key = random.choice(hops_list)
        if last_hops != address or address != destine or address != source:
            keys.append(key)
            keys.append('|')
            hops -= 1
    keys.append(nodes.get(destine))
    return convert_list_to_string(keys)

def talk_to_client(connection, address):
    """
    Funcion que se encarga de mantener una comunicacion con los clientes.
    En donde se redireccionan los datos para permitir una comunicacion cliente-cliente.
    Y cliente-bot-channel-irc
    """
    cont = False
    while True:
        data = connection.recv(1024)
        if not data:
            break
        if cont:
            logging.info(f'{address[0]} received: {data}')
            decryptor = PKCS1_OAEP.new(private_key)
            decrypted = decryptor.decrypt(ast.literal_eval(str(data)))
            p2 = IP(decrypted)
            client_connection = connections[p2[IP].dst]
            if connection != client_connection:
                connections["200.105.99.38"].send(decrypted)
                client_connection.send(decrypted)

            '''if not p[Raw] and connection != client_connection:
                client_connection.send(data)'''
        if data.decode("UTF-8") == "Client: OK":
            cont = True
            connection.send(bytes(public_key.exportKey()))
            print("Public key sent to client.")
            nodes[address[0]] = data.decode('UTF-8')
    nodes.pop(address[0])
    logging.info(f"{address[0]} disconnected")
    connection.close()  # Close the connection


logging.info('>>> Server running')

with ThreadPoolExecutor(max_workers=thread_n) as executor:
    """
    A cada conexion con un cliente se le asigna un hilo.
    """
    while True:
        connection, address = socket.accept()
        connections[address[0]] = connection
        logging.info(f'>>> New connection from: {address}')
        try:
            result = executor.submit(talk_to_client, connection, address)
        except KeyboardInterrupt:
            connection.close()
            socket.close()
