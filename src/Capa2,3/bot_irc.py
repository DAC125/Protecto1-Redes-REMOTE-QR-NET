from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
import socket
import time
import sys
import threading


def handle_irc(new_socket,socket_qrnet):
    """
    Funcion encargada para mantener la comunicacion con el cliente irc y el servidor de la red mesh.
    Esta funcionalidad no esta completada.
    """
    while True:
        try:
            resp = new_socket.recv(2040).decode("UTF-8")
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
            print(f"Received message: {resp}")
            if "send" in resp:
                data = resp.split()
                p = IP(dst=data[4]) / TCP() / Raw(data[5])
                message = bytes(p)
                socket_qrnet.send(message)
                print("[+] Request Sent!")


def handle_server(new_socket,socket_qrnet):
    """
    Esta funcion tiene como objetivo mantener una comunicacion con el bot irc y el server de red mesh.
    Con esto podemos mandar mensajes de un cliente a un canal de el servidor irc.
    """
    while True:
        try:
            packet = socket_qrnet.recv(2040)
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
            print(f"Received message from server")
            packet = IP(packet)
            packet = packet[Raw].load
            to_send_message = "PRIVMSG " + channel + " " + packet.decode().replace(" ", "_") + "\n"
            print(f"Sending message: {to_send_message}")
            new_socket.send(bytes(to_send_message, "UTF-8"))

def connect_bot_to_IRC(server, port, channel, bot_nick, bot_pass):
    """
    Esta funcion es para realizar la conexion del bot al servidor irc.
    Se encarga de conectarse a un canal y enviar mensajes de la red mesh a un canal del irc.
    """
    # Definición del socket
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_qrnet = socket.socket()
    socket_qrnet.connect(("18.223.241.184", 8001))
    socket_qrnet.settimeout(2)
    new_socket.settimeout(2)
    print(f"Connecting to: {server} {port}")
    new_socket.connect((server, port))
    
    # Autentificación
    new_socket.send(bytes("USER " + bot_nick + " " + bot_nick +" " + bot_nick + " :Python bot\n", "UTF-8"))
    new_socket.send(bytes("NICK " + bot_nick + "\n", "UTF-8"))
    new_socket.send(bytes("NICKSERV IDENTIFY " + bot_nick + " " + bot_pass + "\n", "UTF-8"))
    time.sleep(5)
    
    # Unirse al canal
    new_socket.send(bytes("JOIN " + channel + "\n", "UTF-8"))
    print(f"Joined the channel {channel}")

    # Función del bot
    try:
        while True:
            h1 = threading.Thread(target=handle_irc, args=(new_socket, socket_qrnet))
            h2 = threading.Thread(target=handle_server, args=(new_socket, socket_qrnet))
            h1.start()
            h2.start()
            time.sleep(3)
    except(KeyboardInterrupt):
        socket_qrnet.close()
        new_socket.close()

if __name__ == "__main__":
    argv = sys.argv
    if not ("-h" in argv and "-p" in argv and "-c" in argv and
        "-b" in argv and "-p" in argv):
        print('Usage: python3 bot_irc.py -h host -p port -c channel -b bot_nick -p password')

    server   = argv[argv.index("-h") + 1]
    port     = int(argv[argv.index("-p") + 1])
    channel  = "#" + argv[argv.index("-c") + 1]
    bot_nick = argv[argv.index("-b") + 1]
    bot_pass = argv[argv.index("-p") + 1]

    connect_bot_to_IRC(server, port, channel, bot_nick, bot_pass)
