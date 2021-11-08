import os
from time import sleep
from scapy.all import *
import numpy as np
from itertools import groupby, chain
import qrcode
import cv2
import sys
from PIL import Image
import psutil
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

"""sys.path.append("../Capa2,3/")

from Client import *"""

class DispLuzAdap:
    """
    Clase que se encarga de manejar la información un dispositivo de luz en donde 
    se convierten, se dividen los datos en tramas, y se envian y reciben estos qrs
    para ser docodificados.
    """

    def __init__(self):
        """
        Constructor de la clase
        """
        self.max_frame_size = 128

    def dividePayload(self,packet):
        frames = []
        framesPayloads  = []
        frame = Ether()/packet
        payload = bytes(frame[Raw])
        print(len(frame))
        if(len(frame) > self.max_frame_size):
            fieldsSize = len(frame) - len(frame[Raw])
            del frame[Raw]
            payloadLimit = self.max_frame_size - fieldsSize
            bytesList = list(payload)
            newFramePayLoad = []
            count = 0
            for i in range(0, len(bytesList)):
                if(count == payloadLimit):
                    newFramePayLoad.append(bytesList[i])
                    framesPayloads.append(newFramePayLoad)
                    newFramePayLoad = []
                    count = 0
                else:
                    newFramePayLoad.append(bytesList[i])
                    count+=1
            for i in framesPayloads:
                payLoad = bytes(i).decode('utf-8')
                frames.append(frame/Raw(payLoad))
        else:
            del frame[Raw]
            payLoad = payload.decode('utf-8')
            frames.append(frame/Raw(payLoad))
        return frames

    def send(self, packet):
        src = packet.src
        des = packet.dst
        frames = self.dividePayload(packet)
        for frame in frames:
            a = bytes(frame)
            b = list(a)
            frameStr = "" 
            frameStr += str(b[0])
            for by in range(1,len(b)): 
                    frameStr += ("-" + str(b[by]))  
            img = qrcode.make(frameStr)
            type(img)
            srcReplaced = src.replace(':', '')
            desReplaced = des.replace(':', '')
            img.save("./QRTransmission/"+str(srcReplaced)+"-"+str(desReplaced)+".png")
            imgShow = Image.open("./QRTransmission/"+str(srcReplaced)+"-"+str(desReplaced)+".png")
            imgShow.show() 
            sleep(5)
            for proc in psutil.process_iter():
                if proc.name() == "eog":
                    proc.kill()

    def readQRs(self):
        cap = cv2.VideoCapture(0)
        detector = cv2.QRCodeDetector()
        while cap.isOpened():
            _,img = cap.read()
            data,one, _ = detector.detectAndDecode(img)
            if data:
                a = data
                break
            cv2.imshow('qrcodescanner app',img)
            if cv2.waitKey(1) == ord('q'):
                break
        data = str(a)
        print(data)
        #cap.release(a)
        cv2.destroyAllWindows()
        return(data)

    def send_data(self, socket_, p1, server_public_key):
        """
        Funcion que se encarga de convertir un paquete de scapy a bytes encryptarlo usando rsa y enviarlo al
        servidor para que este lo envie al otro cliente.
        """
        print(socket_)
        try:
            p2 = p1[IP]
            message = bytes(p2)
            encryptor = PKCS1_OAEP.new(server_public_key)
            encrypted = encryptor.encrypt(message)
            socket_.send(encrypted)
            print("[+] Request Sent!")
        except Exception as e:
            raise e

    def receive(self, command):
        packet = IP(dst=command[1], chksum=0) / TCP() / Raw(command[2])
        del packet[IP].chksum
        del packet[TCP].chksum
        self.send(packet)
        self.send_data(server,packet,server_public_key)

        #ACA ENVIO EL PAQUETE HACIA LA OTRA LAYER


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.connect(("18.223.241.184", 8000))

try:
    # Tell server that connection is OK
    server.send("Client: OK".encode())
    # Receive public key string from server
    server_string = server.recv(1024)
    server_string = server_string.decode()
    # Convert string to key
    server_public_key = RSA.importKey(server_string)

    device = DispLuzAdap()

    while True:
        command = str(input("$ "))
        command = command.split()
        if "send" in command:
            device.receive(command)
except KeyboardInterrupt:
    server.close()


