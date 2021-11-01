import os
from time import sleep
from scapy.all import *
import numpy as np
from itertools import groupby, chain
import qrcode
import cv2
from bitstring import BitArray
import sys
from PIL import Image  


'''str1 = "" 

frame = Ether(src='ff:19:4b:10:38:79', dst='00:19:4b:10:38:79') / IP(src='192.168.2.10', dst='192.168.1.1') / Raw("Hola")

src = frame.src
des = frame.dst
a= bytes(frame)
b = list(a)
packetStr = "" # traverse in the string  
packetStr += str(b[0])
for by in range(1,len(b)): 
        packetStr += ("-" + str(b[by]))  
img = qrcode.make(packetStr)
type(img)
srcReplaced = src.replace(':', '')
desReplaced = des.replace(':', '')
img.save("./QRTransmission/"+str(srcReplaced)+"-"+str(desReplaced)+".png")



print(b)
c = bytes(b)
print(c)'''

a = "HOLAAAAAA"

b = a.encode('utf-8')

print(b)

c = list(b)

print(c)

d = bytes(c)

print(d)

e = d.decode('utf-8')

print(e)

frame = Ether(src='ff:19:4b:10:38:79', dst='00:19:4b:10:38:79') / IP(src='192.168.2.10', dst='192.168.1.1',chksum = 0) / TCP() / Raw("hola")
del frame[IP].chksum
del frame[TCP].chksum
frame.show2()

packet = IP(src='192.168.2.10', dst='192.168.1.1',chksum = 0) / TCP() / Raw("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum")

print(sys.getsizeof("Hola"))



class DispLuzAdap:
    """
    Clase que se encarga de manejar la información en un dispositivo wavenet.
    La cual tiene como atributos la lista de nodos, el tamaño máximo de un paquete
    y la duración de un sonido de 1 segundo (1000 ms)
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
        del packet[IP].chksum
        del packet[TCP].chksum
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
            sleep(3)
            imgShow.close()

    def readQRs(self):
        cap = cv2.VideoCapture(-1)
        detector = cv2.QRCodeDetector()
        while cap.isOpened():
            _,img = cap.read()
            data,one,_ = detector.detectAndDecode(img)
            if data:
                a = data
                break
            cv2.imshow('qrcodescanner app',img)
            if cv2.waitKey(1) == ord('q'):
                break
        cap.release(a)
        cv2.destroyAllWindows()
        return(str(a))

    def receive(self, packet):
        qrData = self.readQRs()
        byteData = bytes(qrData)
        packet = Ether(byteData)
        del packet[Ether]
        del packet[IP].chksum
        del packet[TCP].chksum
        #ACA ENVIO EL PAQUETE HACIA LA OTRA LAYER
        print('')





                
device = DispLuzAdap()

device.send(packet)
