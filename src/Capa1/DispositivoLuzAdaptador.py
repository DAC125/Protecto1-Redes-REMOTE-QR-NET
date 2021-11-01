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

    def receive(self, packet):
        qrData = self.readQRs()
        byteData = bytes(qrData)
        packet = Ether(byteData)
        del packet[Ether]
        del packet[IP].chksum
        del packet[TCP].chksum
        #ACA ENVIO EL PAQUETE HACIA LA OTRA LAYER




packet = IP(src='192.168.2.10', dst='192.168.1.1',chksum = 0) / TCP() / Raw("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum")
                
device = DispLuzAdap()

device.send(packet)
