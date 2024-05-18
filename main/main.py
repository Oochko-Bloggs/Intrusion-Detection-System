import pyshark
import netifaces
import ipaddress
import json
import base64
import requests

class pckt(object):
    def __init__(self,time_stamp:str='',ipsrc:str='',ipdst:str='',srcport:str='',dstport:str='',transport_layer:str='',highest_layer:str=''): # type: ignore
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer         

class apiserver(object):
    def __init__(self,ip:str,port:str):
        self.ip = ip
        self.port = port

        


intFace = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intFace)

def server_connection(packet:capture,server:apiserver):
    #Determin if we are communicating with our server
    '''
        Args
            packet: captured packets by pyshark
            server: apiserver object 

        return : Boolean 
    '''
    if(hasattr(packet,'ip') and hasattr(packet,'tcp')):
        if ((packet.ip.src == server.ip) or (packet.ip.dst == server.ip)):
            return True
        else:
            return False
        

server = apiserver('192.168.24.24','8080')


def is_private_ip(ip_addr:str)->bool:
    
    #if the given ip address is private return boolean value    
    
    ip = ipaddress.ip_address(ip_addr)
    return ip.is_private
    
def report(message:pckt):
    '''
        Dispatch the message 
    '''    
    tmp = json.dump(message.__dict__)

    jsonString = tmp.encode('ascii')
    b64 = base64.b64encode(jsonString)

    jsonPayload = b64.decode('utf-8').replace("'",'"')
    print(jsonPayload)
    
    try:
        x = requests.get('http://{}:{}/apip/?{}'.format(server.ip,server.port,jsonPayload))
    except err as ConnectionError:
        #loggin to local file 
        pass
    
def filter(packet:capture):
    if server_connection(packet,server) is True:
        #Bail out
        return 
    
    if hasattr(packet,'icmp'):
        DataStruc = pckt()
        DataStruc.ipdst = packet.ip.dst
        DataStruc.ipsrc = packet.ip.src
        DataStruc.highest_layer = packet.highest_layer
        DataStruc.time_stamp = packet.sniff_timestamp
        report(DataStruc)   
            
    if packet.transport_layer == 'TCP' or packet.transport_layer == 'UDP':
        DataStruc = pckt()
        if hasattr(packet,'ipv6'):
            # Bail if packet has ipv6 address
            return None
        if hasattr(packet,'ip'):
            if(is_private_ip(packet.ip.src) is True) and (is_private_ip(packet.ip.dst) is True):
                DataStruc.ipsrc = packet.ip.src
                DataStruc.ipdst = packet.ip.dst
                DataStruc.time_stamp = packet.sniff_timestamp
                DataStruc.highest_layer = packet.highest_layer
                DataStruc.transport_layer = packet.transport_layer  
                if hasattr(packet,'UDP'):
                    DataStruc.dstport = packet.udp.dstport
                    DataStruc.srcport = packet.udp.srcport
                if hasattr(packet,'TCP'):
                    DataStruc.dstport = packet.tcp.dstport
                    DataStruc.srcport = packet.tcp.srcport
                report(DataStruc)
                    
        pass
  


for packet in capture.sniff_continuously():
    filter(packet)
    