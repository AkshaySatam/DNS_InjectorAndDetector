import argparse
from scapy.all import *
import socket
import fcntl
import struct
import datetime

dnsMap={}

def dnsDetect(packet):
    if DNS in packet and packet[DNS].qr == 1 and packet[DNS].ancount >= 1:
        global dnsMap
        if packet[DNS].id not in dnsMap:
            dnsMap[packet[DNS].id]=packet
            #print('Packet added to Map')
        else:
            #get mac address from packet
            # Will have to check if this is correct
            macAddr2 = packet[Ether].src
            firstPacket = dnsMap[packet[DNS].id]
            ipAdds = getIPsFromDNS(packet)
            ipAdds2= getIPsFromDNS(firstPacket)
            #check if the MAC address is same. if not raise an alarm
            if macAddr2 != firstPacket[Ether].src:
                print()                
                print(str(datetime.datetime.now())+' DNS poisoning attempt')
                print('TXID '+str(packet[DNS].id)+' Request '+packet[DNS].qd.qname.decode('utf-8')[:-1])
                #Doubtful about this stmt
                print('Answer 1 ',str(ipAdds2))
                print('Answer 2 ',str(ipAdds))
                print()
            #else:
                #print('False positives')
                #print('TXID '+str(packet[DNS].id)+' Request '+packet[DNS].qd.qname.decode('utf-8')[:-1])
                #Doubtful about this stmt
                #print('Answer 1 ',str(ipAdds2))
                #print('Answer 2 ',str(ipAdds))



def getIPsFromDNS(packet):
    ipAdds = []
    ancount = packet[DNS].ancount
    for index in range(ancount):
        ipAdds.append(packet[DNSRR][index].rdata)
    return ipAdds


def main():
    argParser = argparse.ArgumentParser(add_help=False)
    argParser.add_argument('-r', nargs='?', default=None)
    argParser.add_argument('-i', nargs='?', default=conf.iface)
    argParser.add_argument('fExp', nargs='*', default=None)
    args = argParser.parse_args()

   
    interface = args.i
    traceFile = args.r
    
    filterExp = ''
    if args.fExp is None:
        filterExp = 'port 53'
    else:
        for f in args.fExp:
            filterExp = filterExp + f + ' '


    #print filterExp
    #print interface        
    #print traceFile

    if traceFile is not None:
        sniff(offline=traceFile,filter=filterExp,prn=dnsDetect)
    else:
        sniff(iface=interface,filter=filterExp,prn=dnsDetect)


if __name__ == '__main__':
    main()

