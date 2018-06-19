#!/usr/bin/python

# ---------------- READ ME ---------------------------------------------
# This Script is Created Only For Practise And Educational Purpose Only
# This Script Is Created For http://bitforestinfo.blogspot.com
# This Script is Written By

# import modules
import socket 
import struct
import binascii
import os
import pye

# print author details on terminal
#print pye.__author__

# if operating system is windows
#if os.name == "nt":
 #   s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
  #  s.bind(("YOUR_INTERFACE_IP",0))
   # s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
   # s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# if operating system is linux
s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))

# create loop 
while True:
    flag = 0
    # Capture packets from network
    pkt=s.recvfrom(65565)

    # extract packets with the help of pye.unpack class 
    unpack=pye.unpack()

    if unpack.eth_header(pkt[0][0:14])['Protocol'] == 2054:
        print("\n\n===&gt;&gt; [+] ------------ Ethernet Header----- [+]")
        # print data on terminal
        for a, b in unpack.eth_header(pkt[0][0:14]).items():
            #a, b = i
            # if a == "Protocol" and b == '2054':
            #     flag = 1
            print("{} : {} | ".format(a,b))
        print("\n===&gt;&gt; [+] ------------ IP Header ------------[+]")
        for a, b in unpack.ip_header(pkt[0][14:34]).items():
            #a,b=i
            print("{} : {} | ".format(a,b))
        print("\n===&gt;&gt; [+] ------------ Tcp Header ----------- [+]")
        for  a, b in unpack.tcp_header(pkt[0][34:54]).items():
            #a,b=i
            print("{} : {} | ".format(a,b))