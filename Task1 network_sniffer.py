import socket
import struct
import binascii
import os
import logging

logging.basicConfig(
    filename='sniffer_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

def parse_ip_header(data):
    ip_header = data[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    ihl = iph[0] & 0xF
    iph_length = ihl * 4

    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])

    return src_addr, dst_addr, protocol, iph_length

def main():
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("Permission denied: Run as administrator.")
        return

    sniffer.bind(("192.168.8.27", 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("[*] Sniffer started. Generate traffic (ping, browse)... Ctrl+C to stop.")

    try:
        while True:
            packet, _ = sniffer.recvfrom(65535)

            src, dst, proto, header_len = parse_ip_header(packet)
            payload = packet[header_len:header_len+50]

            msg = f"Src: {src} → Dst: {dst} | Proto: {proto} (6=TCP, 17=UDP, 1=ICMP)"
            print(msg)
            logging.info(msg)

            print(f"Payload (hex): {binascii.hexlify(payload)}")

    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main() 


