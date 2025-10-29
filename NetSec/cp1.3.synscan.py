from scapy.all import *

import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])

    # NOTE: print one IPAddress,port combination per line without any extra spaces
    # For example:
    # 10.4.61.4,994
    # #ignored comment line
    # 10.4.61.4,25

    # TODO: add SYN scan code
    for port in range(1, 1025):
        # Build SYN packet
        ip = IP(dst=ip_addr)
        tcp = TCP(sport=RandShort(), dport=port, flags='S')
        pkt = ip / tcp

        # Send SYN, wait for SYN+ACK
        resp = sr1(pkt, timeout=1, verbose=0)

        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            # Print IP,port as required
            print(f"{ip_addr},{port}")

            # Send RST to close the connection
            rst_pkt = IP(dst=ip_addr) / TCP(sport=RandShort(), dport=port, flags='R')
            send(rst_pkt, verbose=0)
