
# ARP Spoofing Packet Sniffer

This project demonstrates an ARP spoofing attack on a local network, capturing and logging sensitive data such as usernames and passwords. The attack sends malicious ARP packets to the target and gateway, tricking them into thinking the attacker’s machine is the other.

> **Warning**: Use this script only for educational purposes and only on networks where you have explicit permission. Unauthorized access to networks is illegal.

## Features

- ARP Spoofing: Poison the ARP tables of the target and the gateway, redirecting traffic through the attacker machine.
- Packet Sniffing: Capture HTTP request data including sensitive information like usernames, emails, and passwords.
- Packet Logging: Save captured packets to a `.pcap` file for later analysis.

## Requirements

Before running the script, make sure you have the following Python dependencies installed:

- **Scapy**: For packet manipulation and sniffing
- **Colorama**: For colored terminal output

You can install these dependencies by running:

```
pip install scapy colorama
```

Additionally, ensure that you have the necessary permissions to run network sniffing tools (e.g., root privileges on Linux/macOS or Administrator privileges on Windows).

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/arp-spoofing-sniffer.git
    cd arp-spoofing-sniffer
    ```

2. Run the script:

    ```bash
    python arp_spoof_sniffer.py
    ```

3. Input the following when prompted:

    - **Target IP address**: The IP address of the victim machine (default: `192.168.50.200`).
    - **Gateway IP address**: The IP address of your network's gateway (default: `192.168.50.1`).
    - **Packet capture file**: The name of the `.pcap` file where captured packets will be saved.

4. Once the script is running, it will start sending ARP packets and listening for data from the target. It will display any interesting data found, such as usernames and passwords, and save the packets to the specified `.pcap` file.

5. Press `Ctrl+C` to stop the attack and restore the ARP tables. If any packets were captured, they will be saved to the `.pcap` file.

## Example Output

```bash
Enter your target machine's IP address[192.168.50.200]=>
Enter your gateway's IP address[192.168.50.1]=>
Enter the name of the file that you want to save packets in => captured_packets
Finding MAC addresses
Done!
Attacker's MAC: 00:11:22:33:44:55
Target's MAC: 00:66:77:88:99:00
Router's MAC: 00:aa:bb:cc:dd:ee
ARP poisoning is started!
Press Ctrl+C to reARP and quit.
[*] Listening for packets from 192.168.50.200...
----------------interesting information----------------
username: johndoe
password: secret123
===================================================
```

## Captured Data

The tool looks for sensitive information in HTTP traffic, such as:

- **Usernames**
- **Passwords**
- **Email addresses**

If it finds any of the keywords in the packets, it will print them in red in the terminal output.

## File Format

Captured packets will be saved as a `.pcap` file, which can be analyzed with tools like Wireshark.

## Important Notes

- **ARP Spoofing**: This technique is used to deceive a network by associating the attacker's MAC address with the IP address of another machine (the target or the gateway). It's a common tactic in man-in-the-middle (MITM) attacks.
- **Legal Disclaimer**: Ensure you have authorization to run this script on the target network. Performing ARP spoofing on networks without permission is illegal and unethical.
- **Network Security**: This tool can be used to learn more about network vulnerabilities. It demonstrates how easy it is to intercept unencrypted data on a local network.

## License

This project is for educational purposes and is licensed under the MIT License.

---

If you have any questions or suggestions, feel free to reach out.
