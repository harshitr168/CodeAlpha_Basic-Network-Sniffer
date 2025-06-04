from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def analyze_packet(packet):
    print("\n--- Packet Captured ---")
    print("Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for common protocols
        if packet.haslayer(TCP):
            print("Protocol Type: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("Protocol Type: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("Protocol Type: ICMP")

        # Print payload if available
        if packet.haslayer(Raw):
            print("Payload:")
            print(packet[Raw].load)
        else:
            print("No Payload.")
    else:
        print("Non-IP Packet")

# Start sniffing (change iface to your network interface if needed)
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=False)

