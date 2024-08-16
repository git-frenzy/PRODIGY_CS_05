from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"source IP address: {ip_layer.src}")
        print(f"destination IP address: {ip_layer.dst}")
        
        if packet.haslayer(TCP):
            print("Protocol: TCP")
            tcp_layer = packet.getlayer(TCP)
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            if tcp_layer.payload:
                print(f"Payload: {tcp_layer.payload}")

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            udp_layer = packet.getlayer(UDP)
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            if udp_layer.payload:
                print(f"Payload: {udp_layer.payload}")

        if packet.haslayer(Raw):
            print(f"Raw Data: {packet[Raw].load}")
        
        print("\n")

def start_sniffing(interface):
    print(f"Starting packet capture on {interface}")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing("eth0")
