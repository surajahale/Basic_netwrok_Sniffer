from scapy.all import sniff

def packet_callback(packet):
    try:
        print(packet.show())
    except Exception as e:
        print(f"Error processing packet: {e}")

print("Starting the network sniffer...")

try:
    sniff(prn=packet_callback, count=10)
except Exception as e:
    print(f"An error occurred: {e}")
