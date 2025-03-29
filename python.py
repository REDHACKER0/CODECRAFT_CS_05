# Import necessary libraries
from scapy.all import *
from scapy.layers.inet import IP, Raw  # Import required layers
import datetime

# Function to display packet information
def packet_callback(packet):
    if IP in packet:  # Check if IP layer is present
        # Capture packet details
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        print("\nPacket Summary:")
        print("Source IP: {}".format(source_ip))
        print("Destination IP: {}".format(dest_ip))
        print("Protocol: {}".format(protocol))
        
        # Check for and display payload data
        if Raw in packet:
            print("Payload Data: {}".format(packet[Raw].load.decode(errors='ignore')))

# Print starting message
print("Starting packet sniffer...")

# Start sniffing packets
sniff(prn=packet_callback, count=10)  # Sniff and process 10 packets