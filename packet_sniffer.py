from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
import sys
import socket
import ipaddress
from datetime import datetime
import requests

class PacketSniffer:
    def __init__(self, iface=None):
        """
        Initialize the PacketSniffer object.

        Parameters
        ----------
        iface : str, optional
            The network interface to sniff on (e.g., 'eth0'). If None, the default interface will be used.
        """
        self.iface = iface

    def get_geolocation(self, ip):
        """
        Get the geographical location of an IP address using a geolocation API.

        Parameters
        ----------
        ip : str
            The IP address to geolocate.

        Returns
        -------
        dict
            A dictionary containing location data (e.g., city, region, country).
        """
        try:
            response = requests.get(f"http://ipinfo.io/{ip}/json")
            location_data = response.json()
            return location_data
        except requests.RequestException as e:
            print(f"Error fetching geolocation for IP {ip}: {e}")
            return None

    def packet_callback(self, packet):
        """
        Callback function that is called for each captured packet.

        Parameters
        ----------
        packet : scapy.packet.Packet
            The captured packet.
        """
        print("\n=== New Packet ===")

        # Decode Ethernet layer
        if Ether in packet:
            print(f"Ethernet Frame: {packet[Ether].src} -> {packet[Ether].dst} (Type: {hex(packet[Ether].type)})")

        # Decode IP layer
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            ttl = packet[IP].ttl
            proto = packet[IP].proto
            print(f"IP Packet: {ip_src} -> {ip_dst} (TTL: {ttl}, Protocol: {proto})")

            # Geolocate source and destination IPs
            src_location = self.get_geolocation(ip_src)
            dst_location = self.get_geolocation(ip_dst)

            if src_location:
                print(f"Source IP Location: {src_location.get('city', 'Unknown City')}, "
                      f"{src_location.get('region', 'Unknown Region')}, "
                      f"{src_location.get('country', 'Unknown Country')}")
            
            if dst_location:
                print(f"Destination IP Location: {dst_location.get('city', 'Unknown City')}, "
                      f"{dst_location.get('region', 'Unknown Region')}, "
                      f"{dst_location.get('country', 'Unknown Country')}")

        # Decode TCP layer
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            print(f"TCP Segment: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport} (Flags: {tcp_flags})")

        # Decode UDP layer
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Datagram: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

        # Decode raw payload data
        if Raw in packet:
            payload = packet[Raw].load
            try:
                decoded_payload = payload.decode('utf-8')
                print(f"Payload: {decoded_payload}")
            except UnicodeDecodeError:
                print(f"Payload (non-UTF-8): {payload}")

    def start_sniffing(self):
        """
        Start sniffing packets.
        """
        print(f"Starting packet capture on interface: {self.iface if self.iface else 'default'}")
        sniff(iface=self.iface, prn=self.packet_callback, store=False)

# EXAMPLE USAGE
if __name__ == "__main__":
    sniffer = PacketSniffer(iface="en0")  # Replace "eth0" with the appropriate network interface name
    sniffer.start_sniffing()
    
#run  with sudo permissions
