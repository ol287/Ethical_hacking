import socket
import threading
import queue
import time

class PortScanner:
    def __init__(self, target_ip, start_port=1, end_port=1024, timeout=1.0, num_threads=100):
        """
        Initialize the PortScanner object.

        Parameters:
        target_ip (str): The IP address of the target to scan.
        start_port (int): The starting port number for the scan (default is 1).
        end_port (int): The ending port number for the scan (default is 1024).
        timeout (float): Timeout in seconds for each port connection attempt (default is 1.0).
        num_threads (int): Number of threads to use for scanning (default is 100).
        """
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.num_threads = num_threads
        self.port_queue = queue.Queue()
        self.open_ports = []
        self.lock = threading.Lock()

    def scan_port(self, port):
        """
        Scan a specific port on the target IP address.

        Parameters:
        port (int): The port number to scan.

        Returns:
        None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    print(f"[+] Port {port} is open")

                try:
                    banner = sock.recv(1024).decode().strip()
                    if banner:
                        with self.lock:
                            print(f"    Service banner: {banner}")
                    else:
                        with self.lock:
                            print("    No banner available")
                except:
                    with self.lock:
                        print("    Unable to retrieve banner")
            sock.close()
        except socket.error as e:
            print(f"[-] Error on port {port}: {e}")

    def threader(self):
        """
        Worker function for threading. Continuously processes the port_queue.

        Returns:
        None
        """
        while True:
            port = self.port_queue.get()
            self.scan_port(port)
            self.port_queue.task_done()

    def run(self):
        """
        Start the port scanning process using multiple threads.

        Returns:
        None
        """
        print(f"[*] Starting scan on {self.target_ip} from port {self.start_port} to {self.end_port}")

        # Fill the queue with the range of ports to scan
        for port in range(self.start_port, self.end_port + 1):
            self.port_queue.put(port)

        # Start threads
        for _ in range(self.num_threads):
            thread = threading.Thread(target=self.threader)
            thread.daemon = True
            thread.start()

        # Wait for all threads to complete
        self.port_queue.join()
        print(f"[*] Scan complete. Open ports: {self.open_ports}")

# Example usage:
if __name__ == "__main__":
    target_ip = "192.168.1.1"  # Replace with the target IP address
    scanner = PortScanner(target_ip, start_port=1, end_port=1024, timeout=1.0, num_threads=100)
    scanner.run()
