import json
from scapy.all import ARP, Ether, srp, get_if_list, conf
import socket

class NetworkScan:
    def __init__(self, network=None):
        self.network = network or self.get_local_network()
        self.devices = []
        
    def get_local_network(self):
        """Get the actual local network IP range"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            network_base = '.'.join(local_ip.split('.')[:-1]) + '.0'
            print(f"Your local IP: {local_ip}")
            print(f"Scanning network: {network_base}/24")
            return network_base
            
        except Exception as e:
            print(f"Could not auto-detect network: {e}")
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network_base = '.'.join(local_ip.split('.')[:-1]) + '.0'
            print(f"Using fallback - Your IP: {local_ip}")
            print(f"Scanning network: {network_base}/24")
            return network_base
    
    def do_scan(self):
        print(f"Available network interfaces: {get_if_list()}")
        print(f"Scapy is using interface: {conf.iface}")
        
        target = f"{self.network}/24"
        print(f"Target network: {target}")
        print("Scanning This may take 5-15 seconds\n")
        
        # Create ARP request packet
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        try:
            answered, unanswered = srp(packet, timeout=5, verbose=0, retry=3)
            

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Unknown"
                
                device = {
                    'IP': ip, 
                    'MAC': mac,
                    'Hostname': hostname
                }
                
                print(f"{ip:<18}{mac:<20}{hostname}")
                self.devices.append(device)
            
        except Exception as e:
            print(f"ip not found : {e}" )
                
        return self.devices

if __name__ == "__main__":
    print("NETWORK DEVICE SCANNER")
    scanner = NetworkScan()
    devices = scanner.do_scan()
    
    if devices:
        print(f" Summary: Successfully found {len(devices)} device(s)")
        
        with open('network_devices.json', 'w') as f:
            json.dump(devices, f, indent=2)
        
        print("Full results:")
        print(json.dumps(devices, indent=2))
        print(f"\n Results saved to: network_devices.json")
    else:
        print("\n Scan completed but no devices found.")