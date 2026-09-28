import argparse
import ipaddress
import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, DNS, DNSQR, Ether, srp, conf
from scapy.interfaces import resolve_iface
import socket

# Seconds to wait for each hostname lookup method before trying the next
LOOKUP_TIMEOUT = 1.5

# Adapters created by VPNs and virtualisation software. They don't lead to the physical LAN, so skip them.
VIRTUAL_ADAPTER = re.compile(
    r"vpn|wireguard|wintun|openvpn|tailscale|zerotier|nordlynx|anyconnect|forti|globalprotect|pangp|"
    r"juniper|pulse secure|sonicwall|hamachi|wan miniport|virtual|vmware|virtualbox|hyper-v|vethernet|"
    r"docker|wsl|loopback|\b(tap|tun|wg|ppp|utun|zt)\w*\b",
    re.IGNORECASE,
)

class NetworkScan:
    def __init__(self, network=None, timeout=5, retry=3, iface=None, listen_time=8):
        self.timeout = timeout
        self.retry = retry
        self.listen_time = listen_time
        self.devices = []
        self.gateway = None
        self.gateway_mac = None
        self.isolation_note = None
        if network:
            self.network = self.parse_network(network)
            self.iface = iface or self.find_iface_for(self.network)
        else:
            self.network, detected_iface = self.get_local_network()
            self.iface = iface or detected_iface

    @staticmethod
    def parse_network(network):
        """Validate a network given as CIDR (e.g. 10.0.0.0/16); a bare IP is treated as /24"""
        if "/" not in network:
            network += "/24"
        return str(ipaddress.ip_network(network, strict=False))

    @staticmethod
    def is_physical(iface):
        """True unless the interface is a VPN/virtual adapter or not connected"""
        try:
            dev = resolve_iface(iface)
            text = f"{dev.name} {dev.description}"
            flags = str(getattr(dev, "flags", ""))
        except Exception:
            text, flags = str(iface), ""
        return not VIRTUAL_ADAPTER.search(text) and "DISCONNECTED" not in flags

    def lan_interfaces(self):
        """Private subnets attached directly to a physical adapter, best first.

        Read from the routing table rather than asking which interface reaches the internet,
        because with a VPN on that answer is the VPN tunnel instead of the home network.
        """
        gateway_metric = {}
        for net, mask, gw, iface, addr, metric in conf.route.routes:
            if mask == 0 and gw != "0.0.0.0":
                gateway_metric[iface] = min(metric, gateway_metric.get(iface, metric))

        lans = []
        for net, mask, gw, iface, addr, metric in conf.route.routes:
            if mask in (0, 0xFFFFFFFF) or gw != "0.0.0.0":
                continue
            network = ipaddress.IPv4Network((net, bin(mask).count("1")))
            if not network.is_private or network.is_link_local or network.is_loopback or network.is_multicast:
                continue
            if not self.is_physical(iface):
                continue
            # Prefer adapters that also have a default gateway (i.e. a router), lowest metric first
            rank = (iface not in gateway_metric, gateway_metric.get(iface, 0))
            lans.append((rank, network, iface, addr))
        lans.sort(key=lambda lan: lan[0])
        return [(network, iface, addr) for _, network, iface, addr in lans]

    def find_iface_for(self, network):
        """The physical adapter whose subnet overlaps the requested network, if any"""
        target = ipaddress.ip_network(network)
        for lan, iface, _ in self.lan_interfaces():
            if lan.overlaps(target):
                return iface
        return None

    def get_local_network(self):
        """Get the local network range and the physical adapter it is on"""
        lans = self.lan_interfaces()
        if lans:
            network, iface, local_ip = lans[0]
            print(f"Your local IP: {local_ip}")
            if network.prefixlen < 22:
                print(f"{network} is large; scanning only the /24 around your IP (use --network to scan it all)")
                network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            print(f"Scanning network: {network}")
            return str(network), iface

        print("Could not find a physical network adapter; falling back to the default route (may be a VPN)")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        except OSError:
            local_ip = socket.gethostbyname(socket.gethostname())
        finally:
            s.close()

        network = self.parse_network(local_ip)
        print(f"Your local IP: {local_ip}")
        print(f"Scanning network: {network}")
        return network, None

    def get_gateway(self):
        """The router on the scanned adapter, which usually also runs the LAN's DNS"""
        for net, mask, gw, iface, addr, metric in conf.route.routes:
            if mask == 0 and gw != "0.0.0.0" and (self.iface is None or iface == self.iface):
                return gw
        return None

    @staticmethod
    def query_ptr(ip, server, port):
        """Send a reverse (PTR) DNS query for ip to server:port and return the name, or None"""
        reverse_name = ipaddress.ip_address(ip).reverse_pointer
        query = DNS(id=random.randint(0, 0xFFFF), rd=1, qd=DNSQR(qname=reverse_name, qtype="PTR"))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(LOOKUP_TIMEOUT)
            try:
                s.sendto(bytes(query), (server, port))
                reply = DNS(s.recv(4096))
            except (OSError, ValueError):
                return None
        for i in range(reply.ancount or 0):
            answer = reply.an[i]
            if answer.type == 12:  # PTR
                name = answer.rdata.decode() if isinstance(answer.rdata, bytes) else str(answer.rdata)
                return name.rstrip(".")
        return None

    @staticmethod
    def query_netbios(ip):
        """Ask a device for its NetBIOS name (Windows PCs, NAS drives, Samba). Returns the name or None"""
        # Node status request for the wildcard name "*", encoded as NetBIOS first-level encoding
        encoded = b"CK" + b"A" * 30
        request = (random.randint(0, 0xFFFF).to_bytes(2, "big") + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                   + b"\x20" + encoded + b"\x00" + b"\x00\x21\x00\x01")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(LOOKUP_TIMEOUT)
            try:
                s.sendto(request, (ip, 137))
                reply = s.recv(4096)
            except OSError:
                return None
        # Header (12) + name (34) + type/class/ttl/length (10), then the name count and 18-byte entries
        if len(reply) < 57:
            return None
        for i in range(reply[56]):
            entry = reply[57 + i * 18: 57 + (i + 1) * 18]
            if len(entry) < 18:
                break
            name, suffix, flags = entry[:15], entry[15], int.from_bytes(entry[16:18], "big")
            # Suffix 0x00 is the workstation name; skip group names such as the workgroup
            if suffix == 0x00 and not flags & 0x8000:
                return name.decode(errors="ignore").strip()
        return None

    def get_hostname(self, ip):
        """Try each way of naming a device in turn, falling back to "Unknown" when none answers"""
        lookups = [
            lambda: socket.gethostbyaddr(ip)[0],             # system DNS
            lambda: self.gateway and self.query_ptr(ip, self.gateway, 53),  # router's DNS, bypassing a VPN's
            lambda: self.query_ptr(ip, ip, 5353),            # mDNS / Bonjour, asked of the device directly
            lambda: self.query_netbios(ip),                  # NetBIOS
        ]
        for lookup in lookups:
            try:
                name = lookup()
            except (OSError, ValueError):
                name = None
            if name and name != ip:
                return name.removesuffix(".local")
        return "Unknown"

    def get_own_ip(self):
        """This machine's address on the scanned adapter"""
        try:
            return resolve_iface(self.iface or conf.iface).ip
        except Exception:
            return None

    def listen_for_others(self, duration):
        """Actively look for devices the ARP scan couldn't reach, by asking over mDNS multicast.

        Client isolation blocks the unicast ARP replies from other clients, but access points
        usually keep flooding the mDNS multicast group, so a device that answers our mDNS query
        proves it is present even though the scan couldn't see it. A finding here is a reliable
        positive; silence is inconclusive, because a device can be asleep or speak no mDNS at all.

        Returns the set of other devices' IPs that answered, or None if the socket can't be set up.
        """
        own_ip, gateway = self.get_own_ip(), self.gateway
        group = "224.0.0.251"  # the mDNS multicast group
        # Ask every Bonjour-capable device to name itself. Devices reply to the multicast group, which
        # access points usually keep flooding even under client isolation (it's how Chromecast and
        # AirPlay stay discoverable there), so this surfaces devices a plain ARP scan can't reach.
        # The first name enumerates every responder; the rest coax device types that ignore it.
        query_names = [
            "_services._dns-sd._udp.local",  # standard "list all services" meta-query
            "_googlecast._tcp.local",        # Chromecast, Google/Android TV, Nest
            "_airplay._tcp.local",           # Apple TV, AirPlay speakers
            "_ipp._tcp.local",               # network printers
        ]
        queries = [bytes(DNS(rd=0, qd=DNSQR(qname=n, qtype="PTR"))) for n in query_names]
        others = set()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 5353))
            # Join the group so the OS and NIC stop filtering it out, then send from our own adapter
            member = socket.inet_aton(group) + socket.inet_aton(own_ip or "0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, member)
            if own_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own_ip))
        except OSError:
            sock.close()
            return None

        sock.settimeout(0.5)
        deadline, next_query = time.time() + duration, 0.0
        while time.time() < deadline:
            now = time.time()
            if now >= next_query:
                for query in queries:
                    try:
                        sock.sendto(query, (group, 5353))
                    except OSError:
                        pass
                next_query = now + 1.0
            try:
                _, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if ip not in (own_ip, gateway) and not ip.startswith(("0.", "127.")):
                others.add(ip)
        sock.close()
        return others

    def check_isolation(self, devices):
        """Tell client isolation apart from a network that genuinely has only two devices.

        Both look identical to an ARP scan: only this machine and the router answer. To separate
        them, ask over mDNS for devices the scan couldn't reach. Finding one is proof of isolation;
        finding none is only suggestive, since a device can be asleep or not speak mDNS.
        """
        if not devices:
            return None
        own_ip, gateway = self.get_own_ip(), self.gateway
        others = [d for d in devices if d['IP'] not in (own_ip, gateway)]
        if others:
            return None

        print(f"Only this machine and the router answered; probing {self.listen_time}s over mDNS to "
              f"tell client isolation from a genuinely quiet network\n")
        heard = self.listen_for_others(self.listen_time)
        if heard is None:
            return ("Only this machine and the router answered, and the mDNS probe couldn't run, so "
                    "this could be client isolation or genuinely just two devices.")
        if heard:
            return (f"Client isolation confirmed: {len(heard)} other device(s) answered an mDNS probe "
                    f"even though only this machine and the router answered the scan. Their direct "
                    f"replies to us are being blocked (AP/station isolation), which is common on guest, "
                    f"hotel and public Wi-Fi.")
        return ("Likely just two devices online (this machine and the router): nothing answered the "
                "scan and no other device replied to an mDNS probe. This is probably not client "
                "isolation, but a device that is asleep or doesn't speak mDNS could still be hidden.")

    @staticmethod
    def get_vendor(mac):
        """Manufacturer from the MAC's first three bytes, which helps identify devices with no hostname"""
        # The "locally administered" bit marks a randomised MAC, used by phones and tablets for privacy
        if int(mac[1], 16) & 2:
            return "Private MAC (phone/tablet)"
        vendor = conf.manufdb._get_manuf(mac)
        return "Unknown" if vendor == mac else vendor

    def do_scan(self):
        iface = resolve_iface(self.iface or conf.iface)
        print(f"Using interface: {iface.description or iface.name}")

        print(f"Target network: {self.network}")
        print("Scanning This may take 5-15 seconds\n")

        # Create ARP request packet
        arp = ARP(pdst=self.network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        self.devices = []
        try:
            answered, unanswered = srp(packet, iface=self.iface, timeout=self.timeout, verbose=0, retry=self.retry)

            replies = {received.psrc: received.hwsrc for sent, received in answered}

            # Name lookups wait on timeouts, so run them for all devices at once
            self.gateway = self.get_gateway()
            self.gateway_mac = replies.get(self.gateway)
            with ThreadPoolExecutor(max_workers=32) as pool:
                hostnames = dict(zip(replies, pool.map(self.get_hostname, replies)))

            for ip, mac in replies.items():
                hostname = hostnames[ip]
                vendor = self.get_vendor(mac)
                device = {
                    'IP': ip,
                    'MAC': mac,
                    'Hostname': hostname,
                    'Vendor': vendor
                }

                print(f"{ip:<18}{mac:<20}{hostname:<24}{vendor}")
                self.devices.append(device)

        except Exception as e:
            print(f"Scan failed: {e}")

        self.devices.sort(key=lambda d: ipaddress.ip_address(d['IP']))
        self.isolation_note = self.check_isolation(self.devices)
        return self.devices

def parse_args():
    parser = argparse.ArgumentParser(description="Find devices on the local network using ARP.")
    parser.add_argument("-n", "--network", help="network to scan in CIDR form, e.g. 10.0.0.0/16 (default: auto-detected /24)")
    parser.add_argument("-i", "--iface", help="network adapter to scan from, e.g. Wi-Fi or eth0 (default: auto-detected, skipping VPNs)")
    parser.add_argument("-t", "--timeout", type=float, default=5, help="seconds to wait for replies (default: 5)")
    parser.add_argument("-r", "--retry", type=int, default=3, help="times to resend unanswered requests (default: 3)")
    parser.add_argument("-l", "--listen", type=float, default=8, help="seconds to listen for other devices when only the router answers, to spot client isolation (default: 8)")
    parser.add_argument("-o", "--output", default="network_devices.json", help="JSON file to save results to")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print("NETWORK DEVICE SCANNER")
    try:
        scanner = NetworkScan(args.network, timeout=args.timeout, retry=args.retry, iface=args.iface, listen_time=args.listen)
    except ValueError as e:
        raise SystemExit(f"Invalid network: {e}")
    devices = scanner.do_scan()

    if devices:
        print(f" Summary: Successfully found {len(devices)} device(s)")
        if scanner.isolation_note:
            print(f"\n Note: {scanner.isolation_note}")

        with open(args.output, 'w') as f:
            json.dump(devices, f, indent=2)

        print("Full results:")
        print(json.dumps(devices, indent=2))
        print(f"\n Results saved to: {args.output}")
    else:
        print("\n Scan completed but no devices found.")
