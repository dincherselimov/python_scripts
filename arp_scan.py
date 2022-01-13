import sys
from datetime import datetime

from scapy.config import conf
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def arp_scan(interface, ips):
    print("[*] Scanning...")
    start_time = datetime.now()

    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
                     timeout=2,
                     iface=interface,
                     inter=0.1)

    print("\n[*] IP - MAC")
    for snd, rcv in ans:
        print(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))
    stop_time = datetime.now()
    total_time = stop_time - start_time
    print("\n[*] Scan Complete. Duration:", total_time)


if __name__ == "__main__":
    arp_scan(sys.argv[1], sys.argv[2])
