from scapy.all import ARP, Ether, srp

INTERFACE = "wlan0"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

ADDRESS = input("Enter the first three octets of the address: ")

def main():

    for ip in range(1, 51):
        target = f"{ADDRESS}.{ip}"

        packet = Ether(dst=BROADCAST_MAC) / ARP(pdst=target)

        answered, unanswered = srp(
            packet,
            iface=INTERFACE,
            timeout=1,
            verbose=False
        )

        for _, response in answered:
            print(f"IP Address : {response.psrc}")
            print(f"MAC Address: {response.hwsrc}")
            print("-" * 30)


if __name__ == "__main__":
    main()
