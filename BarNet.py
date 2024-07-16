import scapy.all as scapy
import optparse
import time

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-r", "--range", dest="ip_address", help="Enter IP Address range")
    parse_object.add_option("-c", "--count", dest="count", type="int", help="Number of packets to send")

    (user_input, arguments) = parse_object.parse_args()

    if not user_input.ip_address:
        print("Enter IP Address range")
        exit()

    if not user_input.count:
        print("Enter number of packets to send")
        exit()

    return user_input

def scan_my_network(ip, count):
    seen_ips = set()
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    
    for _ in range(count):
        arp_request_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet / arp_request_packet
        answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

        for element in answered_list:
            ip_address = element[1].psrc
            mac_address = element[1].hwsrc
            if ip_address not in seen_ips:
                seen_ips.add(ip_address)
                print(f"{ip_address}\t\t{mac_address}")

        time.sleep(1)  # Optional: Add delay between packet sending

user_input = get_user_input()
scan_my_network(user_input.ip_address, user_input.count)
