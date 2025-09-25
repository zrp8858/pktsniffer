import argparse
from unittest import case

from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ETHER_TYPES
from scapy.packet import Packet
from scapy.utils import rdpcap

def generate_argument_parser() -> argparse.ArgumentParser:
    # TODO: complete usage and description fields
    parser = argparse.ArgumentParser(usage='USAGE',
                                     description='DESCRIPTION',
                                     add_help=True)

    parser.add_argument('filepath',
                        type=str,
                        help='Path to .pcap file to sniff.')

    return parser

def parse_ethernet_header(packet: Packet) -> bool:
    """
    Parses the ethernet header of a given IPv4 packet.
    Prints the information to the console.
    :param packet: The target packet.
    :return: True if the packet was parsed, False otherwise.
    """
    ethernet_header = packet.getlayer(Ether)
    ethertype = ETHER_TYPES[ethernet_header.type]

    if ethertype != 'IPv4': return False

    print('Ethernet Header:'
          f'\n\tPacket Size: {len(packet)} bytes'
          f'\n\tDestination MAC: {ethernet_header.dst}'
          f'\n\tSource MAC: {ethernet_header.src}'
          f'\n\tEthertype: {ethertype}')

    return True

def parse_ip_header(packet: Packet) -> str:
    """
    Parses the IP header of a given IPv4 packet.
    Prints the information to the console.
    :param packet: The target IPv4 packet.
    :return: The protocol associated with the packet.
    """
    ip_header = packet.getlayer(IP)
    protocol = IP_PROTOS[ip_header.proto]

    print('IP Header:'
          f'\n\tVersion: {ip_header.version}'
          f'\n\tHeader Length: {ip_header.ihl * 4} bytes'
          f'\n\tType of Service: {ip_header.tos}'
          f'\n\tTotal Length: {ip_header.len} bytes'
          f'\n\tIdentification: {ip_header.id}'
          f'\n\tFlags: {ip_header.flags}'
          f'\n\tFragment Offset: {ip_header.frag}'
          f'\n\tTime to Live: {ip_header.ttl}'
          f'\n\tProtocol: {protocol}'
          f'\n\tHeader Checksum: {ip_header.chksum}'
          f'\n\tSource IP: {ip_header.src}'
          f'\n\tDestination IP: {ip_header.dst}')

    return protocol

def parse_encapsulated_header(packet: Packet, protocol: str) -> bool:
    """
    Parses the encapsulated header of a given packet.
    Only parses TCP, UDP, and ICMP headers.
    Prints the information to the console.
    :param packet: the targeted packet.
    :param protocol: The protocol associated with the packet.
    :return: True if packet was parsed, False otherwise.
    """
    match protocol:
        case 'tcp':
            tcp_header = packet.getlayer(TCP)
            print('TCP Header:'
                  f'\n\tSPort: {tcp_header.sport}'
                  f'\n\tDPort: {tcp_header.dport}'
                  f'\n\tSEQ: {tcp_header.seq}'
                  f'\n\tACK: {tcp_header.ack}'
                  f'\n\tDataofs: {tcp_header.dataofs}'
                  f'\n\tReserved: {tcp_header.reserved}'
                  f'\n\tFlags: {tcp_header.flags}'
                  f'\n\tWindow: {tcp_header.window}'
                  f'\n\tChecksum: {tcp_header.chksum}'
                  f'\n\tUrgptr: {tcp_header.urgptr}'
                  f'\n\tOptions: {tcp_header.options}')
            return True
        case 'udp':
            udp_header = packet.getlayer(UDP)
            print('UDP Header:'
                  f'\n\tSPort: {udp_header.sport}'
                  f'\n\tDPort: {udp_header.dport}'
                  f'\n\tLength: {udp_header.len}'
                  f'\n\tChecksum: {udp_header.chksum}')
            return True
        case 'icmp':
            icmp_header = packet.getlayer(ICMP)
            print('ICMP Header:'
                  f'\n\tType: {icmp_header.type}'
                  f'\n\tCode: {icmp_header.code}'
                  f'\n\tChecksum: {icmp_header.chksum}'
                  f'\n\tID: {icmp_header.id}'
                  f'\n\tSeq: {icmp_header.seq}'
                  f'\n\tTS Ori: {icmp_header.ts_ori}'
                  f'\n\tTS Rx: {icmp_header.ts_rx}'
                  f'\n\tTS Tx: {icmp_header.ts_tx}'
                  f'\n\tGW: {icmp_header.gw}'
                  f'\n\tPtr: {icmp_header.ptr}'
                  f'\n\tReserved: {icmp_header.reserved}'
                  f'\n\tLength: {icmp_header.length}'
                  f'\n\tAddress Mask: {icmp_header.addr_mask}'
                  f'\n\tNext Hop MTU: {icmp_header.nexthopmtu}'
                  f'\n\tUnused: {icmp_header.unused}'
                  f'\n\tExtpad: {icmp_header.extpad}'
                  f'\n\tExt: {icmp_header.ext}')
            return True
        case _:
            return False

def read_pcap_file(filepath: str):
    try:
        for i in range(77,80):
            contents = rdpcap(filepath)
            if parse_ethernet_header(contents[i]):
                protocol = parse_ip_header(contents[i])
                parse_encapsulated_header(contents[i], protocol)
    except FileNotFoundError:
        print(f'File {filepath} not found.')
    except PermissionError:
        print(f'No permission to read {filepath}.')
    except Exception as e:
        print(f'Unknown error accessing {filepath}: {e}')

def main():
    parser = generate_argument_parser()
    args = parser.parse_args()

    read_pcap_file(args.filepath)

if __name__ == '__main__':
    main()