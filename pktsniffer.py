import argparse

from scapy.data import IP_PROTOS
from scapy.layers.inet import IP
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

def read_pcap_file(filepath: str):
    try:
        contents = rdpcap(filepath)
        if parse_ethernet_header(contents[0]):
            parse_ip_header(contents[0])
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