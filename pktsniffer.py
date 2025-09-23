import argparse

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

def parse_ethernet_header(packet: Packet) -> str:
    """
    Parses the ethernet header of a given packet.
    Prints the information to the console.
    :param packet: The target packet.
    :return: The ethertype of the packet as a string.
    """
    ethernet_header = packet.getlayer(Ether)
    ethertype = ETHER_TYPES[ethernet_header.type]

    print('Ethernet header:')
    print(f'\tPacket Size: {len(packet)} bytes')
    print(f'\tDestination MAC: {ethernet_header.dst}')
    print(f'\tSource MAC: {ethernet_header.src}')
    print(f'\tEthertype: {ethertype}')

    return ethertype

def read_pcap_file(filepath: str):
    try:
        contents = rdpcap(filepath)
        ethertype = parse_ethernet_header(contents[0])
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