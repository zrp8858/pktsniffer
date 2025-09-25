import argparse
from platform import android_ver
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
                        help='Path to .pcap file to analyze.')
    parser.add_argument('-c',
                        type=int,
                        default=-1,
                        help='Number of packets to analyze.')
    parser.add_argument('--host',
                        type=str,
                        help='Filter packets with the given IPv4 address.')
    parser.add_argument('--port',
                        type=int,
                        default=None,
                        help='Filter packets with the given src port or dst port.')
    parser.add_argument('--tcp',
                        action='store_true',
                        help='Filter packets with the TCP protocol.')
    parser.add_argument('--udp',
                        action='store_true',
                        help='Filter packets with the UDP protocol.')
    parser.add_argument('--icmp',
                        action='store_true',
                        help='Filter packets with the ICMP protocol.')
    parser.add_argument('--net',
                        type=str,
                        help='Filter packets within the given network.')

    return parser

def parse_ethernet_header(packet: Packet) -> tuple[str, bool]:
    """
    Parses the ethernet header of a given IPv4 packet.
    :param packet: The target packet.
    :return: A tuple containing:
                [0]: The parsed header
                [1]: True if the packet meets filter criteria, False otherwise
    """
    ethernet_header = packet.getlayer(Ether)
    # Throw out the packet if it doesn't have this layer
    if not ethernet_header:
        return '', False

    ethertype = ETHER_TYPES[ethernet_header.type]
    # Throw out the packet if it isn't IPv4
    if ethertype != 'IPv4': return '', False

    ethernet_parsed = ('Ethernet Header:'
                       f'\n\tPacket Size: {len(packet)} bytes'
                       f'\n\tDestination MAC: {ethernet_header.dst}'
                       f'\n\tSource MAC: {ethernet_header.src}'
                       f'\n\tEthertype: {ethertype}')

    return ethernet_parsed, True

def parse_ip_header(packet: Packet,
                    protocol_filter: list[str],
                    host_filter: str=None,
                    net_filter: str=None) -> tuple[str, str, bool]:
    """
    Parses the IP header of a given IPv4 packet.
    :param packet: The target IPv4 packet.
    :param protocol_filter: A list of protocols to filter by.
    :param host_filter: An IPv4 address to filter by.
    :param net_filter: An IPv4 network address to filter by.
    :return: A tuple containing:
                [0]: The parsed header
                [1]: The protocol of the packet
                [2]: True if the packet meets filter criteria, False otherwise
    """
    ip_header = packet.getlayer(IP)
    # Throw out the packet if it doesn't have this layer
    if not ip_header:
        return '', '', False

    protocol = IP_PROTOS[ip_header.proto]

    ip_summary = ('IP Header:'
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

    pass_protocol_filter = protocol in protocol_filter
    if host_filter:
        pass_host_filter = ip_header.src == host_filter or ip_header.dst == host_filter
    else:
        pass_host_filter = True
    if net_filter:
        pass_net_filter = True
    else:
        pass_net_filter = True

    pass_filter = pass_protocol_filter and pass_host_filter and pass_net_filter

    return ip_summary, protocol, pass_filter

def parse_encapsulated_header(packet: Packet, protocol: str, port_filter: int=None) -> tuple[str, bool]:
    """
    Parses the encapsulated header of a given packet.
    Only parses TCP, UDP, and ICMP headers.
    :param packet: The targeted packet.
    :param protocol: The protocol associated with the packet.
    :param port_filter: The port to filter by.
    :return: A tuple containing:
                [0]: The parsed header
                [1]: True if the packet meets filter criteria, False otherwise
    """
    match protocol:
        case 'tcp':
            tcp_header = packet.getlayer(TCP)

            if port_filter:
                pass_port_filter = tcp_header.dport == port_filter or tcp_header.sport == port_filter
            else:
                pass_port_filter = True

            tcp_summary = ('TCP Header:'
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
            return tcp_summary, pass_port_filter
        case 'udp':
            udp_header = packet.getlayer(UDP)

            if port_filter:
                pass_port_filter = udp_header.dport == port_filter or udp_header.sport == port_filter
            else:
                pass_port_filter = True

            udp_summary = ('UDP Header:'
                  f'\n\tSPort: {udp_header.sport}'
                  f'\n\tDPort: {udp_header.dport}'
                  f'\n\tLength: {udp_header.len}'
                  f'\n\tChecksum: {udp_header.chksum}')
            return udp_summary, (port_filter and (udp_header.sport == port_filter or udp_header.dport == port_filter))
        case 'icmp':
            icmp_header = packet.getlayer(ICMP)
            icmp_summary = ('ICMP Header:'
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
            return icmp_summary, not port_filter
        case _:
            return '', False

def read_pcap_file(filepath: str, args: argparse.Namespace):
    # Establishing filters to pass to parse_ip_header
    host_filter = args.host
    net_filter = args.net
    protocol_filter = ['tcp', 'udp', 'icmp']
    if args.tcp or args.udp or args.icmp:
        if not args.tcp: protocol_filter.remove('tcp')
        if not args.udp: protocol_filter.remove('udp')
        if not args.icmp: protocol_filter.remove('icmp')

    # Establishing a port filter to pass to parse_encapsulated_header
    port_filter = args.port

    try:
        contents = rdpcap(filepath)

        # Ensuring we don't read in more than we have
        max_packet = min(len(contents), args.c)
        # If max_packet is -1 (default argument), read all the packets
        max_packet = len(contents) if max_packet < 0 else max_packet

        for i in range(max_packet):
            parsed_ethernet = parse_ethernet_header(contents[i])
            if not parsed_ethernet[1]:
                continue

            parsed_ip = parse_ip_header(contents[i], protocol_filter, host_filter, net_filter)
            if not parsed_ip[2]:
                continue

            parsed_encapsulated = parse_encapsulated_header(contents[i], parsed_ip[1], port_filter)
            if not parsed_encapsulated[1]:
                continue

            # Packet matches all filter requirements, print summary
            print(f'Packet {i}'
                  f'\n{parsed_ethernet[0]}'
                  f'\n{parsed_ip[0]}'
                  f'\n{parsed_encapsulated[0]}\n')

    except FileNotFoundError:
        print(f'File {filepath} not found.')
    except PermissionError:
        print(f'No permission to read {filepath}.')
    except Exception as e:
        print(f'Unknown error accessing {filepath}: {e}')

def main():
    parser = generate_argument_parser()
    args = parser.parse_args()

    read_pcap_file(args.filepath, args)

if __name__ == '__main__':
    main()