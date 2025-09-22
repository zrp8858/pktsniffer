import argparse

def generate_argument_parser() -> argparse.ArgumentParser:
    # TODO: complete usage and description fields
    parser = argparse.ArgumentParser(usage='USAGE',
                                     description='DESCRIPTION',
                                     add_help=True)

    parser.add_argument('filepath',
                        type=str,
                        help='Path to .pcap file to sniff.')

    return parser


def main():
    parser = generate_argument_parser()
    args = parser.parse_args()

if __name__ == '__main__':
    main()