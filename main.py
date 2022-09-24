import sys
import argparse
from obfile import storage

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Command line utility to encrypt or decrypt the file with AES256.")
    parser.add_argument("-e", "--encrypt", nargs=1, action="store", help="encrypt the specified file", type=str)
    parser.add_argument("-d", "--decrypt", nargs=1, help="decrypt the specified file", type=str)
    parser.add_argument("-r", "--remove", action="store_true", help="delete original file after any operation")
    args = parser.parse_args()

    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)

    try:
        if len(args.encrypt) == 1 and args.decrypt is None:
            storage.encrypt_file(args.encrypt[0], args.remove)
    except TypeError:
        if args.encrypt is None and len(args.decrypt) == 1:
            storage.decrypt_file(args.decrypt[0], args.remove)
