import argparse
import sys

from obfile import storage

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Command line utility to encrypt or decrypt the file with AES256')
    parser.add_argument('-e', '--encrypt', nargs=1, help="encrypt the specified file", type=storage.encrypt_file)
    parser.add_argument('-d', '--decrypt', nargs=1, help="decrypt the specified file", type=storage.decrypt_file)

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
