import argparse
import sys

from obfile import storage

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="obfile", description="Command line utility to encrypt or decrypt the file with AES256.", \
        formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=47))
    parser.add_argument("-e", "--encrypt", nargs=1, action="store", help="encrypt the specified file", type=str)
    parser.add_argument("-d", "--decrypt", nargs=1, help="decrypt the specified file", type=str)
    parser.add_argument("-r", "--remove", action="store_true", help="delete original file after any operation")
    parser.add_argument("-er", "--encrypt-dir", nargs=1, action="store", help="encrypt directory recursively", type=str)
    parser.add_argument("-dr", "--decrypt-dir", nargs=1, help="decrypt directory recursively", type=str)
    parser.add_argument("--depth", default=0, help="depth of directory to recursively preform any operation", type=int)

    args = parser.parse_args()

    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)

    if args.encrypt is not None and len(args.encrypt) == 1:
        storage.encrypt_file(args.encrypt[0], None, args.remove)

    if args.decrypt is not None and len(args.decrypt) == 1:
        storage.decrypt_file(args.decrypt[0], None, args.remove)

    if args.encrypt_dir is not None and len(args.encrypt_dir) == 1:
        storage.encrypt_dir(args.encrypt_dir[0], args.depth, args.remove)

    if args.decrypt_dir is not None and len(args.decrypt_dir) == 1:
        storage.decrypt_dir(args.decrypt_dir[0], args.depth, args.remove)
