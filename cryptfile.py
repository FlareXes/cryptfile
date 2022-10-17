import os
import sys
import glob
import pickle
import argparse
from getpass import getpass

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
from Cryptodome.Random import get_random_bytes


class Security:
    @staticmethod
    def encrypt(data, key):
        random_bytes = get_random_bytes(32).__str__()
        private_key = scrypt(password=key, salt=random_bytes,
                             key_len=32, N=2 ** 20, r=8, p=1)

        cipher = AES.new(private_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        configs = {'salt': random_bytes, 'ciphertext': ciphertext,
                   'nonce': cipher.nonce, 'tag': tag}
        return configs

    @staticmethod
    def decrypt(configs, key):
        random_bytes = configs['salt']
        ciphertext = configs['ciphertext']
        nonce = configs['nonce']
        tag = configs['tag']

        private_key = scrypt(password=key, salt=random_bytes,
                             key_len=32, N=2 ** 20, r=8, p=1)
        cipher = AES.new(private_key, AES.MODE_GCM, nonce)

        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data


class Utils:
    @staticmethod
    def filter_files(directory: str, dot_enc: bool = False):
        if os.path.isdir(directory):
            dir_obj = os.scandir(directory)
            if dot_enc:
                return [file.name for file in dir_obj if file.is_file() and file.name.endswith('.enc')]
            return [file.name for file in dir_obj if file.is_file()]

    @staticmethod
    def depth_lister(root_directory: str, depth: int):
        if depth < 0:
            for subdir, _, _ in os.walk(root_directory):
                yield subdir
        else:
            for i in range(0, depth + 1):
                dirs_depth = glob.glob(os.path.join(root_directory, '*/' * i))
                for dir_depth in dirs_depth:
                    yield dir_depth


class Storage(Security, Utils):
    @staticmethod
    def save_file(data, file):
        with open(file + ".enc", "wb") as f:
            pickle.dump(data, f, -1)

    @staticmethod
    def open_file(file):
        with open(file, "rb") as f:
            data = pickle.load(f)
        return data

    @staticmethod
    def remove_file(file):
        os.remove(file)

    def encrypt_file(self, file, key=None, remove_original: bool = False):
        with open(file, "rb") as f:
            data = f.read()
        if key is None: key = getpass("Password: ")
        enc_data = Security.encrypt(data, key)
        self.save_file(enc_data, file)
        if remove_original: self.remove_file(file)

    def encrypt_dir(self, directory, depth: int = 0, remove_original: bool = False):
        key = getpass("Password: ")
        for sub_dir in Utils.depth_lister(directory, depth):
            files = Utils.filter_files(sub_dir)
            for file in files:
                self.encrypt_file(os.path.join(sub_dir, file), key, remove_original)

    def decrypt_file(self, enc_file, key=None, remove_original: bool = False):
        enc_data = self.open_file(enc_file)
        if key is None: key = getpass("Password: ")
        dec_data = Security.decrypt(enc_data, key)
        with open(enc_file.split(".enc")[0], "wb") as f:
            f.write(dec_data)
        if remove_original: self.remove_file(enc_file)

    def decrypt_dir(self, directory, depth: int = 0, remove_original: bool = False):
        key = getpass("Password: ")
        for sub_dir in Utils.depth_lister(directory, depth):
            files = Utils.filter_files(sub_dir, True)
            for file in files:
                self.decrypt_file(os.path.join(sub_dir, file), key, remove_original)


def main():
    parser = argparse.ArgumentParser(prog="cryptfile",
                                     description="Command line utility to encrypt or decrypt the file with AES256.",
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=47))
    parser.add_argument("-e", "--encrypt", nargs=1, action="store", help="encrypt the specified file", type=str)
    parser.add_argument("-d", "--decrypt", nargs=1, help="decrypt the specified file", type=str)
    parser.add_argument("-r", "--remove", action="store_true", help="delete original file after any operation")
    parser.add_argument("-er", "--encrypt-dir", nargs=1, action="store", help="encrypt directory recursively", type=str)
    parser.add_argument("-dr", "--decrypt-dir", nargs=1, help="decrypt directory recursively", type=str)
    parser.add_argument("--depth", default=0, help="depth of directory to recursively preform any operation", type=int)

    args = parser.parse_args()

    if len(sys.argv) == 1: parser.print_help(); sys.exit(1)

    if args.encrypt is not None and len(args.encrypt) == 1:
        Storage().encrypt_file(args.encrypt[0], None, args.remove)

    if args.decrypt is not None and len(args.decrypt) == 1:
        Storage().decrypt_file(args.decrypt[0], None, args.remove)

    if args.encrypt_dir is not None and len(args.encrypt_dir) == 1:
        Storage().encrypt_dir(args.encrypt_dir[0], args.depth, args.remove)

    if args.decrypt_dir is not None and len(args.decrypt_dir) == 1:
        Storage().decrypt_dir(args.decrypt_dir[0], args.depth, args.remove)


if "__main__" == __name__:
    main()
