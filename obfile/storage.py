import os
import pickle
from getpass import getpass

from obfile import security
from obfile import utils


def save_file(data, file):
    with open(file + ".enc", "wb") as f:
        pickle.dump(data, f, -1)


def open_file(file):
    with open(file, "rb") as f:
        data = pickle.load(f)
    return data


def remove_file(file):
    os.remove(file)


def encrypt_file(file, key=None, remove_original: bool = False):
    with open(file, "rb") as f:
        data = f.read()
    if key is None: key = getpass("Password: ")
    enc_data = security.encrypt(data, key)
    save_file(enc_data, file)
    if remove_original: remove_file(file)


def encrypt_dir(directory, depth: int = 0, remove_original: bool = False):
    key = getpass("Password: ")
    for sub_dir in utils.depth_lister(directory, depth):
        files = utils.filter_files(sub_dir)
        for file in files:
            encrypt_file(os.path.join(sub_dir, file), key, remove_original)


def decrypt_file(enc_file, key=None, remove_original: bool = False):
    enc_data = open_file(enc_file)
    if key is None: key = getpass("Password: ")
    dec_data = security.decrypt(enc_data, key)
    with open(enc_file.split(".enc")[0], "wb") as f:
        f.write(dec_data)
    if remove_original: remove_file(enc_file)


def decrypt_dir(directory, depth: int = 0, remove_original: bool = False):
    key = getpass("Password: ")
    for sub_dir in utils.depth_lister(directory, depth):
        files = utils.filter_files(sub_dir, True)
        for file in files:
            decrypt_file(os.path.join(sub_dir, file), key, remove_original)
