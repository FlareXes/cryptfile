import pickle
from obfile import security
from getpass import getpass

def save_file(data, file):
    with open(file + ".enc", "wb") as f:
        pickle.dump(data, f, -1)


def open_file(file):
    with open(file, "rb") as f:
        data = pickle.load(f)
    return data


def encrypt_file(file):
    with open(file, "rb") as f:
        data = f.read()
    enc_data = security.encrypt(data, getpass("Password: "))
    save_file(enc_data, file)


def decrypt_file(enc_file):
    enc_data = open_file(enc_file)
    dec_data = security.decrypt(enc_data, getpass("Password: "))
    with open(enc_file.split(".enc")[0], "wb") as f:
        f.write(dec_data)
