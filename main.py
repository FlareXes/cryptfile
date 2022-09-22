from obsfile import security
from obsfile import storage


def encrypt_file(file):
    with open(file, "rb") as f:
        data = f.read()
    enc_data = security.encrypt(data, input("Password: "))
    storage.save_file(enc_data, file)


def decrypt_file(enc_file):
    enc_data = storage.open_file(enc_file)
    dec_data = security.decrypt(enc_data, input("Password: "))
    with open(enc_file.split(".enc")[0], "wb") as f:
        f.write(dec_data)


if __name__ == '__main__':
    encrypt_file("file.txt")
    decrypt_file("file.txt.enc")
