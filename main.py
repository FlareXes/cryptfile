from obfile import storage

if __name__ == '__main__':
    storage.encrypt_file("last_pic.png")
    storage.decrypt_file("pic.png.enc")
