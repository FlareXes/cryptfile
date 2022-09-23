import pickle


def save_file(data, file):
    with open(file + ".enc", "wb") as f:
        pickle.dump(data, f, -1)


def open_file(file):
    with open(file, "rb") as f:
        data = pickle.load(f)
    return data
