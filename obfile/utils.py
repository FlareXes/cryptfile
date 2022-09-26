import glob
import os


def filter_files(directory: str, dot_enc: str = False):
    if os.path.isdir(directory):
        dir_obj = os.scandir(directory)
        if dot_enc:
            return [file.name for file in dir_obj if file.is_file() and file.name.endswith('.enc')]
        return [file.name for file in dir_obj if file.is_file()]


def depth_lister(root_directory: str, depth: int):
    for i in range(0, depth + 1):
        dirs_depth = glob.glob(os.path.join(root_directory, '*/' * i))
        for dir_depth in dirs_depth:
            yield dir_depth
