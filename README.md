# obfile
`Obfile` or `Obfuscate File` is a command line utility to encrypt or decrypt the file with AES256.

# Installation
```bash
git clone https://github.com/FlareXes/obfile.git && cd obfile

pip install -r requirements.txt
```

# Usage
### Files
- To encrypt the file
    ```
    python main.py -e <filename>
    ```
    Above command will generate a `.enc` file with is encrypted with password


- To decrypt the file
    ```
    python main.py -d <filename>.enc
    ```

- To remove original file after any operation
    ```
    python main.py -d <filename>.enc -r
    ```
### Directory
- To encrypt the directory
    ```
    python main.py -er <dirname>
    ```
    Recursively encrypt all files inside directory but not inside subdirectories


- To encrypt the directory with depth
    ```
    python main.py -er <dirname> --depth 2
    ```
    Recursively encrypt all files inside specified directory till defined depth


- To encrypt whole directory till possible
    ```
    python main.py -er <dirname> --depth -1
    ```
    Any negative value of `--depth` will recursively encrypt all files inside specified directory


- To decrypt the specified directory
    ```
    python main.py -dr <dirname> --depth 2
    ```
  Decrypt the file inside specified directory till depth 2


- To remove original file after any operation use `-r`
    ```
    python main.py -dr <dirname> --depth -1 -r
    ```

---

> Note: `obfile` doesn't follow symbolic links.
# Licence 
Licenced Under [MIT License](LICENSE)