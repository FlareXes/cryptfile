# Cryptfile
`Cryptfile` is a command line utility to encrypt or decrypt the file with AES256.

# Installation
```
git clone https://github.com/FlareXes/cryptfile.git && cd cryptfile

chmod +x setup

./setup
```

# Usage
### File
- To encrypt the file
    ```
    cryptfile -e <filename>
    ```
    Above command will generate a `.enc` file with is encrypted with password


- To decrypt the file
    ```
    cryptfile -d <filename>.enc
    ```

- To remove original file after any operation
    ```
    cryptfile -d <filename>.enc -r
    ```
### Directory
- To encrypt the directory
    ```
    cryptfile -er <dirname>
    ```
    Recursively encrypt all files inside directory but not inside subdirectories


- To encrypt the directory with depth
    ```
    cryptfile -er <dirname> --depth 2
    ```
    Recursively encrypt all files inside specified directory till defined depth


- To encrypt whole directory till possible
    ```
    cryptfile -er <dirname> --depth -1
    ```
    Any negative value of `--depth` will recursively encrypt all files inside specified directory


- To decrypt the specified directory
    ```
    cryptfile -dr <dirname> --depth 2
    ```
  Decrypt the file inside specified directory till depth 2


- To remove original file after any operation use `-r`
    ```
    cryptfile -dr <dirname> --depth -1 -r
    ```

---

> Note: `Cryptfile` doesn't follow symbolic links.

# Licence 
This work by [FlareXes](https://github.com/FlareXes) is Licenced Under [GNU GPLv3](LICENCE)
