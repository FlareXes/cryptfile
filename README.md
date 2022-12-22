# Cryptfile
`Cryptfile` is a command line utility to encrypt or decrypt the file with AES256.

# Installation
```
git clone https://github.com/FlareXes/cryptfile.git && cd cryptfile

chmod +x setup

./setup
```

# Usage

> Note: `Cryptfile` doesn't follow symbolic links.

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
    cryptfile -ed <dirname>
    ```

- To decrypt the specified directory
    ```
    cryptfile -dd <dirname>
    ```

---

# Licence 
This work by [FlareXes](https://github.com/FlareXes) is Licenced Under [GNU GPLv3](LICENCE)
