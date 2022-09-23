# obfile
`Obfile` or `Obfuscate File` is a command line utility to encrypt or decrypt the file with AES256.

# Installation
```bash
pip install -r requirements.txt
```

# Usage
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


# Licence 
Licenced Under [MIT License](LICENSE)