# crypto

Need the os, random, and argparse modules for python.

# Set Up.
create a public key:

1) Open you favorite python interpreter
2) Import crypto
3) find a large prime and generator and store them in the interpreter.
4) run the command:
    create_public_key(prime,generator,public_key_path,secret_key_path)

** Note that a prime and generator is given as prme (2048 bit) and gen. Use other prime/generator pairs if desired. **

Now in the file crypto.py, in lines 6,7 change the information to where the private key is located (pvtkl) and where the public key is (pblkl). I recommend putting the sercet key on a flash drive.

# Encrypting a file
1) run the following command in the terminal.
    python crypto.py -e 'file_path'
** Note that the files name becomes encrypted[time_of_encryption].hcrypt  **

# Decrypting a file
1) run the following command in the terminal.
    python crypto.py -d 'file_path'
