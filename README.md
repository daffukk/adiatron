# Adiatron
Adiatron is a command-line tool for encrypting and decrypting files of any size.
It uses public-key cryptography for secure key exchange and authenticated streaming
encryption to process large files with constant memory usage.

## TODO
- [ ] Keys selection(TUI)
- [ ] Auto archiving if directory is given
- [ ] Select usb drive for keys
- [ ] -o argument for customizing output filename
- [ ] Keys passphrase support
- [ ] --keydir, --pubkey and --seckey arguments for customizing keys directory
- [ ] --version flag

## How it works

1. A random symmetric stream key is generated
2. The stream key is encrypted using the recipient's public key
3. File data is encrypted in chunks using authenticated streaming encryption
4. Each chunk is verified during decryption to prevent tampering

Here is an encrypted file structure:
```md
[ box_nonce ][ boxed_stream_key ][ secretstream_header ][ encrypted chunks... ]
```

## Installation

### Dependencies
- libsodium
- cmake
- tar(optional)

### Build
```bash
./build.sh
```

---

## Usage 

To encrypt files:
```bash
./adiatron encrypt file.mp4
```
To decrypt files:
```bash
./adiatron decrypt file.mp4.enc
```
Type `./adiatron` to display all examples and options.

> [!NOTE]
> See [Tips and Issues](#tips-and-issues) section for more information.


### How public-key exchange works

1. **Sender (Alice)** generates a key pair and sends **her public key** to the receiver.  
2. **Receiver (Bob)** generates a key pair and sends **his public key** to the sender.  
3. Now:
   - Alice encrypts messages using **Bob's public key** + her secret key.  
   - Bob decrypts messages using **Alice's public key** + his secret key.


## Tips and Issues
> [!TIP]
> Keys are automatically generated during file encryption or decryption.\
> However, you can generate keys in advance by using the command:
> ```
> ./adiatron keygen
> ```

> [!TIP]
> You can create a short alias by adding this line to your shell configuration file(e.g., `~/.bashrc` or `~/.zshrc`):
> ```bash
> alias adiatron=/path/to/adiatron
> ```


## License
This project is licensed under [MIT](https://github.com/daffukk/adiatron/blob/main/LICENSE)
