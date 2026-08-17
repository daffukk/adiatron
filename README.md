# Adiatron
Adiatron is a command-line tool for encrypting and decrypting files and directories
of any size. It uses public-key cryptography for secure key exchange and
authenticated streaming encryption, processing data in chunks to keep memory
usage constant regardless of file size.

Directories are encrypted natively, without relying on external archiving
tools like tar. Each file is stored as an independent, individually keyed
entry inside the encrypted archive, with per-file encryption keys derived
from a single master key — laying the groundwork for future selective
operations (e.g. listing or extracting individual files without decrypting
the entire archive).


## How it works
1. A random symmetric stream key is generated
2. The stream key is encrypted using the recipient's public key
3. Total amount of files in directory(or 1 for a single file) is written to the header
4. Each file is encrypted in separate entry

Here is an encrypted file structure:
```md
[ boxNonce ][ boxedKey ][ fileCount ]
[ entry: metaLen | metaBlock | dataLen | dataBlock ]
```

## Installation

### Dependencies
- libsodium
- cmake
- make

### Build

```bash
make
```
Or build it with cmake manually.

---

## Usage 

To encrypt files or directories:
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


## TODO
- [ ] Write some comments in code
- [ ] Optimize process!!!
- [ ] Dividing encrypted file to volumes(e.g. encrypted.enc.0001, encrypted.enc.0002) by using --volume or --vol-size flags
- [ ] .config/adiatron default configuration directory
- [ ] Keys selection(TUI)
- [ ] Select usb drive for keys
- [ ] Keys passphrase support
- [ ] --version flag
- [ ] Hyper-secure mode
    - [ ] Partially decrypt a directory to list filenames
    - [ ] Select a file from an encrypted directory by filename or hash, decrypt it into RAM, and ensure it is not written to disk, swap, or cache

filesystem:
- [ ] Symlink and hardlink support
- [ ] List option to list encrypted archive content without decrypting it
- [ ] Partially decrypt archive(for example take 1 file)
- [ ] Add files in encrypted archive 
- [ ] Progress bar 
- [ ] Encrypt file entries(keys headers and so on) and add encrypted "roadmap" to manage them
- [ ] CLI autocompletion

## License
This project is licensed under [MIT](https://github.com/daffukk/adiatron/blob/main/LICENSE)
