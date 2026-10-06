<div align="center">

# Adiatron

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/daffukk/adiatron/build.yml?logo=cmake&label=Build%20adiatron)
![GitHub License](https://img.shields.io/github/license/daffukk/adiatron?color=%23708238)
![GitHub top language](https://img.shields.io/github/languages/top/daffukk/adiatron?logo=c%2B%2B&color=pink)
![GitHub commits since latest release](https://img.shields.io/github/commits-since/daffukk/adiatron/latest)
![GitHub last commit](https://img.shields.io/github/last-commit/daffukk/adiatron)

---
</div>


A modern command-line encryption tool that processes files and directories in streaming chunks, maintaining constant memory usage regardless of archive size. Built with [libsodium](https://doc.libsodium.org/), it uses authenticated encryption and public-key cryptography for secure key exchange.

Directories are encrypted natively, without relying on external archiving tools like tar. Each file is stored as an independent, individually keyed entry inside the encrypted archive, with per-file encryption keys derived from a single master key — laying the groundwork for future selective operations


## Getting Started

### Prerequisites

- C++20 compatible compiler
- [libsodium](https://github.com/jedisct1/libsodium) development headers
- CMake >= 3.10

### Build

1. Clone the repo
   ```bash
   git clone https://github.com/daffukk/adiatron.git
   ```

2. Compile application 
   ```bash
   cd adiatron
   make              # Simple build
   # or
   cmake -B build && cmake --build build
   ```


## Usage

### Core Commands

```bash
adiatron <MODE> <INPUT> [OPTIONS]
```

#### Modes

| Mode    | Description |
|---------|-------------|
| `encrypt` | Encrypt a file or directory into `.aear` archive |
| `decrypt` | Decrypt an archive (requires your secret key) |
| `list`    | View archive contents without full decryption |
| `extract` | Pull out a single file by ID (0-indexed) |
| `add`     | Append files to an existing archive |
| `keygen`  | Generate new keypair (auto-detect or explicit paths) |
| `--help`  | Display usage information |
| `--version` | Display version |

#### Examples

```bash
# Encrypt a single file
adiatron encrypt secret.pdf

# Encrypt an entire directory
adiatron encrypt documents/

# List archive contents (needs keys)
adiatron list archive.aear

# Extract file #42 without decrypting others
adiatron extract archive.aear 42

# Add new files to existing archive
adiatron add archive.aear newfile.txt

# Generate encrypted keys with passphrase
adiatron keygen --passphrase
```

#### Common Options

```bash
-p, --passphrase     Encrypt secret key with passphrase
-v, --verbose        Show per-file progress
-o, --filename PATH  Custom output filename
--ftime              Preserve original file modification times
--atime              Set mtime to epoch (1970-01-01)
--keydir DIR         Override keys directory (default: "keys")
--pkey PATH          Explicit public key path
--skey PATH          Explicit secret key path
--nokeyformat        Skip key format validation (raw bytes only)
```
## Roadmap

- [ ] Update readme
    - [ ] Add information about multi-file usage 
- [X] Fix filecounter when encrypting and decrypting(just add +1)
- [X] Multi-file support
- [X] Add auto build and publish release workflow
- [ ] Symlink and hardlink support
- [X] Update `main.cpp` code, those if else if else if else. And it would be nice to update arguments parsing logic.
- [ ] `crypto_pwhash_OPSLIMIT`, `crypto_pwhash_MEMLIMIT` and `crypto_pwhash_ALG` flags for lower/higher encryption power(for example ``--maxmem``).
- [ ] Dividing encrypted file to volumes(e.g. `encrypted.aear.0001`, `encrypted.aear.0002`) by using `--volume` or `--vol-size` flags
- [ ] Keys selection(TUI)
- [X] `--version` flag
- [ ] Hyper-secure mode, decryption only in RAM
- [ ] `--rnames` or similar flag that will randomize filenames in archive.
- [ ] Extract one file from archive without decrypting this file.
- [ ] `.config/adiatron` default configuration directory
- [ ] Progress bar 
- [ ] Encrypt file entries(keys and headers) and add encrypted "roadmap" to manage them
- [ ] Select usb drive for keys
- [ ] CLI autocompletion
- [ ] Vim style list mode


## License

MIT License – See [LICENSE](LICENSE) for details.

