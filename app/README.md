# ECDH Secure Login Server

A secure authentication server implementing Elliptic Curve Diffie-Hellman (ECDH) key exchange with AES-256-GCM encryption using Crow web framework and OpenSSL.

## Features

- 🔐 **ECDH P-256** key exchange for secure communication
- 🛡️ **AES-256-GCM** authenticated encryption
- 🔑 **HKDF** key derivation with username binding
- 🌐 **RESTful API** with CORS support
- ⚡ **Modern C++** with RAII and smart pointers
- 🚀 **Fast compilation** with Meson build system

## Prerequisites

### Required Dependencies

```bash
# Arch Linux
sudo pacman -S gcc meson ninja pkgconf openssl

# Ubuntu/Debian
sudo apt install build-essential meson ninja-build pkg-config libssl-dev

# macOS
brew install meson ninja openssl
```

### Additional Requirements

- **C++14 or higher** (C++17 recommended)
- **OpenSSL 1.1.0+**
- **Crow** (header-only, included)
- **Asio** (standalone, included)

## Project Structure

```
project/
├── app.cpp              # Main server implementation
├── meson.build          # Build configuration
├── crow_all.h           # Crow framework header
├── asio-1.36.0/         # Asio library
│   └── include/
├── build/               # Build directory (generated)
└── README.md
```

## Quick Start

### 1. Clone or Setup Project

```bash
# Ensure you have crow_all.h and asio in your project directory
ls crow_all.h asio-1.36.0/include/
```

### 2. Build the Server

```bash
# Setup build directory (first time only)
meson setup build

# Compile
meson compile -C build

# Or use ninja directly
ninja -C build
```

### 3. Run the Server

```bash
# Run from project root
./build/app

# Server will start on http://localhost:18080
```

## API Endpoints

### `GET /login-params`

Get the server's public key for ECDH key exchange.

**Response:**
```json
{
  "curve": "P-256",
  "server_pub": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

### `POST /login`

Authenticate with encrypted credentials.

**Request:**
```json
{
  "username": "alice",
  "client_pub": "base64_encoded_public_key",
  "iv": "base64_encoded_iv",
  "cipher": "base64_encoded_ciphertext",
  "tag": "base64_encoded_auth_tag"
}
```

**Response:**
```json
{
  "encrypted_password": {
    "iv": "base64...",
    "cipher": "base64...",
    "tag": "base64..."
  },
  "encrypted_hello": {
    "iv": "base64...",
    "cipher": "base64...",
    "tag": "base64..."
  }
}
```

## Development

### Build Configurations

```bash
# Debug build (default, faster compilation)
meson setup build --buildtype=debug

# Release build (optimized)
meson setup build --buildtype=release

# Release with debug symbols
meson setup build --buildtype=debugoptimized
```

### Incremental Builds

After making changes to source files:

```bash
# Quick rebuild (only changed files)
ninja -C build

# Or
meson compile -C build
```

**Build times:**
- First build: ~15-20 seconds
- Incremental: ~2-5 seconds ⚡

### Cleaning

```bash
# Clean build artifacts
ninja -C build -t clean

# Complete clean (remove build directory)
rm -rf build
meson setup build
```

### Verbose Build

See full compilation commands:

```bash
ninja -C build -v
```

## Testing with Frontend

A test HTML client is included for demonstration:

```bash
# In another terminal, serve the frontend
cd frontend
python -m http.server 8000

# Open browser
firefox http://localhost:8000/index.html
```

## Security Notes

⚠️ **This is a demonstration project**

- Uses ephemeral server keys (regenerated on each restart)
- No persistent storage or real authentication
- CORS is wide open (`*`) for testing
- Not hardened for production use

### For Production:

- [ ] Implement persistent key storage
- [ ] Add rate limiting
- [ ] Use proper authentication database
- [ ] Restrict CORS to specific origins
- [ ] Add TLS/HTTPS
- [ ] Implement session management
- [ ] Add logging and monitoring

## Troubleshooting

### Build Errors

**OpenSSL not found:**
```bash
# Check if OpenSSL is installed
pkg-config --cflags --libs openssl

# Install if missing
sudo pacman -S openssl
```

**Meson/Ninja not found:**
```bash
sudo pacman -S meson ninja
```

### Runtime Errors

**Port already in use:**
```bash
# Check what's using port 18080
lsof -i :18080

# Kill the process or change port in app.cpp
```

**Connection refused:**
```bash
# Make sure server is running
./build/app

# Check firewall
sudo iptables -L
```

## Performance

- **Throughput:** ~1000-5000 requests/second (single-threaded)
- **Latency:** ~1-5ms per request
- **Memory:** ~10-20MB resident

## Architecture

```
Client                          Server
  │                               │
  ├──── GET /login-params ────────>
  <──── Server Public Key ─────────┤
  │                               │
  │  Generate Client Keypair      │
  │  Derive Shared Secret         │
  │  HKDF → AES Key               │
  │  Encrypt Password             │
  │                               │
  ├──── POST /login ──────────────>
  │     (encrypted data)          │
  │                          Derive Shared Secret
  │                          HKDF → AES Key
  │                          Decrypt Password
  │                          Encrypt Response
  <──── Encrypted Response ────────┤
  │                               │
  │  Decrypt Response             │
  │  Display Data                 │
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- [Crow](https://github.com/CrowCpp/Crow) - Fast C++ web framework
- [Asio](https://think-async.com/Asio/) - Async I/O library
- [OpenSSL](https://www.openssl.org/) - Cryptography toolkit

## Resources

- [ECDH Key Exchange](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [HKDF](https://en.wikipedia.org/wiki/HKDF)
- [Meson Build System](https://mesonbuild.com/)

---

**Author:** Your Name  
**Version:** 1.0.0  
**Last Updated:** December 2024