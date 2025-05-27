# RabbitMQ Password Hash Decoder 🐰🔓

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-cross--platform-lightgrey.svg)

A simple and efficient Python tool to decode Base64-encoded RabbitMQ password hashes and extract their components (salt and hash).

## 📋 Description

RabbitMQ stores user passwords as SHA-256 hashes with a 4-byte salt, all encoded in Base64. This tool allows you to easily decode these hashes for:

- **Security Analysis**: Examine password storage mechanisms
- **Penetration Testing**: Analyze RabbitMQ configurations during security assessments
- **Digital Forensics**: Extract and analyze authentication data
- **Educational Purposes**: Understand RabbitMQ's password hashing scheme

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/PothinM/rabbitmq-hash-decoder.git
cd rabbitmq-hash-decoder
```

```bash
# Run the decoder
python3 rabbit_decoder.py <base64_hash>
```

## 🔧 Installation

No external dependencies required! This tool uses only Python's standard library.
Requirements

    Python 3.6 or higher
    No additional packages needed

Download

```
git clone https://github.com/PothinM/rabbitmq-hash-decoder.git
cd rabbitmq-hash-decoder
chmod +x rabbit_decoder.py
```

## 💡 Usage
Basic Usage

```
python3 rabbit_decoder.py "xKp01UfSCRxOfXLKJrEKyGT1CE4="
```

Command Line Options

usage: `rabbit_decoder.py [-h] [-r] [-q] [-v] hash`

Decode RabbitMQ password hashes from Base64 format

positional arguments:
  hash              Base64 encoded RabbitMQ password hash

optional arguments:
  * `-h, --help`        show this help message and exit
  * `-r, --raw`         Output only raw values without formatting
  * `-q, --quiet`       Minimal output mode
  * `-v, --version`     show program's version number and exit

Examples
Standard Output
```
 $  python3 rabbit_decoder.py "xKp01UfSCRxOfXLKJrEKyGT1CE4="

 🔓 RabbitMQ Password Hash Decoder
════════════════════════════════════

📥 Input Hash: xKp01UfSCRxOfXLKJrEKyGT1CE4=

✅ Successfully decoded!
────────────────────────────────────
🧂 Salt (4 bytes): c4aa74d5
🔐 Hash (32 bytes): 47d20d1c4e7d72ca26b10ac864f5084e
🔢 Algorithm: SHA-256 with salt
📊 Total decoded length: 36 bytes
```
Raw Output Mode
```
 $  python3 rabbit_decoder.py -r "xKp01UfSCRxOfXLKJrEKyGT1CE4="
c4aa74d5
47d20d1c4e7d72ca26b10ac864f5084e
```
Quiet Mode
```
$ python3 rabbit_decoder.py -q "xKp01UfSCRxOfXLKJrEKyGT1CE4="
Salt: c4aa74d5
Hash: 47d20d1c4e7d72ca26b10ac864f5084e
```
## 🏗️ How RabbitMQ Password Hashing Works

RabbitMQ uses a specific format for storing password hashes:

    Generate a random 4-byte salt
    Concatenate the salt with the password
    Hash using SHA-256: SHA-256(salt + password)
    Combine salt + hash (36 bytes total)
    Encode in Base64 for storage

[4-byte salt][32-byte SHA-256 hash] → Base64 encoding

## 🛠️ Technical Details
Input Validation

    Validates Base64 format
    Checks decoded length (must be 36 bytes)
    Handles padding issues automatically

Error Handling

    Invalid Base64 encoding
    Incorrect hash length
    File not found errors
    Keyboard interrupts (Ctrl+C)

Output Formats

    Standard: Beautiful formatted output with emojis and colors
    Raw: Simple hex values for scripting
    Quiet: Minimal labeled output

## 🎯 Use Cases

* Security Auditing
```bash
#Analyze multiple hashes from a RabbitMQ configuration
cat rabbitmq_hashes.txt | while read hash; do
    echo "Analyzing: $hash"
    python3 rabbit_decoder.py -q "$hash"
    echo "---"
done
```

* Forensic Analysis
```bash
# Extract salt patterns for analysis
python3 rabbit_decoder.py -r "$hash" | head -1 > salts.txt
```
* Penetration Testing
    * Use during RabbitMQ security assessments to understand password storage mechanisms.

## 🚀 Features

  * 🎯 Precise: Accurately decodes RabbitMQ password hashes
  * 🛡️ Robust: Comprehensive error handling and input validation
  * ⚡ Fast: Lightweight with no external dependencies
  * 🎨 User-Friendly: Multiple output modes for different needs
  * 📱 Portable: Works on Windows, Linux, and macOS
  * 🔧 Scriptable: Perfect for automation and batch processing

## 📚 Educational Resources

  * [RabbitMQ Password Hashing Documentation](https://www.rabbitmq.com/passwords.html)
  * [RabbitMQ Access Control](https://www.rabbitmq.com/access-control.html)
  * [SHA-256 Algorithm](https://en.wikipedia.org/wiki/SHA-2)

## 🤝 Contributing

Contributions are welcome! Feel free to:

  * 🐛 Report bugs
  * 💡 Suggest new features
  * 🔧 Submit pull requests
  * 📖 Improve documentation

## Development Setup

```
git clone https://github.com/PothinM/rabbitmq-hash-decoder.git
cd rabbitmq-hash-decoder
```
```
# Run tests (if any)
python3 -m pytest
```

```
# Check code style
python3 -m flake8 rabbit_decoder.py
```

## 📄 License

  This project is licensed under the MIT License - see the LICENSE file for details.

## ⚖️ Legal Disclaimer

This tool is intended for:

  * ✅ Educational purposes
  * ✅ Authorized security testing
  * ✅ Systems you own or have permission to test

  Users are responsible for complying with applicable laws and regulations.

## 🙏 Acknowledgments

  Thanks to the RabbitMQ team for clear documentation
  Inspired by the cybersecurity community's need for simple, effective tools
  Built with ❤️ for security professionals and enthusiasts

## 📞 Support

  * 🐛 Issues: [GitHub Issues](https://github.com/PothinM/rabbitmq-hash-decoder/issues)
  * 💬 Discussions: [GitHub Discussions](https://github.com/PothinM/rabbitmq-hash-decoder/discussions)
  * 📧 Contact: pothin.mt@gmail.com

## ⭐ If this tool was helpful to you, please consider giving it a star! ⭐

## Made with ❤️ for the cybersecurity community

## 🏷️ Tags
* rabbitmq
* password
* hash decoder
* base64
* security pentesting
* forensics
* python
* cybersecurity
