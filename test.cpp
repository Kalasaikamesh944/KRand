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

#include "KRand.h"
#include <iostream>
#include <string>

void display_menu() {
    std::cout << "\n===== KRand Security Tool =====" << std::endl;
    std::cout << "1. Encrypt Text" << std::endl;
    std::cout << "2. Decrypt Text" << std::endl;
    std::cout << "3. Port Scan" << std::endl;
    std::cout << "4. Advanced Port Scan" << std::endl;
    std::cout << "5. Packet Sniffing" << std::endl;
    std::cout << "6. Vulnerability Scan" << std::endl;
    std::cout << "7. SSH Brute Force" << std::endl;
    std::cout << "8. Network Enumeration" << std::endl;
    std::cout << "9. Exit" << std::endl;
    std::cout << "Select an option: ";
}

int main() {
    KRand krand;
    int choice;
    std::string input, key, ip, user, password_list;
    std::string interface;
    int start_port, end_port;

    while (true) {
        display_menu();
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1:
                std::cout << "Enter text to encrypt: ";
                std::getline(std::cin, input);
                key = KRand::generate_time_based_key();
                std::cout << "Encrypted: " << KRand::encrypt(input, key) << std::endl;
                break;

            case 2:
                std::cout << "Enter text to decrypt: ";
                std::getline(std::cin, input);
                std::cout << "Enter key: ";
                std::getline(std::cin, key);
                std::cout << "Decrypted: " << KRand::decrypt(input, key) << std::endl;
                break;

            case 3:
                std::cout << "Enter target IP: ";
                std::getline(std::cin, ip);
                std::cout << "Enter start port: ";
                std::cin >> start_port;
                std::cout << "Enter end port: ";
                std::cin >> end_port;
                krand.port_scan(ip, start_port, end_port);
                break;

            case 4:
                std::cout << "Enter target IP: ";
                std::getline(std::cin, ip);
                krand.advanced_port_scan(ip);
                break;

            case 5:
                std::cout << "Starting packet sniffing..." << std::endl;
                std::cout << "Enter the interface name...  ";
                std::cin >> interface; 
                krand.packet_sniffing(interface);
                break;

            case 6:
                std::cout << "Running vulnerability scan..." << std::endl;
                krand.vulnerability_scan();
                break;

            case 7:
                std::cout << "Enter target IP: ";
                std::getline(std::cin, ip);
                std::cout << "Enter username: ";
                std::getline(std::cin, user);
                std::cout << "Enter password list file: ";
                std::getline(std::cin, password_list);
                krand.ssh_brute_force(ip, user, password_list);
                break;

            case 8:
                std::cout << "Enter network range (e.g., 192.168.1.0/24): ";
                std::getline(std::cin, input);
                krand.network_enumeration(input);
                break;

            case 9:
                std::cout << "Exiting..." << std::endl;
                return 0;

            default:
                std::cout << "Invalid choice, try again." << std::endl;
                break;
        }
    }
}
