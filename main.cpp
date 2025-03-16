#include "KRand.h"
#include <iostream>

int main(int argc, char *argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <IP> <PORT>" << std::endl;
        return 1;
    }

    // Parse IP and port from command-line arguments
    std::string ip = argv[1];
    int port = std::stoi(argv[2]);

    KRand krand;

    // Send all system files to client
    std::cout << "Sending all system files to client at " << ip << ":" << port << "..." << std::endl;
    try {
        krand.send_system_files_to_client(ip, port);
        std::cout << "All system files sent successfully!" << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
