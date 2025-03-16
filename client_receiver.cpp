#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector> 
#include <cstdint>

namespace fs = std::filesystem;

// Function to receive files from the server
void receive_files_from_server(const std::string &save_directory, int port) {
    // Create the save directory if it doesn't exist
    if (!fs::exists(save_directory)) {
        fs::create_directories(save_directory);
    }

    // Create a socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        throw std::runtime_error("Failed to create socket");
    }

    // Bind the socket to the port
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == -1) {
        close(server_sock);
        throw std::runtime_error("Failed to bind socket");
    }

    // Listen for incoming connections
    if (listen(server_sock, 1) == -1) {
        close(server_sock);
        throw std::runtime_error("Failed to listen on socket");
    }

    std::cout << "Waiting for server to connect on port " << port << "..." << std::endl;

    // Accept a connection from the server
    sockaddr_in client_addr{};
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sock = accept(server_sock, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
    if (client_sock == -1) {
        close(server_sock);
        throw std::runtime_error("Failed to accept connection");
    }

    std::cout << "Server connected. Receiving files..." << std::endl;

    // Buffer for receiving data
    const size_t BUFFER_SIZE = 1024 * 1024; // 1 MB buffer
    std::vector<char> buffer(BUFFER_SIZE);

    while (true) {
        // Receive the file path length
        uint32_t path_length;
        if (recv(client_sock, &path_length, sizeof(path_length), 0) <= 0) {
            break; // End of transmission
        }

        // Receive the file path
        std::vector<char> file_path_buffer(path_length);
        if (recv(client_sock, file_path_buffer.data(), path_length, 0) <= 0) {
            break;
        }
        std::string file_path(file_path_buffer.begin(), file_path_buffer.end());

        // Prepend the save directory to the file path
        std::string full_path = save_directory + "/" + file_path;

        // Create the directory structure if it doesn't exist
        fs::path dir_path = fs::path(full_path).parent_path();
        if (!fs::exists(dir_path)) {
            fs::create_directories(dir_path);
        }

        // Receive the file size
        uint64_t file_size;
        if (recv(client_sock, &file_size, sizeof(file_size), 0) <= 0) {
            break;
        }

        // Open the file for writing
        std::ofstream file(full_path, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file for writing: " << full_path << std::endl;
            continue;
        }

        // Receive the file content
        uint64_t remaining_bytes = file_size;
        while (remaining_bytes > 0) {
            size_t bytes_to_receive = std::min(buffer.size(), remaining_bytes);
            ssize_t bytes_received = recv(client_sock, buffer.data(), bytes_to_receive, 0);
            if (bytes_received <= 0) {
                break;
            }
            file.write(buffer.data(), bytes_received);
            remaining_bytes -= bytes_received;
        }

        std::cout << "Received file: " << full_path << " (" << file_size << " bytes)" << std::endl;
    }

    std::cout << "File transfer complete." << std::endl;

    // Close the sockets
    close(client_sock);
    close(server_sock);
}

int main() {
    try {
        // Directory to save received files
        std::string save_directory = "received_files";

        // Port to listen on
        int port = 4444;

        // Receive files from the server
        receive_files_from_server(save_directory, port);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
