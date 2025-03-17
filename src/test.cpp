#include <iostream>
#include "KRand.h"  // Ensure KRand.h is in /usr/local/include

int main() {
    std::cout << "Testing KRand Library..." << std::endl;
    std::string interface = "wlan0";
    KRand krand;
    krand.packet_sniffing(interface);
    return 0;
}
