#include "include/pcap.h"
#include <iostream>
#include <string>
#include <vector>

int main() {
    std::string filename{"pcap_files/tcp_1.pcap"};
    auto res = pcap::to_byte_vector(filename, 0, 8);
    std::cout << "Byte vector size/length: " << res.size() << '\n';
    std::cout << "Read bytes as hex string: " << pcap::byte_vec_to_hex_str(res) << '\n';

    return 0;
}