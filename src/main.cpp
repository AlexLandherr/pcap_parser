#include "include/pcap.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstddef>
#include <bit>
#include <iomanip>
#include <cstdint>
#include <bitset>
#include <ios>
#include <sstream>
#include <fstream>
#include <stdexcept>

int main() {
    std::string filename{"pcap_files/tcp_1.pcap"};
    std::fstream fs{filename, std::ios::in | std::ios::binary};
    if (!fs.is_open()) {
        std::cerr << "Failed to open '" << filename << "'" << '\n';
    } 

    //Add try-catch statement later.
    auto header_vector = pcap::to_byte_vector(fs, 0, 24);

    pcap::Pcap_File_Header h = pcap::populate_pcap_file_header(header_vector);
    
    std::cout << "magic_num: " << pcap::uint32_t_as_hex_str(h.magic_number) << '\n';

    std::cout << "major_version: " << h.major_version << '\n';
    std::cout << "minor_version: " << h.minor_version << '\n';

    std::cout << "Reserved_1: " << h.Reserved_1 << '\n';
    std::cout << "Reserved_2: " << h.Reserved_2 << '\n';

    std::cout << "SnapLen: " << h.SnapLen << '\n';

    std::cout << "LinkType: " << h.LinkType << '\n';
    
    std::cout << "Byte vector size/length: " << header_vector.size() << '\n';
    //std::cout << "Read bytes as hex string: " << pcap::byte_vec_to_hex_str(header_vector) << '\n';

    return 0;
}