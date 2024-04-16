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
    //variables for timestamp resolution and data endianness.
    int ts_decimal_places = 0;
    std::endian data_endianness;

    std::string filename{"pcap_files/tcp_1.pcap"};
    std::fstream fs{filename, std::ios::in | std::ios::binary};
    if (!fs.is_open()) {
        std::cerr << "Failed to open '" << filename << "'" << '\n';
    } 

    //Add try-catch statement later.
    auto header_vector = pcap::to_byte_vector(fs, 0, 24);
    pcap::Pcap_File_Header h = pcap::populate_pcap_file_header(header_vector);

    //Determine endianness and ts resolution (decimal places).
    switch (h.magic_number) {
        case 0xa1b2c3d4:
            data_endianness = std::endian::little; //change to little
            ts_decimal_places = 6; //change to 9?
            break;
        case 0xd4c3b2a1:
            data_endianness = std::endian::big; //change to big
            ts_decimal_places = 6; //change to 9?
            break;
        case 0xa1b23c4d:
            data_endianness = std::endian::little; //change to little
            ts_decimal_places = 9; //change to 6?
            break;
        case 0x4d3cb2a1:
            data_endianness = std::endian::big; //change to big
            ts_decimal_places = 9; //change to 6?
            break;
        default:
            std::cerr << "Unable to determine ts resolution and data endianness. Value: " << pcap::uint32_t_as_hex_str(h.magic_number) << " not recognized." << '\n';
            break;
    }
    
    std::cout << "magic_num: " << pcap::uint32_t_as_hex_str(h.magic_number) << '\n';

    //Swap check.
    if (std::endian::native != data_endianness) {
        std::cout << "Data endianness different from system endianness!" << '\n';
        h.major_version = __builtin_bswap16(h.major_version);
        h.minor_version = __builtin_bswap16(h.minor_version);

        h.SnapLen = __builtin_bswap32(h.SnapLen);
        h.LinkType = __builtin_bswap16(h.LinkType);
    }

    std::cout << "major_version: " << h.major_version << '\n';
    std::cout << "minor_version: " << h.minor_version << '\n';

    std::cout << "Reserved_1: " << h.Reserved_1 << '\n';
    std::cout << "Reserved_2: " << h.Reserved_2 << '\n';

    std::cout << "SnapLen: " << h.SnapLen << '\n';

    std::cout << "LinkType: " << h.LinkType << '\n'; //Shows as '0', should be '1'. Why?!!!
    
    switch (data_endianness) {
        case std::endian::little:
            std::cout << "Data endianness: little-endian" << '\n';
            break;
        case std::endian::big:
            std::cout << "Data endianness: big-endian" << '\n';
            break;
    }

    std::cout << "Timestamp resolution (decimal places): " << ts_decimal_places << '\n';
    
    //std::cout << "Byte vector size/length: " << header_vector.size() << '\n';
    //std::cout << "Read bytes as hex string: " << pcap::byte_vec_to_hex_str(header_vector) << '\n';

    return 0;
}