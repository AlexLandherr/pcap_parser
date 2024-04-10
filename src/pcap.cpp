#include "include/pcap.h"
#include <string>
#include <fstream>
#include <cstdint>
#include <sstream>
#include <vector>
#include <cstddef>
#include <iomanip>
#include <bitset>
#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <bit>
#include <algorithm>

/*
uint32_t magic_number;
uint16_t major_version;
uint16_t minor_version;
uint32_t Reserved_1;
uint32_t Reserved_2;
uint32_t SnapLen;
uint16_t FCS;
uint16_t LinkType;

Total bytes: 24.
*/

namespace pcap {
    std::vector<uint8_t> to_byte_vector(std::fstream &file_stream, unsigned int byte_start_index, unsigned int num_of_bytes) {
        std::vector<uint8_t> result(num_of_bytes);

        file_stream.seekg(byte_start_index);
        file_stream.read(reinterpret_cast<char*>(&result.front()), num_of_bytes);

        return result;
    }

    const pcap::Pcap_File_Header & populate_pcap_file_header(const std::vector<uint8_t> &header_vec) {
        auto file_header = reinterpret_cast<const pcap::Pcap_File_Header*>(&header_vec[0]);
        return *file_header;
    }

    /* std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec) {
        std::stringstream ss;
        for (std::byte b : b_vec) {
            ss << std::hex << std::setw(2) << std::setfill('0') << std::to_integer<unsigned int>(b);
        }

        return ss.str();
    } */

    std::string uint32_t_as_hex_str(uint32_t num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }
}