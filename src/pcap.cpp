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

namespace pcap {
    std::vector<uint8_t> to_byte_vector(std::fstream &file_stream, unsigned int byte_start_index, unsigned int num_of_bytes) {
        std::vector<uint8_t> result(num_of_bytes);

        file_stream.seekg(byte_start_index);
        file_stream.read(reinterpret_cast<char*>(&result.front()), num_of_bytes);

        return result;
    }

    const pcap::Pcap_File_Header &populate_pcap_file_header(const std::vector<uint8_t> &header_vec) {
        auto file_header = reinterpret_cast<const pcap::Pcap_File_Header*>(&header_vec[0]);
        return *file_header;
    }

    std::string uint32_t_as_hex_str(uint32_t num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }

    std::string human_readable_pcap_file_header(pcap::Pcap_File_Header &header) {
        std::stringstream hs;
        std::endian data_endianness;
        int ts_decimal_places = 0;

        //Determine endianness and ts resolution (decimal places).
        switch (header.magic_number) {
            case 0xa1b2c3d4:
                data_endianness = std::endian::little; //change to little
                ts_decimal_places = 6;
                break;
            case 0xd4c3b2a1:
                data_endianness = std::endian::big; //change to big
                ts_decimal_places = 6;
                break;
            case 0xa1b23c4d:
                data_endianness = std::endian::little; //change to little
                ts_decimal_places = 9;
                break;
            case 0x4d3cb2a1:
                data_endianness = std::endian::big; //change to big
                ts_decimal_places = 9;
                break;
            default:
                hs << "Unable to determine ts resolution and data endianness. Value: " << pcap::uint32_t_as_hex_str(header.magic_number) << " not recognized." << '\n';
                break;
        }

        hs << "magic_num: " << pcap::uint32_t_as_hex_str(header.magic_number) << '\n';

        //Swap check.
        if (std::endian::native != data_endianness) {
            header.major_version = __builtin_bswap16(header.major_version);
            header.minor_version = __builtin_bswap16(header.minor_version);

            header.SnapLen = __builtin_bswap32(header.SnapLen);
            header.LinkType = __builtin_bswap16(header.LinkType);
        }

        hs << "major_version: " << header.major_version << '\n';
        hs << "minor_version: " << header.minor_version << '\n';

        hs << "Reserved_1: " << header.Reserved_1 << '\n';
        hs << "Reserved_2: " << header.Reserved_2 << '\n';

        hs << "SnapLen: " << header.SnapLen << '\n';

        hs << "LinkType: " << header.LinkType << '\n';
        
        switch (data_endianness) {
            case std::endian::little:
                hs << "Data endianness: little-endian" << '\n';
                break;
            case std::endian::big:
                hs << "Data endianness: big-endian" << '\n';
                break;
        }

        hs << "Timestamp resolution (decimal places): " << ts_decimal_places << '\n';
        
        return hs.str();
    }
}