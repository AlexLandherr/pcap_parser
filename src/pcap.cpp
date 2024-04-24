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
#include <cstdio>

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

    const pcap::Pcap_Record_Header &populate_pcap_record_header(const std::vector<uint8_t> &record_header_vec) {
        auto record_header = reinterpret_cast<const pcap::Pcap_Record_Header*>(&record_header_vec[0]);
        return *record_header;
    }

    pcap::Pcap_File_Header get_pcap_file_header(std::string &file_str) {
        std::FILE* f = std::fopen(file_str.c_str(), "rb");
        if (f == NULL) {
            throw std::invalid_argument("Error opening file!");
            /* std::perror("Error opening file!");
            return 1; */
        }

        pcap::Pcap_File_Header fh_buf;

        const std::size_t n = std::fread(&fh_buf, sizeof(pcap::Pcap_File_Header), 1, f);
        if (n != 1) {
            std::perror("std::fread failed!");
            std::exit(EXIT_FAILURE);
            //return 1;
        }

        return fh_buf;
    }

    std::string uint32_t_as_hex_str(uint32_t &num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }

    std::string human_readable_pcap_file_header(pcap::Pcap_File_Header &file_header) {
        std::stringstream hs;
        std::endian data_endianness;
        int ts_decimal_places = 0;

        //Determine endianness and ts resolution (decimal places).
        switch (file_header.magic_number) {
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
                hs << "Unable to determine ts resolution and data endianness. Value: " << pcap::uint32_t_as_hex_str(file_header.magic_number) << " not recognized." << '\n';
                break;
        }

        hs << "magic_num: " << pcap::uint32_t_as_hex_str(file_header.magic_number) << '\n';

        //Swap check.
        if (std::endian::native != data_endianness) {
            file_header.major_version = __builtin_bswap16(file_header.major_version);
            file_header.minor_version = __builtin_bswap16(file_header.minor_version);

            file_header.SnapLen = __builtin_bswap32(file_header.SnapLen);
            file_header.LinkType = __builtin_bswap16(file_header.LinkType);
        }

        hs << "major_version: " << file_header.major_version << '\n';
        hs << "minor_version: " << file_header.minor_version << '\n';

        hs << "Reserved_1: " << file_header.Reserved_1 << '\n';
        hs << "Reserved_2: " << file_header.Reserved_2 << '\n';

        hs << "SnapLen: " << file_header.SnapLen << '\n';

        hs << "LinkType: " << file_header.LinkType << '\n';
        
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

    std::string human_readable_pcap_record_header(pcap::Pcap_Record_Header &record_header, int &ts_decimal_places) {
        std::stringstream rs;
        rs << "Timestamp (Unix): " << record_header.ts_seconds << "." << std::setw(ts_decimal_places) << std::setfill('0') << record_header.ts_frac << '\n';
        rs << "CapLen: " << record_header.CapLen << '\n';
        rs << "OrigLen: " << record_header.OrigLen << '\n';

        return rs.str();
    }
}