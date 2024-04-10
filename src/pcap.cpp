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
    std::vector<std::byte> to_byte_vector(std::fstream &file_stream, unsigned int byte_start_index, unsigned int num_of_bytes) {
        /* if (!std::filesystem::exists(file_path)) {
            throw std::invalid_argument("File '" + file_path + "' does not exist.");
        }
        std::fstream s{file_path, std::ios::in | std::ios::binary};
        std::filesystem::path f_path{file_path};
        auto f_size = std::filesystem::file_size(f_path);
        if ((f_size - byte_start_index) < num_of_bytes) {
            std::string err_msg = "Requested number of bytes (" + std::to_string(num_of_bytes) + ") from position "
            + std::to_string(byte_start_index) + "goes outside the file.";

            throw std::invalid_argument(err_msg);
        }  */

        std::vector<std::byte> result(num_of_bytes);
        file_stream.seekg(byte_start_index);
        file_stream.read(reinterpret_cast<char*>(&result.front()), num_of_bytes);

        //Check if file can be opened.
        /* if (!s.is_open()) {
            std::cerr << "Failed to open '" << file_path << "'" << '\n';
        } else {
            s.seekg(byte_start_index);
            s.read(reinterpret_cast<char*>(&result.front()), num_of_bytes);
        } */

        return result;
    }

    pcap::Pcap_Header populate_pcap_file_header(std::vector<std::byte> header_vec) {
        pcap::Pcap_Header header;

        //Determine endianness.
        unsigned int first_byte = std::to_integer<unsigned int>(header_vec[0]);
        if (first_byte == 0xa1) {
            header.data_endianness = std::endian::big;
        } else {
            header.data_endianness = std::endian::little;
        }

        //Check timestamp resolution.
        if (header.data_endianness == std::endian::big) {
            unsigned int third_byte = std::to_integer<unsigned int>(header_vec[2]);
            if (third_byte == 0xc3) {
                header.timestamp_res = 6;
            } else {
                header.timestamp_res = 9;
            }
        } else if (header.data_endianness == std::endian::little) {
            if (first_byte == 0xd4) {
                header.timestamp_res = 6;
            } else {
                header.timestamp_res = 9;
            }
        }

        //Setting magic_number.
        std::vector<std::byte> magic_num_vec = std::vector<std::byte>(header_vec.begin(), header_vec.begin() + 4);
        header.magic_number = std::to_integer<uint8_t>(magic_num_vec[0]) << 24 | std::to_integer<uint8_t>(magic_num_vec[1]) << 16 | std::to_integer<uint8_t>(magic_num_vec[2]) << 8 | std::to_integer<uint8_t>(magic_num_vec[3]);

        //Setting major_version and minor_version.
        header.major_version = std::to_integer<uint16_t>(header_vec[4]);
        header.minor_version = std::to_integer<uint16_t>(header_vec[6]);

        /*As per IETF specifications these fields are ignored when writing
        the result after reading the pcap file header bytes.*/
        //Setting Reserved_1.
        header.Reserved_1 = 0;
        //Setting Reserved_2.
        header.Reserved_2 = 0;

        //Setting SnapLen.
        std::vector<std::byte> snaplen_vec = std::vector<std::byte>(header_vec.begin() + 16, header_vec.begin() + 20);
        std::vector<std::byte> reversed_snaplen_vec = snaplen_vec;

        std::reverse(reversed_snaplen_vec.begin(), reversed_snaplen_vec.end());
        
        header.SnapLen = std::to_integer<uint8_t>(reversed_snaplen_vec[0]) << 24 | std::to_integer<uint8_t>(reversed_snaplen_vec[1]) << 16 | std::to_integer<uint8_t>(reversed_snaplen_vec[2]) << 8 | std::to_integer<uint8_t>(reversed_snaplen_vec[3]);

        //Behövs stycket ens nedan?
        /* if (std::endian::native == header.data_endianness) { //Varför fungerar inte std::endian::native != header.data_endianness ?
            //Flip byte order in vector.
            std::vector<std::byte> reversed_snaplen_vec = snaplen_vec;
            std::reverse(reversed_snaplen_vec.begin(), reversed_snaplen_vec.end());
            header.SnapLen = std::to_integer<uint8_t>(reversed_snaplen_vec[0]) << 24 | std::to_integer<uint8_t>(reversed_snaplen_vec[1]) << 16 | std::to_integer<uint8_t>(reversed_snaplen_vec[2]) << 8 | std::to_integer<uint8_t>(reversed_snaplen_vec[3]);
        } else {
            //No need to flip byte order, std::endian::native == header.data_endianness.
            header.SnapLen = std::to_integer<uint8_t>(snaplen_vec[0]) << 24 | std::to_integer<uint8_t>(snaplen_vec[1]) << 16 | std::to_integer<uint8_t>(snaplen_vec[2]) << 8 | std::to_integer<uint8_t>(snaplen_vec[3]);
        } */

        return header;
    }

    std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec) {
        std::stringstream ss;
        for (std::byte b : b_vec) {
            ss << std::hex << std::setw(2) << std::setfill('0') << std::to_integer<unsigned int>(b);
        }

        return ss.str();
    }

    std::string uint32_t_as_hex_str(uint32_t num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }
}