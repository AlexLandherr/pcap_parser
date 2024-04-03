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

namespace pcap {
    std::vector<std::byte> to_byte_vector(std::string file_path, unsigned int byte_start_index, unsigned int num_of_bytes) {
        std::vector<std::byte> result(num_of_bytes);
        std::fstream s{file_path, std::ios::in | std::ios::binary};

        //Check if file can be opened.
        if (!s.is_open()) {
            std::cerr << "Failed to open '" << file_path << "'" << '\n';
        } else {
            s.seekg(byte_start_index);
            s.read(reinterpret_cast<char*>(&result.front()), num_of_bytes);
        }

        return result;
    }

    std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec) {
        std::stringstream ss;
        for (std::byte b : b_vec) {
            ss << std::hex << std::setw(2) << std::setfill('0') << std::to_integer<int>(b);
        }

        return ss.str();
    }
}