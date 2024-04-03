#include <string>
#include <vector>
#include <cstddef>

#ifndef PCAP_H
#define PCAP_H

namespace pcap {
    std::vector<std::byte> to_byte_vector(std::string file_path, unsigned int byte_start_index, unsigned int num_of_bytes);
    std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec);
}

#endif