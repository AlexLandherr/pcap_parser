#include <string>
#include <vector>
#include <cstddef>
#include <bit>
#include <fstream>

#ifndef PCAP_H
#define PCAP_H

namespace pcap {
    struct Pcap_File_Header {
        uint32_t magic_number;
        uint16_t major_version;
        uint16_t minor_version;
        uint32_t Reserved_1;
        uint32_t Reserved_2;
        uint32_t SnapLen;
        uint16_t FCS;
        uint16_t LinkType;
    };

    std::vector<uint8_t> to_byte_vector(std::fstream &file_stream, unsigned int byte_start_index, unsigned int num_of_bytes);
    const pcap::Pcap_File_Header & populate_pcap_file_header(const std::vector<uint8_t> &header_vec);

    std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec);
    std::string uint32_t_as_hex_str(uint32_t num);
}

#endif