#include <string>
#include <vector>
#include <cstddef>
#include <bit>

#ifndef PCAP_H
#define PCAP_H

namespace pcap {
    struct Pcap_Header {
        uint32_t magic_number;
        uint16_t major_version;
        uint16_t minor_version;
        int32_t Reserved_1;
        uint32_t Reserved_2;
        uint32_t SnapLen;
        uint16_t FCS_section;
        uint16_t LinkType;
        std::endian data_endianness;
        int timestamp_res;
    };

    std::vector<std::byte> to_byte_vector(std::string file_path, unsigned int byte_start_index, unsigned int num_of_bytes);
    pcap::Pcap_Header populate_header(std::vector<std::byte> header_vec);

    std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec);
    std::string uint32_t_as_hex_str(uint32_t num);
}

#endif