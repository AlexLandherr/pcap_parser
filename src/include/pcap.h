#include <string>
#include <vector>
#include <cstddef>
#include <bit>
#include <fstream>
#include <array>
#include <cstdio>

#ifndef PCAP_H
#define PCAP_H

namespace pcap {
    enum
    {
    MAX_FRAME_SIZE = 1536
    };

    struct Pcap_File_Header {
        uint32_t magic_number;
        uint16_t major_version;
        uint16_t minor_version;
        int32_t Reserved_1;
        uint32_t Reserved_2;
        uint32_t SnapLen;
        uint32_t LinkType;
    };

    struct Pcap_Record_Header {
        uint32_t ts_seconds;

        //Fractional part of timestamp (after decimal sign/point).
        uint32_t ts_frac;

        /*Number of octets/bytes captured from the packet (i.e. length of Packet Data Field).*/
        uint32_t CapLen;

        /*Actual length of packet when transmitted on the network, can be different from CapLen if
          packet was truncated by capture process.*/
        uint32_t OrigLen;
    };

    struct Pcap_Record {
        pcap::Pcap_Record_Header header;
        std::array<uint8_t, MAX_FRAME_SIZE> frame; //aka Packet Data field.
    };

    struct Eth_Frame_Header {
        std::array<uint8_t, 6> dst_mac_addr;
        std::array<uint8_t, 6> src_mac_addr;
        uint16_t eth_type;
    };

    std::vector<uint8_t> to_byte_vector(std::fstream &file_stream, unsigned int byte_start_index, unsigned int num_of_bytes);
    const pcap::Pcap_File_Header &populate_pcap_file_header(const std::vector<uint8_t> &header_vec);
    const pcap::Pcap_Record_Header &populate_pcap_record_header(const std::vector<uint8_t> &record_header_vec);

    //pcap::Pcap_File_Header get_pcap_file_header(std::string &file_str);
    pcap::Pcap_File_Header get_pcap_file_header(std::FILE* f_stream);
    pcap::Pcap_Record_Header get_pcap_record_header(std::FILE* f_stream);
    pcap::Pcap_Record get_pcap_record(std::FILE* f_stream, pcap::Pcap_Record_Header record_header);
    pcap::Eth_Frame_Header get_eth_frame_header(pcap::Pcap_Record &record);

    //std::string byte_vec_to_hex_str(std::vector<std::byte> &b_vec);
    std::string uint32_t_as_hex_str(uint32_t &num);

    std::string human_readable_pcap_file_header(pcap::Pcap_File_Header file_header);
    std::string human_readable_pcap_record_header(pcap::Pcap_Record_Header &record_header, int &ts_decimal_places);
}

#endif