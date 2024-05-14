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
    static inline uint16_t bswap16(uint16_t x) {
        return __builtin_bswap16(x);
    }

    static inline uint32_t bswap32(uint32_t x) {
        return __builtin_bswap32(x);
    }
    
    enum {
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
        //uint8_t frame[MAX_FRAME_SIZE];
    };

    struct Eth_Header {
        std::array<uint8_t, 6> dst_mac_addr;
        std::array<uint8_t, 6> src_mac_addr;
        uint16_t eth_type;
    };

    pcap::Pcap_File_Header get_file_header(std::FILE* f_stream);
    pcap::Pcap_Record_Header get_record_header(std::FILE* f_stream);
    pcap::Pcap_Record get_record(std::FILE* f_stream, const pcap::Pcap_Record_Header &record_header);
    pcap::Eth_Header get_eth_header(const pcap::Pcap_Record &record);

    std::string format_uint32_t(const uint32_t &num);

    std::string format_file_header(const pcap::Pcap_File_Header &file_header, const std::endian &data_endianness, const int &ts_decimal_places);
    std::string format_record_header(const pcap::Pcap_Record_Header &record_header, const int &ts_decimal_places);
    std::string format_eth_header(const pcap::Eth_Header &ethernet_header);
}

#endif