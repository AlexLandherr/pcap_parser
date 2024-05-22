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

    struct File_Header {
        uint32_t magic_number;
        uint16_t major_version;
        uint16_t minor_version;
        int32_t Reserved_1;
        uint32_t Reserved_2;
        uint32_t SnapLen;
        uint32_t LinkType;
    };

    struct Record_Header {
        uint32_t ts_seconds;

        //Fractional part of timestamp (after decimal sign/point).
        uint32_t ts_frac;

        /*Number of octets/bytes captured from the packet (i.e. length of Packet Data Field).*/
        uint32_t CapLen;

        /*Actual length of packet when transmitted on the network, can be different from CapLen if
          packet was truncated by capture process.*/
        uint32_t OrigLen;
    };

    struct Record {
        pcap::Record_Header header;
        std::array<uint8_t, MAX_FRAME_SIZE> frame; //aka Packet Data field.
        //uint8_t frame[MAX_FRAME_SIZE];
    };

    struct Eth_Header {
        std::array<uint8_t, 6> dst_mac_addr;
        std::array<uint8_t, 6> src_mac_addr;
        uint16_t eth_type;
    };

    /* struct Eth_Frame {
        pcap::Eth_Header header;
        std::array<uint8_t, 1500> data; //IP, ARP etc.
    }; */

    struct IPv4_Header {
        uint8_t version_IHL;
        uint8_t DSCP_ECN;
        uint16_t total_len;
        uint16_t ID;
        uint16_t flag_frag_offset;
        uint8_t TTL;
        uint8_t protocol;
        uint16_t header_chksum;
        uint32_t src_addr;
        uint32_t dst_addr;
    };

    struct TCP_Header {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t sequence_num;
        uint32_t ACK_num; //If ACK set in flags.
        uint8_t data_offset_reserved; //Data Offset & Reserved bits.
        uint8_t flags; //8 1-bit flags.
        uint16_t window_size;
        uint16_t chk_sum;
        uint16_t urg_pointer; //If URG set flags.
    };

    struct UDP_header {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length; //Size of UDP header + UDP data in bytes.
        uint16_t chk_sum;
    };

    pcap::File_Header get_file_header(std::FILE* f_stream);
    pcap::Record_Header get_record_header(std::FILE* f_stream);
    pcap::Record get_record(std::FILE* f_stream, const pcap::Record_Header &record_header);
    pcap::Eth_Header get_eth_header(const pcap::Record &record);
    /* pcap::Eth_Frame get_eth_frame(const pcap::Record &record);
    pcap::IPv4_Header get_IPv4_Header(const pcap::Eth_Frame &eth_frame); */

    std::string format_uint32_t(const uint32_t &num);

    std::string format_file_header(const pcap::File_Header &file_header, const std::endian &data_endianness, const int &ts_decimal_places);
    std::string format_record_header(const pcap::Record_Header &record_header, const int &ts_decimal_places);
    std::string format_eth_header(const pcap::Eth_Header &ethernet_header);
    std::string format_IPv4_header(const pcap::IPv4_Header &IP_header);
    std::string format_TCP_header(const pcap::TCP_Header &TCP_header);
}

#endif