#include <string>
#include <vector>
#include <cstddef>
#include <bit>
#include <bitset>
#include <fstream>
#include <array>
#include <cstdio>

#ifndef DATA_FORMATS_H
#define DATA_FORMATS_H

namespace data_formats {
    enum {
        MAX_FRAME_SIZE = 1536
    };

    enum ports {
        HTTP_PORT_NUM = 80,
        TEST_HTTP_PORT_NUM = 8080
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
        data_formats::Record_Header header;
        std::array<uint8_t, MAX_FRAME_SIZE> frame; //aka Packet Data field.
        //uint8_t frame[MAX_FRAME_SIZE];
    };

    struct Eth_Header {
        std::array<uint8_t, 6> dst_mac_addr;
        std::array<uint8_t, 6> src_mac_addr;
        uint16_t eth_type;
    };

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

    struct IPv6_Header {
        uint32_t version_diffserv_ECN_flow_label;
        uint16_t payload_length;
        uint8_t next_header; //Same function as 'Protocol' field in IPv4.
        uint8_t hop_limit; //Same as TTL in IPv4.
        std::bitset<128> src_addr;
        std::bitset<128> dst_addr;
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
}

#endif