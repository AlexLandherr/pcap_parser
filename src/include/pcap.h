#include "data_formats.h"
#include <string>
#include <vector>
#include <cstddef>
#include <bit>
#include <bitset>
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

    data_formats::File_Header get_file_header(std::FILE* f_stream);
    data_formats::Record_Header get_record_header(std::FILE* f_stream);
    data_formats::Record get_record(std::FILE* f_stream, const data_formats::Record_Header &record_header);
    data_formats::Eth_Header get_eth_header(const data_formats::Record &record);

    std::string format_uint32_t(const uint32_t &num);

    std::string format_file_header(const data_formats::File_Header &file_header, const std::endian &data_endianness, const int &ts_decimal_places);
    std::string format_record_header(const data_formats::Record_Header &record_header, const int &ts_decimal_places);

    std::string format_eth_header(const data_formats::Eth_Header &ethernet_header);
    std::string format_IPv4_header(const data_formats::IPv4_Header &IP_header);

    void format_HTTP_header(const data_formats::Record &record, const int &curr, std::stringstream &tcp_udp_s, const uint32_t &TCP_data_size);
    std::string format_TCP_UDP_header(const data_formats::IPv4_Header &IP_header, const data_formats::Record &record, int &curr);

    void format_IPv4_IPv6_header(data_formats::Eth_Header* eth_header, const data_formats::Record &record, int &curr);
}

#endif