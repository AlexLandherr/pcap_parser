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
#include <cstdio>
#include <cstring>
#include <ios>

namespace pcap {
    pcap::Pcap_File_Header get_file_header(std::FILE* f_stream) {
        pcap::Pcap_File_Header fh_buf;

        const std::size_t n = std::fread(&fh_buf, sizeof(pcap::Pcap_File_Header), 1, f_stream);
        if (n != 1) {
            if (std::ferror(f_stream)) {
                std::cout << "I/O error when reading." << '\n';
                std::exit(EXIT_FAILURE);
            } else if (std::feof(f_stream)) {
                std::cout << "EOF." << '\n';
                std::exit(EXIT_SUCCESS);
            }
        }
        
        return fh_buf;
    }

    pcap::Pcap_Record_Header get_record_header(std::FILE* f_stream) {
        pcap::Pcap_Record_Header rh_buf;

        const std::size_t n = std::fread(&rh_buf, sizeof(pcap::Pcap_Record_Header), 1, f_stream);
        if (n != 1) {
            if (std::ferror(f_stream)) {
                std::cout << "I/O error when reading." << '\n';
                std::exit(EXIT_FAILURE);
            } else if (std::feof(f_stream)) {
                std::cout << "EOF." << '\n';
                std::exit(EXIT_SUCCESS);
            }
        }

        return rh_buf;
    }

    pcap::Pcap_Record get_record(std::FILE* f_stream, const pcap::Pcap_Record_Header &record_header) {
        pcap::Pcap_Record r_buf;
        r_buf.header = record_header;

        const std::size_t n = std::fread(&r_buf.frame, record_header.CapLen, 1, f_stream);
        if (n != 1) {
            if (std::ferror(f_stream)) {
                std::cout << "I/O error when reading." << '\n';
                std::exit(EXIT_FAILURE);
            } else if (std::feof(f_stream)) {
                std::cout << "EOF." << '\n';
                std::exit(EXIT_SUCCESS);
            }
        }

        return r_buf;
    }

    pcap::Eth_Header get_eth_header(const pcap::Pcap_Record &record) {
        pcap::Eth_Header eh_buf;

        //.
        std::memcpy(&eh_buf, &record.frame, sizeof(eh_buf));

        return eh_buf;
    }

    std::string format_uint32_t(const uint32_t &num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }

    std::string format_file_header(const pcap::Pcap_File_Header &file_header, const std::endian &data_endianness, const int &ts_decimal_places) {
        std::stringstream hs;
        hs << "magic_num: " << pcap::format_uint32_t(file_header.magic_number) << '\n';
        hs << "major_version: " << file_header.major_version << '\n';
        hs << "minor_version: " << file_header.minor_version << '\n';
        hs << "Reserved_1: " << file_header.Reserved_1 << '\n';
        hs << "Reserved_2: " << file_header.Reserved_2 << '\n';
        hs << "SnapLen: " << file_header.SnapLen << '\n';
        hs << "LinkType: " << file_header.LinkType << '\n';

        switch (data_endianness) {
            case std::endian::little:
                hs << "Data endianness: little-endian" << '\n';
                break;
            case std::endian::big:
                hs << "Data endianness: big-endian" << '\n';
                break;
        }

        hs << "Timestamp resolution (decimal places): " << ts_decimal_places << '\n';
        
        return hs.str();
    }

    std::string format_record_header(const pcap::Pcap_Record_Header &record_header, const int &ts_decimal_places) {
        std::stringstream rs;
        rs << "Unix: " << record_header.ts_seconds << "." << std::setw(ts_decimal_places) << std::setfill('0') << record_header.ts_frac << " ";
        rs << "CapLen: " << record_header.CapLen << " ";
        rs << "OrigLen: " << record_header.OrigLen << '\n';

        return rs.str();
    }

    std::string format_eth_header(const pcap::Eth_Header &ethernet_header) {
        std::stringstream eth_s;

        //Get destination & source MAC address.
        eth_s << "dst_mac: " << std::hex << std::setw(2) << std::setfill('0') <<
        (uint16_t)ethernet_header.dst_mac_addr[0] << ":" <<
        (uint16_t)ethernet_header.dst_mac_addr[1] << ":" <<
        (uint16_t)ethernet_header.dst_mac_addr[2] << ":" <<
        (uint16_t)ethernet_header.dst_mac_addr[3] << ":" <<
        (uint16_t)ethernet_header.dst_mac_addr[4] << ":" <<
        (uint16_t)ethernet_header.dst_mac_addr[5] << " ";

        eth_s << "src_mac: " << std::hex << std::setw(2) << std::setfill('0') <<
        (uint16_t)ethernet_header.dst_mac_addr[0] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[1] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[2] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[3] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[4] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[5] << " ";

        //Get EtherType.
        eth_s << "eth_type: " << std::setw(4) << std::setfill('0') << std::showbase << ethernet_header.eth_type;

        return eth_s.str();
    }
}