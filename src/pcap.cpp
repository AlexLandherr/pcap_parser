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
    pcap::Pcap_File_Header get_pcap_file_header(std::FILE* f_stream) {
        pcap::Pcap_File_Header fh_buf;

        const std::size_t n = std::fread(&fh_buf, sizeof(pcap::Pcap_File_Header), 1, f_stream);
        if (n != 1) {
            std::perror("std::fread failed!");
            std::exit(EXIT_FAILURE); //Use 'return 1' or not?
            //return 1;
        }

        return fh_buf;
    }

    pcap::Pcap_Record_Header get_pcap_record_header(std::FILE* f_stream) {
        pcap::Pcap_Record_Header rh_buf;

        const std::size_t n = std::fread(&rh_buf, sizeof(pcap::Pcap_Record_Header), 1, f_stream);
        if (n != 1) {
            std::perror("std::fread failed!");
            std::exit(EXIT_FAILURE); //Use 'return 1' or not?
        }

        return rh_buf;
    }

    pcap::Pcap_Record get_pcap_record(std::FILE* f_stream, pcap::Pcap_Record_Header &record_header) {
        pcap::Pcap_Record r_buf;
        r_buf.header = record_header;

        const std::size_t n = std::fread(&r_buf.frame, record_header.CapLen, 1, f_stream);
        if (n != 1) {
            std::perror("std::fread failed!");
            std::exit(EXIT_FAILURE); //Use 'return 1' or not?
        }

        return r_buf;
    }

    pcap::Eth_Header get_eth_header(pcap::Pcap_Record &record) {
        pcap::Eth_Header eth_fh;

        //.
        std::memcpy(&eth_fh, &record.frame, sizeof(eth_fh));

        return eth_fh;
    }

    std::string uint32_t_as_hex_str(uint32_t &num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }

    std::string human_readable_pcap_file_header(pcap::Pcap_File_Header file_header) {
        std::stringstream hs;
        std::endian data_endianness;
        int ts_decimal_places = 0;

        //Determine endianness and ts resolution (decimal places).
        switch (file_header.magic_number) {
            case 0xa1b2c3d4:
                data_endianness = std::endian::little; //change to little
                ts_decimal_places = 6;
                break;
            case 0xd4c3b2a1:
                data_endianness = std::endian::big; //change to big
                ts_decimal_places = 6;
                break;
            case 0xa1b23c4d:
                data_endianness = std::endian::little; //change to little
                ts_decimal_places = 9;
                break;
            case 0x4d3cb2a1:
                data_endianness = std::endian::big; //change to big
                ts_decimal_places = 9;
                break;
            default:
                hs << "Unable to determine ts resolution and data endianness. Value: " << pcap::uint32_t_as_hex_str(file_header.magic_number) << " not recognized." << '\n';
                break;
        }

        hs << "magic_num: " << pcap::uint32_t_as_hex_str(file_header.magic_number) << '\n';

        //Swap check.
        if (std::endian::native != data_endianness) {
            file_header.major_version = __builtin_bswap16(file_header.major_version);
            file_header.minor_version = __builtin_bswap16(file_header.minor_version);

            file_header.SnapLen = __builtin_bswap32(file_header.SnapLen);
            file_header.LinkType = __builtin_bswap16(file_header.LinkType);
        }

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

    std::string human_readable_pcap_record_header(pcap::Pcap_Record_Header &record_header, int &ts_decimal_places) {
        std::stringstream rs;
        rs << "Unix: " << record_header.ts_seconds << "." << std::setw(ts_decimal_places) << std::setfill('0') << record_header.ts_frac << " ";
        rs << "CapLen: " << record_header.CapLen << " ";
        rs << "OrigLen: " << record_header.OrigLen << '\n';

        return rs.str();
    }

    std::string human_readable_eth_header(pcap::Eth_Header &ethernet_header) {
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