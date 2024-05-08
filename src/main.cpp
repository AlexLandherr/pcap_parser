#include "include/pcap.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstddef>
#include <bit>
#include <iomanip>
#include <cstdint>
#include <bitset>
#include <ios>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <cstdio>

int main() {
    //variables for timestamp resolution and data endianness.
    int ts_decimal_places = 0;
    std::endian data_endianness;

    std::string filename{"pcap_files/tcp_1.pcap"};
    /* std::fstream fs{filename, std::ios::in | std::ios::binary};
    if (!fs.is_open()) {
        std::cerr << "Failed to open '" << filename << "'" << '\n';
    } */

    //Add try-catch statement later.
    /* auto header_vector = pcap::to_byte_vector(fs, 0, 24);
    pcap::Pcap_File_Header fh = pcap::populate_pcap_file_header(header_vector); */

    //File stream for entire program.
    std::FILE* f_stream = std::fopen(filename.c_str(), "rb");
    if (f_stream == NULL) {
        std::perror("Error opening file!");
        return 1;
    }


    pcap::Pcap_File_Header fh = pcap::get_pcap_file_header(f_stream);

    //Determine endianness and ts resolution (decimal places).
    switch (fh.magic_number) {
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
            std::cerr << "Unable to determine ts resolution and data endianness. Value: " << pcap::uint32_t_as_hex_str(fh.magic_number) << " not recognized." << '\n';
            break;
    }

    //Swap check.
    if (std::endian::native != data_endianness) {
        std::cout << "Data endianness different from system endianness!" << '\n';
        fh.major_version = __builtin_bswap16(fh.major_version);
        fh.minor_version = __builtin_bswap16(fh.minor_version);

        fh.SnapLen = __builtin_bswap32(fh.SnapLen);
        fh.LinkType = __builtin_bswap32(fh.LinkType);
    }

    std::cout << pcap::human_readable_pcap_file_header(fh);
    std::cout << "****" << '\n';

    /* //Print out Packet Records in loop.
    //Populate first record header.
    pcap::Pcap_Record_Header rh = pcap::get_pcap_record_header(f_stream);

    //Swap check.
    if (std::endian::native != data_endianness) {
        rh.ts_seconds = __builtin_bswap32(rh.ts_seconds);
        rh.ts_frac = __builtin_bswap32(rh.ts_frac);
        rh.CapLen = __builtin_bswap32(rh.CapLen);
        rh.OrigLen = __builtin_bswap32(rh.OrigLen);
    }

    //Use std::min() to check/set CapLen.
    rh.CapLen = std::min(rh.CapLen, static_cast<uint32_t>(pcap::MAX_FRAME_SIZE));

    //Populating the full record struct by getting the Packet Data field from a Packet Record.
    pcap::Pcap_Record record = pcap::get_pcap_record(f_stream, rh);

    std::cout << "Record: 0 (or 1)" << '\n';
    std::cout << pcap::human_readable_pcap_record_header(record.header, ts_decimal_places);

    pcap::Eth_Header eth_header = pcap::get_eth_header(record);
    if (std::endian::native != std::endian::big) {
        eth_header.eth_type = __builtin_bswap16(eth_header.eth_type);
    }
    std::cout << "dst_mac_addr: " << pcap::mac_address_as_str(eth_header.dst_mac_addr) << '\n';
    std::cout << "src_mac_addr: " << pcap::mac_address_as_str(eth_header.src_mac_addr) << '\n';
    std::cout << "eth_type: " << pcap::eth_type_as_hex_str(eth_header.eth_type) << '\n'; */
    
    int count = 0;
    while (true) {
        //Print out Packet Records in loop.
        //Populate record header.
        pcap::Pcap_Record_Header rh = pcap::get_pcap_record_header(f_stream);

        //Swap check.
        if (std::endian::native != data_endianness) {
            rh.ts_seconds = __builtin_bswap32(rh.ts_seconds);
            rh.ts_frac = __builtin_bswap32(rh.ts_frac);
            rh.CapLen = __builtin_bswap32(rh.CapLen);
            rh.OrigLen = __builtin_bswap32(rh.OrigLen);
        }

        //Use std::min() to check/set CapLen.
        rh.CapLen = std::min(rh.CapLen, static_cast<uint32_t>(pcap::MAX_FRAME_SIZE));

        //Populating the full record struct by getting the Packet Data field from a Packet Record.
        pcap::Pcap_Record record = pcap::get_pcap_record(f_stream, rh);

        std::cout << "Record " << (count + 1) << ":" << '\n';
        std::cout << pcap::human_readable_pcap_record_header(record.header, ts_decimal_places);

        pcap::Eth_Header eth_header = pcap::get_eth_header(record);
        if (std::endian::native != std::endian::big) {
            eth_header.eth_type = __builtin_bswap16(eth_header.eth_type);
        }
        std::cout << "dst_mac_addr: " << pcap::mac_address_as_str(eth_header.dst_mac_addr) << '\n';
        std::cout << "src_mac_addr: " << pcap::mac_address_as_str(eth_header.src_mac_addr) << '\n';
        std::cout << "eth_type: " << pcap::eth_type_as_hex_str(eth_header.eth_type) << '\n';
        std::cout << '\n';

        count++;
    }

    return 0;
}