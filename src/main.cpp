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
#include <array>

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

    pcap::File_Header fh = pcap::get_file_header(f_stream);

    //Determine endianness and ts resolution (decimal places).
    switch (fh.magic_number) {
        case 0xa1b2c3d4: {
            data_endianness = std::endian::little; //change to little
            ts_decimal_places = 6;
            break;
        }
        case 0xd4c3b2a1: {
            data_endianness = std::endian::big; //change to big
            ts_decimal_places = 6;
            break;
        }
        case 0xa1b23c4d: {
            data_endianness = std::endian::little; //change to little
            ts_decimal_places = 9;
            break;
        }
        case 0x4d3cb2a1: {
            data_endianness = std::endian::big; //change to big
            ts_decimal_places = 9;
            break;
        }
        default: {
            std::cerr << "Unable to determine ts resolution and data endianness. Value: " << pcap::format_uint32_t(fh.magic_number) << " not recognized." << '\n';
            break;
        }
    }

    //Swap check.
    if (std::endian::native != data_endianness) {
        std::cout << "Data endianness different from system endianness!" << '\n';
        fh.major_version = pcap::bswap16(fh.major_version);
        fh.minor_version = pcap::bswap16(fh.minor_version);

        fh.SnapLen = pcap::bswap32(fh.SnapLen);
        fh.LinkType = pcap::bswap32(fh.LinkType);
    }

    //Check if LinkType is Ethernet.
    if (fh.LinkType != 1) {
        std::cout << "LinkType other than Ethernet detected! Exiting program." << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::cout << pcap::format_file_header(fh, data_endianness, ts_decimal_places);
    std::cout << "****" << '\n';
    std::cout << "Size of 'IPv4_Header' struct in bytes: " << sizeof(pcap::IPv4_Header) << '\n';
    std::cout << "****" << '\n';
    
    int count = 0;
    while (true) {
        //Print out Packet Records in loop.
        //Populate record header.
        pcap::Record_Header rh = pcap::get_record_header(f_stream);

        //Swap check.
        if (std::endian::native != data_endianness) {
            rh.ts_seconds = pcap::bswap32(rh.ts_seconds);
            rh.ts_frac = pcap::bswap32(rh.ts_frac);
            rh.CapLen = pcap::bswap32(rh.CapLen);
            rh.OrigLen = pcap::bswap32(rh.OrigLen);
        }

        //Use std::min() to check/set CapLen.
        rh.CapLen = std::min(rh.CapLen, static_cast<uint32_t>(pcap::MAX_FRAME_SIZE));

        //Populating the full record struct by getting the Packet Data field from a Packet Record.
        pcap::Record record = pcap::get_record(f_stream, rh);

        std::cout << "Record " << (count + 1) << ":" << '\n';
        std::cout << pcap::format_record_header(record.header, ts_decimal_places);

        pcap::Eth_Frame eth_frame = pcap::get_eth_frame(record);
        if (std::endian::native != std::endian::big) {
            eth_frame.header.eth_type = pcap::bswap16(eth_frame.header.eth_type);
        }

        //Checking EtherType.
        switch (eth_frame.header.eth_type) {
            case 0x0800: {
                std::cout << "EtherType: IPv4." << '\n';
                std::cout << pcap::format_eth_header(eth_frame.header) << '\n';
                
                //Eventual printout/extraction of IP packet info.
                pcap::IPv4_Header IP_header = pcap::get_IPv4_Header(eth_frame);
                std::array<uint8_t, 40> IPv4_opts_arr;

                //Extracting version and IHL values with bit masking.
                uint8_t IP_version = (IP_header.version_IHL >> 4) & ((1 << 4) - 1);
                uint8_t IHL = IP_header.version_IHL & ((1 << 4) - 1);

                //Calculate IP payload size in bytes.

                if (std::endian::native != std::endian::big) {
                    //swap version_IHL?
                    //swap DSCP_ECN?
                    IP_header.total_len = pcap::bswap16(IP_header.total_len);
                    IP_header.ID = pcap::bswap16(IP_header.ID);
                    IP_header.flag_frag_offset = pcap::bswap16(IP_header.flag_frag_offset);
                    //swap TTL?
                    //swap protocol?
                    IP_header.header_chksum = pcap::bswap16(IP_header.header_chksum);
                    //Avoid swapping IP addresses?
                    //IP_header.src_addr = pcap::bswap32(IP_header.src_addr);
                    //IP_header.dst_addr = pcap::bswap32(IP_header.dst_addr);
                }
                std::cout << pcap::format_IPv4_header(IP_header) << '\n';
                
                break;
            }
            case 0x86DD: {
                std::cout << "EtherType: IPv6." << '\n';
                std::cout << pcap::format_eth_header(eth_frame.header) << '\n';
                //Eventual printout/extraction of IP packet info.
                break;
            }
            default: {
                std::cout << "Default." << '\n';
                break;
            }
        }
        
        std::cout << '\n';

        count++;
    }

    return 0;
}