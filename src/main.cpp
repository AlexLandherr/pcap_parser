#include "include/pcap.h"
#include "include/data_formats.h"
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
    //Variables for timestamp resolution and data endianness.
    int ts_decimal_places = 0;
    std::endian data_endianness;

    std::string filename{"pcap_files/chargen-udp.pcap"};

    //File stream for entire program.
    std::FILE* f_stream = std::fopen(filename.c_str(), "rb");
    if (f_stream == NULL) {
        std::perror("Error opening file!");
        return 1;
    }

    data_formats::File_Header fh = pcap::get_file_header(f_stream);

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

    std::cout << pcap::format_file_header(fh, data_endianness, ts_decimal_places) << '\n';
    std::cout << "****" << '\n';
    
    int count = 1;
    while (true) {
        int curr = 0;
        //Print out Packet Records in loop.
        data_formats::Record_Header rh = pcap::get_record_header(f_stream);

        //Swap check.
        if (std::endian::native != data_endianness) {
            rh.ts_seconds = pcap::bswap32(rh.ts_seconds);
            rh.ts_frac = pcap::bswap32(rh.ts_frac);
            rh.CapLen = pcap::bswap32(rh.CapLen);
            rh.OrigLen = pcap::bswap32(rh.OrigLen);
        }

        //Use std::min() to check/set CapLen.
        rh.CapLen = std::min(rh.CapLen, static_cast<uint32_t>(data_formats::MAX_FRAME_SIZE));

        //Populating the full record struct by getting the Packet Data field from a Packet Record.
        data_formats::Record record = pcap::get_record(f_stream, rh);
        data_formats::Eth_Header* eth = (data_formats::Eth_Header*) &record.frame[curr];
        curr += sizeof(data_formats::Eth_Header);

        if (std::endian::native != std::endian::big) {
            eth->eth_type = pcap::bswap16(eth->eth_type);
        }

        std::cout << "Record " << count << ":" << '\n';
        std::cout << pcap::format_record_header(record.header, ts_decimal_places);

        /*Determine EtherType (IPv4 or IPv6) aka OSI level 3 and format said header,
          then determine TCP or UDP (OSI level 4) and format said header.*/
        pcap::format_IPv4_IPv6_header(eth, record, curr);
        
        std::cout << '\n';

        count++;
    }

    return 0;
}