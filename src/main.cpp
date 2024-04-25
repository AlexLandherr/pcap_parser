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

    //Print out Packet Records in loop.
    //Read first record header as vector of bytes.
    //auto record_header_vec = pcap::to_byte_vector(fs, 24, 16);

    //Populate first record header.
    //pcap::Pcap_Record_Header rh = pcap::populate_pcap_record_header(record_header_vec);
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

    std::cout << "Record: 0 (or 1)" << '\n';
    std::cout << pcap::human_readable_pcap_record_header(rh, ts_decimal_places);
    
    /* int count = 0;
    while (true) {
        //Read record header as vector of bytes.
        auto record_header_vec = pcap::to_byte_vector(fs, 24, 16);

        //Populate record header.
        pcap::Pcap_Record_Header rh = pcap::populate_pcap_record_header(record_header_vec);

        //Swap check.
        if (std::endian::native != data_endianness) {
            rh.ts_seconds = __builtin_bswap32(rh.ts_seconds);
            rh.ts_frac = __builtin_bswap32(rh.ts_frac);
            rh.CapLen = __builtin_bswap32(rh.CapLen);
            rh.OrigLen = __builtin_bswap32(rh.OrigLen);
        }

        //Use std::min() to check/set CapLen?
        rh.CapLen = std::min(rh.OrigLen, fh.SnapLen);

        //Populate record.
        pcap::Pcap_Record r;
        r.header = rh;
    } */

    return 0;
}