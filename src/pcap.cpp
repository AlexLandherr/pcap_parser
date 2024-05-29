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
    pcap::File_Header get_file_header(std::FILE* f_stream) {
        pcap::File_Header fh_buf;

        const std::size_t n = std::fread(&fh_buf, sizeof(pcap::File_Header), 1, f_stream);
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

    pcap::Record_Header get_record_header(std::FILE* f_stream) {
        pcap::Record_Header rh_buf;

        const std::size_t n = std::fread(&rh_buf, sizeof(pcap::Record_Header), 1, f_stream);
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

    pcap::Record get_record(std::FILE* f_stream, const pcap::Record_Header &record_header) {
        pcap::Record r_buf;
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

    std::string format_uint32_t(const uint32_t &num) {
        std::stringstream ss;
        ss << std::hex << num;
        return ss.str();
    }

    std::string format_file_header(const pcap::File_Header &file_header, const std::endian &data_endianness, const int &ts_decimal_places) {
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

        hs << "Timestamp resolution (decimal places): " << ts_decimal_places;
        
        return hs.str();
    }

    std::string format_record_header(const pcap::Record_Header &record_header, const int &ts_decimal_places) {
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
        (uint16_t)ethernet_header.src_mac_addr[0] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[1] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[2] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[3] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[4] << ":" <<
        (uint16_t)ethernet_header.src_mac_addr[5] << " ";

        //Get EtherType.
        eth_s << "eth_type: " << std::setw(4) << std::setfill('0') << std::showbase << ethernet_header.eth_type;

        return eth_s.str();
    }

    std::string format_IPv4_header(const pcap::IPv4_Header &IP_header) {
        std::stringstream IP_s;

        IP_s << "IP version: " << (uint16_t)((IP_header.version_IHL >> 4) & ((1 << 4) - 1)) << ' ';
        IP_s << "IHL: " << (uint16_t)(IP_header.version_IHL & ((1 << 4) - 1)) << ' ';
        IP_s << "Total Length: " << IP_header.total_len << ' ';
        IP_s << "TTL: " << (uint16_t)IP_header.TTL << ' ';
        IP_s << "Protocol: " << (uint16_t)IP_header.protocol << ' ';

        //Getting source & destination IPv4 address.
        //src_IPv4.
        uint16_t src_a = (IP_header.src_addr >> (8 * 0)) & 0xff;
        uint16_t src_b = (IP_header.src_addr >> (8 * 1)) & 0xff;
        uint16_t src_c = (IP_header.src_addr >> (8 * 2)) & 0xff;
        uint16_t src_d = (IP_header.src_addr >> (8 * 3)) & 0xff;

        //dst_IPv4.
        uint16_t dst_a = (IP_header.dst_addr >> (8 * 0)) & 0xff;
        uint16_t dst_b = (IP_header.dst_addr >> (8 * 1)) & 0xff;
        uint16_t dst_c = (IP_header.dst_addr >> (8 * 2)) & 0xff;
        uint16_t dst_d = (IP_header.dst_addr >> (8 * 3)) & 0xff;

        IP_s << "src_IPv4: " << src_a << "." << src_b << "." << src_c << "." << src_d << ' ';
        IP_s << "dst_IPv4: " << dst_a << "." << dst_b << "." << dst_c << "." << dst_d;

        return IP_s.str();
    }

    std::string format_TCP_UDP_header(const pcap::IPv4_Header &IP_header, const pcap::Record &record, int &curr) {
        std::stringstream tcp_udp_s;

        switch (IP_header.protocol) {
            case 0x06: {
                //Eventual printout/extraction of TCP info.
                pcap::TCP_Header& tcp = *(pcap::TCP_Header*) &record.frame[curr];
                if (std::endian::native != std::endian::big) {
                    tcp.src_port = pcap::bswap16(tcp.src_port);
                    tcp.dst_port = pcap::bswap16(tcp.dst_port);
                    tcp.sequence_num = pcap::bswap32(tcp.sequence_num);
                    tcp.ACK_num = pcap::bswap32(tcp.ACK_num);
                    //Swap data_offset_reserved?
                    //Swap flags?
                    tcp.window_size = pcap::bswap16(tcp.window_size);
                    tcp.chk_sum = pcap::bswap16(tcp.chk_sum);
                    tcp.urg_pointer = pcap::bswap16(tcp.urg_pointer);
                }

                tcp_udp_s << "TCP_src_port: " << tcp.src_port << ' ';
                tcp_udp_s << "TCP_dst_port: " << tcp.dst_port << ' ';
                tcp_udp_s << "Data offset: " << (uint16_t)((tcp.data_offset_reserved >> 4) & ((1 << 4) - 1)) << ' ';
                tcp_udp_s << "Window size: " << tcp.window_size;

                //If data offset > 5 read options field.
                uint8_t data_offset = ((tcp.data_offset_reserved >> 4) & ((1 << 4) - 1));
                if (data_offset > 5) {
                    tcp_udp_s << "\nTCP Options Info: " << '\n';
                    uint8_t* head = (uint8_t*)&tcp + 20;
                    uint8_t* tail = head + ((data_offset - 5) * 4);

                    while (head < tail) {
                        switch (*head) {
                            case 0: { //End of options list.
                                tcp_udp_s << "//End of options list." << '\n';
                                return 0;
                            }
                            case 1: { //No operation.
                                tcp_udp_s << "//No operation." << '\n';
                                head += 1;
                                break;
                            }
                            case 2: { //Maximum segment size.
                                if (head[1] != 4 && !((tcp.flags >> 1) & 1)) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//Maximum segment size." << '\n';
                                head += head[1];
                                break;
                            }
                            case 3: { //Window scale.
                                if (head[1] != 3 && !((tcp.flags >> 1) & 1)) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//Window scale." << '\n';
                                head += head[1];
                                break;
                            }
                            case 4: { //Selective Acknowledgement permitted.
                                if (head[1] != 2 && !((tcp.flags >> 1) & 1)) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//Selective Acknowledgement permitted." << '\n';
                                head += head[1];
                                break;
                            }
                            case 5: { //Selective ACKnowledgement (SACK).
                                const std::array<uint8_t, 4> good_values = {10, 18, 26, 34};
                                if (std::find(good_values.begin(), good_values.end(), head[1]) != good_values.end()) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//Selective ACKnowledgement (SACK)." << '\n';
                                head += head[1];
                                break;
                            }
                            case 8: { //Timestamp and echo of previous timestamp.
                                if (head[1] != 10) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//Timestamp and echo of previous timestamp." << '\n';
                                head += head[1];
                                break;
                            }
                            case 28: { //User Timeout Option.
                                if (head[1] != 4) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//User Timeout Option." << '\n';
                                head += head[1];
                                break;
                            }
                            case 29: { //TCP Authentication Option (TCP-AO).
                                if (!(head[1] <= (tail - head))) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//TCP Authentication Option (TCP-AO)." << '\n';
                                head += head[1];
                                break;
                            }
                            case 30: { //Multipath TCP (MPTCP).
                                if (!(head[1] <= (tail - head))) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "//Multipath TCP (MPTCP).";
                                head += head[1];
                                break;
                            }
                            default: {
                                if (tail - head < 2) {
                                    std::exit(EXIT_FAILURE);
                                } else if (tail - head < head[1]) {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                        }
                    }
                }

                //Increment curr?
                        
                break;
            }
            case 0x11: {
                //Eventual printout/extraction of UDP info.
                pcap::UDP_header& udp = *(pcap::UDP_header*) &record.frame[curr];
                if (std::endian::native != std::endian::big) {
                    udp.src_port = pcap::bswap16(udp.src_port);
                    udp.dst_port = pcap::bswap16(udp.dst_port);
                    udp.length = pcap::bswap16(udp.length);
                    udp.chk_sum = pcap::bswap16(udp.chk_sum);
                }

                tcp_udp_s << "UDP_src_port: " << udp.src_port << ' ';
                tcp_udp_s << "UDP_dst_port: " << udp.dst_port << ' ';
                tcp_udp_s << "Length (header + data): " << udp.length << ' ';
                tcp_udp_s << "chk_sum: " << udp.chk_sum;
                
                break;
            }
            default: {
                tcp_udp_s << "Default." << '\n';
                break;
            }
        }

        return tcp_udp_s.str();
    }
}