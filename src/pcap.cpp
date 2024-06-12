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
#include <cctype>

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
        rs << "OrigLen: " << record_header.OrigLen << '\n' << "******" << '\n';

        return rs.str();
    }

    std::string format_eth_header(const pcap::Eth_Header &ethernet_header) {
        std::stringstream eth_s;

        //Get destination & source MAC address.
        eth_s << "dst_mac: " << std::hex << std::setfill('0') <<
        std::setw(2) << (uint16_t)ethernet_header.dst_mac_addr[0] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.dst_mac_addr[1] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.dst_mac_addr[2] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.dst_mac_addr[3] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.dst_mac_addr[4] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.dst_mac_addr[5] << " ";

        eth_s << "src_mac: " <<
        std::setw(2) << (uint16_t)ethernet_header.src_mac_addr[0] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.src_mac_addr[1] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.src_mac_addr[2] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.src_mac_addr[3] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.src_mac_addr[4] << ":" <<
        std::setw(2) << (uint16_t)ethernet_header.src_mac_addr[5] << " ";

        //Get EtherType.
        eth_s << "eth_type: " << std::setw(4) << std::setfill('0') << std::showbase << ethernet_header.eth_type << ' ';
        switch (ethernet_header.eth_type) {
            case 0x0800: {
                eth_s << "(IPv4)";
                break;
            }
            case 0x86DD: {
                eth_s << "(IPv6)";
                break;
            }
            default: {
                eth_s << "(Default.)";
                break;
            }
        }

        eth_s << '\n' << "******";

        return eth_s.str();
    }

    std::string format_IPv4_header(const pcap::IPv4_Header &IP_header) {
        std::stringstream IP_s;

        IP_s << "IPv" << (uint16_t)((IP_header.version_IHL >> 4) & ((1 << 4) - 1)) << ' ';
        IP_s << "IHL: " << (uint16_t)(IP_header.version_IHL & ((1 << 4) - 1)) << ' ';
        IP_s << "total_length: " << IP_header.total_len << ' ';
        IP_s << "ttl: " << (uint16_t)IP_header.TTL << ' ';
        switch (IP_header.protocol) {
            case 0x06: {
                IP_s << "protocol: 0x06 (TCP) ";
                break;
            }
            case 0x11: {
                IP_s << "protocol: 0x11 (UDP) ";
                break;
            }
            default: {
                IP_s << "protocol: Default. ";
                break;
            }
        }

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
        IP_s << "dst_IPv4: " << dst_a << "." << dst_b << "." << dst_c << "." << dst_d << '\n';

        IP_s << "******";

        return IP_s.str();
    }

    void format_HTTP_header(const pcap::Record &record, const int &curr, std::stringstream &tcp_udp_s, const uint32_t &TCP_data_size) {
        std::string tcp_data_str = "";
        uint8_t* head_tcp_data = (uint8_t*)&record.frame[curr];
        uint8_t* tail_tcp_data = head_tcp_data + TCP_data_size;

        while (head_tcp_data < tail_tcp_data) {
            //Empty line detection for HTTP/1.1 messages for line that marks end of HTTP header.
            bool break_point = *head_tcp_data == '\n' && head_tcp_data[1] == '\r';
            if (break_point) {
                break;
            } else {
                tcp_data_str.push_back(*head_tcp_data);
            }
            head_tcp_data += 1;
        }
        tcp_udp_s << tcp_data_str;
    }

    std::string format_TCP_UDP_header(const pcap::IPv4_Header &IP_header, const pcap::Record &record, int &curr) {
        std::stringstream tcp_udp_s;

        switch (IP_header.protocol) {
            case 0x06: {
                //Printout/extraction of TCP info.
                pcap::TCP_Header& tcp = *(pcap::TCP_Header*) &record.frame[curr];
                if (std::endian::native != std::endian::big) {
                    tcp.src_port = pcap::bswap16(tcp.src_port);
                    tcp.dst_port = pcap::bswap16(tcp.dst_port);
                    tcp.sequence_num = pcap::bswap32(tcp.sequence_num);
                    tcp.ACK_num = pcap::bswap32(tcp.ACK_num);
                    //Don't swap data_offset_reserved.
                    //Don't swap flags.
                    tcp.window_size = pcap::bswap16(tcp.window_size);
                    tcp.chk_sum = pcap::bswap16(tcp.chk_sum);
                    tcp.urg_pointer = pcap::bswap16(tcp.urg_pointer);
                }

                tcp_udp_s << "tcp_src_port: " << tcp.src_port << ' ';
                tcp_udp_s << "tcp_dst_port: " << tcp.dst_port << ' ';
                tcp_udp_s << "data_offset: " << (uint16_t)((tcp.data_offset_reserved >> 4) & ((1 << 4) - 1)) << ' ';
                tcp_udp_s << "window_size: " << tcp.window_size << ' ';

                //If data offset > 5 read options field.
                uint8_t data_offset = ((tcp.data_offset_reserved >> 4) & ((1 << 4) - 1));

                //Get size of TCP data section.
                uint16_t IHL = IP_header.version_IHL & ((1 << 4) - 1);
                uint32_t TCP_data_size = IP_header.total_len - ((data_offset * 4) + (IHL * 4));
                tcp_udp_s << "TCP data (bytes): " << TCP_data_size;
                
                if (data_offset > 5) {
                    tcp_udp_s << "\nTCP Options Info: ";
                    uint8_t* head = (uint8_t*)&tcp + 20;
                    uint8_t* tail = head + ((data_offset - 5) * 4);

                    while (head < tail) {
                        switch (*head) {
                            case 0: { //End of options list.
                                head += 1;
                                break;
                            }
                            case 1: { //No operation.
                                tcp_udp_s << "NOP" << ' ';
                                head += 1;
                                break;
                            }
                            case 2: { //Maximum segment size.
                                if (head[1] == 4 && ((tcp.flags >> 1) & 1)) {
                                    tcp_udp_s << "MSS" << ' ';
                                    head += head[1];
                                    break;
                                } else {
                                    std::cout << "Failure on MSS." << '\n';
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 3: { //Window scale.
                                if (head[1] == 3 && ((tcp.flags >> 1) & 1)) {
                                    tcp_udp_s << "WS" << ' ';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 4: { //Selective Acknowledgement permitted.
                                if (head[1] == 2 && ((tcp.flags >> 1) & 1)) {
                                    tcp_udp_s << "SACK_permitted" << ' ';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 5: { //Selective ACKnowledgement (SACK).
                                const std::array<uint8_t, 4> good_values = {10, 18, 26, 34};
                                if (std::find(good_values.begin(), good_values.end(), head[1]) != good_values.end()) {
                                    std::exit(EXIT_FAILURE);
                                }
                                tcp_udp_s << "SACK" << ' ';
                                head += head[1];
                                break;
                            }
                            case 8: { //Timestamp and echo of previous timestamp.
                                if (head[1] == 10) {
                                    tcp_udp_s << "TS_Echo_Prior_TS" << ' ';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 28: { //User Timeout Option.
                                if (head[1] == 4) {
                                    tcp_udp_s << "UTO" << ' ';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 29: { //TCP Authentication Option (TCP-AO).
                                if (head[1] <= (tail - head)) {
                                    tcp_udp_s << "TCP-AO" << ' ';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 30: { //Multipath TCP (MPTCP).
                                if (head[1] <= (tail - head)) {
                                    tcp_udp_s << "MPTCP" << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
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

                //Increment curr.
                curr += data_offset * 4;

                //If TCP_data_size > 0 print/parse it.
                //Printout/parseout of TCP data section (assumes regular text).
                if (TCP_data_size > 0 && (tcp.src_port == pcap::ports::TEST_HTTP_PORT_NUM || tcp.dst_port == pcap::ports::TEST_HTTP_PORT_NUM)) {
                    tcp_udp_s << "\nTCP HTTP data:" << '\n';
                    pcap::format_HTTP_header(record, curr, tcp_udp_s, TCP_data_size);
                }

                tcp_udp_s << "\n******";

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

    void format_IPv4_IPv6_header(pcap::Eth_Header* eth_header, const pcap::Record &record, int &curr) {
        //Checking EtherType.
        switch (eth_header->eth_type) {
            case 0x0800: {
                std::cout << pcap::format_eth_header(*eth_header) << '\n';
                
                //Printout/extraction of IPv4 packet info.
                pcap::IPv4_Header& ip = *(pcap::IPv4_Header*) &record.frame[curr];

                if (std::endian::native != std::endian::big) {
                    ip.total_len = pcap::bswap16(ip.total_len);
                    ip.ID = pcap::bswap16(ip.ID);
                    ip.flag_frag_offset = pcap::bswap16(ip.flag_frag_offset);
                    ip.header_chksum = pcap::bswap16(ip.header_chksum);
                }
                std::cout << pcap::format_IPv4_header(ip) << '\n';

                //Extracting IHL value with bit masking.
                //If IHL > 5 read options field.
                uint16_t IHL = ip.version_IHL & ((1 << 4) - 1);
                if (IHL > 5) {
                    std::cout << "IPv4 Options Info:" << '\n';
                    uint8_t* head = (uint8_t*)&ip + 20;
                    uint8_t* tail = head + ((IHL - 5) * 4);

                    while (head < tail) {
                        switch (*head) {
                            case 0: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "End of options list." << '\n';
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 1: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "No operation." << '\n';
                                    head += 1;
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            /* case 2: {
                                std::cout << "Security (defunct)." << '\n';
                                break;
                            } */
                            case 7: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "Record Route." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 10: {
                                std::cout << "ZSU - Experimental Measurement." << '\n';
                                head += head[1];
                                break;
                            }
                            case 11: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "MTUP - MTU Probe." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 12: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "MTUR - MTU Reply." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 15: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "ENCODE." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 25: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "QS - Quick Start." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 30: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 0) {
                                    std::cout << "EXP - RFC3692-style Experiment." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 68: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 2 && (head[0] & 0b11111) == 4) {
                                    std::cout << "TS - Time Stamp." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 82: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 2 && (head[0] & 0b11111) == 18) {
                                    std::cout << "TR - Traceroute." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 94: {
                                if (((head[0] >> 7) & 1) == 0 && ((head[0] >> 5) & 0b11) == 2 && (head[0] & 0b11111) == 30) {
                                    std::cout << "EXP - RFC3692-style experiment." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 130: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 2) {
                                    std::cout << "SEC - Security (RIPSO)." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 131: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 3) {
                                    std::cout << "LSR - Loose Source Route." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 133: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 5) {
                                    std::cout << "E-SEC - Extended Security (RIPSO)." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 134: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 6) {
                                    std::cout << "CIPSO - Commercial IP Security Option." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 136: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 8) {
                                    std::cout << "SID - Stream ID." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 137: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 9) {
                                    std::cout << "SSR - Strict Source Route." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 142: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 14) {
                                    std::cout << "VISA - Experimental Access Control." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 144: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 16) {
                                    std::cout << "IMITD - IMI Traffic Descriptor." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 145: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 17) {
                                    std::cout << "EIP - Extended Internet Protocol." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 147: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 19) {
                                    std::cout << "ADDEXT - Address Extension." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 148: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 20) {
                                    std::cout << "RTRALT - Router Alert." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 149: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 21) {
                                    std::cout << "SDB - Selective Direct Broadcast." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 151: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 23) {
                                    std::cout << "DPS - Dynamic Packet State." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 152: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 24) {
                                    std::cout << "UMP - Upstream Multicast Packet." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 158: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 0 && (head[0] & 0b11111) == 30) {
                                    std::cout << "EXP - RFC3692-style Experiment." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 205: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 2 && (head[0] & 0b11111) == 13) {
                                    std::cout << "FINN - Experimental Flow Control." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            case 222: {
                                if (((head[0] >> 7) & 1) == 1 && ((head[0] >> 5) & 0b11) == 2 && (head[0] & 0b11111) == 30) {
                                    std::cout << "EXP - RFC3692-style Experiment." << '\n';
                                    head += head[1];
                                    break;
                                } else {
                                    std::exit(EXIT_FAILURE);
                                }
                            }
                            default: {
                                std::cout << "Option Type not recognized, exiting program." << '\n';
                                std::exit(EXIT_FAILURE);
                            }
                        }
                    }
                }

                curr += IHL * 4;

                //Checking protocol (TCP or UDP).
                std::cout << pcap::format_TCP_UDP_header(ip, record, curr) << '\n';
                
                break;
            }
            case 0x86DD: {
                std::cout << pcap::format_eth_header(*eth_header) << '\n';
                //Eventual printout/extraction of IP packet info.
                break;
            }
            default: {
                std::cout << "Default." << '\n';
                break;
            }
        }
    }
}