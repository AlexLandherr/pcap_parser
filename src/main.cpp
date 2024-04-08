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

/*
uint32_t magic_number;
uint16_t major_version;
uint16_t minor_version;
int32_t Reserved_1;
uint32_t Reserved_2;
uint32_t SnapLen;
uint16_t FCS_section;
uint16_t LinkType;
std::endian data_endianness;
int timestamp_res;
*/

void print_uint32_t_fixed_len(uint32_t num) {
    std::bitset<32> p(num);
    std::cout << p << '\n';
}

void print_uint8_t_fixed_len(uint8_t num) {
    std::bitset<8> p(num);
    std::cout << p << '\n';
}

void print_uint16_t_fixed_len(uint16_t num) {
    std::bitset<16> p(num);
    std::cout << p << '\n';
}

int main() {
    /* uint32_t r = 0;
    std::vector<std::byte> b_vec;
    b_vec.push_back(std::byte{0xd4}); //0b11010100, index 0
    b_vec.push_back(std::byte{0xc3}); //0b11000011, index 1
    b_vec.push_back(std::byte{0xb2}); //0b10110010, index 2
    b_vec.push_back(std::byte{0xa1}); //0b10100001, index 3
    //r = std::to_integer<uint8_t>(b_vec[3]) | std::to_integer<uint8_t>(b_vec[2]) << 8 | std::to_integer<uint8_t>(b_vec[1]) << 16 | std::to_integer<uint8_t>(b_vec[0]) << 24;
    r = std::to_integer<uint8_t>(b_vec[0]) << 24 | std::to_integer<uint8_t>(b_vec[1]) << 16 | std::to_integer<uint8_t>(b_vec[2]) << 8 | std::to_integer<uint8_t>(b_vec[3]);
    print_uint32_t_fixed_len(r);
    std::cout << "11010100110000111011001010100001" << '\n';
    std::cout << uint32_t_as_hex_str(r) << '\n'; */

    /* uint8_t x = 0b00000101;
    uint8_t y = 0b00000010;
    uint8_t z = y | x << 4;
    uint8_t z = x | y;
    print_uint8_t_fixed_len(z);
    uint8_t a = 0b00000001;
    uint8_t b = 0b00000010;
    uint8_t c = 0b00000011;
    uint8_t d = 0b00000100;
    uint32_t result = 0;
    std::cout << "result before modification:" << '\n';
    print_uint32_t_fixed_len(result);

    result = d | c << 8 | b << 16 | a << 24;

    std::cout << "result before modification:" << '\n';
    print_uint32_t_fixed_len(result); */
    
    std::string filename{"pcap_files/tcp_1.pcap"};
    auto header_vector = pcap::to_byte_vector(filename, 0, 24);
    pcap::Pcap_Header h = pcap::populate_header(header_vector);
    
    std::cout << "magic_num: " << pcap::uint32_t_as_hex_str(h.magic_number) << '\n';

    std::cout << "major_version: " << h.major_version << '\n';
    std::cout << "minor_version: " << h.minor_version << '\n';

    std::cout << "Reserved_1: " << h.Reserved_1 << '\n';
    std::cout << "Reserved_2: " << h.Reserved_2 << '\n';

    std::cout << "SnapLen: " << h.SnapLen << '\n';

    switch (h.data_endianness) {
        case std::endian::big:
            std::cout << "Data endianness: big-endian" << '\n';
            break;
        case std::endian::little:
            std::cout << "Data endianness: little-endian" << '\n';
            break;
        default:
            std::cout << "default." << '\n';
            break;
    }
    
    std::cout << "ts resolution (decimal places): " << h.timestamp_res << '\n';
    
    /* std::cout << "Byte vector size/length: " << header_vector.size() << '\n';
    std::cout << "Read bytes as hex string: " << pcap::byte_vec_to_hex_str(header_vector) << '\n'; */

    return 0;
}