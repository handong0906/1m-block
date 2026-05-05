#ifndef TCPHEADER_H
#define TCPHEADER_H

#include <stdint.h>

#pragma pack(push, 1)
struct tcpheader
{
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgpointer;

    uint8_t headerLen() const {
        return ((offset_reserved & 0xF0) >> 4) * 4;
    }
};
#pragma pack(pop)

#endif // TCPHEADER_H
