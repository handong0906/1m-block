#ifndef IPHEADER_H
#define IPHEADER_H

#include <stdint.h>

#pragma pack(push, 1)
struct ipheader
{
    uint8_t version_ihl;
    uint8_t DSCP_ECN;
    uint16_t Total_Length;
    uint16_t Identification;
    uint16_t Flags_Offset;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t Checksum;
    uint32_t SrcIP;
    uint32_t DstIP;

    uint8_t headerLen() const {
        return (version_ihl & 0x0F) * 4;
    }
};
#pragma pack(pop)

#endif 
