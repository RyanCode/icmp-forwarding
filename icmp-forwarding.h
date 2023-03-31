/*
 * @Author: RyanWilson
 * @Date: 2022-12-26 11:26:32
 */
#ifndef ICMP_FORWARDING_H
#define ICMP_FORWARDING_H

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <stddef.h>

#define IP_LEN 16
#define IPS_LEN 10
/*
----------------------------------------------------------------
|版本(4)|首部(4)| 服务类型(8)  |           总长度(16)              |
|----------------------------------------------------------------
|          标识(16)          |标志(3)|        片偏移(13)          |
|----------------------------------------------------------------
|   生存时间(8) |   协议(8)   |             校验和(16)             |
|----------------------------------------------------------------
|                           源地址(32)                           |
|----------------------------------------------------------------
|                           目的地址(32)                         |
|----------------------------------------------------------------
|                           选项（如果有）(32)                    |
|----------------------------------------------------------------
|                           数据(32)                             |
|----------------------------------------------------------------
*/

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/*
0               1               2                               4
0 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 0 1 2 3 4
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             unused                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Internet Header + 64 bits of Original Data Datagram      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct icmp
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_cksum;
};

struct icmp_data
{
    int checksum;
    char *buffer;
    int b_len;
    char *dest;
    LIST_ENTRY(icmp_data) entries;
};
LIST_HEAD(listhead, icmp_data);

typedef struct icmp_data icmp_data;

#endif