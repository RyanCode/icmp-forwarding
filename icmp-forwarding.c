/*
 * @Author: RyanWilson
 * @Date: 2022-12-21 16:53:15
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <pthread.h>

#include "icmp-forwarding.h"
#include "icmp.h"

char **ips = NULL;
struct listhead ECHO_LIST_HEAD;
struct listhead TSTAMP_LIST_HEAD;

char **get_local_ipv4()
{
    char **local_ips = (char **)malloc(sizeof(char *) * IPS_LEN);
    int sockfd;
    struct ifconf ifc;
    char buf[1024] = {'\0'};
    char ipbuf[IP_LEN];
    struct ifreq *ifr;
    ifc.ifc_len = 1024;
    ifc.ifc_buf = buf;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        return NULL;
    }

    ioctl(sockfd, SIOCGIFCONF, &ifc);
    ifr = (struct ifreq *)buf;

    int i = 0;
    for (i = 0; i < (ifc.ifc_len / sizeof(struct ifreq)); i++, ifr++)
    {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr, ipbuf, IP_LEN);
        local_ips[i] = (char *)malloc(IP_LEN);
        memcpy(local_ips[i], ipbuf, IP_LEN);
    }
    local_ips[i] = 0;

    return local_ips;
}

icmp_data *new_icmp_data(int b_len, int d_len)
{
    icmp_data *data = (icmp_data *)malloc(sizeof(icmp_data));
    data->buffer = (char *)malloc(b_len);
    data->dest = (char *)malloc(d_len);

    return data;
}

void delete_icmp_data(icmp_data *data)
{
    free(data->buffer);
    data->buffer = NULL;

    free(data->dest);
    data->dest = NULL;

    free(data);
}

int resolve(const char *hostname, int port, struct sockaddr_in *addr)
{
    int ret;
    struct hostent *he;

    bzero(addr, sizeof(struct sockaddr_in));

    ret = inet_aton(hostname, &addr->sin_addr);
    if (ret == 0)
    {
        he = gethostbyname(hostname);
        errno = h_errno;
        if (!he)
            return -1;
        addr->sin_addr = *(struct in_addr *)(he->h_addr);
    }

    addr->sin_family = AF_INET;
    addr->sin_port = htons((short)port);

    return 0;
}

void print_data(const unsigned char *data, int len, int cols)
{
    int i;
    for (i = 0; i < len; ++i)
    {
        if (i % cols == 0)
            printf("| %02x ", data[i]);
        else
            printf("%02x ", data[i]);
        if ((i + 1) % cols == 0)
            printf("|\n");
    }

    if (i == len && i % cols != 0)
    {
        while (1)
        {
            if (i % cols != 0)
                printf("-- ");
            else
            {
                printf("|\n");
                break;
            }
            ++i;
        }
    }
}

void print_icmp(struct icmp *icmp, int len)
{
    printf("------------ icmp header ------------\n");
    printf("type:             %d\n", icmp->icmp_type);
    printf("code:             %d\n", icmp->icmp_code);
    printf("checksum:         %04x\n", icmp->icmp_cksum);
}

int print_ip(const struct ip *ip, int len)
{
    int iphlen, flag, offset;
    unsigned char *data;

    iphlen = ip->ip_hl << 2;
    data = (unsigned char *)ip + iphlen;

    len -= iphlen;
    printf("------------ ip header ------------\n");
    printf("src ip:           %s\n", inet_ntoa(ip->ip_src));
    printf("dst ip:           %s\n", inet_ntoa(ip->ip_dst));
    return 0;
}

static uint16_t in_cksum(uint16_t *buf, int nwords)
{
    // #define BYTE_ORDER == LITTLE_ENDIAN
    uint32_t sum;
    int i = 0;

    for (sum = 0; i < nwords; i++)
    {
        uint16_t cu = buf[i];
        if (i == 1)
            cu = 0;
        // little endian to big endian
        cu = (cu >> 8) | (cu << 8);
        sum += cu;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    sum = ~sum;

    // exchange low 16bit with hight 16bit;example 37df->df37
    sum = sum << 8 & 0xffff | sum >> 8 & 0xff;

    return sum;
}

int send_to(char *dst, char *data, int length)
{
    struct sockaddr_in ai;
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sd < 0)
    {
        printf("socket fail:%d\n", sd);
        return -1;
    }
    resolve(dst, 0, &ai);
    int res = sendto(sd, data, length, 0, (struct sockaddr *)&ai, sizeof(ai));
    close(sd);

    if (res < 0)
    {
        printf("send data fail!");
        return -1;
    }
    return 0;
}

int up_division(int m)
{
    return m % 2 != 0 ? m / 2 + 1 : m / 2;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
#define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct ip *ip;                   /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const char *payload;                   /* Packet payload */

    u_int size_ip;
    u_int size_tcp;
    struct icmp *icmp;
    int iphlen, ip_packet_length = header->len - SIZE_ETHERNET;

    // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
    printf("------------recieve all packets-------------\n");
    print_data(packet, header->len, 30);

    /*ethernet packet SIZE_ETHERNET*/
    ethernet = (struct sniff_ethernet *)(packet);

    /*ip packet*/
    ip = (struct ip *)(packet + SIZE_ETHERNET);
    print_ip(ip, ip_packet_length);
    for (size_t i = 0; i < IPS_LEN; i++)
    {
        // Filter out the icmp data sent by the machine
        if (ips[i] && strcmp(ips[i], inet_ntoa(ip->ip_src)) == 0)
        {
            printf("this packet will be discarded\n\n");
            return;
        }
    }

    /*icmp packet*/
    iphlen = (ip->ip_hl) << 2;
    icmp = (struct icmp *)((char *)ip + iphlen);
    int icmplen = ip_packet_length - iphlen;
    print_icmp(icmp, icmplen);

    char buffer[icmplen];
    memcpy(buffer, (char *)icmp, icmplen);
    printf("------------icmp payloads-------------\n");
    // If it is an odd number, then the even number is taken upward to calculate the checksum.
    int ch_len = up_division(icmplen);
    print_data((unsigned char *)buffer, icmplen, 30);

    // test for check sum
    if (in_cksum((uint16_t *)buffer, ch_len) != icmp->icmp_cksum)
        printf("check sum warning:%04x\n", in_cksum((uint16_t *)buffer, ch_len));

    switch (icmp->icmp_type)
    {
    case ICMP_ECHOREPLY:
    {
        icmp_data *data = NULL;
        LIST_FOREACH(data, &ECHO_LIST_HEAD, entries)
        {
            if (data && data->buffer)
            {
                char *tmp = (char *)malloc(data->b_len + 1);
                memcpy(tmp, data->buffer, data->b_len);
                tmp[data->b_len] = '\0';
                tmp[0] = 0;

                int cksum = in_cksum((uint16_t *)tmp, up_division(data->b_len));

                /*only recieve a replay packet should we remove the request packet from this list.*/
                if (icmp->icmp_cksum == cksum)
                {
                    printf("match icmp check sum of:%04x,and will forward to:%s.\n", cksum, data->dest);
                    send_to(data->dest, buffer, icmplen);
                    LIST_REMOVE(data, entries);
                    delete_icmp_data(data);
                }
            }
        }
        break;
    }
    case ICMP_ECHO:
    {
        // create a new node
        icmp_data *node = new_icmp_data(icmplen, 16);

        node->checksum = icmp->icmp_cksum;
        node->b_len = icmplen;
        memcpy(node->buffer, (char *)icmp, node->b_len);
        strcpy(node->dest, inet_ntoa(ip->ip_src));

        LIST_INSERT_HEAD(&ECHO_LIST_HEAD, node, entries);
        send_to(inet_ntoa(ip->ip_dst), buffer, icmplen);
        break;
    }
    case ICMP_TIMXCEED:
    {
        printf("gateway will ignore this type packet:ICMP_TIMXCEED.\n");
        break;
    }
    case ICMP_UNREACH:
    {
        printf("gateway will ignore this type packet:ICMP_UNREACH.\n");
        break;
    }
    case ICMP_TSTAMP:
    {
        break;
    }
    case ICMP_TSTAMPREPLY:
    {
        break;
    }
    default:
        break;
    }
    printf("\n\n\n");
}

void *loop_recv(void *arg)
{
    pcap_t *handle = (pcap_t *)arg;
    pcap_loop(handle, -1, got_packet, NULL);
    return 0;
}

/*
 *---machineA---------------gateway-----------------machineB-----
 *------[src_a,dst_b]--------------------[src_g,dst_b]----------->
 *<-----[src_b,dst_a]--------------------[src_b,dst_g]------------
 */
int main(int argc, char **argv)
{
    struct sockaddr_in rcv;
    socklen_t len = sizeof(rcv);
    char buf[65535];
    struct ip *ip;
    int t_length, i;
    struct icmp *icmp;

    int list_size = 30;
    icmp_data **data_ping = (icmp_data **)malloc(sizeof(icmp_data) * list_size);

    LIST_INIT(&ECHO_LIST_HEAD);
    LIST_INIT(&TSTAMP_LIST_HEAD);

    ips = get_local_ipv4();
    for (i = 0; i < IPS_LEN; i++)
    {
        if (!ips[i])
        {
            t_length = i;
            break;
        }
        printf("this dst ip will not forwarded:%s\n", ips[i]);
    }

    // https://www.tcpdump.org/pcap.html
    pcap_t *handle;                                      /* Session handle */
    char dev[][10] = {"eth0", "eth1", "bridge0", "en0"}; /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];                       /* Error string */
    struct bpf_program fp;                               /* The compiled filter expression */
    char filter_exp[] = "icmp";                          /* The filter expression */
    bpf_u_int32 mask;                                    /* The netmask of our sniffing device */
    bpf_u_int32 net;                                     /* The IP of our sniffing device */
    struct pcap_pkthdr header;                           /* The header that pcap gives us */
    const u_char *packet;                                /* The actual packet */

    for (size_t i = 0; i < sizeof(dev) / (sizeof(char) * 10); i++)
    {
        char *c_dev = dev[i];
        if (pcap_lookupnet(c_dev, &net, &mask, errbuf) == -1)
        {
            fprintf(stderr, "Can't get netmask for device %s\n", c_dev);
            net = 0;
            mask = 0;
            continue;
        }

        handle = pcap_open_live(c_dev, BUFSIZ * 4, 1, 1000, errbuf);
        if (handle == NULL)
        {
            fprintf(stderr, "Couldn't open device %s: %s\n", c_dev, errbuf);
            return (2);
        }

        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }

        if (pcap_setfilter(handle, &fp) == -1)
        {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }

        pthread_t thread_id;
        u_char buffer[BUFSIZ * 4];

        // pcap_next_ex();
        if (pthread_create(&thread_id, NULL, loop_recv, handle))
            printf("thread create error!\n");
    }
    pause();
}
