#ifndef TRACERT_H
#define TRACERT_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

typedef struct _tracert_packet {
    struct iphdr ip_header;
    struct icmphdr icmp_payload;
} __attribute__((packed)) traceret_packet;

// max hop parameter
#define MAX_HOP 30

// value of ip protocol field of ICMP
#define IP_PROTOCOL_ICMP 1

// ICMP ECHo type & code
#define ECHOREPLY_TYPE 0
#define ECHOREPLY_CODE 0

#define ICMP_ECHO_TYPE 8
#define ICMP_ECHO_CODE 0

// ICMP time exceed message type & code
#define TIMEXCEED_TYPE 11
#define TIMEXCEED_CODE 0

#define BUFFER_SIZE 1024

#define TIMEOUT 1000

#define IP_STR_LENGTH 16 // total length of IP address (3 digits per point, plus 3 points plus the '/0' sign)

#define DEST_REACHED 1
#define TIMEXCEED_REACHED 0

/**
 * @brief setting up the sockaddr_in
 */
void set_sockaddr_in(char *ip_addr, struct sockaddr_in *dest_address);

/**
 * @brief setting the traceroute packet by the desired ttl
 */
void set_packet(traceret_packet *packet, int ttl);

#endif