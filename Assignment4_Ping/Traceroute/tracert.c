#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>
#include "tracert.h"

extern char *optarg;

char *ip_address = NULL;

struct sockaddr_in dest_address;

typedef struct {
    int is_dest;
    struct timeval time_sent;
} dest_flag;

dest_flag *dest_instance; // a global, shared memory flag struct that is used to signal that the destination address has sent us an ECHO packet, meaning were done

// variables of socket identifier and socket options
 int sock_send;
 int sock_recv;
 int sock_opt_send;

 int counter = 1;

 /**
  * @brief: checksum function for the ICMP header
  */
unsigned short checksum(void *b, int len) {
    uint16_t *buffer = b;
	unsigned int sum = 0;
	unsigned short result;

	for ( sum = 0; len > 1; len = len - 2) {
		sum = sum + (*buffer);
        buffer++;
    }

	if (len == 1) {
        sum += *(uint8_t*)buffer;
    }

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

/**
 * @brief: validate if we got a time exceeded message with TTL code, or a echo response message
 */
int handle_packet(struct iphdr *ip_header) {
    struct icmphdr *icmp_header = (struct icmphdr*)((char*)ip_header + ip_header->ihl * 4);

    if (icmp_header->type == TIMEXCEED_TYPE && icmp_header->code == TIMEXCEED_CODE) {
        return TIMEXCEED_REACHED; // 0 (FALSE)

    } else if (icmp_header->type == ECHOREPLY_TYPE && icmp_header->code == ECHOREPLY_CODE) {
        return DEST_REACHED; // 1 (TRUE)
    }
}

void display(char *buffer, int bytes, int *p_timeout_flag) {
    char src_addr[IP_STR_LENGTH];

    struct timeval recv_time;
    struct timeval sent_time;

    memset(&recv_time, 0, sizeof(struct timeval));
    memset(&sent_time, 0, sizeof(struct timeval));

    // get the time where the packet was sent
    memcpy(&sent_time, &(dest_instance->time_sent), sizeof(struct timeval));

    struct iphdr *ip_header = (struct iphdr*)buffer;

    inet_ntop(AF_INET, &(ip_header->saddr), src_addr, IP_STR_LENGTH);

    // if we got an ECHO REPLY
    if (handle_packet(ip_header)) {

        // validate we got the same IP address as the desired destination
        if (strcmp(src_addr, ip_address) == 0) {
            dest_instance->is_dest = DEST_REACHED;
        }  
    }

    if (bytes < ip_header->ihl * 4 + (int)sizeof(struct icmphdr))
        return;
        /*
        the ip header might contain options field, in that case the header will be bigger,
        if the amout of bytes recevied is less then the minimum (the ip header length and the icmp header length)
        the packet is malformed, and there's no need to process it
        */

    int ip_header_length = ip_header->ihl * 4;
            
    struct icmphdr *icmp_header = (struct icmphdr*)(buffer + ip_header->ihl * 4);

    if (bytes - ip_header_length < 8) return;
        /*
        the minimum size of an ICMP header is 8 bytes (by RFC 792)
        if we got less than 8 bytes it means the icmp header is malformed, and there's no point in processing it
        */

    int icmp_header_length = bytes - ip_header_length;

    // validating icmp checksum 
    if (checksum(icmp_header, icmp_header_length) != 0) {
        perror("checksum not valid");
        return;
    }

    // if we got here it means the ICMP checksum is valid, and we can continue to process the packet

    // get the current time, the time when we received the packet
    gettimeofday(&recv_time, NULL);

    // Calculate RTT in milliseconds
    double rtt = (recv_time.tv_sec - sent_time.tv_sec) * 1000.0 + (recv_time.tv_usec - sent_time.tv_usec) / 1000.0;

    if (!(*p_timeout_flag)) {
        printf("%d %s ", ip_header->id, src_addr);
    } else  if ((*p_timeout_flag)) {
        printf("%d ", ip_header->id);
    }

    if ((*p_timeout_flag)) {
        printf(" *\n");
    } else {
        printf(" % .3f ms\n", rtt);
    }
}

/**
 * @brief listening to received packets and processing them to strip the IP header and determine the ICMP response
 * @details:
 * if we got a "time exceeded message" (type = 11, code = 0) we keep the source ip 
 * if we got a "echo response message" (type = 0, code = 0) we keep the source ip and break our ping loop
 * we define a timeval so we can caluclate the RTT of the packet
 * @attention: we don't need to calculate the ip checksum, the kernel calculate it itself, but we do need to calculate the icmp header checksum
 */
void listener() {
    int timeout_flag = 0;

    struct sockaddr_in addr;
	unsigned char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(dest_address);

    traceret_packet *recv_packet;

    struct pollfd fds[1];
    fds[0].fd = sock_recv;
    fds[0].events = POLLIN; // Wait for incoming data

    while(dest_instance->is_dest == 0) {
        int poll_result = poll(fds, 1, TIMEOUT);

        if (poll_result == 0) {
            timeout_flag = 1;
            continue;
        }

        // if we reached here, it means a response were sent before the timeout

        memset(buffer, 0, sizeof(buffer));

        int bytes = recvfrom(sock_recv, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_len);

        if (bytes < 0) {
            perror("recvfrom error");
            continue;
        }

        if (bytes < (ssize_t)sizeof(struct iphdr))
            continue; // if we got less than the size of a ip header, we got nothing to proceess, so jump back to the start of the loop

       display(buffer, bytes, timeout_flag);

       timeout_flag = 0;

        // struct iphdr *ip_header = (struct iphdr*)buffer;

        // if (bytes < ip_header->ihl * 4 + (int)sizeof(struct icmphdr))
        //     continue;
        //     /*
        //     the ip header might contain options field, in that case the header will be bigger,
        //     if the amout of bytes recevied is less then the minimum (the ip header length and the icmp header length)
        //     the packet is malformed, and there's no need to process it
        //     */

        // int ip_header_length = ip_header->ihl * 4;
        
        // struct icmphdr *icmp_header = (struct icmphdr*)(buffer + ip_header_length);

        // if (bytes - ip_header_length < 8) {
        //     continue;
        // }
        //     /*
        //     the minimum size of an ICMP header is 8 bytes (by RFC 792)
        //     if we got less than 8 bytes it means the icmp header is malformed, and there's no point in processing it
        //     */

        // int icmp_header_length = bytes - ip_header_length;

        // // validating icmp checksum 
        // if (checksum(&icmp_header, icmp_header_length) != 0) {
        //     perror("checksum not valid");
        //     continue;
        // }

        // // if we got here it means the ICMP checksum is valid, and we can continue to process the packet

        // struct timeval *sent_time = (struct timeval*)(buffer + ip_header_length + icmp_header_length);

        // // Calculate RTT in milliseconds
        // double rtt = (recv_time->tv_sec - sent_time->tv_sec) * 1000.0 + (recv_time->tv_usec - sent_time->tv_usec) / 1000.0;

        // printf(" %.3f ms\n", rtt);
    }
}


/**
 * @brief setting up the sockaddr_in with the ip address we want
 */
void set_sockaddr_in(char *ip_addr, struct sockaddr_in *dest_address) {
    memset(dest_address, 0, sizeof(*dest_address));
    dest_address->sin_family = AF_INET;
    dest_address->sin_port = 0; // no need of porting i a raw IP header
    if (inet_pton(AF_INET, ip_addr, &dest_address->sin_addr) <= 0) {
        perror("invalid IP Address");
        exit(EXIT_FAILURE);    
    }
}

/**
 * @brief setting the traceroute packet by the desired ttl
 */
void set_packet(traceret_packet *packet, int ttl) {
    // initializing the packet to zero
    memset(packet, 0, sizeof(traceret_packet));

    // setting the ip address
    int ip_flag = inet_pton(AF_INET, ip_address, &(packet->ip_header.daddr));
    if (ip_flag <= 0) {
        perror("Invalid IP Address");
        exit(EXIT_FAILURE);
    }

    // setting the ip header
    packet->ip_header.version = 4;
    packet->ip_header.tos = 0;
    packet->ip_header.protocol = IP_PROTOCOL_ICMP;
    packet->ip_header.id = htons(ttl); // incrementing by one every iteration
    packet->ip_header.ttl = ttl;
    packet->ip_header.frag_off = htons(0); // allow to framgnet if needed
    packet->ip_header.saddr = 0;
    packet->ip_header.ihl = 5; // Header Length is counted as 32bit binary "words" (4Byte words), the header is made of 5 32bit words

    // setting the icmp payload
    memset(&(packet->icmp_payload), 0, sizeof(struct icmphdr));
    packet->icmp_payload.type = ICMP_ECHO_TYPE;
    packet->icmp_payload.code = ICMP_ECHO_CODE;
    packet->icmp_payload.un.echo.id = getpid();
    packet->icmp_payload.un.echo.sequence = htons(ttl);

    // setting the checksum
    packet->icmp_payload.checksum = 0;
    packet->icmp_payload.checksum = checksum(&(packet->icmp_payload), sizeof(struct icmphdr));

    // setting the total length of the header and the checksum
    packet->ip_header.tot_len = sizeof(traceret_packet);
    packet->ip_header.check = 0; // letting the kernel set the checksum
}

/**
 * @brief sending a packet 3 times, as mentioned in the assignment
 * @param address: socketaddr_in struct, represent the ip address
 * @param ttl: the TTL were setting to the IP header
 * @details: right before we send the packet, we set the timeval value inside to the current time of the day, so we can later calculate RTT
 */
void send_packet(struct sockaddr_in address, int ttl) {
    traceret_packet packet;

    set_packet(&packet, ttl);
    
    // sending each packet 3 times
    for (int i = 0; i < 3; i++) {

        if (sendto(sock_send, &packet, sizeof(packet), 0, (struct sockaddr*)(&address), sizeof(address)) <= 0) {
                perror("sendto");
            }
            sleep(1);
        }
}

/**
 * @details here were sending the packets, theres a loop that allow us to hop up to 30 routers
 */
void trace_route_to(struct sockaddr_in dst_addr) {

    /*
    while the counter is still 30 or less (we havent reached the maximum hops yet)
    or the destination flag is raised to one - signaling we reached the destination
    */
    while (counter <= MAX_HOP && dest_instance->is_dest == 0) {
        gettimeofday(&(dest_instance->time_sent), NULL); // set timestamp of the dest_instance
        send_packet(dst_addr, counter); // sending 3 packets per router
        ++counter;
    }
}

/**
 * @details: the main function, creates and handles the two processes create by fork(),
 * one for the trace_route_to() and one for listener()
 * we need to use two sockets, one for sending and one for receiving
 */

int main(int argc, char *argv[]) {
    int opt;

    int hop_counter = 1;

     while((opt = getopt(argc, argv, "a:")) != -1) {
        switch (opt) {
            case 'a':
                ip_address = optarg;
                break;
            case '?':
                fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);            
                exit(EXIT_FAILURE);  
        }
    }

    set_sockaddr_in(ip_address, &dest_address);

    dest_instance = mmap(NULL, sizeof(dest_flag)
    , PROT_READ | PROT_WRITE,
     MAP_SHARED | MAP_ANONYMOUS, -1, 0);

     if (dest_instance == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
     }

     // when we just starting, surely we havent got to the dest yet
     dest_instance->is_dest = 0;


    // raw socket, designed to send raw IP pacekts
    sock_send = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock_send < 0) {
        perror("socket send");
        exit(1);
    }

    // raw socket, design to send (and receive raw ICMP packets)
    sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_recv < 0) {
        perror("socket recv");
        return;
    }

    // used for telling the kernel to set the IPHDRINCL flag on
    const int on = 1;

    // telling the kernel through the socket to not create its own IP header, but let us create our own
    sock_opt_send = setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    if (sock_opt_send < 0) {
        perror("socket options");
        exit(1);
    }

    // forking the kernel to get a child process
    pid_t process_id = fork();

    printf("traceroute to %s, %d hops max\n", ip_address, MAX_HOP);

    // calling the child process
    if (process_id == 0) {
        listener();
        exit(1);
    // calling the parent process
    } else {
        trace_route_to(dest_address);
        wait(NULL);
    }

    return 0;
}