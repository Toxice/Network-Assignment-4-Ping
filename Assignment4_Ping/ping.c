#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

extern char* optarg;

int packet_sequence = 1; // packet sequence

#define PACKET_SIZE 64
/*
    struct of ICMP Packet
*/
typedef struct {
struct icmphdr icmp_header;
char message[PACKET_SIZE - sizeof(struct icmphdr)];
} icmp_packet;

char payload[PACKET_SIZE - sizeof(struct icmphdr)] = "ABCDEFGHIJKLMNOP";

/**
 * @brief this is a PING program, similar to the ping we know and love,
 * the only difference is this Ping allows to use 3 flags that did not exist in the origianl:
 * ping -a <ip_addr> : recives the ip address
 * ping -a -c <ip_addr> : pings the ip address up to c times
 * ping -a -c -f <ip_addr> : 
 * 
 * use case example:
 * ============================================================
 *  ./ping -c 4 -a 8.8.8.8                                    =
 *   Pinging 8.8.8.8 with 64 bytes of data:                   =
    64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=5.980ms    =  
    64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=6.830ms    =
    64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=6.970ms    =  
    64 bytes from 8.8.8.8: icmp_seq=4 ttl=117 time=8.450ms    = 
===============================================================
 */

#define TIMEOUT_SEC 10000 // timeout of maximum 10 seconds (counted as 10,000 miliseconds)
#define ICMP_ECHO_CODE 0 // ICMP Echo Code
#define BUFFER_SIZE 1024 // size on bytes

/**
 * @brief sums up all of the packet data and summing back any leftover bits and NOTing the value in the end
 * @details this function is made to create the Checksum value for the ICMP protocol
 * it works by casting the buffer (whos a ICMP Packet) to a uint16_t (Unsigned 2 Bytes Integer) and summing up every 2 Bytes
 * since the summation might (and probably will) result in a value larger than 16 bits (2 Bytes) we need the placeholder for the sum to
 * be larger than 2 Bytes, therfore we use unsigned int for the sum and not a uint16_t
 * @par Algorithm
 * we first use a uint16_t pointer for the buffer, since we want to deal with 2 Bytes at a time we use a pointer for uint16_t (its like using an 
 * array of 64 Bytes, but getting only 2 Bytes at a time)
 * since were dealing with 2 Bytes of data at a time, we subtract 2 from the length of the packet in the for loop.
 * in each iteration we sum up the 2 bytes from the packet to the sum (initialized to zero at the beggining)
 * and moving the buffer pointer one address at a time
 * 
 * finally, we could encounter a situation where the length be an odd number, so the for loop won't be enough to sum up all the data,
 * we need to check in the end if the length is 1, and to sum that last byte to the sum,
 * since there is only one Byte left, we need to cast the rest of the buffer to a Byte representation, so we use uint8_t (just as easy we could use
 * unsigned char)
 * 
 * finally, if the sum has more than 16 Bytes, we need to cut first 2 Bytes (since sum is unsigned short its made of 4 Bytes, hence we need to add
 *  the first 2 Bytes to the sum) and add them to the rest of the sum.
 * to achieve this we shift right the sum, to get only the first 16 bits and adding that the sum while ANDing it with 0xFFFF
 * (sum bits) xxxxxxxx_xxxxxxxx_xxxxxxxx_xxxxxxxx
 *                                                  AND
 * (0xFFFF)   00000000_00000000_11111111_11111111
 * 
 * by doing that we ensure to add the first 2 Bytes only once.
 * 
 * finally - we return the NOT value of sum (in the result variable)
 * since we want the checksum to be 2 Bytes, the return value is an unsigned short, we also could use uint16_t
 * 
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

/*
    Display to the terminal
*/
void display(void *buffer, int bytes) {

}

/**
 * @brief sets the packet to the desired values (sets the packet as an ECHO Request Packet)
 * 
 * @param *p_packet - Pointer to an ICMP Packet
 * 
 * @par Setup:
 *  sets the ICMP Packet with the proper values an an ECHO REQUEST
 *  sets the checksum
 *  sets the type as ECHO REQUEST (8) -> (00001000)
 *  sets the code as ECHO CODE (0)
 *  sets the ID as the process id
 *  the sequence global variable sequence as 1, sets the packet and then accumalate it by one every time
 */
void set_packet(icmp_packet *p_packet) {
    memset(p_packet, 0, sizeof(icmp_packet));
    memcpy(p_packet->message, payload, sizeof(p_packet->message));
    p_packet->icmp_header.checksum = checksum(p_packet, sizeof(p_packet));
    p_packet->icmp_header.type = ICMP_ECHO;
    p_packet->icmp_header.code = ICMP_ECHO_CODE;
    p_packet->icmp_header.un.echo.id = getpid();
    p_packet->icmp_header.un.echo.sequence = packet_sequence++;
}

/*
p_packet.icmp_header->checksum = checksum(p_packet->message, strlen(p_packet->message));
    p_packet->icmp_header->type = ICMP_ECHO_TYPE_REQUEST;
    p_packet->icmp_header->code = ICMP_CODE;
    p_packet->icmp_header->un.echo.id = htons(getpid());
    p_packet->icmp_header->un.echo.sequence = packet_sequence++;
*/

/**
 * @brief sending ICMP Packet to the address we want
 * @par Alggorithm
 * first - we set the ICMP Packet to Zero, to ensure theres not garbage values inside
 * we set up the socket as a raw socket ready to receive ICMP Packets
 * now we need to set configurations for the socket.
 * we need it to use the socket identifier we used before and we need it to be at the Network Layer, hence SOL_IP (Socket Layer IP)
 * so we use the flags SOL_IP (Socket Layer IP), IP_TTL (IP Time To Live) and set the TTL value with the variable ttl_config.
 * since Linux sets a prefixed value when Pinging, we want to set our own TTL, so we can know how many hoppers (routers) 
 * were used to reach the destination
 * since the Linux Kernel has control on scheduling the Ping Process (as well as all other processes (programs)) running, he will let it run once
 * and then immediately halt it until a packet arrives.
 * since we can't wait forever for a packet to arrive we can't allow that.
 * we set the process to be of non blocking nature, and set up a timer of 10 seconds for a packet to arrive.
 * in the ping loop - were checking for a receivied packet before sending a packet, when creating the socket a packet might arrive to the
 * socket before we even send one, it could be a packet who was waiting before to be sent, so we need to check for a ghost packet like that and drop it
 */
void ping(struct sockaddr_in *address, int number_of_pings) {
    int ttl_config = 256;
    icmp_packet packet;

    struct sockaddr_in r_addr;

    int sock;

    sock = socket(PF_INET, SOCK_RAW, proto->p_proto); // setting up the socket as a raw socket for ICMP (PF_INET is basically the same as AF_INET)
    if (sock < 0) {
        perror("socket");
        // might happen if not runned by the Admin, or by failure of memory allocation
    }

    int sock_options = setsockopt(sock, SOL_IP, IP_TTL, &ttl_config, sizeof(ttl_config));
    if (sock_options != 0) {
        perror("Set TTL option");
        return;
    }

    int socket_non_blocking_flag = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (socket_non_blocking_flag != 0) {
        perror("Request Non Blocking I/O");
    }

    for(int i = 0; i < number_of_pings; i++) {
        int len = sizeof(r_addr);
		printf("Msg #%d\n",packet_sequence);
		if (recvfrom(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&r_addr, &len) > 0) {
            printf("***Got message!***\n");
        }

        set_packet(&packet);
        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)address, sizeof(*address)) <= 0) {
            perror("sendto");
        }
        sleep(1);
    }

}

int pid = -1; // process ID

struct protoent *proto = NULL; // offical name of the protocol
/**
 * @details structure of CLI is: ./ping <options flags> <host ip>
 * were using the getopt() function to simlify the process
 * 
 */
int main(int argc, char *argv[]) {
    int opt;

    struct sockaddr_in address;

    char *ip_addr = NULL; // placeholder for the IP (-a)
    int loops = 0; // place holder for the number of times to ping the address (-c)
    int is_flood = 0; // placeholder for the flood flag (-f)

    while( (opt = getopt(argc, argv, "a:c:f")) != -1) {
        switch (opt) {
            case 'a':
                ip_addr = optarg;
                break;
            case 'c':
                loops = atoi(optarg);
                break;
            case 'f':
                is_flood = 1;
                break;
            case '?':
                fprintf(stderr, "Usage: %s -a <address> -c <count> [-f]\n", argv[0]);            
                exit(EXIT_FAILURE);
            default:
                abort();    
        }
    }

    proto = getprotobyname("ICMP");
    
    fprintf(stdout, "hello"); // what to show
    return 0;
    }


