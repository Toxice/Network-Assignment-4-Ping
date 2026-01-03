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

extern char* optarg;

#define PACKET_SIZE 64
/*
    struct of ICMP Packet
*/
typedef struct {
struct icmphdr *icmp_header;
char *message[PACKET_SIZE - sizeof(struct icmphdr)];
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
#define ICMP_ECHO_REQUEST 8 // ICMP Type FLAG
#define ICMP_ECHO_RESPONSE 0 // ICMP Type FLAG
#define IDENTIFIER 0 // ICMP Identifier 
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

/*

*/
void ping(struct sockaddr_in *address) {

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


