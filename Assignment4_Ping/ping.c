#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
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

#define _POSIX_C_SOURCE 200809L

extern char *optarg;

char *ip_address = NULL; // placeholder for the IP (-a)

int packet_sequence = 1; // packet sequence

int flood_flag = 0; // placeholder for the flood flag (-f)

int sock = -1; // global socket descriptor 

struct protoent *proto = NULL;

#define PACKET_SIZE 64
#define BUFFER_SIZE 1024
#define IP_STR_LENGTH 16 // total length of IP Address plus the '/0' character to make it a legit string
#define TIMEOUT 10000 // timeout of 10 seconds, counted as 10,000 miliseconds

#define ICMP_ECHO_CODE 0 // ICMP Echo Code
#define BUFFER_SIZE 1024 // size on bytes

#define MAX 1000000.0

double sum_rtt = 0;
double min_rtt = 0;
double max_rtt = 0;
double avg_rtt = 0;

double *p_avg = &avg_rtt;


typedef struct {
    int packets_received;
    double sum_rtt;
    double min_rtt;
    double max_rtt;
} ping_stats_t;

ping_stats_t *shared_stats = NULL; // Global pointer to shared memory


/*
    struct of ICMP Packet
*/
typedef struct {
struct icmphdr icmp_header;
char message[PACKET_SIZE - sizeof(struct icmphdr)];
} icmp_packet;


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

void set_min(double current_rtt) {
    if (current_rtt < (shared_stats->min_rtt)) {
        shared_stats->min_rtt = current_rtt;
    }
}

void set_max(double current_rtt) {
    if (current_rtt > shared_stats->max_rtt) {
        shared_stats->max_rtt = current_rtt;
    }
}

/**
 * @brief calculate the RTT of a packet
 */
double get_round_trip_time(struct timeval *start, struct timeval *end) {
    long seconds = end->tv_sec - start->tv_sec;
    long microseconds = end->tv_usec - start->tv_usec;

    if (microseconds < 0) {
        microseconds += 1000000;
        seconds -= 1;
    }

    return (seconds * 1000.0) + (microseconds / 1000.0);
}

/**
 * @brief displays the data received from the listener function
 * @par Algorithm:
 *  we know the IP header has a field named IHL (Internet Header Length) which indicates about the size of the header itself.
 *  according to the IP RFC, the IHL counts the number of 32 bit words (4 Byte Words), since the header has atleast 5 32 bits fields, the minimum
 *  value of IHL will be 5, since we dont have any options fields, this will always be 5.
 *  we know need to multiply the IHL value by 4, so we get the number of bits total in the header (4Byte = 32Bit) (5 * 4Byte = 5 * 32Bit = 160Bits Total)
 *  about the ntohs (network  to host short) function - it is used to convert a number from a Big to a Little Endian
 *  about the inet_ntop (interent network to presentation) function - it is used to convert the IP address from a binary format
 *  to a human readble format (string)
 */
void display(char *buffer, int bytes) {

    char src_addr[IP_STR_LENGTH];

    struct timeval time_recv, time_sent;
    memset(&time_recv, 0, sizeof(struct timeval));
    memset(&time_sent, 0, sizeof(struct timeval));

    double rtt_micro_seconds = 0.0;

    gettimeofday(&time_recv, NULL);

    // collecting the IP header
	struct iphdr *ip = (struct iphdr *)buffer;
	
    // collecting the ICMP header (were skipping the entire IP header)
	struct icmphdr *icmp = (struct icmphdr *)(buffer + ip->ihl * 4);

    // collecting the source IP Address for displaying on the terminal
    inet_ntop(AF_INET, &(ip->saddr), src_addr, IP_STR_LENGTH);

    struct timeval *p_time_payload = (struct timeval*)((char*)icmp + sizeof(icmp));

    memcpy(&time_sent, p_time_payload, sizeof(struct timeval));

    rtt_micro_seconds = get_round_trip_time(&time_sent, &time_recv);

    // making sure we only print to the terminal when the response packet is of type ECHO Reply (0)
    if (icmp->type == ICMP_ECHOREPLY) {
        shared_stats->packets_received++;
        shared_stats->sum_rtt += rtt_micro_seconds;
        set_max(rtt_micro_seconds);
        set_min(rtt_micro_seconds);

    // printing the PING output...
    printf("%d bytes from %s: icmp_sequence = %d ttl = %d time = %.3f ms \n", 
    ntohs(ip->tot_len),
    src_addr,
    ntohs(icmp->un.echo.sequence),
    ip->ttl,
    rtt_micro_seconds);
    } else {
        // do nothing - if we got a non ICMP ECHO REPLY we dont process it
    }
}

void listener(void) {
    struct sockaddr_in addr;
	unsigned char buffer[BUFFER_SIZE];

    struct pollfd pfd[1];

    pfd[0].fd = sock;
    pfd[0].events = POLLIN;

	if (sock < 0)
	{
		perror("socket");
		exit(0);
	}
    while(1)
	{	
        int ret = poll(pfd, 1, TIMEOUT);

        if (ret == -1) {
            perror("poll error");
            exit(1);
        } else if (ret == 0) {
            printf("timeout event: no packet was reached for 10 seconds, exisitng.\n");
            break;
        } 

        if (pfd[0].revents & POLLIN) {
            socklen_t len = sizeof(addr);
		    memset(buffer, 0, sizeof(buffer));

            int bytes;

            bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &len);

            if ( bytes > 0 ) {
                display((char*)buffer, bytes);
                } else {
                    perror("recvfrom failed");
                } 
        }
    }
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
    memset(p_packet->message, 0, sizeof(p_packet->message));

    p_packet->icmp_header.type = ICMP_ECHO; // Type of ECHO Request (8)
    p_packet->icmp_header.code = ICMP_ECHO_CODE; // Code of ECHO Request 90
    p_packet->icmp_header.un.echo.id = getpid(); // inherited from the process's ID
    p_packet->icmp_header.un.echo.sequence = htons(packet_sequence++); // set as 1 at the beggining, jump by one every iteration

    struct timeval packet_sent_time;
    gettimeofday(&packet_sent_time, NULL);

    memset(p_packet->message, 0, sizeof(struct timeval));
    memcpy(p_packet->message, &packet_sent_time, sizeof(struct timeval));

    p_packet->icmp_header.checksum = checksum(p_packet, sizeof(icmp_packet)); // calculating Checksum of the packet, must be calculated last (after we set all the packet's parameters)
}

void set_sockaddr_in(char *ip_addr, struct sockaddr_in *dest_address) {
    memset(dest_address, 0, sizeof(*dest_address));
    dest_address->sin_family = AF_INET;
    dest_address->sin_port = 0;

    if (inet_pton(AF_INET, ip_addr, &dest_address->sin_addr) <= 0) {
        perror("Invalid IP Address");
        exit(EXIT_FAILURE);
    }
}

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
    int ttl_config = 255;
    icmp_packet packet;

     struct timeval timeout;
    timeout.tv_sec = TIMEOUT; // 10 seconds  
    timeout.tv_usec = 0;

    int sock_options_ttl;
    int sock_options_timeout;

    if (sock < 0) {
        perror("socket");
        // might happen if not runned by the Admin, or by failure of memory allocation
    }

     // setting TTL configurations
    sock_options_ttl = setsockopt(sock, SOL_IP, IP_TTL, &ttl_config, sizeof(ttl_config));
    if (sock_options_ttl != 0) {
        perror("Set TTL option");
        return;
    }

    // setting up a timer of 10 sseconds
    sock_options_timeout = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (sock_options_timeout != 0) {
        perror("set timeout option");
        return;
    }

    // the actual ping loop
    for(int i = 0; i < number_of_pings; i++) {

        set_packet(&packet);

        if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)address, sizeof(*address)) <= 0) {
            perror("sendto");
        }
        if (flood_flag == 0) sleep(1);
    }

}

int pid = -1; // process ID
 // offical name of the protocol
/**
 * @details structure of CLI is: ./ping <options flags> <host ip>
 * were using the getopt() function to simlify the process
 * 
 */
int main(int argc, char *argv[]) {
    int opt;

    struct sockaddr_in dest_address;

    int loops = 1; // place holder for the number of times to ping the address (-c)

    while((opt = getopt(argc, argv, "a:c:f")) != -1) {
        switch (opt) {
            case 'a':
                ip_address = optarg;
                break;
            case 'c':
                loops = atoi(optarg);
                break;
            case 'f':
                flood_flag = 1;
                break;
            case '?':
                fprintf(stderr, "Usage: %s -a <address> -c <count> [-f]\n", argv[0]);            
                exit(EXIT_FAILURE);  
        }
    }

    if (ip_address == NULL) {
        fprintf(stderr, "Error: IP address required (-a)\n");
        exit(EXIT_FAILURE);
    }

    // setting up the proto struct as ICMP
    proto = getprotobyname("ICMP");
    if (!proto) {
    fprintf(stderr, "Error: Could not look up ICMP protocol\n");
    exit(EXIT_FAILURE);
}

    // setting up a raw socket, at the network level as IP socket that able to send ICMP packets
    sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if (sock < 0) {
        perror("socket");
    }

    // setting up the sockaddr_in struct to the IP we wish to send to
    set_sockaddr_in(ip_address, &dest_address);

    printf("Pinging %s with %d bytes of data:\n",ip_address, PACKET_SIZE);

    // counts the amount of received packets
    //packets_received = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    //*packets_received = 0;

    shared_stats = mmap(NULL, sizeof(ping_stats_t)
    , PROT_READ | PROT_WRITE,
     MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    // Initialize shared memory
    shared_stats->packets_received = 0;
    shared_stats->sum_rtt = 0;
    shared_stats->min_rtt = MAX;
    shared_stats->max_rtt = 0;

    // forking the kernel to get a child process
    pid_t process_id = fork();

    if (process_id < 0) {
        perror("fork failed");
        exit(1);
    }

    if (process_id == 0) {
        // calling the child process
        listener();
        exit(0);
    } else {
        // calling the parent process
        ping(&dest_address, loops);

        sleep(1); // let the listener a chance to catch the last packet
    }

    printf("\n--- %s statistics ---\n", ip_address);
    if (shared_stats->packets_received > 0 && flood_flag != 1) {
    printf("%d packets transmitted, %d packets received\n", loops, shared_stats->packets_received);
    printf("rtt min/avg/max = %f/%f/%f ms\n", shared_stats->min_rtt, ((shared_stats->sum_rtt)/(shared_stats->packets_received)), shared_stats->max_rtt);
    } else if (flood_flag == 1) {
        printf("%d packets transmitted, sent in flood mood, can't keep track of received packets\n", loops);
    }
     kill(process_id, SIGKILL);
     wait(NULL);

    return 0;
    }


