#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>


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

#define PAKCET_SIZE 64 // packet size in bytes
#define TIMEOUT_SEC 10 // timeout as specifed in the assignment PDF

// creating the packet's struct
struct ping_packet {
    struct icmphdr icmp_header;
    char payload[PAKCET_SIZE - sizeof(struct icmphdr)];
};


int main(int argc, char *argv[]) {
    // here the ping will be executed...
    return 0;
}

