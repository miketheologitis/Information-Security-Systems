#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include <net/ethernet.h>
#include <netinet/in.h>

/* For port information (to find service on application layer) */
#include <netdb.h>


/* standard: dest/source MAC addresses (6-bytes each) + type (2-bytes)
             without the 4-byte FCS (which is not in the capture)
*/
#define ETHERNET_HEADER_LEN 14 

/* UDP headers are fixed to 8 bytes in size */
#define UDP_HEADER_LEN 8

/* Ethernet header */
struct ethernet_h {
        u_char  dest_mac[ETHER_ADDR_LEN];  /* destination MAC address */
        u_char  src_mac[ETHER_ADDR_LEN];   /* source MAC address */
        u_short type;                      /* IP - ARP - RARP - etc */
};

/* IP header (See -> https://en.wikipedia.org/wiki/IPv4#Header) */

struct ip_h {
    u_char  version_ihl;     /* 1-byte: Version (4-bit) - IHL (4-bit) */
    u_char  dscp_ecn;        /* 1-byte: DSCP (6-bit) - ECN (2-bit) */
    u_short total_length;    /* total length */
    u_short identification;  /* identification */
    u_short fragment_offset; /* 2-bytes: flags (3-bit), fragment_offset (13-bit) */
    u_char  time_to_live;    /* time to live */
    u_char  protocol;        /* protocol */
    u_short checksum;        /* checksum */
    struct in_addr src_ip;   /* source IP address */
    struct in_addr dst_ip;   /* dest IP address */
};

/* TCP header (See -> https://en.wikipedia.org/wiki/Transmission_Control_Protocol) */

struct tcp_h {
    u_short src_port;    /* source port */
    u_short dst_port;    /* destination port */
    u_int seq_number;    /* sequence number */
    u_int ackn_number;   /* acknowledgement number */
    u_char  flags_1;     /* 1-byte: data offset (4-bit), reserved (3-bit), NS (1-bit) */
    u_char  flags_2;     /* 1-byte: 1-bit each of CWR, ECE, URG, ACK, PSH, RST, SYN, FIN */
    u_short window_size; /* window size */
    u_short checksum;    /* checksum */
    u_short urgent_p;    /* urgent pointer */
};

/* UDP header (See -> https://en.wikipedia.org/wiki/User_Datagram_Protocol) */

struct udp_h {
    u_short src_port;    /* source port */
    u_short dst_port;    /* destination port */
    u_short length;      /* length */
    u_short checksum;    /* checksum */
};

/* 
 My definition of this is that one TCP connection
 consists of 2 tcp_streams. One from SERVER1 -> SERVER2, and one for SERVER2->SERVER1.
 So each tcp_stream is responsible for one end of the connection keeping track of its'
 next expected sequence number. 

 It is used for finding retransmitted packets and additional info.
 2 tcp_stream are created (if not already) when SYN flag is present
 and the 3-way handshake is done, and deleted when RST, FIN flags are set.
 More info on the update_tcp_streams function

 (Not to be confused with the struct network_flow bellow)
 */
struct tcp_stream {
    in_addr_t src_ip;         /* source IP address */
    in_addr_t dst_ip;         /* dest IP address */
    u_short src_port;         /* source port */
    u_short dst_port;         /* destination port */ 
    u_char  protocol;         /* protocol */   

    /* 
     next expected sequence number. Generally, it is the seq_number + payload_len
     unless ACK-SYN, ACK-RST, ACK-FIN flags are set (with payload_len = 0) where
     its +1. Many comments bellow, on the update_tcp_stream function about this
    */
    u_int next_expected_seq_number;    

    /* flag, If dst sent the first FIN, then this is set to 1, in any other case its 0 */
    u_int FIN_responder;

    /* flag for FIN sequence in the case of the initializer that has to send the last ACK 
       if 1 tcp_stream gets deleted on the next ACK, 0 in any other case (nothing happens) */
    u_int delete_after_next_ACK;

    struct tcp_stream *next; /* next linked tcp stream */
};

/* 
 linked list of network flows 

 By the assignment's definition a connection
 consists of 2 network flows (SRC->DST, DST->SRC)

*/
struct network_flow {
    in_addr_t src_ip;         /* source IP address */
    in_addr_t dst_ip;         /* dest IP address */
    u_short src_port;         /* source port */
    u_short dst_port;         /* destination port */ 
    u_char  protocol;         /* protocol */   

    struct network_flow *next;
};


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_packet_info(struct in_addr src_ip, struct in_addr dst_ip, int src_port, int dst_port,
                       char* description, int tcpudp_header_len, int payload_len, char* more_info);

char* tcp_port_use(int port1, int port2);

void tcp_udp_port_description(int port1, int port2, char proto[4], char** description);

void update_tcp_streams(struct in_addr src_ip, struct in_addr dst_ip, 
                        u_short src_port, u_short dst_port, u_char  protocol,
                        u_int seq_number, u_int payload_len, u_char flags_2, char **more_info);

struct tcp_stream* find_tcp_stream(struct in_addr src_ip, struct in_addr dst_ip, 
                                   u_short src_port, u_short dst_port, u_char protocol);

void delete_tcp_stream(struct tcp_stream* stream);

int tcp_streams_equal(struct tcp_stream* tmp1, struct tcp_stream* tmp2);

void update_network_flows(struct in_addr src_ip, struct in_addr dst_ip, 
                          u_short src_port, u_short dst_port, u_char  protocol);

void free_tcp_streams();

void free_network_flows();

void usage();

void analysis(char *input_file);




FILE* file;

int tcp_count = 0; //all processed tcp packets
int udp_count = 0; //all processed udp packets
int packets_proc_count = 0; //all processed packets

int total_tcp_bytes = 0; //total tcp bytes
int total_udp_bytes = 0; //total udp bytes

int total_network_flows = 0;
int total_tcp_network_flows = 0;
int total_udp_network_flows = 0;

int total_retrasmitted_packets = 0;

/* 
 skipped tcp segment packets are packets where the given sequence number is bigger
 than the expected one 
*/
int total_skipped_segments = 0; 

/* Head of the tcp_stream linked list */
struct tcp_stream *tcp_head = NULL;

/* Head of the network_flow linked list */
struct network_flow *flow_head = NULL;




int main (int argc, char **argv) 
{
    int opt;
    
    if(argc != 2 && argc != 3) usage();

    /*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "r:h")) != -1) {
		switch (opt) {
		case 'r':
			analysis(strdup(optarg));
			break;
        case 'h':
			usage();
			break;
		default:
			usage();
		}
	}

    exit(EXIT_SUCCESS);
}

/*
 * Prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    monitor -r input_file \n" 
	    "    monitor -h\n" 
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -r    input_file    Packet analysis on .pcap file 'input_file'.\n"
        "                     Decodes and prints basic information about\n"
        "                     each TCP or UDP packet. At the end some \n"
        "                     Statistics about the capture are also printed.\n"
        "                     An 'analysis.txt' file will be created storing\n"
        "                     all this information.\n\n"
	    " -h                  Prints this help message\n"
	);
	exit(EXIT_FAILURE);
}


void analysis(char *input_file){
    pcap_t *fp;

    /* error buffer is assumed to be able 
     * to hold at least PCAP_ERRBUF_SIZE chars */
    char errbuf[PCAP_ERRBUF_SIZE];

    //fp = pcap_open_offline("test_pcap_5mins.pcap", errbuf);
    fp = pcap_open_offline(input_file, errbuf);

    file = fopen("analysis.txt", "w");

    if (fp == NULL) { //something went wrong
	    fprintf(stderr, "%s\n", errbuf);
        fclose(file);
	    exit(EXIT_FAILURE);
    }

    /* collect and process packets using the process_packet() routine
        we will use 0 to indicate that there is no limit to packets processed
        and NULL arguments
    */
    if (pcap_loop(fp, 0, process_packet, NULL) < 0) {
        fprintf(stderr, "%s\n", pcap_geterr(fp)); //print error
        fclose(file);
        exit(EXIT_FAILURE);
    }
    printf("\n********************* STATISTICS **********************\n");
    printf("a. Total number of network flows captured     : %d\n", total_network_flows);
    printf("b. Total number of TCP network flows captured : %d\n", total_tcp_network_flows);
    printf("c. Total number of UDP network flows captured : %d\n", total_udp_network_flows);
    printf("d. Total number of packets received           : %d\n", packets_proc_count);
    printf("e. Total number of TCP packets received       : %d\n", tcp_count);
    printf("f. Total number of UDP packets received       : %d\n", udp_count);
    printf("g. Total bytes of TCP packets received        : %d\n", total_tcp_bytes);
    printf("h. Total bytes of UDP packets received        : %d\n", total_udp_bytes);
    printf("\n");
    printf("Total number of retrasmitted TCP packets      : %d\n\n", total_retrasmitted_packets);
    printf("Total TCP packets where data loss is detected\n"
           "(the sequence number is larger than expected) : %d\n\n", total_skipped_segments);

    fprintf(file, "\n********************* STATISTICS **********************\n");
    fprintf(file, "a. Total number of network flows captured     : %d\n", total_network_flows);
    fprintf(file, "b. Total number of TCP network flows captured : %d\n", total_tcp_network_flows);
    fprintf(file, "c. Total number of UDP network flows captured : %d\n", total_udp_network_flows);
    fprintf(file, "d. Total number of packets received           : %d\n", packets_proc_count);
    fprintf(file, "e. Total number of TCP packets received       : %d\n", tcp_count);
    fprintf(file, "f. Total number of UDP packets received       : %d\n", udp_count);
    fprintf(file, "g. Total bytes of TCP packets received        : %d\n", total_tcp_bytes);
    fprintf(file, "h. Total bytes of UDP packets received        : %d\n", total_udp_bytes);
    fprintf(file, "\n");
    fprintf(file, "Total number of retrasmitted TCP packets      : %d\n\n", total_retrasmitted_packets);
    fprintf(file, "Total TCP packets where data loss is detected\n"
            "(the sequence number is larger than expected) : %d\n\n", total_skipped_segments);

    pcap_close(fp);
    fclose(file);

    /* free the two linked lists */
    free_tcp_streams();
    free_network_flows();
}


/*
 *
 * Callback routine for each packet in our capture to be processed
 * Called by pcap_loop()
 * 
 * args: a u_char pointer to arguments which is passed in from pcap_loop() 
 *       !!! (will be NULL) !!!
 * 
 * header: a const struct pcap_pkthdr pointer to a structure with the following members:
 *         ts     - a struct timeval containing the time when the packet was captured
 *         caplen - a bpf_u_int32 giving the number of bytes of the packet that are 
 *                  available from the capture
 *         len    - a bpf_u_int32 giving the length of the packet, in bytes (which might be 
 *                  more than the number of bytes available from the capture, if the length 
 *                  of the packet is larger than the maximum number of bytes to capture)
 * 
 * packet: a const u_char pointer to the first caplen (as given in the struct 
 *         pcap_pkthdr a pointer to which is passed to the callback routine) 
 *         bytes of data from the packet (which won't necessarily 
 *         be the entire packet)
 * 
*/

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* pointers to the headers */
	const struct ethernet_h *ethernet_header;  /* ethernet header */
	const struct ip_h *ip_header;              /* IP header */
	const struct tcp_h *tcp_header;            /* TCP header */
    const struct udp_h *udp_header;

	int ip_header_len;
	int tcp_header_len;
	int payload_len;

    /* for higher level protocols */
    char* higher_protocol; 

    /* for additional packet info (retransmition, spurial, etc) */
    char* more_info; 

    packets_proc_count++;


    /* make sure we have an IP packet */
	ethernet_header = (struct ethernet_h*)(packet);
    if (ntohs(ethernet_header->type) != ETHERTYPE_IP) {
        return;
    }

    /* define/compute ip header offset */
	ip_header = (struct ip_h*)(packet + ETHERNET_HEADER_LEN);
	
    /* if TCP/IP protocol */
    if(ip_header->protocol == IPPROTO_TCP){

        /* The second half of the first byte of the IP header is the IP header length
           so I 'bitwise AND' to get ONLY the second half of the byte 

           IMPORTAND: It refers to how many 4-byte (32-bit) segments follow so we
                      we have to multiply with 4 to get the actual bytes 
        */
        ip_header_len = (ip_header->version_ihl & 0x0F) * 4;

         /* The beginning of the TCP header is after Ethernet, IP headers. So we have to 
           move the pointer like this. */
	    tcp_header = (struct tcp_h*)(packet + ETHERNET_HEADER_LEN + ip_header_len);

        /* The first half of the 12th byte of the TCP header is the TCP header length
           so I 'bitwise AND' to get ONLY the first half of the byte, and also shift
           its' value by 4 bits (Get the Data Offset only)

           IMPORTAND: It refers to how many 4-byte (32-bit) segments follow so we
                      we have to multiply with 4 to get the actual bytes 
        */
        tcp_header_len = ((tcp_header->flags_1 & 0xF0) >> 4) * 4;

        /* compute tcp payload len in bytes */
	    payload_len = ntohs(ip_header->total_length) - (ip_header_len + tcp_header_len);

        /* create the higher_protocol string  with higher layer info using etc/services */ 
        tcp_udp_port_description(ntohs(tcp_header->src_port), ntohs(tcp_header->dst_port),
                                 "tcp/ip", &higher_protocol);
        
        /* Updates network_flow linked list and increments corresponding counters */
        update_network_flows(ip_header->src_ip, ip_header->dst_ip, 
                             tcp_header->src_port, tcp_header->dst_port,
                             ip_header->protocol);

        /* 
         Updates tcp_stream linked list based on this packet, taking into account TCP-flags.
         Packet additional info stored in more_info buffer. This is done to find 
         retransmissions (having stored next_expected_seq_number TCP) and playing with the flags.
         Please for more info read the comments of this function.
        */
        update_tcp_streams(ip_header->src_ip, ip_header->dst_ip, 
                          tcp_header->src_port, tcp_header->dst_port,
                          ip_header->protocol, tcp_header->seq_number,
                          payload_len, tcp_header->flags_2, &more_info);

        print_packet_info(ip_header->src_ip, ip_header->dst_ip,
                          ntohs(tcp_header->src_port), ntohs(tcp_header->dst_port),
                          higher_protocol, tcp_header_len, payload_len, more_info);

        tcp_count++;
        total_tcp_bytes += header->len; //header->len gives total packet bytes

        free(higher_protocol);
        free(more_info);
    }
    else if(ip_header->protocol == IPPROTO_UDP){

        /* The second half of the first byte of the IP header is the IP header length
           so I 'bitwise AND' to get ONLY the second half of the byte 

           IMPORTAND: It refers to how many 4-byte (32-bit) segments follow so we
                      we have to multiply with 4 to get the actual bytes 
        */
        ip_header_len = (ip_header->version_ihl & 0x0F) * 4;

        /* The beginning of the UDP header is after Ethernet, IP headers. So we have to 
           move the pointer like this. */
	    udp_header = (struct udp_h*)(packet + ETHERNET_HEADER_LEN + ip_header_len);

        /* compute udp payload len in bytes */
	    payload_len = ntohs(udp_header->length) - UDP_HEADER_LEN;

        /* Updates network_flow linked list and increments corresponding counters */
        update_network_flows(ip_header->src_ip, ip_header->dst_ip, 
                             udp_header->src_port, udp_header->dst_port,
                             ip_header->protocol);

        /* create the protocol higher_protocol with higher layer info using etc/services */ 
        tcp_udp_port_description(ntohs(udp_header->src_port), ntohs(udp_header->dst_port),
                                 "udp/ip", &higher_protocol);
        
        print_packet_info(ip_header->src_ip, ip_header->dst_ip,
                          ntohs(udp_header->src_port), ntohs(udp_header->dst_port),
                          higher_protocol, UDP_HEADER_LEN, payload_len, "");  
                   
        udp_count++;
        total_udp_bytes += header->len; //header->len gives total packet bytes
        free(higher_protocol);
    }
}

/*
 * Find the service using etc/services of linux which has the most common services
 * on many ports (application layer).
 *
 * proto: "tcp/ip" or "udp/ip"
 * description: double pointer for return description
 * 
*/
void tcp_udp_port_description(int port1, int port2, char proto[7], char** description){

    *description = malloc(50);
    strcpy(*description, proto);

    struct servent *appl_name1;
    appl_name1 = getservbyport(htons(port1), NULL);

    struct servent *appl_name2;
    appl_name2 = getservbyport(htons(port2), NULL);

    if(appl_name1 == NULL && appl_name2 == NULL){ //unknown application
        return;
    }

    strcat(*description, " ");

    if(appl_name1 != NULL){
        strcat(*description, appl_name1->s_name);
        return;
    }

    strcat(*description, appl_name2->s_name);

}


/*
 *
 * In this function I do a mini packet analysis using the tcp_stream linked list.
 * Additional information will be returned about this packet on @parameter more_info
 * to be printed afterwards. This includes Retransmitted packets, and more...
 * 
 * Updates the tcp_stream linked list using the TCP flags SYN, RST, ACK, FIN
 * detecting the 3-way handshake and the FIN-ACK, RST closing routine.
 * Creations/Deletions of tcp_streams will happen according to the flags and more.
 * 
 * In normal data transmition (in the middle of SYN, FIN-RST)
 * If the given seq number ntohl(seq_number) is not equal to the expected 
 * sequence number then there is something wrong.
 *
 *   1. If this seq_number < next_expected_seq_number then we can safely assume
 *      that this is RETRANSMITTED packet.
 *   2.a. If this seq_number > next_expected_seq_number then we can assume that
 *        we lost packets along the way , but we cant do anything about it other
 *        than update the next_expected_seq_number.
 *   2.b. if seq_number == next_expected_seq_number everything is going normally
 *        and we update the next_expected_seq_number
 * 
 * More:
 * 
 * flags_2: 1-byte, 1-bit each -> CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
 * 
 * Opening connection (new tcp stream):
 * 
 * SYN = 1
 * synchronizing sequence number. Only the first packet sent from 
 * each end should have this flag set. Some other flags and fields change meaning 
 * based on this flag. SYN flag must be seen when starting a new tcp stream!
 *      next_expected_sequence_number = seq_number + 1
 *
 * ACK = 1, SYN = 1 
 * Handshake
 *      next_expected_seq_number = seq_number + 1
 * 
 * 
 * Middle of connection (update tcp stream):
 * 
 * ACK = 1 
 * Indicates that the Acknowledgment field is significant. 
 * All packets after the initial SYN packet sent by the client 
 * should have this flag set.
 * && payload_len = 0
 *       next_expected_seq_number STAYS the SAME 
 * && payload_len > 0
 *       next_expected_seq_number = seq_number + payload_len
 * 
 * 
 * End of connection (delete tcp stream):
 * 
 * FIN = 1 (normally && ACK = 1)
 * If its the initializer then will send one more ACK response (after the 
 * responders' ACK, FIN) and (delete tcp stream)
 *      next_expected_seq_number = seq_number + 1 (FIN)
 * 
 * If its the responder then does nothing more (has already sent ACK to the FIN
 * before, as above) and we delete tcp stream
 *      next_expected_seq_number = seq_number + 1 (FIN)
 * 
 * !!!! The FIN flag tcp_stream initializer will be kept alive until the final ACK !!!!
 * 
 * RST = 1
 *     close both ends of the connection (both tcp streams)
 * Note: I know there is a possibility for an ACK reply to happen (after RST), but 
 *       I will not consider it (If there are such packets, they will be marked
 *       with additional info on the console). Im not wireshark. 
 * 
 * flags_2: 1-byte, 1-bit each -> CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
 * 
*/
void update_tcp_streams(struct in_addr src_ip, struct in_addr dst_ip, 
                        u_short src_port, u_short dst_port, u_char protocol,
                        u_int seq_number, u_int payload_len, u_char flags_2, char **more_info)
{
    *more_info = malloc(400);
    strcpy(*more_info, "");

    /* TCP header flags */
    u_int ACK, RST, SYN, FIN;
    
    /* flags_2: 8-bit |CWR, ECE, URG, ACK, PSH, RST, SYN, FIN| */
    ACK = (flags_2 & 0x10) >> 4;
    RST = (flags_2 & 0x04) >> 2;
    SYN = (flags_2 & 0x02) >> 1;
    FIN = (flags_2 & 0x01);

    /* first tcp stream */ 
    if(tcp_head == NULL){

        tcp_head = (struct tcp_stream*) malloc(sizeof(struct tcp_stream));
        tcp_head->src_ip = src_ip.s_addr;
        tcp_head->dst_ip = dst_ip.s_addr;
        tcp_head->src_port = src_port;

        if(SYN) tcp_head->next_expected_seq_number = ntohl(seq_number)+1;
        else tcp_head->next_expected_seq_number = ntohl(seq_number)+payload_len;

        tcp_head->FIN_responder = 0;
        tcp_head->delete_after_next_ACK = 0;
        tcp_head->protocol = protocol;
        tcp_head->next = NULL;
        return;
    }
    
    struct tcp_stream *stream = find_tcp_stream(src_ip, dst_ip, src_port, 
                                               dst_port, protocol);                                                          

    /* Check if the tcp stream was not found (not created) */
    if(stream == NULL){
        /* Since we need to create the tcp stream, we have to check
           if the SYN flag is set, otherwise this packet was sent to a 
           an already closed connection */
        if(SYN){
            /* go to last tcp stream */
            struct tcp_stream *tail = tcp_head;
            while(tail->next != NULL) tail = tail->next;
            
            /* create the next tcp stream */
            tail->next = (struct tcp_stream*) malloc(sizeof(struct tcp_stream));
            tail->next->src_ip = src_ip.s_addr;
            tail->next->dst_ip = dst_ip.s_addr;
            tail->next->src_port = src_port;
            tail->next->dst_port = dst_port;
            /* See the comments above (SYN=1) for next_expected_seq_number */
            tail->next->next_expected_seq_number = ntohl(seq_number)+1;
            tail->next->FIN_responder = 0;
            tail->next->delete_after_next_ACK = 0;
            tail->next->protocol = protocol;
            tail->next->next = NULL;
        }
        else{
            strcat(*more_info, "More info: TCP 3-way handshake routine hasn't been captured (and SYN = 0).\n"
                               "           Possibly, connection opened PRIOR to capture start.\n"
                               "           (Confirm this by following TCP-stream on Wireshark)\n");
        }
        return;
    }

    /* 
     From here and onwards, corresponding tcp stream was found 
     but we have to check FIN, RST flags (because we might need to delete streams) 
     Read comments above.
    */

    if(RST){
        /* reverse stream DST->SRC */ 
        struct tcp_stream *reverse_stream = find_tcp_stream(dst_ip, src_ip, dst_port, 
                                                          src_port, protocol);
        if(reverse_stream == NULL) {
            delete_tcp_stream(stream);
            return;
        }
        delete_tcp_stream(stream);
        delete_tcp_stream(reverse_stream);
        return ;
    }

    if(FIN){
        
        /* Because we don't know yet if we are the FIN initializer or responder */
        stream->next_expected_seq_number = ntohl(seq_number)+1;

        /* Check if this FIN is our response to the DST (the DST initialized the FIN) */
        if(stream->FIN_responder){
            /* 
             Means this FIN is a response to an already sent FIN 
             So we have nothing more to do, other than delete this stream
            */
            delete_tcp_stream(stream);
            return;
        }

        /* 
         Onwards we are certain SRC is the FIN initializer, so we have to do:
         1. find the reverse stream and set the FIN_responder = 1
         2. set our delete_after_next_ACK flag to 1, so this stream is deleted
            on our last ACK response to the responders' FIN !
        */
        struct tcp_stream *reverse_stream = find_tcp_stream(dst_ip, src_ip, dst_port, 
                                                          src_port, protocol);

        stream->delete_after_next_ACK = 1;

        /* this should NOT happen, but I check it */                                                             
        if(reverse_stream == NULL) {
            strcat(*more_info, "More info: SRC initialized connection termination (FIN set),\n"
                               "           but reverse connection has already been closed by DST.\n"
                               "           (Posibly, connection closed with RST).\n");
            delete_tcp_stream(stream);
            return ;
        }

        reverse_stream->FIN_responder = 1;
        
        stream->delete_after_next_ACK = 1;

        return ;
    }

    /* We have to check delete_after_next_ACK as explained above*/
    if(ACK && stream->delete_after_next_ACK){
        delete_tcp_stream(stream);
        return ;
    }
    /* 
     From here and onwards, FIN, RST flag are not set, and this packet is not
     an ACK response to a SRC-initialized FIN connection termination.
     We are in normal data transmition!
     
     If the given seq number ntohl(seq_number) is not equal to the expected 
     sequence number then there is something wrong.

     1. If this seq_number < next_expected_seq_number then we can safely assume
        that this is RETRANSMITTED packet.
     2.a. If this seq_number > next_expected_seq_number then we can assume that
          we lost packets along the way , but we cant do anything about it other
          than update to the new seq_number.
     2.b. if seq_number == next_expected_seq_number everything is going normally
          and we update the next_expected_seq_number
    */

    if(ntohl(seq_number) < stream->next_expected_seq_number){
        total_retrasmitted_packets++;
        strcat(*more_info, "More info: Retransmitted\n");
    }
    else if(ntohl(seq_number) > stream->next_expected_seq_number){
        total_skipped_segments++;
        stream->next_expected_seq_number = ntohl(seq_number)+payload_len;
        strcat(*more_info, "More info: Previous segment not captured (data loss).\n"
                           "           (the TCP sequence number is larger than expected)\n");
    }
    else{
        stream->next_expected_seq_number = ntohl(seq_number)+payload_len;
    }

    return ;
}

/* returns tcp stream if found, otherwise returns NULL */
struct tcp_stream* find_tcp_stream(struct in_addr src_ip, struct in_addr dst_ip, 
                                   u_short src_port, u_short dst_port, u_char protocol)
{
    struct tcp_stream *tmp = tcp_head;

    while(tmp != NULL){
        /* check if the tcp stream exists */
        if(tmp->src_ip == src_ip.s_addr && tmp->dst_ip == dst_ip.s_addr &&
           tmp->src_port == src_port && tmp->dst_port == dst_port && tmp->protocol == protocol)
           {
               break;
           }
        tmp = tmp->next;
    }
    return tmp;
}

void delete_tcp_stream(struct tcp_stream* stream){
    if(tcp_streams_equal(stream, tcp_head)) {
        tcp_head = stream->next;
        free(stream);
        return;
    }

    struct tcp_stream* prev = tcp_head;

    while(prev != NULL){
        if(tcp_streams_equal(prev->next, stream)){
            prev->next = stream->next;
            free(stream);
            return;
        }
        prev = prev->next;
    }
}

int tcp_streams_equal(struct tcp_stream* tmp1, struct tcp_stream* tmp2){

    if(tmp1->src_ip == tmp2->src_ip && tmp1->dst_ip == tmp2->dst_ip &&
       tmp1->src_port == tmp2->src_port && tmp1->dst_port == tmp2->dst_port && 
       tmp1->protocol == tmp2->protocol) return 1;
    return 0;

}


void print_packet_info(struct in_addr src_ip, struct in_addr dst_ip, int src_port,
                       int dst_port, char* description, int tcpudp_header_len, int payload_len, char* more_info)
{
    char* source_ip_str = malloc(30);
    char* dest_ip_str = malloc(30);

    sprintf(source_ip_str, "%s", inet_ntoa(src_ip));
    sprintf(dest_ip_str, "%s", inet_ntoa(dst_ip));
    
    printf("\n****** %d. *******"
           "\nSrc IP: %s"
           "\nDst IP: %s"
           "\nSrc Port: %d"
           "\nDst Port: %d"
           "\nProtocol: %s"
           "\nHeader Bytes: %d"
           "\nPayload Bytes: %d"
           "\n%s\n",
           packets_proc_count, source_ip_str, dest_ip_str, src_port, dst_port,
           description, tcpudp_header_len, payload_len, more_info);
    
    fprintf(file, "\n****** %d. *******"
                  "\nSrc IP: %s"
                  "\nDst IP: %s"
                  "\nSrc Port: %d"
                  "\nDst Port: %d"
                  "\nProtocol: %s"
                  "\nHeader Bytes: %d"
                  "\nPayload Bytes: %d"
                  "\n%s\n",
                  packets_proc_count ,source_ip_str, dest_ip_str, src_port, dst_port,
                  description, tcpudp_header_len, payload_len, more_info);

    free(source_ip_str);
    free(dest_ip_str);
}


void update_network_flows(struct in_addr src_ip, struct in_addr dst_ip, 
                          u_short src_port, u_short dst_port, u_char  protocol)
{
    struct network_flow* tmp = flow_head;

    /* if first flow */
    if(flow_head == NULL){
        flow_head = (struct network_flow*) malloc(sizeof(struct network_flow));
        flow_head->src_ip = src_ip.s_addr;
        flow_head->dst_ip = dst_ip.s_addr;
        flow_head->src_port = src_port;
        flow_head->dst_port = dst_port;
        flow_head->protocol = protocol;
        flow_head->next = NULL;

        total_network_flows++;
        if(protocol == IPPROTO_TCP) total_tcp_network_flows++;
        if(protocol == IPPROTO_UDP) total_udp_network_flows++;
    }

    while(tmp != NULL){
        /* check if the network flow exists (if it exists return, nothing changes) */
        if(tmp->src_ip == src_ip.s_addr && tmp->dst_ip == dst_ip.s_addr &&
           tmp->src_port == src_port && tmp->dst_port == dst_port && tmp->protocol == protocol)
           {
               return;
           }
        tmp = tmp->next;
    }

    /* we know this packet flow has not been created, so store it */

    /* go to last tcp stream */
    struct network_flow *tail = flow_head;
    while(tail->next != NULL) tail = tail->next;

    /* create the netowrk flow at the end */
    tail->next = (struct network_flow*) malloc(sizeof(struct network_flow));
    tail->next->src_ip = src_ip.s_addr;
    tail->next->dst_ip = dst_ip.s_addr;
    tail->next->src_port = src_port;
    tail->next->dst_port = dst_port;
    tail->next->protocol = protocol;
    tail->next->next = NULL;

    total_network_flows++;
    if(protocol == IPPROTO_TCP) total_tcp_network_flows++;
    if(protocol == IPPROTO_UDP) total_udp_network_flows++;
}

void free_tcp_streams(){
    struct tcp_stream *prev;
    struct tcp_stream *curr = tcp_head;

    while(curr!=NULL){
        prev = curr;
        curr = curr->next;
        free(prev);
    }
}

void free_network_flows(){
    struct network_flow *prev;
    struct network_flow *curr = flow_head;

    while(curr!=NULL){
        prev = curr;
        curr = curr->next;
        free(prev);
    }
}