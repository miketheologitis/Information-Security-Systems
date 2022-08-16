GCC version : gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
Author: Michail Theologitis
AM: 2017030043

*******************************USAGE*******************************************

> make

Usage:
	./monitor -r input_file
	./monitor -h
Options:
 -n    <input_file>     Packet analysis on .pcap file <input_file>
 						Decodes and prints basic information about
 						each TCP or UDP packet. At the end some 
 						Statistics about the capture are also printed.
 						An 'analysis.txt' file will be created storing
 						all this information.
 						     
 -h                     Prints this help message


*******************************GENERAL*******************************************

First of all, TCP/UDP analysis will be done only on ipv4 protocol. Not ipv6.

This program uses libpcap and processes the .pcap file. Each UDP or TCP packet
is decoded and basic information are printed. At the end some Statistics about
the capture are also printed (everything in assigment6.pdf).

My code is filled with comments, explaining everything line-line. What I want to
explain in this README is the idea behind my mini TCP analysis to find when a
TCP packet is in Retransmission.

Firstly, I have to take this out of the way so I can continue my TCP-packet analysis
idea.

In the assignment "network flow" is 
defined as a 5-tuple consisted of {source IPv4 address, source port, 
destination IPv4 address, destination port, protocol}. When I detect a 
packet from SRC to DST (either TCP or UDP) then I check if a network 
flow exists, and if not, I create it. In general, by this definition,
in any connection between host-server, there are 2 network flows.
One from host->server and one from server->host. By the assignment's 
definition this network flow doesn't get deleted, even after the connection ends.
So if a connection closes and re-opens the 2 network flows are still in
memory.

----------------------------------------------------------------------------------------------

Back to my TCP packet analysis:

Firstly, UDP does not have a retransmission mechanism. UDP doesn't care for packet loss.
If an UDP packet arrives and has a bad checksum, it is simply dropped. 
Neither the sender of the packet is informed about this, nor the recipient is informed.
UDP is used when lost packets are not much of an issue. This is its' nature.

On the other hand, TCP has a retransmission mechanism. Not only, does it have a
checksum, but also a 32-bit sequence number, 32-bit Acknowledgment number, 1-bit ACK, ...
and many other flags helping for normal data transmission and no packet loss.

For finding retransmitted packets, what is really importand here are the following:

1-bit flags: SYN, FIN, RST, ACK
32-bit number: sequence number

SYN :
	It is used in first step of connection establishment phase or 3-way handshake process
    between the two hosts. Only the first packet from sender as well as receiver should have this flag set.	
    !!!! This is used for synchronizing sequence number 
    !!!! i.e. to tell the other end which sequence number they should accept. 
FIN :
	It is used to request for connection termination.
RST : 
	It is used to terminate the connection forcefully (without waiting for ACK).
ACK :
	It is used to acknowledge packets which are successful received by the host.
	
sequence number:
	Sequence number of data bytes of a segment in a session.
	1. If (SYN=1) then this is the initial sequence number.
	2. If (SYN=0) then this is the accumulated sequence number 
	   of the first data byte of this segment for the current session

So the key idea here, is that we want for each Connection (host->server AND 
server->host) to keep track of the next expected sequence number. Also we HAVE
to take into account the above flags, in order to keep track and update the
next expected sequence number the correct way.

Next expected sequence number is updated (when processing a packet SERVER1 -> HOST1) and 
must be equal to the next received packet's (same connection SERVER1 -> HOST1) sequence number.
This is always the case in normal TCP packet transmission.

********************************************************************************************
In my program I have a struct tcp_stream. My definition of this is that one TCP connection
consists of 2 tcp_streams. One from SERVER1 -> SERVER2, and one for SERVER2->SERVER1.
So each tcp_stream is responsible for one end of the connection keeping track of its'
next expected sequence number. Apart from the (src_ip, dst_ip, src_port, dst_port, protocol)
there are 2 additional flags helping me for the deletion of those streams (connection close).
IMPORTAND NOTE:
	These 2 tcp_streams are are created when SYN flag is present
 	and the 3-way handshake is done, and deleted when RST, FIN flags are set.
 	More info on the update_tcp_streams function's comments
*********************************************************************************************

In normal data transmition (in the middle of SYN, FIN-RST)
If the given seq number sequence_number is not equal to the expected 
sequence number then there is something wrong.

1.   If this sequence_number < next_expected_sequence_number then we can safely assume
     that this is RETRANSMITTED packet.
2.a. If this sequence_number > next_expected_sequence_number then we can assume that
	 we lost packets along the way , but we cant do anything about it other
	 than update the next_expected_seq_number.
2.b. if seq_number == next_expected_seq_number everything is going normally
	 and we update the next_expected_seq_number

But, the general rules are the following:

1. Opening connection (new tcp_stream)
SYN = 1
   next_expected_sequence_number = sequence_number + 1
   
ACK = 1, SYN = 1  (Handshake)
   next_expected_seq_number = seq_number + 1

2. Middle of connection (update tcp_stream)

(RST, FIN, SYN not set, ACK we don't care)
  next_expected_seq_number = sequence_number + payload_len

3. End of connection (delete tcp_stream):

FIN = 1 (usually && ACK = 1)
	If its the initializer then will send one more ACK response (after the 
	responders' ACK, FIN) and (delete tcp stream)
	next_expected_seq_number = seq_number + 1
 
	If its the responder then does nothing more (has already sent ACK to the FIN
	before, as above) and we delete tcp stream
	    next_expected_seq_number = seq_number + 1
	!!!! The FIN flag tcp_stream initializer will be kept alive until the final ACK !!!!
RST = 1
	close both ends of the connection (both tcp streams)
	Note: I know there is a TINY possibility for an ACK reply to happen (after RST), but 
      	  I will not consider it (If there are such packets, they will be marked
	      with additional info on the console). Im not wireshark.

Please note that the way a tcp_stream is deleted is carefully thought out, and uses the
FIN_responder, delete_after_next_ACK flags of the tcp_stream to take care of 
most FIN=1 connection close possibilities. More info as comments on update_tcp_stream()
function on the code. (It is easier to see this on the code, because each step is explained
with comments and you see it live!).

update_tcp_stream() fills a buffer with information ("Previous segment not captured (data loss)",
"Retransmitted", ... etc) and this buffer is printed with each packet you see on the console and 
on the file analysis.txt file.


LAST VERY IMPORTAND NOTE:
	If the .pcap capture file you give me, has not captured the 3-way hanshake (FIN-ACK) for
	connection establishment, means the connection was opened before capture start, my program
	will print this information about these packets: 
	
	"TCP 3-way handshake routine hasn't been captured (and SYN = 0).
     Possibly, connection opened PRIOR to capture start."
     (Confirm this by following TCP-stream on Wireshark)"
     
     When a connection was opened before capture started and packets are being transmitted 
     without (my program) having seen an SYN flag set, the above info will be printed.
     
     When you see this info message (around 600/14261 packets) you can confirm it 
     using wireshark. Some of those packets were actually in Retransmission but there 
     is no way to ackowledge this in a simple ~500 lines of code program. It goes too far, 
     and I cannot take into account everything.

Any of the additional info packet messages you see printed, you can confirm the info printed
on wireshark. I am confident my TCP analysis was done in a simplified but solid way and
the additional packet info messages you see are TECHNICALLY correct!































































pcap_t *pcap_open_offline(const char *fname, char *errbuf)

is called to open a ''savefile'' for reading. 
fname specifies the name of the file to open. The file has the same format 
as those used by tcpdump(8) and tcpslice(8). The name "-" in a synonym for stdin. 
Alternatively, you may call pcap_fopen_offline() to read dumped data from 
an existing open stream fp. Note that on Windows, that stream should be opened in 
binary mode. errbuf is used to return error text and is only set when 
pcap_open_offline() or pcap_fopen_offline() fails and returns NULL.

------------------------------------------------------------------------------------------

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)

pcap_loop() is similar to pcap_dispatch() except it keeps reading packets until 
cnt packets are processed or an error occurs. It does not return when live read 
timeouts occur. Rather, specifying a non-zero read timeout to pcap_open_live() 
and then calling pcap_dispatch() allows the reception and processing of any packets 
that arrive when the timeout occurs. A negative cnt causes pcap_loop() to loop forever 
(or at least until an error occurs). -1 is returned on an error; 0 is returned if 
cnt is exhausted; -2 is returned if the loop terminated due to a call to pcap_breakloop()
before any packets were processed. If your application uses pcap_breakloop(), 
make sure that you explicitly check for -1 and -2, rather than just checking for 
a return value < 0.

-------------------------------------------------------------------------------------------

int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)


pcap_dispatch() is used to collect and process packets. cnt specifies the maximum number
of packets to process before returning. This is not a minimum number; when reading a live 
capture, only one bufferful of packets is read at a time, so fewer than cnt packets may be
processed. A cnt of -1 processes all the packets received in one buffer when reading a live
capture, or all the packets in the file when reading a ''savefile''. 

callback specifies a routine to be called with three arguments:
1. a u_char pointer which is passed in from pcap_dispatch() 
2. a const struct pcap_pkthdr pointer to a structure with the following members:

ts - a struct timeval containing the time when the packet was captured

caplen - a bpf_u_int32 giving the number of bytes of the packet that are 
         available from the capture

len - a bpf_u_int32 giving the length of the packet, in bytes (which might be 
      more than the number of bytes available from the capture, if the length 
      of the packet is larger than the maximum number of bytes to capture)

3. a const u_char pointer to the first caplen (as given in the struct pcap_pkthdr a pointer 
to which is passed to the callback routine) bytes of data from the packet (which won't 
necessarily be the entire packet; to capture the entire packet, you will have to provide a 
value for snaplen in your call to pcap_open_live() that is sufficiently large to get all of 
the packet's data - a value of 65535 should be sufficient on most if not all networks).
The number of packets read is returned. 0 is returned if no packets were read from a live 
capture (if, for example, they were discarded because they didn't pass the packet filter, 
or if, on platforms that support a read timeout that starts before any packets arrive, the 
timeout expires before any packets arrive, or if the file descriptor for the capture device 
is in non-blocking mode and no packets were available to be read) or if no more packets are 
available in a ''savefile.'' A return of -1 indicates an error in which case pcap_perror() or 
pcap_geterr() may be used to display the error text. A return of -2 indicates that the loop 
terminated due to a call to pcap_breakloop() before any packets were processed. If your 
application uses pcap_breakloop(), make sure that you explicitly check for -1 and -2, rather 
than just checking for a return value < 0.
