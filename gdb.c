#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#define PORT 1234
#define GDB_RSP_PKT_BUF_MAX (16384)
#define GDB_RSP_WIRE_BUF_MAX ((GDB_RSP_PKT_BUF_MAX * 2) + 4)



static int conn_sock;
static const char control_c = 0x3;

const char hexchars[] = "0123456789abcdef";

void val_to_hex16 (const uint64_t val, const uint8_t xlen, char *buf) {
    assert ((xlen == 8)
	    || (xlen == 16)
	    || (xlen == 32)
	    || (xlen == 64));

    buf[0]  = hexchars [(val >>  4) & 0xF];
    buf[1]  = hexchars [(val >>  0) & 0xF];
    if (xlen == 8) return;

    buf[2]  = hexchars [(val >> 12) & 0xF];
    buf[3]  = hexchars [(val >>  8) & 0xF];
    if (xlen == 16) return;

    buf[4]  = hexchars [(val >> 20) & 0xF];
    buf[5]  = hexchars [(val >> 16) & 0xF];
    buf[6]  = hexchars [(val >> 28) & 0xF];
    buf[7]  = hexchars [(val >> 24) & 0xF];
    if (xlen == 32) return;

    buf[8]  = hexchars [(val >> 36) & 0xF];
    buf[9]  = hexchars [(val >> 32) & 0xF];
    buf[10] = hexchars [(val >> 44) & 0xF];
    buf[11] = hexchars [(val >> 40) & 0xF];
    buf[12] = hexchars [(val >> 52) & 0xF];
    buf[13] = hexchars [(val >> 48) & 0xF];
    buf[14] = hexchars [(val >> 60) & 0xF];
    buf[15] = hexchars [(val >> 56) & 0xF];
}

uint8_t gdb_checksum(const char *buf, const size_t size) {
	uint8_t c = 0;
	size_t j;
	for (j=0; j<size; j++)
		c = (uint8_t) (c + ((uint8_t *) buf) [j]);

	return c;
}


ssize_t gdb_escape (char *dst, const size_t dst_size, const char *src, const size_t src_len) {
    unsigned char *udst = (unsigned char *) dst;
    const unsigned char *usrc = (const unsigned char *) src;
    size_t js = 0, jd = 0;

    while (js < src_len) {
	unsigned char ch = usrc [js];
	if ((ch == '$') || (ch == '#') || (ch == '*') || (ch == '}')) {
	    if ((jd + 1) >= dst_size)
		goto err_dst_too_small;
	    dst [jd]     = '}';
	    udst [jd + 1] = (ch ^ 0x20);
	    jd += 2;
	}
	else {
	    if (jd >= dst_size)
		goto err_dst_too_small;
	    udst [jd] = ch;
	    jd += 1;
	}
	js++;
    }
    return (ssize_t) jd;

 err_dst_too_small:
	printf ("ERROR: destination buffer too small\n");
    return -1;
}





ssize_t gdb_unescape(char *dst, const size_t dst_size, const char *src, const size_t src_len) {
 unsigned char *udst = (unsigned char *) dst;
    const unsigned char *usrc = (const unsigned char *) src;
    size_t js = 0, jd = 0;

    while (js < src_len) {
	unsigned char ch;
	if (src [js] == '}') {
	    if ((js + 1) >= src_len)
		goto err_ends_in_escape_char;

	    ch = usrc [js + 1] ^ 0x20;
	    js += 2;
	}
	else {
	    ch = usrc [js];
	    js += 1;
	}

	if (jd >= dst_size)
	    goto err_dst_too_small;
	udst [jd++] = ch;
    }
    // Insert terminating 0 byte
    if ((jd + 1) >= dst_size)
	goto err_dst_too_small;
    dst [jd++] = 0;
    return (ssize_t) jd;

 err_dst_too_small:
	printf("ERROR: destination buffer too small\n");
    return -1;

 err_ends_in_escape_char:
	printf("ERROR: last char of src is escape char\n");
    return -1;
}

char recv_ack_nack(void) {
	const size_t n_iters_max = 1000000;
    size_t n_iters = 0;
	char ack_resp;

	while(true) {
		ssize_t n = read(conn_sock, &ack_resp, 1); 
		if (n < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				// nothing available yet
				if (n_iters > n_iters_max) {
					printf("no response from gdb received\n");
					return 'E';
				} else {
					usleep(5);
					n_iters++;
				}
			} else {
				printf("failed to receive from gdb\n");
				return 'E';
			}
		} else if (n == 0) {
			if (n_iters > n_iters_max) {
				printf("nothing received in %ld attempts\n", n_iters_max);
			}
			usleep(5);
			n_iters++;
		} else if ((ack_resp == '+') || (ack_resp == '-')) {
			printf("received the resp %c from gdb\n", ack_resp);
			return ack_resp;
		} else {
			printf("received unexpected char from gdb\n");
			return 'E';
		}
	}

}

int send_rsp_pkt_to_gdb(const char *buf, const size_t buf_len) {
	char wire_buf[GDB_RSP_WIRE_BUF_MAX];
	wire_buf[0] = '$';
	
	ssize_t s_wire_len = gdb_escape(&(wire_buf[1]), (GDB_RSP_WIRE_BUF_MAX - 1), buf, buf_len);

	if ((s_wire_len < 0) || ((s_wire_len + 4) >= GDB_RSP_WIRE_BUF_MAX)) {
		printf("ERROR: packet too large\n");
		goto err_exit;
	}

	size_t wire_len = (size_t) s_wire_len;
	
	// compute and insert the checksum
	uint8_t checksum = gdb_checksum(&(wire_buf[1]), wire_len);
	char ckstr[3];
	snprintf(ckstr, sizeof(ckstr), "%02X", checksum);
	wire_buf[wire_len + 1] = '#';
	wire_buf[wire_len + 2] = ckstr[0];
	wire_buf[wire_len + 3] = ckstr[1];
	

	while (true) {
		// Write the packet out to GDB
		size_t n_sent = 0;
		size_t n_iters = 0;
		while (n_sent < (wire_len + 4)) {
		    ssize_t n = write (conn_sock, & (wire_buf [n_sent]), (wire_len + 4 - n_sent));
		    if (n < 0) {
			    printf ("ERROR: write (wire_buf) to gdb failed\n");
				goto err_exit;
		    }
		    else if (n == 0) {
				if (n_iters > 1000000) {
					printf ("ERROR: nothing sent in 1,000,000 write () attempts\n");
				    goto err_exit;
				}
				usleep (5);
				n_iters++;
		    }
		    else {
				n_sent += (size_t) n;
		    }
		}

		// Receive '+' (ack) or '-' (nak) from GDB
		char ch = recv_ack_nack();
		if (ch == '+') {
			printf("Received ack ('+') from GDB \n");
		    return 1;
		} else {
			printf ("Received nak ('-') from GDB\n");
		    continue; // goto err_exit;
		}
   	}	

	err_exit:
    	return -1;
		
}





int send_ack_nak(char ack_char) {
	size_t n_iters = 0;
	while(true) {
		ssize_t n = write(conn_sock, &ack_char, 1);
		if (n < 0) {
			printf("ERROR: write ack_char to gdb failed\n");
			perror(NULL);
			return -1;
		} else if (n == 0) {
			if (n_iters > 1000000) {
				printf("ERROR: nothing sent in 1,000,000 write attempts\n");
				return -1;
			}
			usleep(5);
			n_iters++;
		} else {
			return 0;
		}
	}
}


ssize_t recv_rsp_pkt_gdb(char *buf, const size_t buf_size) {
	char wire_buf[GDB_RSP_WIRE_BUF_MAX];
	size_t free_ptr = 0;
	ssize_t n;

	n = read(conn_sock, &(wire_buf[free_ptr]), (GDB_RSP_WIRE_BUF_MAX - free_ptr));
	if (n < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
			// nothing available yet
		} else {
			printf("recieving a packet from gdb failed\n");
			return -1;
		}
	} else if (n == 0) {
		// eof
		printf("reading EOF from gdb\n");
		return -1;
	} else {
		free_ptr += (size_t) n;
	}




	size_t start = 0;
	while((wire_buf[start] != '$') && (wire_buf[start] != control_c) && (start < free_ptr)) {
		start++;
	}

	// discarding garbage if present
	if (start != 0) {
		printf("WARNING: got junk char before '$'; ignoring \n");
		memmove(wire_buf, &(wire_buf[start]), free_ptr - start);
		free_ptr -= start;
	}	
	
	if (free_ptr == 0) {
		// no '$' or '^C' found
		printf("No '$' or '^C' found\n");
		return 0;
	}

	// Checking for ^C
	if (wire_buf[0] == control_c) {
		if (buf_size < 2) {
			printf("ERROR: buf size is too small\n");
			return -1;
		}

		printf("recieve packet from GDB: returning ctrl+c\n");

		// discarding the packet
		memmove(wire_buf, &(wire_buf[1]), (free_ptr - 1));
		free_ptr--;
		
		buf[0] = control_c;
		buf[1] = 0;
		return 1;
	}

	// if we reach till here we probably have a '$' from the GDB
	
	// scan for the ending '#' of the packet from [1] onwards
	size_t end = 1;
	while (wire_buf[end] != '#') {
		if (end == (free_ptr - 1))
			return 0;
		end++;
	}

	// if we reach till here we probably have '#' at the end of packet

	// check if we have received the two checksum chars after '#'
	if ((free_ptr - end) < 3) {
		// not yet
		return 0;
	}

	// if we reach till here we probably have received a complete packet
	// we will send either a '+' or a '-' acknowledgement

	// compute the checksum of the received chars
	uint8_t computed_checksum = gdb_checksum(&(wire_buf[1]), (end - 1));

	// decode the received checksum
	char chkstr[3] = {(char) wire_buf[end+1], (char) wire_buf[end+2], 0};
	uint8_t received_checksum = (uint8_t) strtoul(chkstr, NULL, 16);

	char ack_char;

	ssize_t ret;	// final return value
	if (computed_checksum != received_checksum) {
		// checksum failed
		ack_char = '-';
		ret = -1;
		printf("ERROR: computed checksum did not match the received checkum\n");
	} else {
		// checkum passed
		ack_char = '+';
		// copy the content to output buf, unescaping as necessary
		ret = gdb_unescape(buf, buf_size, &(wire_buf[1]), (end - 1)); 
	}


	n = send_ack_nak(ack_char);
	if (n < 0)
		ret = -1;

	// discard the packet
	memmove(wire_buf, &(wire_buf[end]), (free_ptr - (end + 3)));
	free_ptr -= (end + 3);

	return ret;

}


void handle_rsp_stop_reason(const char *buf, const size_t buf_len) {
	char response[8];
	snprintf(response, 8, "T%02x", 0x05);
	send_rsp_pkt_to_gdb(response, strlen(response));
}


void handle_rsp_g(const char *buf, const size_t buf_len) {
	// called when gdb sends a 'g' reequest meaning read all registers
	printf("handle all registers read called \n");
	uint64_t value;
	char response[33*16];
	const size_t ASCII_hex_digits = 32 / (8 / 2);
	
	// all riscv 32 registers
	uint8_t j;
	for (j = 0; j < 32; j++)  {
		value = 0;
		val_to_hex16(value, 32, &(response[j * ASCII_hex_digits]));	
	}

	// for PC. Just sending value 0 for now
	val_to_hex16(0, 32, &(response[32 * ASCII_hex_digits]));
	
	// send the final assembled response
	send_rsp_pkt_to_gdb(response, 33 * ASCII_hex_digits);	
}




void handle_rsp_q(const char *buf, const size_t buf_len) {
	printf("The handle rsp q function was called. \n");
	if (strncmp("qSupported", buf, strlen("qSupported")) == 0) {
		char response [32];
		snprintf(response, 32, "PacketSize=%x", GDB_RSP_PKT_BUF_MAX);
		send_rsp_pkt_to_gdb(response, strlen(response));
	} else if (strncmp("qTStatus", buf, strlen("qTStatus")) == 0) {
		printf("Got qTStatus demand from gdb. Need to implement response from it\n");
		char response [32];
		snprintf(response, 32, "T%d", 0);
		send_rsp_pkt_to_gdb(response, strlen(response));
	} else {
		char response[] = "";
		send_rsp_pkt_to_gdb(response, strlen(response));
	 }
}

int main(int argc, char const *argv[]) {
	int server_fd;     
	struct sockaddr_in address;
	int addrlen = sizeof(address);	
	char gdb_rsp_pkt_buf[GDB_RSP_PKT_BUF_MAX];
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( PORT );

	int connection = bind(server_fd, (struct sockaddr *)&address, sizeof(address));
	
	if (connection < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);	
	}

	if(listen(server_fd, 3) < 0) {
		perror("listen error");
		exit(EXIT_FAILURE);
	}

			
	conn_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
	if (conn_sock < 0) {
		perror("acception error");
		exit(EXIT_FAILURE);
	}
	
	char r = recv_ack_nack();
	if (r != '+') {
		printf("Did not get a + response from gdb.. exiting\n");
		goto done;
	} else if (r == 'E') {
		printf("Error receiving response from gdb.. exiting\n");
		goto done;
	}

	while(true) {
		ssize_t sn = recv_rsp_pkt_gdb(gdb_rsp_pkt_buf, GDB_RSP_PKT_BUF_MAX);		
		printf("value of sn is: %ld\n", sn);
		if (sn < 0) {
			printf("ERROR: on receiving response packet from GDB\n");
			break;
		} else if (sn == 0) {
			// complete packet not yet arrived from the GDB
			usleep(10);
			continue;
		} else {
			size_t n = (size_t) sn;
			if (gdb_rsp_pkt_buf [0] == control_c) {
				printf("got control c\n");
        	} else if (gdb_rsp_pkt_buf [0] == '?') {

				printf("got ?\n");
				handle_rsp_stop_reason(gdb_rsp_pkt_buf, n);

        	} else if (gdb_rsp_pkt_buf [0] == 'c') {
				printf("got c\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'D') {
				printf("got D\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'g') {

				handle_rsp_g(gdb_rsp_pkt_buf, n);

        	} else if (gdb_rsp_pkt_buf [0] == 'G') {
				printf("got G\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'm') {
				printf("got m\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'M') {
				printf("got M\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'p') {
				printf("got p\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'P') {
				printf("got P\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'q') {
				printf("got q\n");
				handle_rsp_q(gdb_rsp_pkt_buf, n);
        	} else if (gdb_rsp_pkt_buf [0] == 's') {
				printf("got s\n");
        	} else if (gdb_rsp_pkt_buf [0] == 'X') {
				printf("got X\n");
        	} else {
				printf("WARNING: Unrecognized packet\n");
       	    	send_rsp_pkt_to_gdb("", 0);
			}


    	}
	}
		


	done:
		close(conn_sock);

	return 0;
}

