
// -------------------------------------------------------
// File:            TCP.C
// Project:         Hermes
// Description:     TCP transport layer protocol
//                  implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Dec 10, 2010
// Last Revision:   May 16, 2011
// Revision ID:     6
// -------------------------------------------------------
// Functions:       tcp_checksum()
//                  make_header()
//                  ack_send()
//                  parse_tcp()
//                  tcp_listen()
//                  tcp_open()
//                  tcp_close()
//                  tcp_new()
//                  tcp_send()
//                  tcp_send_text()
//                  tcp_read()
//                  tcp_get_port()
//                  tcp_is_open()
//                  tcp_has_data()
//                  tcp_init()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "cronos.h"
#include "hermes.h"
#include "utils.h"
#include "checksum.h"

#ifdef _TCP

// -----------------
// timming constants
// -----------------
#define MAX_RETRIES             5
#define TIMEOUT_TCP             500
#define TIMEOUT_SYN             200

// ----------------
// TCP header flags
// ----------------
#define URG                     0x20
#define ACK                     0x10
#define PSH                     0x08
#define RST                     0x04
#define SYN                     0x02
#define FIN                     0x01

// ------------------
// TCP sockets status
// ------------------
typedef struct {
    IPV4 peer;
    UInt16 p_rem;
    UInt16 p_loc;
    PPBUF buf;                              // last TCP message
    _UInt32 ack;                            // remote sequence number
    _UInt32 seq;                            // local sequence number
    _UInt32 next;                           // pending sequence number
    union {
        struct {
            bit(f_enabled);
            bit(f_listen);
            bit(f_close);
            bit(f_syn);
            bit(f_fin);
            bit(f_ack);
            bit(f_rst);
        };
        BYTE flags;
    };
    BYTE interface;
} SOCKET_TCP;
SOCKET_TCP sockets_tcp[MAX_SOCKETS_TCP];

#define MASK_FLAGS              0b01111000

// --------------------
// local port selection
// --------------------
static UInt16 next_p_loc;
#define MIN_P_LOC               1024
#define MAX_P_LOC               32767

static BYTE *ptr;
static UInt16 size;
static BYTE ind;
static SOCKET_TCP *sckt;

#define IPH(xxx) ((IP_HDR *)xxx)
#define TCPH(xxx) ((TCP_HDR *)xxx)

// ------------------------------------------------
// Function:        tcp_checksum()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Computes TCP message checksum
// ------------------------------------------------
void tcp_checksum(PPBUF pbuf)
{
    size = pbuf->size;
    ptr = pbuf->data;

    // -------------------
    // Check for odd sizes
    // -------------------
    if(size & 0x01) {
        ptr[size] = 0x00;                      // add a pad to make it even
        size++;
    }

    // -------------------------
    // computes message checksum
    // -------------------------
    check_init();
    while(size) {
        check_update(*ptr);
        ptr++;
        size--;
    }

    // ---------------------------------
    // account for the TCP pseudo-header
    // ---------------------------------
    size = pbuf->size;
    ptr = (BYTE *)&IPH(pbuf->start)->source;
    for(ind=0; ind<8; ind++)
        check_update(*ptr++);
    check_update(0);
    check_update(IPH(pbuf->start)->prot);
    check_update(HIGH(size));
    check_update(LOW(size));
}

// ------------------------------------------------
// Function:        make_header()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Adds a default TCP header into
//                  the message buffer
// ------------------------------------------------
void make_header(PPBUF pbuf)
{
    pbuf->size += sizeof(TCP_HDR);

    TCPH(pbuf->data)->src_port = HTONS(sckt->p_loc);
    TCPH(pbuf->data)->dst_port = HTONS(sckt->p_rem);
    TCPH(pbuf->data)->hlen = 0x05 << 4;
    TCPH(pbuf->data)->flags = 0;
    TCPH(pbuf->data)->window = HTONS((UInt16)MSS);
    TCPH(pbuf->data)->checksum = 0;
    TCPH(pbuf->data)->urgent = 0;

    // ----------------
    // sequence numbers
    // ----------------
    TCPH(pbuf->data)->n_seq.b[0] = sckt->seq.b[3];
    TCPH(pbuf->data)->n_seq.b[1] = sckt->seq.b[2];
    TCPH(pbuf->data)->n_seq.b[2] = sckt->seq.b[1];
    TCPH(pbuf->data)->n_seq.b[3] = sckt->seq.b[0];

    TCPH(pbuf->data)->n_ack.b[0] = sckt->ack.b[3];
    TCPH(pbuf->data)->n_ack.b[1] = sckt->ack.b[2];
    TCPH(pbuf->data)->n_ack.b[2] = sckt->ack.b[1];
    TCPH(pbuf->data)->n_ack.b[3] = sckt->ack.b[0];
}

// ------------------------------------------------
// Function:        ack_send()
// ------------------------------------------------
// Input:           Flags to send
// Output:          -
// ------------------------------------------------
// Description:     Sends an empty TCP packet with
//                  the specified flags
// ------------------------------------------------
BOOL ack_send(BYTE flags)
{
    PPBUF buf;

    buf = ip_new(sckt->peer, 64, sckt->interface);
    if(buf == NULL) return FALSE;

    make_header(buf);
    TCPH(buf->data)->flags = flags;
    sckt->flags &= (~MASK_FLAGS);

    tcp_checksum(buf);
    TCPH(buf->data)->checksum = HTONS(~WORDOF(chk_H, chk_L));

    ip_send(buf);
    release_buffer(buf);
    return TRUE;
}	

// ------------------------------------------------
// Function:        parse_tcp()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Parse incoming TCP messages
// ------------------------------------------------
void parse_tcp(PPBUF pbuf)
{
    SOCKET_TCP *s;
    BYTE flags;
    BYTE hdr;
    BYTE i;

    TCPH(pbuf->data)->dst_port = NTOHS((TCPH(pbuf->data)->dst_port));
    TCPH(pbuf->data)->src_port = NTOHS((TCPH(pbuf->data)->src_port));

    // ---------------------
    // find an active socket
    // ---------------------
    s = sockets_tcp;
    for(i=0; i<MAX_SOCKETS_TCP; i++, s++) {
        if(!s->f_enabled) continue;
        if(TCPH(pbuf->data)->dst_port != s->p_loc) continue;    // check service port
        if(s->f_listen) goto parse;                             // no more tests if socket is listening
        if(TCPH(pbuf->data)->src_port != s->p_rem) continue;    // check active connection: port
        if(IPH(pbuf->start)->source.d != s->peer.d) continue;   // check active connection: IP address
        goto parse;
    }

#ifdef _NAT
    // -----------------------------------------
    // no socket for processing, try NAT routing
    // -----------------------------------------
    retain_buffer(pbuf);
    pbuf->protocol = BUFFER_NAT_TCP;
#endif
	
    // ----------------------------------
    // no socket for processing, dischard
    // ----------------------------------
    return;

parse:
    // ---------------------
    // calculate header size
    // ---------------------
    hdr = TCPH(pbuf->data)->hlen;
    hdr = (hdr & 0xf0) >> 2;

    if((pbuf->size > hdr) && (s->buf))                          // do not overwrite previous data
            return;

    // --------------------
    // update socket status
    // --------------------
    s->peer = IPH(pbuf->start)->source;
    s->p_rem = TCPH(pbuf->data)->src_port;
    s->interface = pbuf->interface;

    // ----------------
    // flags processing
    // ----------------
    flags = TCPH(pbuf->data)->flags;
    if(flags & ACK) {
        // -----------------------------
        // check pending sequence number
        // -----------------------------
        if((s->next.b[0] != TCPH(pbuf->data)->n_ack.b[3]) ||
           (s->next.b[1] != TCPH(pbuf->data)->n_ack.b[2]) ||
           (s->next.b[2] != TCPH(pbuf->data)->n_ack.b[1]) ||
           (s->next.b[3] != TCPH(pbuf->data)->n_ack.b[0])) {
            return;                                             // incorrect sequence: dischard packet
        }

        // -------------------------------------
        // sequence numbers match, accept packet
        // -------------------------------------
        s->seq.d = s->next.d;
        s->f_ack = TRUE;
    } else s->f_ack = FALSE;
	
    if(flags & SYN) {
        // -----------------------------------
        // update socket with sync information
        // -----------------------------------
        s->ack.b[0] = TCPH(pbuf->data)->n_seq.b[3];
        s->ack.b[1] = TCPH(pbuf->data)->n_seq.b[2];
        s->ack.b[2] = TCPH(pbuf->data)->n_seq.b[1];
        s->ack.b[3] = TCPH(pbuf->data)->n_seq.b[0];
        s->ack.d++;                                             // SYN flag takes one sequence number
        s->f_syn = TRUE;
    } else {
        // ----------------------------
        // check remote sequence number
        // ----------------------------
        if((TCPH(pbuf->data)->n_seq.b[0] != s->ack.b[3]) ||
           (TCPH(pbuf->data)->n_seq.b[1] != s->ack.b[2]) ||
           (TCPH(pbuf->data)->n_seq.b[2] != s->ack.b[1]) ||
           (TCPH(pbuf->data)->n_seq.b[3] != s->ack.b[0])) {
            if(pbuf->size > hdr) {
                sckt = s;
                envia_ack(ACK);                                 // sends back the expected sequence number
            }
            return;
        }

        // -------------------------------------
        // sequence numbers match, accept packet
        // -------------------------------------
        s->ack.d += (pbuf->size - hdr);
        s->f_syn = FALSE;
    }

    if(flags & FIN) {
        s->ack.d++;                                             // FIN flag takes one sequence number
        s->f_fin = TRUE;
        if(!s->f_close) {
            // --------------------------------
            // disconnecttion initiated by peer
            // --------------------------------
            sckt = s;
            envia_ack(FIN | ACK);
            s->flags = 0;                                       // close socket
            os_signal(SIG_TCP+i);
            return;
        }
    } else s->f_fin = FALSE;

    if(flags & RST) {
        s->flags = 0;                                           // force disconnection
        os_signal(SIG_TCP+i);
        return;
    }

    if(pbuf->size > hdr) {
        // ------------------------------------
        // packet contains data for application
        // ------------------------------------
        retain_buffer(pbuf);
        pbuf->data += hdr;
        pbuf->ptr = pbuf->data;
        pbuf->size -= hdr;
        s->buf = pbuf;
    }

    os_signal(SIG_TCP+i);                                       // send signal to waiting threads
}

// ------------------------------------------------
// Function:        tcp_listen()
// ------------------------------------------------
// Input:           Socket ID
//                  Service TCP port
// Output:          TRUE when client connected
// ------------------------------------------------
// Description:     Start listening for a TCP
//                  connection on the specified 
//                  port address
// ------------------------------------------------
BOOL tcp_listen(BYTE n, UInt16 p_loc)
{
    BYTE retry;
    SOCKET_TCP *s;

    if(n > MAX_SOCKETS_TCP) return FALSE;
    s = &sockets_tcp[n];
    if(s->f_enabled || s->f_listen) return FALSE;

    // -----------------------------
    // socket in the listening state
    // -----------------------------
    s->flags = 0;
    s->f_enabled = TRUE;
    s->f_listen = TRUE;
    s->p_loc = p_loc;

    // ----------------------------
    // wait for a remote connection
    // ----------------------------
    if(!os_wait(SIG_TCP+n)) goto error;
    if(!s->f_syn) goto error;
    if(s->f_rst || s->f_fin) goto error;

    s->next.d = s->seq.d + 1;
    s->f_listen = FALSE;

    // ---------------------------
    // proceed with the connection
    // ---------------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        sckt = s;
        ack_send(SYN | ACK);
        os_set_timeout(TIMEOUT_TCP);
        os_wait(SIG_TCP+n);
        if(s->f_ack) return TRUE;                               // ack received, connection stablished
        retry++;
    }

error:
    // -----------------
    // connection failed
    // -----------------
    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }
    s->flags = 0;
    return FALSE;
}

// ------------------------------------------------
// Function:        tcp_open()
// ------------------------------------------------
// Input:           Socket ID
//                  Local TCP port
//                  Server IP address
//                  Destination service TCP port
//                  Network interface ID
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Connects a socket to a remote
//                  TCP service
// ------------------------------------------------									   
BOOL tcp_open(BYTE n, UInt16 p_loc, IPV4 ip_rem, UInt16 p_rem, BYTE interface)
{
    BYTE retry;
    SOCKET_TCP *s;

    if(n > MAX_SOCKETS_TCP) return FALSE;
    s = &sockets_tcp[n];
    if(s->f_enabled || s->f_listen) return FALSE;

    // ------------------------
    // prepare socket structure
    // ------------------------
    s->f_enabled = TRUE;
    s->interface = interface;
    s->f_listen = FALSE;
    s->p_loc = p_loc;
    s->p_rem = p_rem;
    s->peer.d = ip_rem.d;
    s->next.d = s->seq.d + 1;

    // --------------------
    // connection procedure
    // --------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        sckt = s;
        ack_send(SYN);

        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+n)) {
            if(s->f_rst) goto error;
            if(s->f_ack && s->f_syn) goto done;
            if(s->f_ack) goto syn_wait;
            if(s->f_syn) goto ack_wait;
        }
        retry++;
    }

error:
    // -----------------
    // connection failed
    // -----------------
    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }
    s->flags = 0;
    return FALSE;

syn_wait:
    // -------------------------
    // ack received, waiting syn
    // -------------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+n)) {
            if(s->f_rst) goto error;
            if(s->f_syn) goto done;
        }
        retry++;
    }
    goto error;
	
ack_wait:
    // -------------------------
    // syn received, waiting ack
    // -------------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        sckt = s;
        ack_send(ACK);

        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+n)) {
            if(s->f_rst) goto error;
            if(s->f_ack) goto done;
        }
        retry++;
    }
    goto error;

done:
    // ---------------------
    // connection stablished
    // ---------------------
    sckt = s;
    ack_send(ACK);
    return TRUE;
}

// ------------------------------------------------
// Function:        tcp_close()
// ------------------------------------------------
// Input:           Socket ID
// Output:          -
// ------------------------------------------------
// Description:     Closes a TCP connection
// ------------------------------------------------
void tcp_close(BYTE n)
{
    BYTE retry;
    SOCKET_TCP *s;

    if(n > MAX_SOCKETS_TCP) return;
    s = &sockets_tcp[n];
    if(!s->f_enabled) return;

    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }

    s->f_close = TRUE;
    s->next.d = s->seq.d + 1;                                // FIN flag takes one sequence number

    // -----------------------
    // disconnection procedure
    // -----------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        sckt = s;
        ack_send(ACK | FIN);

        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+n)) {
            if(s->f_rst) goto error;
            if(s->f_ack && s->f_fin) goto done;
            if(s->f_ack) goto fin_wait;
            if(s->f_fin) goto ack_wait;
        }
        retry++;
    }

error:
    // ---------------------------
    // normal disconnection failed
    // ---------------------------
    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }
    s->flags = 0;
    return;

fin_wait:
    // -------------------------
    // ack received, waiting fin
    // -------------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+n)) {
            if(s->f_rst) goto error;
            if(s->f_fin) goto done;
        }
        retry++;
    }
    goto error;
	
ack_wait:
    // -------------------------
    // fin received, waiting ack
    // -------------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        sckt = s;
        ack_send(ACK);

        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+n)) {
            if(s->f_rst) goto error;
            if(s->f_ack) goto done;
        }
        retry++;
    }
    goto error;

done:
    // ---------------------------------------
    // disconnection procedure ended correctly
    // ---------------------------------------
    sckt = s;
    ack_send(ACK);
    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }
    s->flags = 0;
}

// ------------------------------------------------
// Function:        tcp_reset()
// ------------------------------------------------
// Input:           Socket ID
// Output:          -
// ------------------------------------------------
// Description:     Resets a socket
// ------------------------------------------------
void tcp_reset(BYTE n)
{
    SOCKET_TCP *s;

    if(n > MAX_SOCKETS_TCP) return;
    s = &sockets_tcp[n];
    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }

    // --------------------------
    // sends a reset if necessary
    // --------------------------
    if(s->f_enabled) {
        sckt = s;
        ack_send(ACK | RST);
    }
    s->flags = 0;
}

// ------------------------------------------------
// Function:        tcp_new()
// ------------------------------------------------
// Input:           Socket ID
// Output:          buffer to fill-in
// ------------------------------------------------
// Description:     Prepares a buffer for sending
//                  TCP data
// ------------------------------------------------
PPBUF tcp_new(BYTE s)
{
    PPBUF new;

    if(s > MAX_SOCKETS_TCP) return NULL;
    sckt = &sockets_tcp[s];

    new = ip_new(sckt->peer, MSS, sckt->interface);
    if(new == NULL) return NULL;

    make_header(new);
    TCPH(new->data)->flags = ACK | PSH;

    new->data += sizeof(TCP_HDR);
    new->ptr = new->data;
    new->size = 0;
    IPH(new->start)->prot = IP_PROT_TCP;
    return new;
}

// ------------------------------------------------
// Function:        tcp_send()
// ------------------------------------------------
// Input:           Packet to send
// Output:          -
// ------------------------------------------------
// Description:     Sends a previously allocated
//                  and filled TCP packet
// ------------------------------------------------
BOOL tcp_send(BYTE id, PPBUF pbuf)
{
    SOCKET_TCP *s;
    BYTE retry;

    if(id > MAX_SOCKETS_TCP) return FALSE;
    s = &sockets_tcp[id];
    if(!s->f_enabled) return FALSE;
    if(s->f_listen) return FALSE;
    if(s->buf) return FALSE;

    // -------------------------------
    // update sequence and packet size
    // -------------------------------
    s->next.d = s->seq.d + pbuf->size;
    pbuf->data -= sizeof(TCP_HDR);
    pbuf->size += sizeof(TCP_HDR);

    // --------
    // checksum
    // --------
    tcp_checksum(pbuf);
    TCPH(pbuf->data)->checksum = HTONS(~WORDOF(chk_H, chk_L));

    // ----------------------
    // send data and wait ack
    // ----------------------
    retry = 0;
    while(retry < MAX_RETRIES) {
        s->flags &= (~MASK_FLAGS);
        ip_send(pbuf);
        os_set_timeout(TIMEOUT_TCP);
        if(os_wait(SIG_TCP+id)) {
            if(s->f_rst) break;
            if(s->f_ack) return TRUE;
        }
        retry++;
    }

    // --------------------------------
    // socket error, half disconnection
    // --------------------------------
    if(s->buf) {
        release_buffer(s->buf);
        s->buf = NULL;
    }
    s->flags = 0;
    return FALSE;
}

// ------------------------------------------------
// Function:        tcp_send_text()
// ------------------------------------------------
// Input:           Socket ID
//                  String to send
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Sends a string through a TCP
//                  connection
// ------------------------------------------------
BOOL tcp_send_text(BYTE id, char *texto)
{
    PPBUF buf;
    BYTE res;

    buf = tcp_new(id);
    if(buf == NULL) return FALSE;
    write_string(buf, texto);

    res = tcp_send(id, buf);
    release_buffer(buf);
    return res;
}

// ------------------------------------------------
// Function:        tcp_read()
// ------------------------------------------------
// Input:           Socket ID
// Output:          Last packet or NULL
// ------------------------------------------------
// Description:     Returns the received TCP
//                  packet, NULL if error
// ------------------------------------------------
PPBUF tcp_read(BYTE n)
{
    SOCKET_TCP *s;
    PPBUF res;

    if(n > MAX_SOCKETS_TCP) return NULL;
    s = &sockets_tcp[n];
    if(!s->f_enabled) return NULL;

    if(s->buf == NULL)                                      // check for pending data
        os_wait(SIG_TCP+n);                                 // wait for TCP data

    if(s->buf == NULL) return NULL;

    // ---------------------
    // acknowledges the data
    // ---------------------
    sckt = s;
    envia_ack(ACK);

    res = s->buf;
    s->buf = NULL;
    return res;
}	

// ------------------------------------------------
// Function:        tcp_get_port()
// ------------------------------------------------
// Input:           -
// Output:          Local port address
// ------------------------------------------------
// Description:     Returns the next unused local
//                  port address
// ------------------------------------------------
UInt16 tcp_get_port(void)
{
    SOCKET_TCP *s;
    BYTE i;
    UInt16 p;

    p = next_p_loc;

    // --------------------
    // check active sockets
    // --------------------
search:
    s = sockets_tcp;
    for(i=0; i<MAX_SOCKETS_TCP; i++, s++) {
        if(!s->f_enabled) continue;
        if(!s->f_listen) continue;
        if(s->p_loc == p) {
            if(++p > MAX_P_LOC) p = MIN_P_LOC;
            goto search;
        }
    }

    // -----------------------
    // update next port number
    // -----------------------
    next_p_loc = p + 1;
    if(next_p_loc > MAX_P_LOC) next_p_loc = MIN_P_LOC;

    return p;
}
	
// ------------------------------------------------
// Function:        tcp_is_open()
// ------------------------------------------------
// Input:           Socket ID
// Output:          TRUE if socket is active
// ------------------------------------------------
// Description:     Returns TRUE if socket is
//                  connected or listening
// ------------------------------------------------
BOOL tcp_is_open(BYTE s)
{
    if(s > MAX_SOCKETS_TCP) return FALSE;
    return sockets_tcp[s].f_enabled;
}	

// ------------------------------------------------
// Function:        tcp_has_data()
// ------------------------------------------------
// Input:           Socket ID
// Output:          TRUE if data pending
// ------------------------------------------------
// Description:     Polls the socket for incoming
//                  pending application data
// ------------------------------------------------
BOOL tcp_has_data(BYTE s)
{
    if(s > MAX_SOCKETS_TCP) return FALSE;
    if(sockets_tcp[s].buf == NULL) return FALSE;
    return TRUE;
}	

// ------------------------------------------------
// Function:        tcp_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     TCP protocol initialization
// ------------------------------------------------
void tcp_init(void)
{
    os_set((BYTE *)sockets_tcp, 0, sizeof(sockets_tcp));
    next_p_loc = MIN_P_LOC;
}

#endif
