
// -------------------------------------------------------
// File:            UDP.C
// Project:         Hermes
// Description:     UDP transport layer protocol
//                  implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Dec 10, 2010
// Last Revision:   May 15, 2011
// Revision ID:     3
// -------------------------------------------------------
// Functions:       udp_checksum()
//                  parse_udp()
//                  udp_listen()
//                  udp_read()
//                  udp_open()
//                  udp_close()
//                  udp_new()
//                  udp_send()
//                  udp_get_port()
//                  udp_has_data()
//                  udp_init()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "hermes.h"
#include "checksum.h"
#include "cronos.h"

#ifdef _UDP

// ------------------
// UDP sockets status
// ------------------
typedef struct {
    IPV4 peer;
    UInt16 p_rem;
    UInt16 p_loc;
    PPBUF buf;										// last UDP message
    struct {
        bit(f_enabled);
    };
    BYTE interface;
} SOCKET_UDP;
SOCKET_UDP sockets_udp[MAX_SOCKETS_UDP];

// --------------------
// local port selection
// --------------------
static UInt16 next_p_loc;
#define MIN_P_LOC			1024
#define MAX_P_LOC			32767

static BYTE *ptr;
static UInt16 size;
static BYTE ind;
static SOCKET_UDP *sckt;

#define IPH(xxx) ((IP_HDR *)xxx)
#define UDPH(xxx) ((UDP_HDR *)xxx)

// ------------------------------------------------
// Function:        udp_checksum()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Computes UDP message checksum
// ------------------------------------------------
void udp_checksum(PPBUF pbuf)
{
    size = pbuf->size;
    ptr = pbuf->data;

    // -------------------
    // Check for odd sizes
    // -------------------
    if(size & 0x01) {
        ptr[size] = 0x00;                           // add a pad to make it even
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
    // account for the UDP pseudo-header
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
// Function:        parse_udp()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Parse incoming UDP messages
// ------------------------------------------------
void parse_udp(PPBUF pbuf)
{
    UDPH(pbuf->data)->dst_port = NTOHS((UDPH(pbuf->data)->dst_port));
    UDPH(pbuf->data)->src_port = NTOHS((UDPH(pbuf->data)->src_port));

    // ---------------------
    // find an active socket
    // ---------------------
    sckt = sockets_udp;
    for(ind=0; ind<MAX_SOCKETS_UDP; ind++) {
        if(sckt->f_enabled && (UDPH(pbuf->data)->dst_port == sckt->p_loc))
            goto parse;
        sckt++;
    }

    // ----------------------------------
    // no socket for processing, dischard
    // ----------------------------------
    return;

parse:
    if(sckt->buf) return;                           // do not overwrite previous data

    // --------------------
    // update socket status
    // --------------------
    retain_buffer(pbuf);
    sckt->peer = IPH(pbuf->start)->source;
    sckt->p_rem = UDPH(pbuf->data)->src_port;
    sckt->buf = pbuf;
    sckt->interface = pbuf->interface;
    pbuf->data += sizeof(UDP_HDR);
    pbuf->ptr = pbuf->data;
    pbuf->size -= sizeof(UDP_HDR);

    os_signal(SIG_UDP+ind);                         // send signal to waiting threads
}

// ------------------------------------------------
// Function:        udp_listen()
// ------------------------------------------------
// Input:           Socket ID
//                  Service UDP port
// Output:          TRUE when a packet is received
//                  FALSE timeout (if specified)
// ------------------------------------------------
// Description:     Start listening for UDP packets
//                  on the specified port address
// ------------------------------------------------
BOOL udp_listen(BYTE n, UInt16 p_loc)
{
    if(n > MAX_SOCKETS_UDP) return FALSE;
    sckt = &sockets_udp[n];

    if(sckt->f_enabled && (sckt->buf != NULL))      // data already available
            return TRUE;

    // -----------------------------------
    // enables socket for packet reception
    // -----------------------------------
    sckt->p_loc = p_loc;
    sckt->f_enabled = TRUE;

    // -----------------
    // wait for a signal
    // -----------------
    return os_wait(SIG_UDP+n);
}

// ------------------------------------------------
// Function:        udp_read()
// ------------------------------------------------
// Input:           Socket ID
// Output:          Last packet or NULL
// ------------------------------------------------
// Description:     Returns the received UDP
//                  packet
// ------------------------------------------------
PPBUF udp_read(BYTE n)
{
    PPBUF res;

    if(n > MAX_SOCKETS_UDP) return NULL;
    sckt = &sockets_udp[n];

    if(!sckt->f_enabled) return NULL;               // socket is not enabled

    // ----------------------------------------------
    // returns last message for the application layer
    // ----------------------------------------------
    res = sckt->buf;
    sckt->buf = NULL;
    return res;
}	

// ------------------------------------------------
// Function:        udp_open()
// ------------------------------------------------
// Input:           Socket ID
//                  Local UDP port
//                  Server IP address
//                  Destination service UDP port
//                  Network interface ID
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Initiates a socket for
//                  accessing remote UDP services
// ------------------------------------------------
BOOL udp_open(BYTE n, UInt16 p_loc, IPV4 ip_rem, UInt16 p_rem, BYTE interface)
{
    if(n > MAX_SOCKETS_UDP) return FALSE;
    sckt = &sockets_udp[n];
    if(sckt->f_enabled) return FALSE;					// socket already in use

    // ---------------------------------------
    // update socket information and enable it
    // ---------------------------------------
    sckt->p_loc = p_loc;
    sckt->p_rem = p_rem;
    sckt->peer.d = ip_rem.d;
    sckt->interface = interface;
    sckt->f_enabled = TRUE;
    if(sckt->buf) release_buffer(sckt->buf);
    sckt->buf = NULL;
    return TRUE;
}

// ------------------------------------------------
// Function:        udp_close()
// ------------------------------------------------
// Input:           Socket ID
// Output:          -
// ------------------------------------------------
// Description:     Close a socket
// ------------------------------------------------
void udp_close(BYTE n)
{
    if(n > MAX_SOCKETS_UDP) return;
    sckt = &sockets_udp[n];

    // -------------------------
    // update socket information
    // -------------------------
    sckt->p_loc = 0;
    sckt->f_enabled = FALSE;
    if(sckt->buf) release_buffer(sckt->buf);
    sckt->buf = NULL;
}

// ------------------------------------------------
// Function:        udp_new()
// ------------------------------------------------
// Input:           Socket ID
// Output:          New packet to fill in or NULL
// ------------------------------------------------
// Description:     Creates a new packet for
//                  sending through the socket
// ------------------------------------------------
PPBUF udp_new(BYTE s)
{
    PPBUF new;

    if(s > MAX_SOCKETS_UDP) return NULL;
    sckt = &sockets_udp[s];

    new = ip_new(sckt->peer, MSS, sckt->interface);
    if(new == NULL) return NULL;

    // -------------
    // update header
    // -------------
    UDPH(new->data)->checksum = 0;
    UDPH(new->data)->src_port = HTONS(sckt->p_loc);
    UDPH(new->data)->dst_port = HTONS(sckt->p_rem);

    // --------------
    // prepare buffer
    // --------------
    new->data += sizeof(UDP_HDR);
    new->ptr = new->data;
    new->size = 0;
    IPH(new->start)->prot = IP_PROT_UDP;
    return new;
}

// ------------------------------------------------
// Function:        udp_send()
// ------------------------------------------------
// Input:           Packet to send
// Output:          -
// ------------------------------------------------
// Description:     Sends a previously allocated
//                  and filled UDP packet
// ------------------------------------------------
void udp_send(PPBUF pbuf)
{
    // ------------------
    // update packet size
    // ------------------
    pbuf->data -= sizeof(UDP_HDR);
    pbuf->size += sizeof(UDP_HDR);
    UDPH(pbuf->data)->length = HTONS(pbuf->size);

    // ----------------
    // compute checksum
    // ----------------
    udp_checksum(pbuf);
    UDPH(pbuf->data)->checksum = HTONS(~WORDOF(chk_H, chk_L));

    ip_send(pbuf);
}

// ------------------------------------------------
// Function:        udp_get_port()
// ------------------------------------------------
// Input:           -
// Output:          Local port address
// ------------------------------------------------
// Description:     Returns the next unused local
//                  port address
// ------------------------------------------------
UInt16 udp_get_port(void)
{
    SOCKET_UDP *s;
    BYTE i;
    WORD p;

    p = next_p_loc;

    // --------------------
    // check active sockets
    // --------------------
search:
    s = sockets_udp;
    for(i=0; i<MAX_SOCKETS_UDP; i++, s++) {
        if(!s->f_enabled) continue;
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
// Function:        udp_has_data()
// ------------------------------------------------
// Input:           Socket ID
// Output:          TRUE if data is pending
// ------------------------------------------------
// Description:     Verify if the socket has data
//                  for processing
// ------------------------------------------------
BOOL udp_has_data(BYTE s)
{
    if(s > MAX_SOCKETS_UDP) return FALSE;
    if(sockets_udp[s].buf == NULL) return FALSE;
    return TRUE;
}	

// ------------------------------------------------
// Function:        udp_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     UDP protocol initialization
// ------------------------------------------------
void udp_init(void)
{
    os_set((BYTE *)sockets_udp, 0, sizeof(sockets_udp));
    next_p_loc = MIN_P_LOC;
}

#endif
