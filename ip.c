
// -------------------------------------------------------
// File:            IP.C
// Project:         Hermes
// Description:     Network Layer implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Dec 10, 2010
// Last Revision:   May 15, 2011
// Revision ID:     10
// -------------------------------------------------------
// Functions:       make_ipv4()
//                  ip_checksum()
//                  ip_answer()
//                  ip_new()
//                  ip_send()
//                  parse_ip()
//                  ip_init()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "checksum.h"
#include "cronos.h"
#include "hermes.h"

// -----------------------
// IP protocol information
// -----------------------
IPV4 ip_local[MAX_INTERFACES];                      // IP local address for each network interface
IPV4 ip_mask[MAX_INTERFACES];                       // IP mask for each network interface
IPV4 ip_gateway[MAX_INTERFACES];                    // IP gateway for each network interface
UInt16 id;                                          // datagram ID

#define IPH(xxx) ((IP_HDR *)xxx)

// ------------------------------------------------
// Function:        make_ipv4()
// ------------------------------------------------
// Input:           4 IP octets
// Output:          IP address structure
// ------------------------------------------------
// Description:     Fills in a IP address structure
// ------------------------------------------------
IPV4 make_ipv4(BYTE a, BYTE b, BYTE c, BYTE d)
{
    IPV4 res;
    res.b[0] = a;
    res.b[1] = b;
    res.b[2] = c;
    res.b[3] = d;
    return res;
}	

// ------------------------------------------------
// Function:        ip_checksum()
// ------------------------------------------------
// Input:           Buffer, size
// Output:          -
// ------------------------------------------------
// Description:     Calculates IP header checksum
// ------------------------------------------------
void ip_checksum(BYTE *p, UInt16 t)
{
    check_init();
    while(t) {
        check_update(*p);
        p++;
        t--;
    }
}

// ------------------------------------------------
// Function:        ip_answer()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Reverts message to be sent back
//                  to sender
// ------------------------------------------------
void ip_answer(PPBUF pbuf)
{
    // -----------------
    // changes IP header
    // -----------------
    IPH(pbuf->start)->id = HTONS(id);
    IPH(pbuf->start)->checksum = 0;
    os_swap((BYTE *)&IPH(pbuf->start)->source,			// swap addresses
            (BYTE *)&IPH(pbuf->start)->dest,
            sizeof(IPV4));
    id++;
}	

// ------------------------------------------------
// Function:        ip_new()
// ------------------------------------------------
// Input:           Destination address
//                  Size
//                  Network interface ID
// Output:          Empty message buffer
// ------------------------------------------------
// Description:     Returns a free buffer to be
//                  filled with a higher level
//                  protocol
// ------------------------------------------------
PPBUF ip_new(IPV4 dest, UInt16 tam, BYTE interface)
{
    PPBUF pbuf;

    pbuf = get_buffer(tam);
    if(pbuf == NULL) return NULL;

    // ---------------
    // setup IP header
    // ---------------
    IPH(pbuf->start)->ver_length = 0x45;
    IPH(pbuf->start)->tos = TOSV;
    IPH(pbuf->start)->length = 0;
    IPH(pbuf->start)->id = HTONS(id);
    IPH(pbuf->start)->frag = 0;
    IPH(pbuf->start)->ttl = TTL;
    IPH(pbuf->start)->prot = IP_PROT_TCP;
    IPH(pbuf->start)->checksum = 0;
    IPH(pbuf->start)->source.d = ip_local[interface].d;
    IPH(pbuf->start)->dest.d = dest.d;
    id++;

    // --------------------
    // setup message buffer
    // --------------------
    pbuf->interface = interface;
    pbuf->data += sizeof(IP_HDR);
    pbuf->ptr = pbuf->data;
    pbuf->size = 0;
    return pbuf;
}	

// ------------------------------------------------
// Function:        ip_send()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Transfer an IP message to link
//                  layer
// ------------------------------------------------
void ip_send(PPBUF pbuf)
{
    // ------------------------
    // backup to message header
    // ------------------------
    pbuf->data = pbuf->start;

    // ------------
    // adjusts size
    // ------------
    pbuf->size += sizeof(IP_HDR);
    IPH(pbuf->start)->length = HTONS(pbuf->size);

    // ---------------
    // update checksum
    // ---------------
    IPH(pbuf->start)->checksum = 0;
    ip_checksum((BYTE *)pbuf->start, sizeof(IP_HDR));
    IPH(pbuf->start)->checksum = HTONS(~WORDOF(chk_H, chk_L));

    // ------------------------------
    // verify interface to link layer
    // ------------------------------
    switch(pbuf->interface) {
#ifdef _PPP
        case INTERFACE_PPP:
            ppp_send(pbuf, PPP_PROT_IP);
            break;
#endif
#ifdef _ETH			
        case INTERFACE_ETH:
            eth_send(pbuf, ETH_PROT_IP);
            break;
#endif
    }
	
    pbuf->size -= sizeof(IP_HDR);
}	

// ------------------------------------------------
// Function:        parse_ip()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Process a received IP message
// ------------------------------------------------
void parse_ip(PPBUF pbuf)
{
    UInt16 t;
    BYTE i;

    // -----------------
    // check packet size
    // -----------------
    t = NTOHS(IPH(pbuf->data)->length);
    if(pbuf->size < t) return;								// test for inconsistent sizes
    pbuf->size = t;											// remove pads
    t = (IPH(pbuf->data)->ver_length & 0x0f) << 2;			// IP header size
    i = pbuf->interface;
    if(i >= MAX_INTERFACES) return;							// test for inconsistent interfaces

    // --------------
    // tests checksum
    // --------------
    ip_checksum((BYTE *)pbuf->data, t);
    if(chk_H != 0xff) return;								// wrong checksum
    if(chk_L != 0xff) return;								// wrong checksum

    // -------------------------
    // check destination address
    // -------------------------
    if(IPH(pbuf->data)->dest.d != 0xffffffff)				// broadcast address?
        if(IPH(pbuf->data)->dest.d != ip_local[i].d)	  	// unicast address?
            return;											// not a local IP


    // --------------------------------
    // remove header and check protocol
    // --------------------------------
    pbuf->data += t;
    pbuf->ptr = pbuf->data;
    pbuf->size -= t;
    switch(IPH(pbuf->start)->prot) {
#ifdef _TCP
        case IP_PROT_TCP:
            retain_buffer(pbuf);
            pbuf->protocol = BUFFER_TCP;
            break;
#endif
#ifdef _UDP
        case IP_PROT_UDP:
            retain_buffer(pbuf);
            pbuf->protocol = BUFFER_UDP;
            break;
#endif
#ifdef _ICMP
        case IP_PROT_ICMP:
            retain_buffer(pbuf);
            pbuf->protocol = BUFFER_ICMP;
            break;
#endif
    }
}

// ------------------------------------------------
// Function:        ip_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Network layer initialization
// ------------------------------------------------
void ip_init(void)
{
    // AQUI

//	ip_local[0] = ext_ip_at(CFG_IP_LOCAL);
//	ip_local[1] = ext_ip_at(CFG_IP_LOCAL2);
//	ip_mask[1] = ext_ip_at(CFG_IP_MASK);
//	ip_gateway[1] = ext_ip_at(CFG_IP_GATEWAY);
}
