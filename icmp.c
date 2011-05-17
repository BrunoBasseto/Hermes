
// -------------------------------------------------------
// File:            ICMP.C
// Project:         Hermes
// Description:     ICMP Echo request/reply protocol
//                  implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Dec 10, 2010
// Last Revision:   May 15, 2011
// Revision ID:     2
// -------------------------------------------------------
// Functions:       icmp_checksum()
//                  ping_request()
//                  ping()
//                  icmp_parse()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "checksum.h"
#include "cronos.h"
#include "hermes.h"

#ifdef _ICMP

// ------------------
// ICMP Message types
// ------------------
#define PING_REQUEST                    8
#define PING_REPLY                      0

#define IPH(xxx) ((IP_HDR *)xxx)
#define ICMP(xxx) ((ICMP_HDR *)xxx)

#define MAX_PING                        5
#define TIMEOUT_PING                    300

// ------------------------------------------------
// Function:        icmp_checksum()
// ------------------------------------------------
// Input:           Pointer to data
//                  Size of data
// Output:          -
// ------------------------------------------------
// Description:     Computers ICMP message checksum
// ------------------------------------------------
void icmp_checksum(BYTE *p, BYTE t)
{
    // -------------------
    // check for odd sizes
    // -------------------
    if(t & 0x01) {
        p[t] = 0x00;						// add a pad for make it even
        t++;
    }

    // ----------------------
    // camputes data checksum
    // ----------------------
    check_init();
    while(t) {
        check_update(*p);
        p++;
        t--;
    }
}

// ------------------------------------------------
// Function:        ping_request()
// ------------------------------------------------
// Input:           IP address
//                  Network interface ID
// Output:          -
// ------------------------------------------------
// Description:     Sends a ping request message
// ------------------------------------------------
void ping_request(IPV4 ip, BYTE interface)
{
    PPBUF buf;

    buf = ip_new(ip, 64, interface);
    if(buf == NULL) return;

    // ---------------------
    // assemble ICMP message
    // ---------------------
    IPH(buf->start)->prot = IP_PROT_ICMP;
    ICMP(buf->data)->type = PING_REQUEST;
    ICMP(buf->data)->code = 0;
    ICMP(buf->data)->checksum = 0;
    ICMP(buf->data)->id = random();
    ICMP(buf->data)->seq = random();
    buf->size = sizeof(ICMP_HDR);

    // ------------------
    // calculate checksum
    // ------------------
    icmp_checksum(buf->data, buf->size);
    ICMP(buf->data)->checksum = HTONS(~WORDOF(chk_H, chk_L));

    // -----------------------------
    // sends message to IP interface
    // -----------------------------
    ip_send(buf);
    release_buffer(buf);
}	

// ------------------------------------------------
// Function:        ping()
// ------------------------------------------------
// Input:           Destination IP
//                  Network interface ID
// Output:          TRUE if server alive
// ------------------------------------------------
// Description:     Computers ICMP message checksum
// ------------------------------------------------
BOOL ping(IPV4 ip, BYTE interface)
{
    BYTE retry;
    retry = 0;
    while(retry < MAX_PING) {
        ping_request(ip, interface);
        os_set_timeout(TIMEOUT_PING);
        if(os_wait(SIG_ICMP)) return TRUE;
        retry++;
    }
    return FALSE;
}	

// ------------------------------------------------
// Function:        icmp_parse()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Parse a ICMP message
// ------------------------------------------------
void icmp_parse(PPBUF pbuf)
{
    // ---------------------
    // checksum verification
    // ---------------------
    icmp_checksum(pbuf->data, pbuf->size);
    if(chk_H != 0xff) return;
    if(chk_L != 0xff) return;

    // -------------------------------
    // checks recognized message types
    // -------------------------------
    switch(ICMP(pbuf->data)->type) {
        case PING_REQUEST:
            // ---------
            // answer it
            // ---------
            retain_buffer(pbuf);
            ip_answer(pbuf);
            ICMP(pbuf->data)->type = PING_REPLY;

            // ---------------
            // update checksum
            // ---------------
            ICMP(pbuf->data)->checksum = 0;
            icmp_checksum(pbuf->data, pbuf->size);
            ICMP(pbuf->data)->checksum = HTONS(~WORDOF(chk_H, chk_L));

            // ----------------------------
            // sends answer to IP interface
            // ----------------------------
            ip_send(pbuf);
            release_buffer(pbuf);
            break;

        case PING_REPLY:
            // --------------------------------------
            // answer received, signal waiting thread
            // --------------------------------------
            os_signal(SIG_ICMP);
            break;
    }
}
#endif
