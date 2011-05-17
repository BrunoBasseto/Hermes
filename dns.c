
// -------------------------------------------------------
// File:            DNS.C
// Project:         Hermes
// Description:     DNS name resolving protocol
//                  implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Jan 27, 2011
// Last Revision:   May 16, 2011
// Revision ID:     1
// -------------------------------------------------------
// Functions:       dns_send()
//                  skip_field()
//                  parse_dns()
//                  dns_inicia()
//                  dns_get_ip()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "cronos.h"
#include "net.h"
#include "hermes.h"

#ifdef _DNS

#ifndef _UDP
#error "UDP must be installed for using DNS"
#endif

IPV4 ip_dns[MAX_INTERFACES];                        // DNS server address
UInt16 id_dns;                                      // DNS transaction ID

#define DNS_TIMEOUT             500
#define MAX_RETRIES             3

#define DNS(xxx) ((DNS_HDR *)xxx)

// ------------------------------------------------
// Function:        dns_send()
// ------------------------------------------------
// Input:           URL
// Output:          -
// ------------------------------------------------
// Description:     Send a query message to the
//                  DNS server
// ------------------------------------------------
void dns_send(char *url)
{
    PPBUF buf;
    BYTE *p;
    BYTE *q;
    BYTE n;

    buf = udp_new(SOCKET_DNS);
    if(buf == NULL) return;

    // -----------------
    // DNS query message
    // -----------------
    DNS(buf->data)->id = id_dns;
    DNS(buf->data)->flags = 0x0001;                     // 0x100 = standard query
    DNS(buf->data)->qdcount = 0x0100;                   // 0x001, single query
    DNS(buf->data)->ancount = 0;
    DNS(buf->data)->nscount = 0;
    DNS(buf->data)->arcount = 0;

    // --------------
    // translates URL
    // --------------
    p = buf->data + sizeof(DNS_HDR);
    q = p++;
    n = 0;
    while(*url) {
        if(*url == '.') {
            *q = n;
            q = p;
            n = 0;
        } else {
            *p = *url;
            n++;
        }
        p++;
        url++;
    }
    *q = n;
    *p++ = 0;
    *p++ = 0;                                           // QTYPE = 1, find IP address
    *p++ = 1;
    *p++ = 0;                                           // QCLASS = 1, internet
    *p++ = 1;

    buf->size = p - buf->data;
    udp_send(buf);
    release_buffer(buf);
}

// ------------------------------------------------
// Function:        skip_field()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Skips the current resource
//                  field
// ------------------------------------------------
void skip_field(PPBUF buf)
{	
    if((read_byte(buf) & 0xc0) == 0xc0) {
        // ---------------------------
        // packed string, skip address
        // ---------------------------
        read_byte(buf);
        return;
    }

    // ------------------
    // skip normal string
    // ------------------
    skip_string(buf);
}	

// ------------------------------------------------
// Function:        parse_dns()
// ------------------------------------------------
// Input:           Message buffer
//                  IP to update
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Process an incomming DNS
//                  message
// ------------------------------------------------
BOOL parse_dns(PPBUF buf, IPV4 *ip)
{
    UInt16 tmp;

    // -------------
    // verify answer
    // -------------
    if(DNS(buf->data)->ancount == 0) return FALSE;              // no answer
    if(DNS(buf->data)->id != id_dns) return FALSE;              // wrong id

    skip(buf, sizeof(DNS_HDR));                                 // skip header
    buf->data[buf->size] = 0;

    // ------------------
    // ignore query field
    // ------------------
    skip_field(buf);
    skip(buf, 4);

    // ------------
    // read answers
    // ------------
    while(!is_eof(buf)) {
        skip_field(buf);
        tmp = read_word(buf);
        skip(buf, 6);
        if(tmp == 1) {
            // ----------------------
            // IP address field found
            // ----------------------
            tmp = read_word(buf);
            if(tmp != 4) break;                                 // wrong size
            *ip = read_ip(buf);
            return TRUE;
        } else {
            // -----------------
            // other field, skip
            // -----------------
            tmp = read_word(buf);
            skip(buf, tmp);
        }
    }

    return FALSE;                                               // failed
}

// ------------------------------------------------
// Function:        dns_init()
// ------------------------------------------------
// Input:           URL
// Output:          -
// ------------------------------------------------
// Description:     DNS client initialization
// ------------------------------------------------
void dns_init(void)
{
//    ip_dns[0] = ext_ip_at(CFG_IP_DNS);
    id_dns = 0;
}

// ------------------------------------------------
// Function:        dns_get_ip()
// ------------------------------------------------
// Input:           URL
//                  Network interface ID
// Output:          URL IP or 0.0.0.0 if failed
// ------------------------------------------------
// Description:     Query the DNS sever for a
//                  specific URL
// ------------------------------------------------
IPV4 dns_get_ip(char *url, BYTE interface)
{
    IPV4 res;
    BYTE retry;
    UInt16 loc;
    PPBUF buf;

    res.d = 0;

    udp_close(SOCKET_DNS);
    loc = udp_get_port();
    if(!udp_open(SOCKET_DNS, loc, ip_dns[interface], UDP_DNS, interface)) goto end;

    retry = 0;
    id_dns = WORDOF(random(), random());
    while(retry < MAX_RETRIES) {
        dns_send(url);
        os_set_timeout(DNS_TIMEOUT);
        if(udp_listen(SOCKET_DNS, loc)) {
            buf = udp_read(SOCKET_DNS);
            parse_dns(buf, &res);
            break;
        }
        retry++;
    }

end:
    udp_close(SOCKET_DNS);
    return res;
}	

#endif
