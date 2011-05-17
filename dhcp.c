
// -------------------------------------------------------
// File:            DHCP.C
// Project:         Hermes
// Description:     DHCP implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Jan 27, 2011
// Last Revision:   May 17, 2011
// Revision ID:     2
// -------------------------------------------------------
// Functions:       dhcp_send()
//                  dhcp_discover()
//                  dhcp_req()
//                  dhcp_get_ip()
//                  dhcp_release_ip()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "cronos.h"
#include "hermes.h"

#ifdef _DHCP

#ifndef _UDP
#error "UDP must be installed for using DHCP"
#endif

#ifndef _ETH
#error "Ethernet network interface must be used"
#endif

// ------------------
// DHCP message types
// ------------------
#define DHCPDISCOVER                    1
#define DHCPOFFER                       2
#define DHCPREQUEST                     3
#define DHCPACK                         5
#define DHCPNAK                         6
#define DHCPRELEASE                     7

// -----------------
// DHCP option types
// ------------------
#define DHCP_OPT_TYPE                   53
#define DHCP_OPT_REQ                    55
#define DHCP_OPT_LTIME                  51
#define DHCP_OPT_MASK                   1
#define DHCP_OPT_ROUTER                 3
#define DHCP_OPT_DNS                    6
#define DHCP_OPT_ID                     61
#define DHCP_OPT_IP                     50
#define DHCP_OPT_RWTIME                 58
#define DHCP_OPT_RBTIME                 59
#define DHCP_OPT_END                    255

#define DHCP(xxx) ((BOOTP_HDR *)xxx)
#define IPH(xxx) ((IP_HDR *)xxx)

IPV4 ip_tmp;                                        // temp address
IPV4 ip_dhcp;                                       // DHCP server addres
_UInt32 xid;
static BYTE retry;
			
#define MAX_RETRIES                     10
#define TIMEOUT_DHCP_DISCOVER           1000
#define TIMEOUT_DHCP_REQUEST            300

// ------------------------------------------------
// Function:        dhcp_send()
// ------------------------------------------------
// Input:           Message type
//                  TRUE to broadcast answer
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Send a DHCP message
// ------------------------------------------------
BOOL dhcp_send(BYTE type, BOOL broadcast)
{
    PPBUF buf;

    buf = udp_new(SOCKET_DHCP);
    if(buf == NULL) return FALSE;

    DHCP(buf->data)->op = 1;                            // BOOTREQUEST
    DHCP(buf->data)->htype = 1;                         // ETH 10MBPS
    DHCP(buf->data)->hlen = 6;                          // 6 bytes ETH MAC
    DHCP(buf->data)->hops = 0;
    DHCP(buf->data)->xid = xid.d;
    DHCP(buf->data)->secs = 0;

    if(broadcast) {
        DHCP(buf->data)->flags = HTONS(0x8000);         // server must broadcast answer
        DHCP(buf->data)->ci.d = 0;
    } else {
        DHCP(buf->data)->flags = 0;                     // server must send unicast answer
        DHCP(buf->data)->ci.d = ip_local[INTERFACE_ETH].d;
    }

    DHCP(buf->data)->yi.d = 0;
    DHCP(buf->data)->gi.d = 0;
    DHCP(buf->data)->si.d = ip_dhcp.d;

    os_set((BYTE *)(&DHCP(buf->data)->chaddr), 0, 16+64+128);
    os_copy((BYTE *)&mac_local,
            (BYTE *)(&DHCP(buf->data)->chaddr),
            sizeof(MACADDR));

    // --------------
    // insert options
    // --------------
    skip(buf, BOOTP_HDR_SIZE);
    buf->size = BOOTP_HDR_SIZE;
    write_uint32(buf, 0x63825363);                      // magic cookie

    write_byte(buf, DHCP_OPT_TYPE);                     // DHCP message type
    write_byte(buf, 1);
    write_byte(buf, type);

    write_byte(buf, DHCP_OPT_ID);                       // DHCP source ID
    write_byte(buf, 7);
    write_byte(buf, 1);
    write_buf(buf, (BYTE *)&mac_local, sizeof(MACADDR));

    write_byte(buf, DHCP_OPT_IP);                       // Request IP address
    write_byte(buf, 4);
    write_ip(buf, ip_tmp);

#ifdef _DNS
    write_byte(buf, DHCP_OPT_REQ);                      // Request options
    write_byte(buf, 3);
    write_byte(buf, DHCP_OPT_MASK);
    write_byte(buf, DHCP_OPT_ROUTER);
    write_byte(buf, DHCP_OPT_DNS);
#else
    write_byte(buf, DHCP_OPT_REQ);                      // Request options
    write_byte(buf, 2);
    write_byte(buf, DHCP_OPT_MASK);
    write_byte(buf, DHCP_OPT_ROUTER);
#endif

    write_byte(buf, DHCP_OPT_END);                      // done with options

    udp_send(buf);
    release_buffer(buf);
    return TRUE;
}	

// ------------------------------------------------
// Function:        parse_dhcp()
// ------------------------------------------------
// Input:           Message buffer
// Output:          Opcode or 0xff if failed
// ------------------------------------------------
// Description:     Parse an incoming DHCP message
// ------------------------------------------------
BYTE parse_dhcp(PPBUF pbuf)
{
    BYTE opt;
    BYTE type, size;

    // ---------------------
    // jump to the data area
    // ---------------------
    skip(pbuf, BOOTP_HDR_SIZE);
    opt = 0xff;

    // -----------------
    // check DHCP fields
    // -----------------
    if(DHCP(pbuf->data)->op != 2) return 0xff;
    if(DHCP(pbuf->data)->xid != xid.d) return 0xff;
    if(read_uint32(pbuf) != 0x63825363) return 0xff;

    // ----------------
    // update temp data
    // ----------------
    ip_tmp.d = DHCP(pbuf->data)->yi.d;
    ip_dhcp.d = IPH(pbuf->start)->source.d;

    // -------------
    // parse options
    // -------------
    while(!is_eof(pbuf)) {
        type = read_byte(pbuf);
        size = read_byte(pbuf);
        switch(type) {
            case DHCP_OPT_TYPE:
                opt = read_byte(pbuf);
                skip(pbuf, size-1);
                break;

            case DHCP_OPT_MASK:
                ip_mask[INTERFACE_ETH] = read_ip(pbuf);
                skip(pbuf, size-4);
                break;

            case DHCP_OPT_ROUTER:
                ip_gateway[INTERFACE_ETH] = read_ip(pbuf);
                skip(pbuf, size-4);
                break;

#ifdef _DNS
            case DHCP_OPT_DNS:
                ip_dns[INTERFACE_ETH] = read_ip(pbuf);
                skip(pbuf, size-4);
                break;
#endif

            case DHCP_OPT_END:
                return opt;
                break;

            default:
                skip(pbuf, size);                           // ignore other options
                break;
        }
    }

    return opt;
}

// ------------------------------------------------
// Function:        dhcp_discover()
// ------------------------------------------------
// Input:           -
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Find out a DHCP server address
// ------------------------------------------------
BOOL dhcp_discover(void)
{
    BYTE opt;
    PPBUF pbuf;

    retry = 0;
    while(retry < MAX_RETRIES) {
        if(!dhcp_send(DHCPDISCOVER, TRUE)) return FALSE;
        os_set_timeout(TIMEOUT_DHCP_DISCOVER);
        if(udp_listen(SOCKET_DHCP, UDP_DHCP_CLI)) {
            pbuf = udp_read(SOCKET_DHCP);
            opt = parse_dhcp(pbuf);
            release_buffer(pbuf);
            if(opt == DHCPOFFER) break;
        }
        retry++;
    }

    if(retry >= MAX_RETRIES) return FALSE;
    return TRUE;
}	

// ------------------------------------------------
// Function:        dhcp_req()
// ------------------------------------------------
// Input:           -
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Asks the DHCP server for an IP
//                  address
// ------------------------------------------------
BOOL dhcp_req(void)
{
    BYTE opt;
    PPBUF pbuf;

    retry = 0;
    while(retry < MAX_RETRIES) {
        if(!dhcp_envia(DHCPREQUEST, TRUE)) return FALSE;
        os_set_timeout(TIMEOUT_DHCP_REQUEST);
        if(udp_listen(SOCKET_DHCP, UDP_DHCP_CLI)) {
            pbuf = udp_read(SOCKET_DHCP);
            opt = parse_dhcp(pbuf);
            release_buffer(pbuf);
            if(opt == DHCPACK) break;
        }
        retry++;
    }

    if(retry >= MAX_RETRIES) return FALSE;
    return TRUE;
}	

// ------------------------------------------------
// Function:        dhcp_get_ip()
// ------------------------------------------------
// Input:           -
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Obtain a local IP address
//                  using the DHCP protocol
// ------------------------------------------------
BOOL dhcp_get_ip(void)
{
    IPV4 ip;

    if(ip_local[INTERFACE_ETH].d) return TRUE;                  // already has an IP

    ip.d = 0xffffffff;

    udp_close(SOCKET_DHCP);
    if(!udp_open(SOCKET_DHCP, UDP_DHCP_CLI, ip, UDP_DHCP_SERV, INTERFACE_ETH))
        return FALSE;

    ip_local[INTERFACE_ETH].d = 0;
    ip_tmp.d = 0;
    ip_dhcp.d = 0xffffffff;
    xid.b[0] = random();
    xid.b[1] = random();
    xid.b[2] = random();
    xid.b[3] = random();

    if(!dhcp_discover()) goto fail;                             // find a DHCP server

    udp_close(SOCKET_DHCP);
    if(!udp_open(SOCKET_DHCP, UDP_DHCP_CLI, ip, UDP_DHCP_SERV, INTERFACE_ETH))
        return FALSE;

    if(!dhcp_req()) goto fail;                                  // request an IP address

    ip_local[INTERFACE_ETH].d = ip_tmp.d;
    udp_close(SOCKET_DHCP);
    return TRUE;

fail:
    ip_local[INTERFACE_ETH].d = 0;
    udp_close(SOCKET_DHCP);
    return FALSE;
}	

// ------------------------------------------------
// Function:        dhcp_release_ip()
// ------------------------------------------------
// Input:           -
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Release current dinamic IP
//                  address
// ------------------------------------------------
BOOL dhcp_release_ip(void)
{
    BYTE i;

    if(ip_local[INTERFACE_ETH].d == 0) return TRUE;             // no IP for releasing

    udp_close(SOCKET_DHCP);
    if(!udp_open(SOCKET_DHCP, UDP_DHCP_CLI, ip_dhcp, UDP_DHCP_SERV, INTERFACE_ETH))
        return FALSE;

    for(i=0; i<3; i++) {
        if(!dhcp_envia(DHCPRELEASE, TRUE)) break;
        os_sleep(100);
    }

    udp_close(SOCKET_DHCP);
    ip_local[INTERFACE_ETH].d = 0;
    ip_gateway[INTERFACE_ETH].d = 0;
    ip_mask[INTERFACE_ETH].d = 0;
    ip_dhcp.d = 0xffffffff;
    return TRUE;
}	

#endif
