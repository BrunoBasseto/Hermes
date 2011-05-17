
// -------------------------------------------------------
// File:            ARP.C
// Project:         Hermes
// Description:     Address resolution protocol
//                  implementation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Jan 28, 2011
// Last Revision:   May 17, 2011
// Revision ID:     3
// -------------------------------------------------------
// Functions:       arp_get_map()
//                  cache_add()
//                  arp_parse()
//                  arp_tick()
//                  arp_init()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "cronos.h"
#include "hermes.h"

#ifdef _ETH

// ----------------
// protocol timming
// ----------------
#define CACHE_TIME_ARP                  120
#define TIMEOUT_ARP                     5000
#define TICK_ARP                        10000

// -----------
// ARP opcodes
// -----------
#define ARP_REQUEST                     0x0100
#define ARP_REPLY                       0x0200

// ---------
// ARP cache
// ---------
typedef struct {
    IPV4 ip_address;
    MACADDR mac_address;
    BYTE time;
} ARP_CACHE_ENTRY;
ARP_CACHE_ENTRY arp_cache[MAX_CACHE_ARP];

#define ARP(xxx)		((ARP_HDR *)(xxx))

// ------------------------------------------------
// Function:        arp_get_mac()
// ------------------------------------------------
// Input:           IP to find
//                  MAC to fill in
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Find the mac address for a
//                  given IP
// ------------------------------------------------
BOOL arp_get_mac(IPV4 *ip, MACADDR *mac)
{
    BYTE i;
    PPBUF buf;

    if(ip->d == 0xffffffff) {                               // broadcast IP address
        os_set((BYTE *)mac, 0xff, sizeof(MACADDR));         // broadcast MAC address
        return TRUE;
    }

    // --------------------------
    // search for IP in the cache
    // --------------------------
    for(i=0; i<MAX_CACHE_ARP; i++) {
        if(arp_cache[i].ip_address.d == ip->d) {
            os_copy((BYTE *)&arp_cache[i].mac_address,
                    (BYTE *)mac,
                    sizeof(MACADDR));
            return TRUE;
        }
    }

    // ----------------------------
    // IP not found, send a request
    // ----------------------------
    buf = get_buffer(sizeof(ARP_HDR));
    if(buf != NULL) {
        ARP(buf->data)->opcode = ARP_REQUEST;
        ARP(buf->data)->hardware = 0x0100;
        ARP(buf->data)->protocol = 0x0008;
        ARP(buf->data)->hw_size = 6;
        ARP(buf->data)->pr_size = 4;
        os_copy((BYTE *)&mac_local,
                (BYTE *)&ARP(buf->data)->orig_hw_address,
                sizeof(MACADDR));
        os_set((BYTE *)&ARP(buf->data)->dest_hw_address,
                0xff, sizeof(MACADDR));
        ARP(buf->data)->orig_ip_address.d = ip_local[INTERFACE_ETH].d;
        ARP(buf->data)->dest_ip_address.d = ip->d;
        buf->size = sizeof(ARP_HDR);

        eth_send(buf, ETH_PROT_ARP);
        release_buffer(buf);

        // -----------------------------------------------
        // waits for an answer, then check the cache again
        // -----------------------------------------------
        os_set_timeout(TIMEOUT_ARP);
        if(os_wait(SIG_ARP)) {
            for(i=0; i<MAX_CACHE_ARP; i++) {
                if(arp_cache[i].ip_address.d == ip->d) {
                    os_copy((BYTE *)&arp_cache[i].mac_address,
                            (BYTE *)mac, sizeof(MACADDR));
                    return TRUE;
                }
            }
        }
    }

    return FALSE;                                           // failed
}	

// ------------------------------------------------
// Function:        cache_add()
// ------------------------------------------------
// Input:           IP address, MAC address pair
// Output:          -
// ------------------------------------------------
// Description:     Updates cache information
// ------------------------------------------------
void cache_add(IPV4 *ip, MACADDR *mac)
{
    BYTE i, n, m;

    // ----------------------
    // search for IP in cache
    // ----------------------
    for(i=0; i<MAX_CACHE_ARP; i++) {
        if(arp_cache[i].ip_address.d == ip->d)
            break;
    }

    if(i >= MAX_CACHE_ARP) {
        // ------------------------------
        // new IP, find an empty position
        // ------------------------------
        m = 0xff;
        n = 0;
        for(i=0; i<MAX_CACHE_ARP; i++) {
            if(arp_cache[i].time <= m) {
                m = arp_cache[i].time;
                n = i;
            }
            if(m == 0) break;
        }
    }
	
    if(i >= MAX_CACHE_ARP)
        i = n;                                              // cache full, overwrite the oldest entry

    // ------------
    // update entry
    // ------------
    arp_cache[i].ip_address.d = ip->d;
    os_copy((BYTE *)mac,
            (BYTE *)&arp_cache[i].mac_address,
            sizeof(MACADDR));
}	

// ------------------------------------------------
// Function:        arp_parse()
// ------------------------------------------------
// Input:           Message buffer
// Output:          -
// ------------------------------------------------
// Description:     Parse an incoming ARP message
// ------------------------------------------------
void arp_parse(PPBUF pbuf)
{
    switch(ARP(pbuf->data)->opcode) {
        case ARP_REQUEST:
            if(ARP(pbuf->data)->dest_ip_address.d == ip_local[INTERFACE_ETH].d) {
                // -----------------------
                // query for local address
                // -----------------------
                cache_add(&ARP(pbuf->data)->orig_ip_address,
                          &ARP(pbuf->data)->orig_hw_address);

                retain_buffer(pbuf);
                ARP(pbuf->data)->opcode = ARP_REPLY;
                os_copy((BYTE *)&ARP(pbuf->data)->orig_hw_address,
                        (BYTE *)&ARP(pbuf->data)->dest_hw_address,
                        sizeof(MACADDR));
                ARP(pbuf->data)->dest_ip_address.d = ARP(pbuf->data)->orig_ip_address.d;

                os_copy((BYTE *)&mac_local,
                        (BYTE *)&ARP(pbuf->data)->orig_hw_address,
                        sizeof(MACADDR));
                ARP(pbuf->data)->orig_ip_address.d = ip_local[INTERFACE_ETH].d;

                eth_send(pbuf, ETH_PROT_ARP);
                release_buffer(pbuf);
            }
            break;

        case ARP_REPLY:
            cache_add(&ARP(pbuf->data)->orig_ip_address,
                      &ARP(pbuf->data)->orig_hw_address);
            os_signal(SIG_ARP);
            break;
    }
}

// ------------------------------------------------
// Function:        arp_tick()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Callback timming function
//                  Updates the cache timming info
// ------------------------------------------------
void arp_tick(void)
{
    ARP_CACHE_ENTRY *a;
    BYTE i;

    a = arp_cache;
    for(i=0; i<MAX_CACHE_ARP; i++) {
        if(a->time) {
            a->time--;
            if(a->time == 0) {
                // -------------
                // entry timeout
                // -------------
                os_set((BYTE *)a, 0xff, sizeof(ARP_CACHE_ENTRY));
                a->time = 0;
            }
        }
        a++;
    }

    os_set_timer(TMR_ARP, TICK_ARP, CB_ARP);
}

// ------------------------------------------------
// Function:        arp_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Initializes ARP
// ------------------------------------------------
void arp_init(void)
{
    BYTE i;

    for(i=0; i<MAX_CACHE_ARP; i++) {
        os_set((BYTE *)&arp_cache[i], 0xff, sizeof(ARP_CACHE_ENTRY));
        arp_cache[i].time = 0;
    }

    os_set_callback(CB_ARP, arp_tick);
    os_set_timer(TMR_ARP, TICK_ARP, CB_ARP);
}
#endif
