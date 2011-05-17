
// -------------------------------------------------------
// File:            HERMES.C
// Project:         Hermes
// Description:     Buffer management and message dispatch
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Dec 10, 2010
// Last Revision:   May 15, 2011
// Revision ID:     6
// -------------------------------------------------------
// Functions:       get_buffer()
//                  retain_buffer()
//                  release_buffer()
//                  write_byte()
//                  write_word()
//                  write_dword()
//                  write_string()
//                  write_stringP()
//                  write_ip()
//                  write_buf()
//                  compare_string()
//                  skip()
//                  skip_string()
//                  read_byte()
//                  read_word()
//                  read_dword()
//                  read_ip()
//                  read_integer()
//                  read_buf()
//                  is_eof()
//                  thread_mensagens()
//                  hermes_init()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "cronos.h"
#include "hermes.h"

// ----------------------------
// buffer static data structure
// ----------------------------
TBUFFER buffers[NUM_BUFFERS];

extern char *_string_buf;

// ------------------------------------------------
// Function:        get_buffer()
// ------------------------------------------------
// Input:           Size to allocate
// Output:          Buffer pointer or NULL
// ------------------------------------------------
// Description:     Allocates and returns a free
//                  buffer
// ------------------------------------------------
PPBUF get_buffer(UInt16 size)
{
    BYTE i;
    BYTE *buf;
    PPBUF p;

    // ----------------------------
    // try to find an unused buffer
    // ----------------------------
    p = buffers;
    for(i=0; i<NUM_BUFFERS; i++,p++) {
            if(p->protocol == BUFFER_EMPTY) break;
    }
    if(i >= NUM_BUFFERS) return NULL;

    // -----------------------------------------
    // alocates and initializes buffer structure
    // -----------------------------------------
    buf = (BYTE *)malloc(size);
    if(buf == NULL) return NULL;
    p->rc = 1;
    p->start = buf;
    p->data = buf;
    p->ptr = buf;
    p->size = 0;
    p->protocol = BUFFER_RESERVED;
    return p;
}

// ------------------------------------------------
// Function:        retain_buffer()
// ------------------------------------------------
// Input:           Buffer pointer
// Output:          -
// ------------------------------------------------
// Description:     Holds buffer into memory by
//                  increasing its reference count
// ------------------------------------------------
void retain_buffer(PPBUF b)
{
    if(b == NULL) return;
    b->rc++;
    b->protocol = BUFFER_RESERVED;
}

// ------------------------------------------------
// Function:        release_buffer()
// ------------------------------------------------
// Input:           Buffer pointer
// Output:          -
// ------------------------------------------------
// Description:     Signals buffer release, freeing
//                  memory if reference counter
//                  reaches zero
// ------------------------------------------------
void release_buffer(PPBUF b)
{
    if(b == NULL) return;

    // ------------------------
    // verify reference counter
    // ------------------------
    if(b->rc > 1) b->rc--;
    else if(b->rc == 1) {
        // -------------------
        // buffer can be freed
        // -------------------
        if(b->start != NULL) free((void *)b->start);
        os_set((BYTE *)b, 0, sizeof(TBUFFER));
    }
}	

void crop_buffer(PPBUF b, UInt16 size)
{
    if(b == NULL) return;
    b->data += size;
    if(b->size) b->size -= size;
    b->ptr = b->data;
}	

// ------------------------------------------------
// Function:        write_...()
// ------------------------------------------------
// Input:           buffer, value
// Output:          -
// ------------------------------------------------
// Description:     Adds the value to the buffer's
//                  current position
// ------------------------------------------------
void write_byte(PPBUF buf, BYTE b)
{
    if(buf == NULL) return;
    *buf->ptr++ = b;
    buf->size++;
}	

void write_uint16(PPBUF buf, UInt16 w)
{
    if(buf == NULL) return;
    *buf->ptr++ = HIGH(w);
    *buf->ptr++ = LOW(w);
    buf->size += 2;
}

void write_uint32(PPBUF buf, UInt32 w)
{
    if(buf == NULL) return;
    *buf->ptr++ = ((BYTE *)&w)[3];
    *buf->ptr++ = ((BYTE *)&w)[2];
    *buf->ptr++ = ((BYTE *)&w)[1];
    *buf->ptr++ = ((BYTE *)&w)[0];
    buf->size += 4;
}

void write_string(PPBUF buf, char *s)
{
    UInt16 i;

    if(buf == NULL) return;
    for(i=0; *s; i++)
        *buf->ptr++ = *s++;
    buf->size += i;
}	

void write_stringP(PPBUF buf, char *s)
{
    UInt16 i;
    BYTE *p;

    if(buf == NULL) return;
    p = buf->ptr++;
    for(i=0; *s; i++)
        *buf->ptr++ = *s++;
    buf->size += i+1;
    *p = i;
}	

void write_ip(PPBUF buf, IPV4 ip)
{
    if(buf == NULL) return;
    *buf->ptr++ = ip.b[0];
    *buf->ptr++ = ip.b[1];
    *buf->ptr++ = ip.b[2];
    *buf->ptr++ = ip.b[3];
    buf->size += 4;
}	

void write_buf(PPBUF buf, BYTE *p, UInt16 size)
{
    if(buf == NULL) return;
    buf->size += size;
    while(size) {
        *buf->ptr = *p;
        buf->ptr++;
        p++;
        size--;
    }
}	

char uuencode(BYTE v)
{
    v &= 0x3f;
    if(v < 26) return v + 'A';
    if(v < 52) return v - 52 + 'a';
    if(v < 62) return v - 62 + '0';
    if(v == 62) return '+';
    return '/';
}	

void write_uuencode(PPBUF buf, BYTE *p, UInt16 size)
{
    UInt16 n;

    if(buf == NULL) return;
    n = 0;
    while(size) {
        *buf->ptr++ = uuencode(p[0] >> 2);
        if(size > 1) *buf->ptr = uuencode((p[0] << 4) | (p[1] >> 4)); else *buf->ptr = '='; buf->ptr++;
        if(size > 2) *buf->ptr = uuencode((p[1] << 2) | (p[2] >> 6)); else *buf->ptr = '='; buf->ptr++;
        if(size > 3) *buf->ptr = uuencode(p[2]); else *buf->ptr = '='; buf->ptr++;
        buf->size += 4;
        n += 4;
        if(n == 76) {
            n = 0;
            *buf->ptr++ = '\r';
            *buf->ptr++ = '\n';
            buf->size += 2;
        }
        if(size > 3) size -= 3; else size = 0;
        p += 3;
    }
}	

void write_integer(PPBUF buf, UInt32 v, BYTE d)
{
    char *p;
    BYTE n;

    if(buf == NULL) return;
    p = _string_buf;
    n = 0;
    do {
        *p++ = (v % 10) + '0';
        n++;
        v /= 10;
    } while(v);
    for(; n<d; n++) *p++ = '0';
    buf->size += n;
    while(n) {
        --p;
        *buf->ptr++ = *p--;
        n--;
    }
}	

// ------------------------------------------------
// Function:        compare_string()
// ------------------------------------------------
// Input:           buffer, string
// Output:          TRUE if found
// ------------------------------------------------
// Description:     Tests the next buffer positions
//                  for the string
// ------------------------------------------------
BOOL compare_string(PPBUF buf, char *s)
{
    BYTE *p;
    UInt16 i;
    if(buf == NULL) return FALSE;
    if(s == NULL) return FALSE;
    p = buf->ptr;
    i = 0;
    while(*s) {
        if(*s != *p) return FALSE;
        s++; p++; i++;
        if(i > buf->size) return FALSE;
    }
    buf->ptr = p;
    return TRUE;
}

// ------------------------------------------------
// Function:        skip()
// ------------------------------------------------
// Input:           buffer, byte count
// Output:          -
// ------------------------------------------------
// Description:     Moves the buffer pointer ahead
// ------------------------------------------------
void skip(PPBUF buf, UInt16 size)
{
    if(buf == NULL) return;
    buf->ptr += size;
}

// ------------------------------------------------
// Function:        skip_string()
// ------------------------------------------------
// Input:           buffer
// Output:          -
// ------------------------------------------------
// Description:     Moves the buffer pointer to
//                  the end of current string
// ------------------------------------------------
void skip_string(PPBUF buf)
{
    BYTE *p;
    BYTE *q;
    if(buf == NULL) return;
    p = buf->ptr;
    q = buf->data + buf->size;
    while(*p) {
        p++;
        if(p >= q) break;
    }
    buf->ptr = p+1;
}	

// ------------------------------------------------
// Function:        read_...()
// ------------------------------------------------
// Input:           buffer
// Output:          value
// ------------------------------------------------
// Description:     Reads a value from the current
//                  buffer pointer
// ------------------------------------------------
BYTE read_byte(PPBUF buf)
{
    BYTE res;
    if(buf == NULL) return 0;
    res = buf->ptr[0];
    buf->ptr++;
    return res;
}	

UInt16 read_uint16(PPBUF buf)
{
    WORD res;
    if(buf == NULL) return 0;
    res = WORDOF(buf->ptr[0], buf->ptr[1]);
    buf->ptr += 2;
    return res;
}	

UInt32 read_uint32(PPBUF buf)
{
    _UInt32 res;
    if(buf == NULL) return 0;
    res.b[3] = buf->ptr[0];
    res.b[2] = buf->ptr[1];
    res.b[1] = buf->ptr[2];
    res.b[0] = buf->ptr[3];
    buf->ptr += 4;
    return res.d;
}	

IPV4 read_ip(PPBUF buf)
{
    IPV4 res;
    if(buf == NULL)
        res.d = 0;
    else {
        res.b[0] = buf->ptr[0];
        res.b[1] = buf->ptr[1];
        res.b[2] = buf->ptr[2];
        res.b[3] = buf->ptr[3];
        buf->ptr += 4;
    }
    return res;
}	

UInt32 read_integer(PPBUF buf)
{
    BYTE *p;
    BYTE *q;
    UInt32 res;

    if(buf == NULL) return 0;
    p = buf->ptr;
    q = buf->data + buf->size;
    res = 0;

    // ---------------------------------
    // skip characters other than digits
    // ---------------------------------
    while(p < q) {
        if((*p >= '0') && (*p <= '9')) break;
        p++;
    }

    // -----------------------------------------
    // read a number and convert it into decimal
    // -----------------------------------------
    while(p < q) {
        if((*p >= '0') && (*p <= '9')) {
            res = 10 * res + (*p - '0');
        } else break;
        p++;
    }

    buf->ptr = p;
    return res;
}	

void read_buf(PPBUF buf, BYTE *p, UInt16 size)
{
    while(size) {
        *p = *buf->ptr;
        p++;
        buf->ptr++;
        size--;
    }
}

// ------------------------------------------------
// Function:        is_eof()
// ------------------------------------------------
// Input:           buffer
// Output:          TRUE if completely read
// ------------------------------------------------
// Description:     Verify if the buffer was read
//                  to its end
// ------------------------------------------------
BOOL is_eof(PPBUF buf)
{
    if(buf == NULL) return TRUE;
    if((buf->data + buf->size) > buf->ptr) return FALSE;
    return TRUE;
}	

// ------------------------------------------------
// Function:        hermes_thread()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Main thread of message
//                  processing
// ------------------------------------------------
void hermes_thread(void)
{	
    UInt16 i;
    PPBUF p;

    while(os_not_terminated()) {
        // ------------------
        // wait for a message
        // ------------------
        os_wait(SIG_MESSAGE);

        p = buffers;
        for(i=0; i<NUM_BUFFERS; i++, p++) {
            for(;;) {
                if(p->protocol == BUFFER_EMPTY) break;
                if(p->protocol == BUFFER_RESERVED) break;
                switch(p->protocol) {
#ifdef _PPP
                    case BUFFER_MODEM:
                        p->protocol = BUFFER_RESERVED;
                        modem_parse(p);
                        break;

                    case BUFFER_PPP_LCP:
                        p->protocol = BUFFER_RESERVED;
                        lcp_parse(p);
                        break;

                    case BUFFER_PPP_PAP:
                        p->protocol = BUFFER_RESERVED;
                        pap_parse(p);
                        break;

                    case BUFFER_PPP_IPCP:
                        p->protocol = BUFFER_RESERVED;
                        ipcp_parse(p);
                        break;
#endif
                    case BUFFER_IP:
                        p->protocol = BUFFER_RESERVED;
                        ip_parse(p);
                        break;

                    case BUFFER_ICMP:
                        p->protocol = BUFFER_RESERVED;
                        icmp_parse(p);
                        break;
#ifdef _UDP
                    case BUFFER_UDP:
                        p->protocol = BUFFER_RESERVED;
                        udp_parse(p);
                        break;
#endif
#ifdef _TCP
                    case BUFFER_TCP:
                        p->protocol = BUFFER_RESERVED;
                        tcp_parse(p);
                        break;
#endif
#ifdef _ETH
                    case BUFFER_ARP:
                        p->protocol = BUFFER_RESERVED;
                        arp_parse(p);
                        break;
#endif
#ifdef _NAT
                    case BUFFER_NAT_TCP:
                        p->protocol = BUFFER_RESERVED;
                        nat_parse(p);
                        break;
#endif
                }
                release_buffer(p);
            }
        }
    }

    // ---------------
    // finishes thread
    // ---------------
    p = buffers;
    for(i=0; i<NUM_BUFFERS; i++) {
        p->rc = 0;
        release_buffer(p);
        p++;
    }
}

// ------------------------------------------------
// Function:        hermes_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Communication initialization
// ------------------------------------------------
void hermes_init(void)
{
//	inicia_rand();
    ip_init();
#ifdef _ETH
    eth_init();
    arp_init();
#endif
#ifdef _PPP
    modem_init();
    uart_ppp_int();
    ppp_init();
#endif
#ifdef _TCP
    tcp_init();
#endif
#ifdef _UDP
    udp_init();
#endif
#ifdef _DNS
    dns_init();
#endif
#ifdef _SMTP
    smtp_init();
#endif
#ifdef _NAT
    nat_init();
#endif
    // -----------------
    // clean buffer area
    // -----------------
    os_set((BYTE *)buffers, 0, sizeof(buffers));

    // -------------------
    // start hermes thread
    // -------------------
    os_start(THRD_HERMES, hermes_thread, HERMES_STACK_SIZE);
}
