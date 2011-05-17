#ifndef __HERMES_CONFIG__
#include "hermes_config.h"
#endif

typedef struct {
	struct {
		unsigned protocol: 6;
		unsigned interface: 2;
	};
	BYTE rc;
	UInt16 size;
	BYTE *start;
	BYTE *data;
	BYTE *ptr;
} TBUFFER;	
#define PPBUF TBUFFER *

#define BUFFER_EMPTY			0
#define BUFFER_RESERVED			1
#define BUFFER_IP				2
#define BUFFER_TCP				3
#define BUFFER_UDP				4
#define BUFFER_ICMP				5
//#define TIPO_DHCP				6
#define BUFFER_MODEM			7
#define BUFFER_PPP_LCP			8
#define BUFFER_PPP_IPCP			9
#define BUFFER_PPP_PAP			10
#define BUFFER_ARP				11
#define BUFFER_NAT_TCP			12

#ifdef _PPP
#include "ppp.h"
#include "uart_ppp.h"
#include "modem.h"
#endif

#ifdef _ETH
#include "eth.h"
#include "arp.h"
#endif

#ifdef _TCP
#include "ip.h"
#include "tcp.h"
#endif

#ifdef _UDP
#include "ip.h"
#include "udp.h"
#endif

#ifdef _DHCP
#include "dhcp.h"
#endif

#ifdef _ICMP
#include "icmp.h"
#endif

#ifdef _DNS
#include "dns.h"
#endif

#ifdef _SMTP
#include "smtp.h"
#endif

#ifdef _NAT
#include "nat.h"
#endif

PPBUF get_buffer(UInt16 tam);
void retain_buffer(PPBUF b);
void release_buffer(PPBUF b);
void crop_buffer(PPBUF b, UInt16 tam);
void write_byte(PPBUF buf, BYTE b);
void write_uint16(PPBUF buf, UInt16 w);
void write_uint32(PPBUF buf, UInt32 w);
void write_string(PPBUF buf, char *s);
void write_stringP(PPBUF buf, char *s);
void write_ip(PPBUF buf, IPV4 ip);
void write_buf(PPBUF buf, BYTE *p, UInt16 size);
void write_uuencode(PPBUF buf, BYTE *p, UInt16 size);
void write_integer(PPBUF buf, UInt32 v, BYTE d);
BOOL compare_string(PPBUF buf, char *s);
void skip(PPBUF buf, UInt16 size);
void skip_string(PPBUF buf);
BYTE read_byte(PPBUF buf);
UInt16 read_uint16(PPBUF buf);
UInt32 read_uint32(PPBUF buf);
IPV4 read_ip(PPBUF buf);
UInt32 read_integer(PPBUF buf);
void read_buf(PPBUF buf, BYTE *p, UInt16 size);
BOOL is_eof(PPBUF buf);
void hermes_init(void);
