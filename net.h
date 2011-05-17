
#define UDP_DHCP_CLI            68
#define UDP_DHCP_SERV           67

typedef struct _PACKED {
    BYTE b[6];
} MACADDR;

typedef struct _PACKED {
    UInt16 hardware;
    UInt16 protocol;
    BYTE hw_size;
    BYTE pr_size;
    UInt16 opcode;
    MACADDR orig_hw_address;
    IPV4 orig_ip_address;
    MACADDR dest_hw_address;
    IPV4 dest_ip_address;
} ARP_HDR;

typedef struct _PACKED {
    BYTE ver_length;
    BYTE tos;
    UInt16 length;
    UInt16 id;
    UInt16 frag;
    BYTE ttl;
    BYTE prot;
    UInt16 checksum;
    IPV4 source;
    IPV4 dest;
} IP_HDR;

typedef struct _PACKED {
    BYTE type;
    BYTE code;
    UInt16 checksum;
    UInt16 id;
    UInt16 seq;
} ICMP_HDR;

typedef struct _PACKED {
    UInt16 src_port;
    UInt16 dst_port;
    _UInt32 n_seq;
    _UInt32 n_ack;
    BYTE hlen;
    BYTE flags;
    UInt16 window;
    UInt16 checksum;
    UInt16 urgent;
} TCP_HDR;

typedef struct _PACKED {
    UInt16 src_port;
    UInt16 dst_port;
    UInt16 length;
    UInt16 checksum;
} UDP_HDR;

typedef struct _PACKED {
    BYTE op;
    BYTE htype;
    BYTE hlen;
    BYTE hops;
    UInt32 xid;
    UInt16 secs;
    UInt16 flags;
    IPV4 ci;
    IPV4 yi;
    IPV4 si;
    IPV4 gi;
    BYTE chaddr[16];
} BOOTP_HDR;

#define BOOTP_HDR_SIZE	(192+sizeof(BOOTP_HDR))

typedef struct _PACKED {
    UInt16 id;
    UInt16 flags;
    UInt16 qdcount;
    UInt16 ancount;
    UInt16 nscount;
    UInt16 arcount;
} DNS_HDR;

#define UDP_DNS             53
#define UDP_DNS_LOCAL       1025

// ------------------
// IP type-of-service
// ------------------
#define TOS_MIN_DELAY                   0x10
#define TOS_MAX_THROUGHPUT              0x08
#define TOS_MAX_RELIABILITY             0x04
#define TOS_MIN_COST                    0x02

// --------------
// default values
// --------------
#define TOSV                            TOS_MAX_THROUGHPUT
#define TTL                             64

// ----------------
// protocol numbers
// ----------------
#define IP_PROT_TCP                     6
#define IP_PROT_UDP                     17
#define IP_PROT_ICMP                    1

// -----------------------------
// host and network order macros
// -----------------------------
#define NTOHS(x) (((UInt16)x >> 8) | ((UInt16)x << 8))
#define HTONS(x) (((UInt16)x >> 8) | ((UInt16)x << 8))

// -------------------------
// ethernet protocol numbers
// -------------------------
#define ETH_PROT_IP                     0x0800
#define ETH_PROT_ARP                    0x0806

// --------------------
// PPP protocol numbers
// --------------------
#define PPP_PROT_LCP                    0xc021
#define PPP_PROT_PAP                    0xc023
#define PPP_PROT_IPCP                   0x8021
#define PPP_PROT_MODEM                  0x0000
#define PPP_PROT_IP                     0x0021
