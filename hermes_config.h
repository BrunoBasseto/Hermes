// ------------------
// network interfaces
// ------------------
#define _ETH
//#define _PPP

#define MAX_INTERFACES                  2
#define INTERFACE_PPP                   0
#define INTERFACE_ETH                   1

// ----------------
// protocols to use
// ----------------
#define _TCP
#define _UDP
#define _ICMP
#define _DHCP
#define _DNS
#define _SMTP
//#define _NAT

// ------------------
// PPP configurations
// ------------------
//#define PPP_UART                      1       // UART to use
//#define PPP_FLOW_CONTROL                      // use hardware flow control
//#define PPP_MRU                       512     // maximum packet size

// ------------------
// ETH configurations
// ------------------
#define ETH_SPI                         2       // SPI channel to use
#define ETH_INT                         0       // external interrupt to use

// ------------------
// NAT configurations
// ------------------
//#define MAX_NAT                       8
//#define MAX_NAT_SOCKET                16
//#define NAT_IN                        INTERFACE_PPP
//#define NAT_OUT                       INTERFACE_ETH

// -----------------
// UDP configuration
// -----------------
#define MAX_SOCKETS_UDP                 8
#define SOCKET_DHCP                     1
#define SOCKET_DNS                      2
#define SOCKET_APL                      0
#define SIG_UDP                         10      // first UDP socket signal

// -----------------
// TCP configuration
// -----------------
#define MSS                             512
#define MAX_SOCKETS_TCP                 4
#define SOCKET_SMTP                     3
#define SIG_TCP                         20      // first TCP socket signal

// ------------------
// ICMP configuration
// ------------------
#define SIG_ICMP                        1

// -----------------
// ARP configuration
// -----------------
#define MAX_CACHE_ARP                   8
#define CB_ARP                          0
#define TMR_ARP                         0
#define SIG_ARP                         2

// --------------------
// Hermes configuration
// --------------------
#define NUM_BUFFERS                     4
#define THRD_HERMES                     0       // Hermes main thread ID
#define HERMES_STACK_SIZE               300     // stack size for Hermes
#define SIG_MESSAGE                     0       // Signal ID to awake Hermes main thread
