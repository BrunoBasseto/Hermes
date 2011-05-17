

extern IPV4 ip_local[MAX_INTERFACES];
extern IPV4 ip_mask[MAX_INTERFACES];
extern IPV4 ip_gateway[MAX_INTERFACES];
extern UInt16 id;

IPV4 make_ipv4(BYTE a, BYTE b, BYTE c, BYTE d);
void ip_answer(PPBUF pbuf);
PPBUF ip_new(IPV4 dest, UInt16 tam, BYTE interface);
void ip_send(PPBUF pbuf);
void parse_ip(PPBUF pbuf);
void ip_init(void);
