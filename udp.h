void trata_mens_udp(PPBUF pbuf);
BOOL udp_listen(BYTE n, UInt16 p_loc);
PPBUF udp_read(BYTE n);
BOOL udp_open(BYTE n, UInt16 p_loc, IPV4 ip_rem, UInt16 p_rem, BYTE interface);
void udp_close(BYTE n);
PPBUF udp_new(BYTE s);
void udp_send(PPBUF pbuf);
UInt16 udp_get_port();
BOOL udp_has_data(BYTE s);
void udp_inicia(void);
