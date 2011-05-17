BOOL arp_get_mac(IPV4 *ip, MACADDR *mac);
void insere_mac(IPV4 *ip, MACADDR *mac);
void trata_mens_arp(PPBUF pbuf);
void arp_tick(void);
void arp_inicia(void);
