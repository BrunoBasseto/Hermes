void smtp_quit(void);
BOOL smtp_new(IPV4 server, BYTE interface);
BOOL smtp_from(char *s);
BOOL smtp_to(char *s);
BOOL smtp_data(char *s);
BOOL smtp_send(void);
void smtp_init(void);
