
// -------------------------------------------------------
// File:            SMTP.C
// Project:         Hermes
// Description:     Simple mail transfer protocol
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Jan 12, 2011
// Last Revision:   May 16, 2011
// Revision ID:     1
// -------------------------------------------------------
// Functions:       smtp_ok()
//                  smtp_quit()
//                  smtp_new()
//                  smtp_from()
//                  smtp_to()
//                  smtp_data()
//                  smtp_send()
//                  smtp_inicia()
// -------------------------------------------------------

#include <stdlib.h>
#include "defs.h"
#include "net.h"
#include "cronos.h"
#include "hermes.h"

#ifdef _SMTP

#ifndef _TCP
#error "TCP must be installed for using SMTP"
#endif

typedef enum {
    SMTP_IDLE,
    SMTP_FROM,
    SMTP_RCPT,
    SMTP_DATA
} SMTP_STATE;
SMTP_STATE smtp_state;

#define TIMEOUT_SMTP	2000

// ------------------------------------------------
// Function:        smtp_ok()
// ------------------------------------------------
// Input:           -
// Output:          TRUE if SMTP sever answers ok
// ------------------------------------------------
// Description:     Waits for an answer from the
//                  server and returns TRUE if ok
//                  (2xx or 3xx codes)
// ------------------------------------------------
BOOL smtp_ok(void)
{
    PPBUF buf;
    BOOL res;

    // -------------------
    // wait for a response
    // -------------------
    os_set_timeout(TIMEOUT_SMTP);
    buf = tcp_read(SOCKET_SMTP);
    if(buf == NULL) return FALSE;

    // --------------
    // analyse answer
    // --------------
    res = FALSE;
    if(buf->data[0] == '2') res = TRUE;
    if(buf->data[0] == '3') res = TRUE;

    release_buffer(buf);
    return res;
}	

// ------------------------------------------------
// Function:        smtp_quit()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Ends an SMTP transaction
// ------------------------------------------------
void smtp_quit(void)
{
    if(!tcp_is_open(SOCKET_SMTP)) return;                           // socket already closed

    // ----------------------
    // sends the QUIT command
    // ----------------------
    tcp_send_text(SOCKET_SMTP, "QUIT\r\n");
    smtp_ok();

    // -------------------------
    // waits for a disconnection
    // -------------------------
    os_sleep(500);
    if(tcp_is_open(SOCKET_SMTP)) tcp_close(SOCKET_SMTP);
    smtp_state = SMTP_IDLE;
}

// ------------------------------------------------
// Function:        smtp_new()
// ------------------------------------------------
// Input:           Server address
//                  Network interface ID
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Connects to a SMTP server and
//                  starts a new mail session
// ------------------------------------------------
BOOL smtp_new(IPV4 server, BYTE interface)
{
    if(smtp_state != SMTP_IDLE) return FALSE;

    // -----------------
    // connect to server
    // -----------------
    if(!tcp_open(SOCKET_SMTP, tcp_get_port(), server, 25, interface)) return FALSE;

    if(!smtp_ok()) {
        smtp_quit();
        return FALSE;
    }

    // -----------------
    // send HELO command
    // -----------------
    if(!tcp_send_text(SOCKET_SMTP, "HELO hermes\r\n")) {
        smtp_quit();
        return FALSE;
    }

    if(!smtp_ok()) return FALSE;
    smtp_state = SMTP_FROM;
    return TRUE;
}	

// ------------------------------------------------
// Function:        smtp_from()
// ------------------------------------------------
// Input:           Sender email address
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Adds one MAIL FROM clause
// ------------------------------------------------
BOOL smtp_from(char *s)
{
    PPBUF buf;
    BOOL res;

    if(smtp_state != SMTP_FROM) return FALSE;

    // ----------------------
    // send MAIL FROM command
    // ----------------------
    buf = tcp_new(SOCKET_SMTP);
    if(buf == NULL) return FALSE;

    write_string(buf, "MAIL FROM:<");
    write_string(buf, s);
    write_string(buf, ">\r\n");
    res = tcp_send(SOCKET_SMTP, buf);
    release_buffer(buf);

    if(!res) return FALSE;

    if(!smtp_ok()) return FALSE;
    smtp_state = SMTP_RCPT;
    return TRUE;
}	

// ------------------------------------------------
// Function:        smtp_to()
// ------------------------------------------------
// Input:           Receipt email address
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Adds a RCPT TO clause
// ------------------------------------------------
BOOL smtp_to(char *s)
{
    PPBUF buf;
    BOOL res;

    if(smtp_state != SMTP_RCPT) return FALSE;

    // --------------------
    // send RCPT TO command
    // --------------------
    buf = tcp_new(SOCKET_SMTP);
    if(buf == NULL) return FALSE;

    write_string(buf, "RCPT TO:<");
    write_string(buf, s);
    write_string(buf, ">\r\n");
    res = tcp_send(SOCKET_SMTP, buf);
    release_buffer(buf);

    if(!res) return FALSE;

    if(!smtp_ok()) return FALSE;
    return TRUE;
}	

// ------------------------------------------------
// Function:        smtp_data()
// ------------------------------------------------
// Input:           one line of data
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Sends one line of data inside
//                  the DATA clause
// ------------------------------------------------
BOOL smtp_data(char *s)
{
    if(smtp_state == SMTP_RCPT) {
        // -----------------
        // send DATA command
        // -----------------
        if(!tcp_send_text(SOCKET_SMTP, "DATA\r\n")) return FALSE;
        if(!smtp_ok()) return FALSE;
        smtp_state = SMTP_DATA;
    }

    if(smtp_state == SMTP_DATA) {                                   // DATA command already sent
        if(!tcp_send_text(SOCKET_SMTP, s)) return FALSE;
        return TRUE;
    }

    return FALSE;
}	

// ------------------------------------------------
// Function:        smtp_send()
// ------------------------------------------------
// Input:           -
// Output:          TRUE if succesful
// ------------------------------------------------
// Description:     Completes email and asks for
//                  deliver
// ------------------------------------------------
BOOL smtp_send(void)
{
    if(smtp_state != SMTP_DATA) return FALSE;
    if(!tcp_send_text(SOCKET_SMTP, "\r\n.\r\n")) return FALSE;
    if(!smtp_ok()) return FALSE;
    smtp_state = SMTP_FROM;
    return TRUE;
}	

// ------------------------------------------------
// Function:        smtp_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     SMTP initialization
// ------------------------------------------------
void smtp_init(void)
{
    smtp_state = SMTP_IDLE;
}

#endif
