
// -------------------------------------------------------
// File:            CHECKSUM.C
// Project:         Hermes
// Description:     Auxiliary routines for checksum
//                  calculation
// Author:          Bruno Abrantes Basseto
//                  bruno.basseto@uol.com.br
// Target CPU:      PIC24 / PIC32
// Compiler:        Microchip C30 v3.24
//                  Microchip C32 v1.11a
// Creation:        Dec 10, 2010
// Last Revision:   May 15, 2011
// Revision ID:     10
// -------------------------------------------------------
// Functions:       check_init()
//                  check_update()
// -------------------------------------------------------

#include "defs.h"

// -------------------
// auxiliary variables
// ------------------- 
static BOOL byteH;
BYTE chk_H;							// checksum temp value (most significative)
BYTE chk_L;							// checksum temp value (least significative)

// ------------------------------------------------
// Function:        check_init()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Initializes checksum
//                  calculation
// ------------------------------------------------
void check_init(void)
{
    chk_H = 0;
    chk_L = 0;
    byteH = TRUE;
}

// ------------------------------------------------
// Function:        check_update()
// ------------------------------------------------
// Input:           -
// Output:          -
// ------------------------------------------------
// Description:     Updates checksum information
// ------------------------------------------------
void check_update(BYTE v)
{
    if(byteH) {
        byteH = FALSE;
        // ----------------------------
        // sums into most significative
        // ----------------------------
        chk_H += v;
        if(chk_H < v) {
            // -------------------------
            // overflow, adds modulo-one
            // -------------------------
            if(chk_L == 0xff) {
                chk_H++;
                chk_L = 0;
            } else {
                chk_L++;
            }
        }
    } else {
        byteH = TRUE;
        // -----------------------------
        // sums into least significative
        // -----------------------------
        chk_L += v;
        if(chk_L < v) {
            // -------------------------
            // overflow, adss modulo-one
            // -------------------------
            if(chk_H == 0xff) {
                chk_H = 0;
                chk_L++;
            } else {
                chk_H++;
            }
        }
    }
}
