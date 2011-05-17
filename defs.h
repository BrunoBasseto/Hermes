
typedef enum {
	FALSE,
	TRUE
} BOOL;
#define BYTE unsigned char

#ifdef __PIC32MX__
#define disable() asm volatile ("di\n");
#define enable()  asm volatile ("ei\n");
#define WORD unsigned int
#define UInt32 unsigned int
#define UInt16 unsigned short

#define __interrupt __attribute__((interrupt))
#endif

#ifdef __C30__
#define disable() asm volatile("push SR\n"); SR |= 0xe0;
#define enable() asm volatile ("pop SR\n")
#define WORD unsigned int
#define UInt16 unsigned int
#define UInt32 unsigned long

#define __interrupt __attribute__((interrupt, no_auto_psv))
#endif

typedef union {
	UInt32 d;
	UInt16 w[2];
	BYTE b[4];
} _UInt32;

typedef union {
	UInt32 d;
	BYTE b[4];
} IPV4;

#define bit(X) unsigned X: 1
#define _asm	asm volatile
#define _far __attribute__((far))
#define _rom __attribute__((space(auto_psv)))
#define reset() asm volatile ("reset")
#define _FCY	16000L
#define _delay_ms(X) __delay32(_FCY*X)
#define _delay_10us(X) __delay32((_FCY/100)*X)
#define _PACKED __attribute__((packed))

#define LOW(x) ((x) & 0xff)
#define HIGH(x) ((x) >> 8)
#define WORDOF(x, y) (((UInt16)(x) << 8) | ((UInt16)(y) & 0x00ff))

#define LOWORD(x) ((UInt16)((x) & 0xffff))
#define HIWORD(x) ((UInt16)((x) >> 16))

#define set_bit(X, Y)	 X |= (1 << (Y))
#define clear_bit(X, Y)  X &= (~(1 << (Y)))
#define toggle_bit(X, Y) X ^= (1 << (Y)) 
#define test_bit(X, Y)  (X & (1 << (Y)))
