#ifndef MENTO_MYFUN_
#define MENTO_MYFUN_

#include <sys/types.h>
#include <arpa/inet.h>


extern void getEchoKey(const uint8_t *capBuf);
static u_char encode(u_char base);	/* 算法，将一个字节的8位颠倒并取反 */
extern void fillEchoPacket(uint8_t *echoBuf);
static u_char encode(u_char base);	/* 算法，将一个字节的8位颠倒并取反 */
extern u_char *encodeIP(u_int32_t ip);

#endif
