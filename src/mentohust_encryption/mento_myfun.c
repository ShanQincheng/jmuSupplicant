#include "mento_myfun.h"

static u_int32_t echoKey = 0, echoNo = 0x0000102B; /* Echo阶段所需 */

void fillEchoPacket(uint8_t *echoBuf)
{
  int i;
  u_int32_t dd1=htonl(echoKey + echoNo), dd2=htonl(echoNo);
  u_char *bt1=(u_char *)&dd1, *bt2=(u_char *)&dd2;
  echoNo++;
  for (i=0; i<4; i++) {
    echoBuf[0x18+i] = encode(bt1[i]);
    echoBuf[0x22+i] = encode(bt2[i]);
  }

  return;
}

void getEchoKey(const uint8_t *capBuf)
{
  int i, offset = 0x1c+capBuf[0x1b]+0x69+24;	/* 通过比较了大量抓包，通用的提取点就是这样的 */
  u_char *base;
  echoKey = ntohl(*(u_int32_t *)(capBuf+offset));
  base = (u_char *)(&echoKey);
  for (i=0; i<4; i++)
    base[i] = encode(base[i]);

  return;
}

static u_char encode(u_char base)	/* 算法，将一个字节的8位颠倒并取反 */
{
  u_char result = 0;
  int i;
  for (i=0; i<8; i++) {
    result <<= 1;
    result |= base&0x01;
    base >>= 1;
  }

  return ~result;
}

u_char *encodeIP(u_int32_t ip)
{
  int i;
  unsigned char *p = (unsigned char *)(&ip);
  static u_char pi[4];
  for(i=0; i<4; ++i) {
    pi[i]=encode(p[i]);
    /*
    pi[i]=(pi[i]<<4)|(pi[i]>>4);
    pi[i]=((pi[i]<<2)&0xcc)|((pi[i]>>2)&0x33);
    pi[i]=((pi[i]<<1)&0xaa)|((pi[i]>>1)&0x55);
    pi[i]=~pi[i];*/
  }
  return pi;
}

