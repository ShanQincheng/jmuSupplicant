#ifndef MENTOHUSTV4_
#define MENTOHUSTV4_

#include <stdio.h>
#include <string.h>

#include "rjwhirlpool.h"
#include "rjtiger.h"
#include "rjripemd128.h"
#include "rjsha1.h"
#include "rjmd5.h"
#include "md5.h"
#include "mento_md5.h"
#include "../construct_eap_frames.h"

#define md5_block_size 64


extern unsigned char *computeV4(const unsigned char *src, int len);
extern char *computePwd(const unsigned char *md5);
extern u_char *checkPass(u_char id, const u_char *md5Seed, int seedLen);


#endif
