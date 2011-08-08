/* $Id: util.h,v 1.47 2004/03/01 12:23:25 vern Exp $
//
// Copyright (c) 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003
//      The Regents of the University of California.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that: (1) source code distributions
// retain the above copyright notice and this paragraph in its entirety, (2)
// distributions including binary code include the above copyright notice and
// this paragraph in its entirety in the documentation or other materials
// provided with the distribution, and (3) all advertising materials mentioning
// features or use of this software display the following acknowledgement:
// ``This product includes software developed by the University of California,
// Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
// the University nor the names of its contributors may be used to endorse
// or promote products derived from this software without specific prior
// written permission.
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef util_h
#define util_h

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <stdint.h>
#include <linux/types.h>
#endif


extern uint8_t shared_hmac_md5_key[16];
extern void hash_md5(size_t size, const uint8_t* bytes, uint8_t digest[16]);

extern int hmac_key_set;
extern void hmac_md5(size_t size, const uint8_t* bytes, uint8_t digest[16]);

extern const char* md5_digest_print(const uint8_t digest[16]);
extern void md5_init_random_seed();


#endif
