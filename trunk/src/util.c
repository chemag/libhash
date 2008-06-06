/* $Id: util.cc,v 1.53 2004/03/01 12:23:25 vern Exp $
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


#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

#include "util.h"
#include "md5.h"



void hash_md5(size_t size, const uint8_t* bytes, uint8_t digest[16])
	{
	md5_state_t h;
	md5_init(&h);
	md5_append(&h, bytes, size);
	md5_finish(&h, digest);
	}

const char* md5_digest_print(const uint8_t digest[16])
	{
	int i;
	static char digest_print[256];

	for ( i = 0; i < 16; ++i )
		snprintf(digest_print + i * 2, 3, "%02x", digest[i]);

	return digest_print;
	}

int hmac_key_set = 0;
uint8_t shared_hmac_md5_key[16];


void hmac_md5(size_t size, const uint8_t* bytes, uint8_t digest[16])
	{
	int i;

	if ( ! hmac_key_set )
		fprintf(stderr, "HMAC-MD5 invoked before the HMAC key is set\n");

	hash_md5(size, bytes, digest);

	for ( i = 0; i < 16; ++i )
		digest[i] ^= shared_hmac_md5_key[i];

	hash_md5(16, digest, digest);
	}

void md5_init_random_seed()
	{
	static const int bufsiz = 16;
	u_int32_t buf[16];
	int pos = 0;	/* accumulates entropy */
	int fd;
	u_int32_t result;
	int i;

	/* Gather up some entropy. */
	gettimeofday((struct timeval *)(buf + pos), 0);
	pos += sizeof(struct timeval) / sizeof(u_int32_t);

#if defined(O_NONBLOCK)
	fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
#elif defined(O_NDELAY)
	fd = open("/dev/random", O_RDONLY | O_NDELAY);
#else
	fd = open("/dev/random", O_RDONLY);
#endif

	if ( fd >= 0 )
		{
		int amt = read(fd, buf + pos, sizeof(u_int32_t) * (bufsiz - pos));
		close(fd);

		if ( amt > 0 )
			pos += (amt / sizeof(u_int32_t));
		else
			/* reset the errno */
			errno = 0;
		}

	if ( pos < bufsiz )
		{
		buf[pos++] = getpid();

		if ( pos < bufsiz )
			buf[pos++] = getuid();
		}

	result = 0;
	for ( i = 0; i < pos; ++i )
		{
		result ^= buf[i];
		result = (result << 1) | (result >> 31);
		}
	srandom(result);

	if ( ! hmac_key_set )
		{
		hash_md5(sizeof(buf), (uint8_t*) buf, shared_hmac_md5_key);
		hmac_key_set = 1;
		}

	}


