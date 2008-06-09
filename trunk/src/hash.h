/*
 * Copyright (c) 2008, Jose Maria Gonzalez (chema@cs.berkeley.edu)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the.
 *       distribution
 *     * Neither the name of the copyright holder nor the names of its 
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS 
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* $Id$ */

#ifndef _HASH_H_
#define _HASH_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


/* hash key/yield types */
typedef enum
{
	HASH_OBJECT_TYPE_CONNECTION = 0,
	HASH_OBJECT_TYPE_ONESIDED_CONNECTION,
	HASH_OBJECT_TYPE_UINT32,
	HASH_OBJECT_TYPE_DOUBLE,
	HASH_OBJECT_TYPE_CONNINFO,
	HASH_OBJECT_TYPE_INVALID
} hash_object_type_t;

#define HASH_OBJECT_TYPE_ADDRESS HASH_OBJECT_TYPE_UINT32
#define HASH_OBJECT_TYPE_COUNTER HASH_OBJECT_TYPE_UINT32

/* hash function types */
typedef enum
{
	HASH_FUNCTION_LCG = 0,
	HASH_FUNCTION_ZOBRIST,
	HASH_FUNCTION_MD5,
	HASH_FUNCTION_INVALID
} hash_function_type_t;



/* hash table options */
typedef enum
{
	HASH_TABLE_STORAGE_DYNAMIC = 0,
	HASH_TABLE_STORAGE_STATIC,
	HASH_TABLE_STORAGE_INVALID
} hash_table_storage_t;


typedef enum
{
	HASH_TABLE_COLLISION_CHAINING = 0,
	HASH_TABLE_COLLISION_OPEN_ADDRESSING_LINEAL,
	HASH_TABLE_COLLISION_INVALID
} hash_table_collision_t;



/* hash function */
struct hash_table_t;
typedef struct hash_function_t
{
	hash_function_type_t type;
	uint32_t (*hash) (struct hash_table_t * /* ht */, void * /* k1 */);
	void *state;
} hash_function_t;



/* hash table element */
struct hash_table_item_t;
typedef struct hash_table_item_t
{
	void *key;
	void *yield;
	struct hash_table_item_t *prev;
	uint32_t h;
	struct hash_table_item_t *next;
} hash_table_item_t;


#define DEFAULT_MAX_BUCKET_OCCUPANCY_RATIO .5


/* hash table frame */
typedef struct hash_table_t
{
	/* generic table info */
	hash_table_storage_t storage;
	hash_table_collision_t collision;

	/* key/yield info */
	hash_object_type_t key;
	hash_object_type_t yield;
	int copy_keys;
	int copy_yields;

	/* hash function */
	hash_function_t *hf;

	/* table implementation */
	/* array of hash nodes */
	hash_table_item_t **bucket;
	/* number of buckets in table */
	uint32_t nbuckets;
	/* table occupation (in entries) */
	uint32_t entries;
	/* used to select bits for hashing */
	uint32_t mask;
	/* maximum table occupation ratio */
	float max_bucket_occupancy_ratio;
} hash_table_t;



/* hash table raw API */
hash_table_t *ht_raw_init(hash_object_type_t key, hash_object_type_t yield,
		int copy_keys, int copy_yields, hash_function_t *hf, uint32_t nbuckets,
		float max_bucket_occupancy_ratio);
int ht_raw_destroy(hash_table_t* ht);
int ht_raw_reset(hash_table_t* ht);
int ht_raw_rebuild(hash_table_t* ht, uint32_t nbuckets);

hash_table_item_t *ht_raw_lookup(hash_table_t* ht, void* key, void* yield);
hash_table_item_t *ht_raw_get_next(hash_table_t* ht, hash_table_item_t *item,
		void* key);
uint32_t ht_raw_get_entries(hash_table_t* ht, void* key);
int ht_raw_exists(hash_table_t* ht, void* key, void* yield);
int ht_raw_insert(hash_table_t* ht, void* key, void* yield);
uint32_t ht_raw_remove(hash_table_t* ht, void* key, void* yield);



/* some useful keys/yields */
typedef struct conn_t
{
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
} conn_t;
int conn_should_swap (conn_t *conn, int onesided);
int conncmp (void *o1, void *o2);
int conncpy (void *o1, void *o2);
char *conn_marshall (void *obj);
int osconncmp (void *o1, void *o2);
int osconncpy (void *o1, void *o2);
char *osconn_marshall (void *obj);

int uint32cmp (void *o1, void *o2);
int uint32cpy (void *o1, void *o2);
char *uint32_marshall (void *obj);

int doublecmp (void *o1, void *o2);
int doublecpy (void *o1, void *o2);
char *double_marshall (void *obj);

typedef struct conninfo_t
{
	uint32_t pkts;
	uint32_t pkts_fwd;
	uint32_t pkts_bwd;
	double bytes;
	double bytes_fwd;
	double bytes_bwd;
} conninfo_t;
int conninfocmp (void *o1, void *o2);
int conninfocpy (void *o1, void *o2);
char *conninfo_marshall (void *obj);
void conninfo_add (conninfo_t *dst, conninfo_t *src);



typedef struct hash_object_t
{
	hash_object_type_t type;
	uint32_t len;
	int (*cmp) (void * /* o1 */, void * /* o2 */);
	int (*cpy) (void * /* o1 */, void * /* o2 */);
	char *(*marshall) (void * /* obj */);
/*
	int (*delete) (void *);
*/
} hash_object_t;

static hash_object_t ho[HASH_OBJECT_TYPE_INVALID] =
{
	{/*.type =*/ HASH_OBJECT_TYPE_CONNECTION,
		/*.len =*/ 13,
		/*.cmp =*/ conncmp,
		/*.cpy =*/ conncpy,
		/*.marshall =*/ conn_marshall},

	{/*.type =*/ HASH_OBJECT_TYPE_ONESIDED_CONNECTION,
		/*.len =*/ 13,
		/*.cmp =*/ osconncmp,
		/*.cpy =*/ osconncpy,
		/*.marshall =*/ osconn_marshall},

	{/*.type =*/ HASH_OBJECT_TYPE_UINT32,
		/*.len =*/ sizeof(uint32_t),
		/*.cmp =*/ uint32cmp,
		/*.cpy =*/ uint32cpy,
		/*.marshall =*/ uint32_marshall},

	{/*.type =*/ HASH_OBJECT_TYPE_DOUBLE,
		/*.len =*/ sizeof(double),
		/*.cmp =*/ doublecmp,
		/*.cpy =*/ doublecpy,
		/*.marshall =*/ double_marshall},

	{/*.type =*/ HASH_OBJECT_TYPE_CONNINFO,
		/*.len =*/ 36, /* ZZZ sizeof(conninfo_t) returns 24 ZZZ */
		/*.cmp =*/ conninfocmp,
		/*.cpy =*/ conninfocpy,
		/*.marshall =*/ conninfo_marshall},
};



/* some useful hash functions */

/* LCG API */
hash_function_t *hf_lcg_init();
uint32_t hf_lcg_generic (void *state, char *key, uint32_t len);
uint32_t hf_lcg (hash_table_t *ht, void *key);

/* zobrist API */
typedef struct hf_zobrist_state_t
{
	uint32_t tablelen;
	uint32_t tablemask;
	uint32_t *zobrist[256];
} hf_zobrist_state_t;
hash_function_t *hf_zobrist_init(uint32_t tablelen);
int hf_zobrist_remove(hash_function_t *hf);
int hf_zobrist_init_values (hf_zobrist_state_t *state);
uint32_t hf_zobrist_generic (hf_zobrist_state_t *state, char *key,
		uint32_t len);
uint32_t hf_zobrist (hash_table_t *ht, void *key);

/* MD5 API */
hash_function_t *hf_md5_init();
uint32_t hf_md5_generic (void *state, char *key, uint32_t len);
uint32_t hf_md5 (hash_table_t *ht, void *key);


#endif /* _HASH_H_ */

