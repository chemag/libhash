/*
 *
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



/**
 * \file hash.c
 *
 * \brief This file implements a generic {key,yield} hash table.
 *
 * The hash table is organized as an array of buckets containing chained 
 * lists of items. Every item is a {key,yield} tuple. 
 *
 * \note This isn't exactly a key/yield hash table, as the key need not
 *       be unique. 
 *
 */


#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/md5.h>


#include "hash.h"
#include "util.h"



/**
 * \brief Initialize the hash table
 *
 * \param[in] key Key type
 * \param[in] yield Yield type
 * \param[in] copy_keys Whether the version of the keys in the hash table
 *            is the object that was passed in the insertion, or a copy
 * \param[in] copy_yields Whether the version of the yields in the hash table
 *            is the object that was passed in the insertion, or a copy
 * \param[in] hf Hash function
 * \param[in] nbuckets Initial number of buckets
 * \param[in] max_bucket_occupancy_ratio Maximum bucket occupancy ratio
 * \retval Hash table (NULL if problems)
 */
hash_table_t *ht_raw_init(hash_object_type_t key, hash_object_type_t yield,
		int copy_keys, int copy_yields, hash_function_t *hf,
		uint32_t nbuckets, float max_bucket_occupancy_ratio)
{
	hash_table_t *ht;
	uint32_t h;

	/* allocate the hash table frame */
	ht = (hash_table_t*) malloc (1 * sizeof(hash_table_t));
	if ( ht == NULL )
		{
		fprintf(stderr, "Error: allocating hash table failed\n");
		exit(-1);
		}

	/* store the parameters */
	ht->storage = HASH_TABLE_STORAGE_DYNAMIC;
	ht->collision = HASH_TABLE_COLLISION_CHAINING;
	ht->key = key;
	ht->yield = yield;
	ht->copy_keys = copy_keys;
	ht->copy_yields = copy_yields;
	ht->hf = hf;
	ht->max_bucket_occupancy_ratio = max_bucket_occupancy_ratio;

	/* ensure nbuckets is a power of 2 and larger than 16 */
	ht->nbuckets = 0x40000000;
	while ( ht->nbuckets > nbuckets )
		ht->nbuckets >>= 1;
	if ( ht->nbuckets < 16 )
		ht->nbuckets = 16;

	ht->mask = ht->nbuckets - 1;

	/* allocate and zero memory for table */
	ht->bucket = (hash_table_item_t **) malloc (ht->nbuckets *
			sizeof(hash_table_item_t*));
	for (h = 0; h < ht->nbuckets; ++h)
		ht->bucket[h] = 0;

	/* initialize the number of entries */
	ht->entries = 0;

	return ht;
}



/**
 * \brief Destroy the hash table
 *
 * \param[in] ht Hash table
 * \retval 0 if OK, -1 if problems
 */
int ht_raw_destroy(hash_table_t* ht)
{
	/* reset the hash table */
	(void)ht_raw_reset(ht);

	/* free bucket table */
	free(ht->bucket);

	return 0;
}



/**
 * \brief Reset the hash table (remove all the items)
 *
 * \param[in] ht Hash table
 * \retval 0 if OK, -1 if problems
 */
int ht_raw_reset(hash_table_t* ht)
{
	/* remove all elements */
	(void)ht_raw_remove(ht, NULL, NULL);

	return 0;
}



/**
 * \brief Rebuild the hash table
 *
 * Regenerate the hash table with a different number of buckets
 *
 * \param[in] ht Hash table
 * \param[in] nbuckets Initial number of buckets
 */
int ht_raw_rebuild(hash_table_t* ht, uint32_t nbuckets)
{
	hash_table_t *newht;
	hash_table_item_t *item, *next;
	uint32_t h, i;


	/* log resizing */
	fprintf(stderr, "%s Resizing hash table (%d->%d)\n",
			__func__, ht->nbuckets, nbuckets);

	/* create a new table */
	newht = ht_raw_init(ht->key, ht->yield, ht->copy_keys, ht->copy_yields,
			ht->hf, ht->nbuckets, ht->max_bucket_occupancy_ratio);

	/* rehash items in the old bucket */
	for (i=0;i<ht->nbuckets;++i)
		{
		/* get an element from the old bucket */
		item = ht->bucket[i];
		while (item != NULL)
			{
			next = item->next;
			/* queue the old item in the new hash table */
			h = (newht->hf->hash(newht, item->key)) & newht->mask;
			item->prev = NULL;
			item->h = h;
			item->next = newht->bucket[h];
			newht->bucket[h] = item;
			if ( item->next != NULL )
				item->next->prev = item;
			++newht->entries;
			item = next;
			}
		}

	/* free old hash table */
	if (ht->bucket)
		free(ht->bucket);

	/* copy new hash table contents to old frame */
	memcpy(ht, newht, sizeof(hash_table_t));

	/* free the tmp hash table frame */
 	free(newht);

	return 0;
}



/**
 * \brief Lookup a key in the hash table
 * 
 * This function returns the first item that matches the {key,yield} passed
 * as parameters. If yield is NULL, it returns the first item that matches
 * {key, *}. If key is also NULL, it returns the very first item in the 
 * table.
 *
 * \param[in] ht Hash table
 * \param[in] key Key used for the lookup (NULL accepts all keys)
 * \param[in] yield Yield used for the lookup (NULL accept all yields)
 * \retval hash_table_item_t* Matching item (NULL if none)
 */
hash_table_item_t *ht_raw_lookup(hash_table_t* ht, void* key, void* yield)
{
	hash_table_item_t *item = NULL;
	uint32_t h, h1, h2;
	int exit;

	/* get the hash table bucket range */
	if ( key == NULL ) {
		/* we want any key */
		h1 = 0;
		h2 = ht->nbuckets;
	} else {
		/* hash the key */
		h1 = (ht->hf->hash(ht, key)) & ht->mask;
		h2 = h1 + 1;
	}

	/* lookup the item in the hash table */
	exit = 0;
	for (h = h1; h < h2 && !exit; ++h)
		/* get an entry in the hash table */
		for (item = ht->bucket[h]; item != NULL && !exit; item = item->next)
			if ( (key == NULL) || (ho[ht->key].cmp(key, item->key) == 0) )
				/* key matches */
				if ( (yield == NULL) || (ho[ht->yield].cmp(yield, item->yield) == 0) )
					{
					/* yield matches or does not exist */
					exit = 1;
					break;
					}

	/* return the entry if it exists, or NULL */
	return (item ? item : NULL);
}



/**
 * \brief Gets next yield in hash table
 * 
 * This function returns the next item (next when compared with the item
 * passed as first parameter) in the hash table that match a key
 * 
 * \param[in] item The current item
 * \param[in] key The key used to filter out entries (use NULL to get all)
 * \retval hash_table_item_t* The next item (NULL if none)
 */
hash_table_item_t *ht_raw_get_next(hash_table_t* ht, hash_table_item_t *item, 
		void* key)
{
	uint32_t h;
	hash_table_item_t *next;

	if ( item == NULL )
		{
		/* no item yet => use the key to decide the starting point */
		if ( key == NULL )
			/* hash table start */
			h = 0;
		else
			/* hash the key */
			h = (ht->hf->hash(ht, key)) & ht->mask;

		}
	else
		{
		/* item exists => just get next one */
		next = item->next;
		if ( next != NULL )
			{
			/* if there's a next item, it must be it (or none) */
			if ( (key == NULL) || (ho[ht->key].cmp(key, next->key) == 0) )
				/* the key matches */
				return next;
			else
				/* the key does not match */
				return NULL;
			}

		/* if there's no next item in the current bucket, check the next bucket */
		h = item->h;
		if ( ++h > ht->nbuckets )
			/* no more buckets */
			return NULL;
		}

	if ( key == NULL )
		/* wildcard query */
		for (; h < ht->nbuckets; ++h)
			/* check in this bucket */
			for (next = ht->bucket[h]; next != NULL; next = next->next)
				/* if there's a next, this is the one */
				return next;

	else
		/* specific query => check in this bucket */
		for (next = ht->bucket[h]; next != NULL; next = next->next)
			/* if there's a next, check whether this is the one */
			if ( ho[ht->key].cmp(key, next->key) == 0 )
				return next;
 
	return NULL;
}



/**
 * \brief Get the number of entries associated to a given key
 *
 * \param[in] ht Hash table
 * \param[in] key The key
 * \retval uint32_t Number of entries
 */
uint32_t ht_raw_get_entries(hash_table_t* ht, void* key)
{
	hash_table_item_t *item = NULL;
	uint32_t entries = 0;
#if 0
	uint32_t h, h1, h2;
#endif

	item = ht_raw_get_next(ht, NULL, key);
	for (; item != NULL; item = ht_raw_get_next(ht, item, key))
		++entries;

#if 0

	/* get the hash table bucket range */
	if ( key == NULL )
		/* we want any key */
		return ht->entries;

	/* hash the key */
	h1 = (ht->hf->hash(ht, key)) & ht->mask;
	h2 = h1 + 1;

	/* lookup the item in the hash table */
	for (h = h1; h < h2; ++h)
		/* get an entry in the hash table */
		for (item = ht->bucket[h]; item != NULL; item = item->next)
			if ( ho[ht->key].cmp(key, item->key) == 0 )
				/* key matches */
				++entries;

#endif

	/* return the number of entries */
	return entries;
}



/**
 * \brief Return whether a key or {key,yield} tuple exists in the hash table
 *
 * This is a handy shortcut for lookup
 *
 * \param[in] ht Hash table
 * \param[in] key Key used for the lookup (NULL accepts all keys)
 * \param[in] yield Yield used to filter out items (NULL to disable filtering)
 * \retval int 0 if doesn't exist, 1 otherwise
 */
int ht_raw_exists(hash_table_t* ht, void* key, void* yield)
{
	if ( ht_raw_lookup(ht, key, yield) == NULL )
		return 0;
	return 1;
}




/**
 * \brief Insert a {key,yield} tuple in the hash table
 *
 * This function inserts an item in the hash table. If there is
 * already another item with the exact same contents, the function 
 * just returns -1.
 *
 * \param[in] ht Hash table
 * \param[in] key Key used for the lookup (NULL accepts all keys)
 * \param[in] yield Yield used to filter out items (NULL to disable filtering)
 * \retval 0 if OK, -1 if problems (the item exists already)
 */
int ht_raw_insert(hash_table_t* ht, void* key, void* yield)
{
	int h;
	hash_table_item_t *item;

	/* check if the entry exists already */
	if ( ht_raw_exists(ht, key, yield) )
		return -1;

	/* expand the table if needed */
	while (ht->entries >= (ht->max_bucket_occupancy_ratio * ht->nbuckets))
		ht_raw_rebuild(ht, ht->nbuckets*2);

	/* create the new item */
	item = (hash_table_item_t *) malloc (1* sizeof(hash_table_item_t));
	if ( ht->copy_keys )
		{
		item->key = malloc(1 * ho[ht->key].len);
		ho[ht->key].cpy(item->key, key);
		}
	else
		item->key = key;
	if ( ht->copy_yields )
		{
		item->yield = malloc(1 * ho[ht->yield].len);
		ho[ht->yield].cpy(item->yield, yield);
		}
	else
		item->yield = yield;

	/* insert the new item */
	h = (ht->hf->hash(ht, item->key)) & ht->mask;
	item->prev = NULL;
	item->h = h;
	item->next = ht->bucket[h];
	if ( item->next != NULL )
		item->next->prev = item;
	ht->bucket[h] = item;

	/* update the number of entries */
	++ht->entries;

	return 0;
}




/**
 * \brief Remove an entry
 *
 * \param[in] ht Hash table
 * \param[in] key Key used for the lookup (NULL accepts all keys)
 * \param[in] yield Yield used to filter out items (NULL to disable filtering)
 * \retval Number of entries deleted
 */
uint32_t ht_raw_remove(hash_table_t* ht, void* key, void* yield)
{
	hash_table_item_t *prev, *item, *next;
	uint32_t h, h1, h2;
	uint32_t cnt;

	/* get the hash table bucket range */
	if ( key == NULL ) {
		/* we want any key */
		h1 = 0;
		h2 = ht->nbuckets;
	} else {
		/* hash the key */
		h1 = (ht->hf->hash(ht, key)) & ht->mask;
		h2 = h1 + 1;
	}

	/* lookup the item in the hash table */
	cnt = 0;
	for (h = h1; h < h2; ++h)
		{
		/* get an item from the hash table */
		item = ht->bucket[h];
		for (; item != NULL ; item = next)
			{
			prev = item->prev;
			next = item->next;
			if ( (key == NULL) || (ho[ht->key].cmp(key, item->key) == 0) )
				/* key matches */
				if ( (yield == NULL) || (ho[ht->yield].cmp(yield, item->yield) == 0) )
					{
					/* yield matches or does not exist */
					/* extract item from the chain */
					if ( prev != NULL )
						prev->next = item->next;
					else
						/* first item in the bucket chain */
						ht->bucket[h] = ht->bucket[h]->next;
					if ( next != NULL )
						next->prev = item->prev;
					/* remove item */
					/* (ho[ht->key].free(item->key); */
					free(item->key);
					/* (ho[ht->yield].free(item->yield); */
					free(item->yield);
					free(item);
					/* update the number of entries */
					--ht->entries;
					++cnt;
					}
			}
		}

	return cnt;
}



/*
 * Objects Functions
 */



/**
 * \brief Decide whether to swap the order of a connection object
 * 
 * \param[in] conn connection object
 * \retval 1 if must swap, 0 if must not
 */
int conn_should_swap (conn_t *conn)
{
	if ( conn->saddr > conn->daddr )
		return 1;
	else if ( conn->saddr < conn->daddr )
		return 0;
	else
		return ( conn->sport > conn->dport );
}



/**
 * \brief Compare two connections
 * 
 * \param[in] o1 first connection
 * \param[in] o2 second connection
 * \retval int order (an integer less than, equal to, or greater than zero
 *         if o1 is found, respectively, to be less than, to match, or be
 *         greater than o2)
 */
int conncmp (void *o1, void *o2)
{
	conn_t *conn1, *conn2;
	int swap1, swap2;
	uint32_t word1, word2;

	/* get the connections */
	conn1 = (conn_t *)o1;
	conn2 = (conn_t *)o2;

	/* same connection, same direction */
	if ( conn1->saddr == conn2->saddr &&
			conn1->daddr == conn2->daddr &&
			conn1->sport == conn2->sport &&
			conn1->dport == conn2->dport &&
			conn1->proto == conn2->proto)
		return 0;

	/* same connection, opposite direction */
	if ( conn1->saddr == conn2->daddr &&
			conn1->daddr == conn2->saddr &&
			conn1->sport == conn2->dport &&
			conn1->dport == conn2->sport &&
			conn1->proto == conn2->proto)
		return 0;

	/* return some meaningful order */

	/* check whether we need to swap any connection */
	swap1 = conn_should_swap (conn1);
	swap2 = conn_should_swap (conn2);

	/* compare first addr */
	word1 = (!swap1) ? conn1->saddr : conn1->daddr;
	word2 = (!swap2) ? conn2->saddr : conn2->daddr;
	if ( word1 > word2 )
		return -1;
	else if ( word1 < word2 )
		return 1;

	/* compare second addr */
	word1 = (swap1) ? conn1->saddr : conn1->daddr;
	word2 = (swap2) ? conn2->saddr : conn2->daddr;
	if ( word1 > word2 )
		return -1;
	else if ( word1 < word2 )
		return 1;

	/* compare first port */
	word1 = (!swap1) ? conn1->sport : conn1->dport;
	word2 = (!swap2) ? conn2->sport : conn2->dport;
	if ( word1 > word2 )
		return -1;
	else if ( word1 < word2 )
		return 1;

	/* compare second port */
	word1 = (swap1) ? conn1->sport : conn1->dport;
	word2 = (swap2) ? conn2->sport : conn2->dport;
	if ( word1 > word2 )
		return -1;
	else if ( word1 < word2 )
		return 1;

	/* compare protocols */
	if ( conn1->proto > conn2->proto )
		return -1;
	else if ( conn1->proto < conn2->proto )
		return 1;
	return 0;
}



/**
 * \brief Copy a connection
 * 
 * \param[in] o1 source connection
 * \param[in] o2 destination connection
 * \retval 0 if OK, -1 if problems
 */
int conncpy (void *o1, void *o2)
{
	conn_t *conn1, *conn2;

	/* get the connections */
	conn1 = (conn_t *)o1;
	conn2 = (conn_t *)o2;

	/* copy the 5-tuple */
	conn1->saddr = conn2->saddr;
	conn1->daddr = conn2->daddr;
	conn1->sport = conn2->sport;
	conn1->dport = conn2->dport;
	conn1->proto = conn2->proto;

	return 0;
}



/**
 * \brief Marshall a connection
 * 
 * This functions serializes a connection into a char buffer, so that 
 * generic hashing can be applied
 *
 * \note We want the hash value to be the same for the 2 sides of a
 * connection.
 * 
 * \param[in] obj connection
 * \retval char* Marshalled connection
 */
char *conn_marshall (void *obj)
{
	conn_t *conn;
	int swap;
	static char buf[13];
	uint32_t word, sport32, dport32;


	/* get the connection */
	conn = (conn_t *)obj;

	/* check whether we need to swap src and dst */
	swap = conn_should_swap (conn);

	/* marshall value */
	/* order saddr and daddr to get the same hash for the two directions of
	 * a connection */
	word = (!swap) ? conn->saddr : conn->daddr;
	buf[0] = (char)((word<<0)>>24);
	buf[1] = (char)((word<<8)>>24);
	buf[2] = (char)((word<<16)>>24);
	buf[3] = (char)((word<<24)>>24);
	word = (swap) ? conn->saddr : conn->daddr;
	buf[4] = (char)((word<<0)>>24);
	buf[5] = (char)((word<<8)>>24);
	buf[6] = (char)((word<<16)>>24);
	buf[7] = (char)((word<<24)>>24);
	sport32 = (uint32_t) conn->sport;
	dport32 = (uint32_t) conn->dport;
	word = (!swap) ? ((sport32<<16) | dport32) : ((dport32<<16) | sport32);
	buf[8] = (char)((word<<0)>>24);
	buf[9] = (char)((word<<8)>>24);
	buf[10] = (char)((word<<16)>>24);
	buf[11] = (char)((word<<24)>>24);
	buf[12] = (char)conn->proto;

	return buf;
}



/**
 * \brief Compare two uint32 objects
 * 
 * \param[in] o1 first object
 * \param[in] o2 second object
 * \retval int order (an integer less than, equal to, or greater than zero
 *         if o1 is found, respectively, to be less than, to match, or be
 *         greater than o2)
 */
int uint32cmp (void *o1, void *o2)
{
	uint32_t u1, u2;

	/* get the values */
	u1 = *(uint32_t *)o1;
	u2 = *(uint32_t *)o2;

	/* compare values */
	if ( u1 > u2 )
		return -1;
	else if ( u1 < u2 )
		return 1;
	return 0;
}



int uint32cpy (void *o1, void *o2)
{
	uint32_t *u1, *u2;

	/* get the values */
	u1 = (uint32_t *)o1;
	u2 = (uint32_t *)o2;

	/* copy value */
	*u1 = *u2;
	return 0;
}



char *uint32_marshall (void *obj)
{
	uint32_t u;
	static char buf[64];
	uint32_t i;

	/* get the value */
	u = *(uint32_t *)obj;

	/* marshall value */
	for (i = 0; i < sizeof(uint32_t); ++i)
		buf[i] = *(((char *)&u)+i);

	return buf;
}



/**
 * \brief Compare two double objects
 * 
 * \param[in] o1 first object
 * \param[in] o2 second object
 * \retval int order (an integer less than, equal to, or greater than zero
 *         if o1 is found, respectively, to be less than, to match, or be
 *         greater than o2)
 */
int doublecmp (void *o1, void *o2)
{
	double d1, d2;

	/* get the values */
	d1 = *(double *)o1;
	d2 = *(double *)o2;

	/* compare values */
	if ( d1 > d2 )
		return -1;
	else if ( d1 < d2 )
		return 1;
	return 0;
}



int doublecpy (void *o1, void *o2)
{
	double *d1, *d2;

	/* get the values */
	d1 = (double *)o1;
	d2 = (double *)o2;

	/* copy value */
	*d1 = *d2;
	return 0;
}



char *double_marshall (void *obj)
{
	double d;
	static char buf[128];
	uint32_t i;

	/* get the value */
	d = *(double *)obj;

	/* marshall value */
	for (i = 0; i < sizeof(double); ++i)
		buf[i] = *(((char *)&d)+i);

	return buf;
}



/**
 * \brief Compare two conninfo's
 * 
 * \param[in] o1 first connection
 * \param[in] o2 second connection
 * \retval int order (an integer less than, equal to, or greater than zero
 *         if o1 is found, respectively, to be less than, to match, or be
 *         greater than o2)
 */
int conninfocmp (void *o1, void *o2)
{
	(void)o1;
	(void)o2;

	fprintf(stderr, "This function should not be called\n");
	abort();
	return 0;
}


int conninfocpy (void *o1, void *o2)
{
	conninfo_t *c1, *c2;

	/* get the values */
	c1 = (conninfo_t *)o1;
	c2 = (conninfo_t *)o2;

	/* copy the 6 values */
	c1->pkts = c2->pkts;
	c1->pkts_fwd = c2->pkts_fwd;
	c1->pkts_bwd = c2->pkts_bwd;
	c1->bytes = c2->bytes;
	c1->bytes_fwd = c2->bytes_fwd;
	c1->bytes_bwd = c2->bytes_bwd;

	return 0;
}



char *conninfo_marshall (void *obj)
{
	conninfo_t c;
	static char buf[64];
	uint32_t i;

	/* get the value */
	c = *(conninfo_t *)obj;

	/* marshall value */
	for (i = 0; i < sizeof(conninfo_t); ++i)
		buf[i] = *(((char *)&c)+i);

	return buf;
}



void conninfo_add (conninfo_t *dst, conninfo_t *src)
{
	dst->pkts += src->pkts;
	dst->pkts_fwd += src->pkts_fwd;
	dst->pkts_bwd += src->pkts_bwd;
	dst->bytes += src->bytes;
	dst->bytes_fwd += src->bytes_fwd;
	dst->bytes_bwd += src->bytes_bwd;
}



/**
 * \brief Create a LCG-based Hash Function
 * 
 * This function creates a hash function based on a simple LCG.
 *
 * \note LCG hashing is deterministic across multiple runs
 * 
 * \retval hash_function_t Hash function
 */
hash_function_t *hf_lcg_init()
{
	hash_function_t *hf;

	/* allocate function */
	hf = (hash_function_t*) malloc (1 * sizeof(hash_function_t));

	/* fill up hash function */
	hf->hash = hf_lcg;
	hf->type = HASH_FUNCTION_LCG;
	hf->state = NULL;

	return hf;
}



/** 
 * \brief Simple hash function (LCG-based)
 * 
 * This hash function returns a hash number for a given key. It's not too
 * strong, but that doesn't really matter in our environment. 
 *
 * Obtained from "Numerical Recipes in C. The Art of Scientific Computing," 
 * by W.H. Press et al. ISBN 0-521-43108-5. Discussion available at 
 * http://en.wikipedia.org/wiki/Linear_congruential_generator
 *
 * V_{j+1} = (A V_j + B) mod M, where A = 1664525, B = 1013904223, M = 2^{32}
 * 
 * \param[in] key Key
 * \retval uint32_t Hash value
 */
uint32_t hf_lcg_generic (void *state, char *key, uint32_t len)
{
	uint32_t i, hashvalue, tmp;
	uint32_t A, B;

	/* there's no state */
	(void)state;

	/* init A and B */
	A = 1664525;
	B = 1013904223;

	hashvalue = 0;
	tmp = 0;
	for (i=0; i<len; ++i)
		{
		tmp = (tmp << 8) + (*key++);
		/* every 4 bytes, or in the very last byte, hash the value */
		if ( (((i+1) % 4) == 0) || (i == len-1) )
			{
			/* get the LCG */
			tmp = (tmp * A) + B;
			/* xor with the previous value */
			hashvalue = hashvalue ^ tmp;
			tmp = 0;
			}
		}

	return hashvalue;
}


uint32_t hf_lcg (hash_table_t *ht, void *key)
{
	char *buf;

	/* marshall key before hashing it */
	buf = ho[ht->key].marshall(key);

	return hf_lcg_generic (NULL, buf, ho[ht->key].len);
}



/**
 * \brief Create a Zobrist Hash Function
 * 
 * This function creates a hash function based on a 256xtablelen Zobrist
 * table
 * 
 * \param[in] tablelen Zobrist Table Length
 * \retval hash_function_t Hash function
 */
hash_function_t *hf_zobrist_init(uint32_t tablelen)
{
	hash_function_t *hf;
	hf_zobrist_state_t *state;
	int i;

	/* allocate function */
	hf = (hash_function_t*) malloc (1 * sizeof(hash_function_t));

	/* allocate state */
	state = (hf_zobrist_state_t*) malloc (1 * sizeof(hf_zobrist_state_t));

	/* ensure Zobrist table length is a power of 2 */
	state->tablelen = 0x40000000;
	while ( state->tablelen > tablelen )
		state->tablelen >>= 1;

	state->tablemask = state->tablelen - 1;

	/* allocate Zobrist table */
	for (i=0; i<256; ++i)
		state->zobrist[i] = (uint32_t *) malloc (state->tablelen*sizeof(uint32_t));

	/* init Zobrist table values */
	(void)hf_zobrist_init_values (state);

	/* fill up hash function */
	hf->hash = hf_zobrist;
	hf->type = HASH_FUNCTION_ZOBRIST;
	hf->state = (void *)state;

	return hf;
}



int hf_zobrist_remove(hash_function_t *hf)
{
	int i;
	hf_zobrist_state_t *state;

	if ( hf->type != HASH_FUNCTION_ZOBRIST )
		/* non-Zobrist hash table */
		return -1;

	/* free Zobrist table */
	state = (hf_zobrist_state_t *)hf->state;
	for (i=0;i<256;++i)
		free(state->zobrist[i]);

	return 0;
}




/**
 * \brief Init hash table values
 * 
 * \param[in] state Zobrist hash table state
 * \retval 0 if OK, -1 if problems
 */
int hf_zobrist_init_values (hf_zobrist_state_t *state)
{
	struct timeval the_time;
	uint32_t i, j;

	/* get the PRNG seed */
	gettimeofday (&the_time, NULL);

	/* seed the PRNG */
	srandom(the_time.tv_usec);

	/* init Zobrist table values */
	for (i=0;i<256;++i)
		for (j=0;j<state->tablelen;++j)
			state->zobrist[i][j] = random();

	return 0;
}



/**
 * \brief Simple hash function (Zobrist-based)
 * 
 * This hash function returns a hash number for a given key. It's not too
 * strong, but that doesn't really matter in our environment. 
 *
 * Obtained from 
 * http://en.wikipedia.org/wiki/Zobrist_hashing
 * http://web.archive.org/web/20070822204038/http://www.seanet.com/~brucemo/topics/zobrist.htm
 *
 * \param[in] state hash function state
 * \param[in] key key
 * \param[in] len key length
 * \retval uint32_t Hash value
 */
uint32_t hf_zobrist_generic (hf_zobrist_state_t *state, char *key, uint32_t len)
{
	uint32_t i, hashvalue;

	/* get the hash value */
	hashvalue = 0;
	i = 0;
	while ( i < len )
		hashvalue ^= state->zobrist[(int)(*key++)][i++&state->tablemask];

	return hashvalue;
}



uint32_t hf_zobrist (hash_table_t *ht, void *key)
{
	hf_zobrist_state_t *state;
	char *buf;

	state = (hf_zobrist_state_t *)ht->hf->state;

	/* marshall key before hashing it */
	buf = ho[ht->key].marshall(key);

	return hf_zobrist_generic (state, buf, ho[ht->key].len);
}



/**
 * \brief Create an MD5-based Hash Function
 * 
 * This function creates a hash function based on MD5.
 *
 * \retval hash_function_t Hash function
 */
hash_function_t *hf_md5_init()
{
	hash_function_t *hf;

	/* allocate function */
	hf = (hash_function_t*) malloc (1 * sizeof(hash_function_t));

	/* fill up hash function */
	hf->hash = hf_md5;
	hf->type = HASH_FUNCTION_MD5;
	hf->state = NULL;

	/* init md5 random seed */
	md5_init_random_seed();

	return hf;
}



/** 
 * \brief Simple hash function (MD5-based)
 * 
 * This hash function returns a hash number for a given key. 
 *
 * \param[in] key Key
 * \param[in] len Key length
 * \retval uint32_t Hash value
 */
uint32_t hf_md5_generic (void *state, char *key, uint32_t len)
{
	uint32_t hashvalue;
	uint32_t digest[16];

	(void)state;
	hmac_md5(len, (unsigned char*) key, (unsigned char*) digest);
	hashvalue = digest[0];

	return hashvalue;
}



uint32_t hf_md5 (hash_table_t *ht, void *key)
{
	char *buf;

	/* marshall key before hashing it */
	buf = ho[ht->key].marshall(key);

	return hf_md5_generic (NULL, buf, ho[ht->key].len);
}




#ifdef _HASH_TESTSUITE_

#if 0
#define ESCAPE_CONN "0x%08x, %u, 0x%08x, %u, %i"
#define ARGS_CONN(conn) conn.saddr, conn.sport, conn.daddr, conn.dport, conn.proto
#endif

#define ESCAPE_CONN "%d.%d.%d.%d:%u, %d.%d.%d.%d:%u, %i"
#define ARGS_CONN(conn) \
		((conn)->saddr>>24)&0xff, ((conn)->saddr>>16)&0xff, \
		((conn)->saddr>>8)&0xff, ((conn)->saddr>>0)&0xff, \
		(conn)->sport, \
		((conn)->daddr>>24)&0xff, ((conn)->daddr>>16)&0xff, \
		((conn)->daddr>>8)&0xff, ((conn)->daddr>>0)&0xff, \
		(conn)->dport, (conn)->proto


int test_1();
int main()
{
	(void)test_1();
	return 0;
}



int test_1()
{
	hash_table_t *ht;
	hash_function_t *hf;
	hash_table_item_t *item;
	uint32_t nbuckets, entries;
	float max_bucket_occupancy_ratio;
	int copy_keys, copy_yields;
	conn_t conn;
	uint32_t cnt;
	uint32_t i;
	conn_t conn1 = {
		.saddr = 0x01020304,
		.daddr = 0x05060708,
		.sport = 101,
		.dport = 102,
		.proto = 11
	};
	conn_t conn2 = {
		.saddr = 0x11121314,
		.daddr = 0x15161718,
		.sport = 201,
		.dport = 202,
		.proto = 22
	};

	/* create hash function */
	hf = hf_lcg_init();
	/*hf = hf_zobrist_init(256); */
	/*hf = hf_md5_init();*/

	/* create hash table */
	nbuckets = 1024;
	copy_keys = 1;
	copy_yields = 1;
	max_bucket_occupancy_ratio = DEFAULT_MAX_BUCKET_OCCUPANCY_RATIO;
	ht = ht_raw_init(HASH_OBJECT_TYPE_CONNECTION, HASH_OBJECT_TYPE_COUNTER,
			copy_keys, copy_yields, hf, nbuckets, max_bucket_occupancy_ratio);


	/* add some elements */
	(void)conncpy(&conn, &conn1);
	cnt = 1;
	(void)ht_raw_insert(ht, (void*)&conn, (void*)&cnt);
	fprintf(stdout, "insert: adding {" ESCAPE_CONN ",, %u}\n",
			ARGS_CONN(&conn), cnt);
	fprintf(stdout, "Num entries is %i\n", ht->entries);

	cnt = 11;
	(void)ht_raw_insert(ht, (void*)&conn, (void*)&cnt);
	fprintf(stdout, "insert: adding {" ESCAPE_CONN ",, %u}\n",
			ARGS_CONN(&conn), cnt);
	fprintf(stdout, "Num entries is %i\n", ht->entries);

	(void)conncpy(&conn, &conn2);
	cnt = 2;
	(void)ht_raw_insert(ht, (void*)&conn, (void*)&cnt);
	fprintf(stdout, "insert: adding {" ESCAPE_CONN ",, %u}\n",
			ARGS_CONN(&conn), cnt);
	fprintf(stdout, "Num entries is %i\n", ht->entries);

	/* lookup the last inserted element */
	item = ht_raw_lookup(ht, (void*)&conn, NULL);
	fprintf(stdout, "lookup: {" ESCAPE_CONN ",, *} %s\n",
			ARGS_CONN(&conn),
			( item != NULL ) ? "exists" : "does not exist");

	/* count the number of elements with conn1 */
	memcpy(&conn, &conn1, sizeof(conn_t));
	entries = ht_raw_get_entries(ht, &conn);
	fprintf(stdout, "get_entries: there are %u entries for {" ESCAPE_CONN "}\n",
			entries, ARGS_CONN(&conn));
	item = NULL;
	for (i=0; i<entries; ++i)
		{
		/* get next entry */
		item = ht_raw_get_next(ht, item, (void*)&conn);
		cnt = *(uint32_t *)item->yield;
		fprintf(stdout, "\t%i: {" ESCAPE_CONN ",, %u}\n",
				i, ARGS_CONN(&conn), cnt);
		}

	/* remove last element */
	fprintf(stdout, "remove: removing {" ESCAPE_CONN ",, *}\n",
			ARGS_CONN(&conn));
	ht_raw_remove(ht, (void*)&conn, NULL);
	fprintf(stdout, "Num entries is %i\n", ht->entries);

	/* lookup the last removed element */
	item = ht_raw_lookup(ht, (void*)&conn, NULL);
	fprintf(stdout, "lookup: {" ESCAPE_CONN ",, *} %s\n",
			ARGS_CONN(&conn),
			( item != NULL ) ? "exists" : "does not exist");

	/* reset table */
	fprintf(stdout, "reset: resetting table\n");
	(void)ht_raw_reset(ht);
	fprintf(stdout, "Num entries is %i\n", ht->entries);


	/* destroy table */
	(void)ht_raw_destroy(ht);

	return 0;
}


#endif /* _HASH_TESTSUITE_ */

