/**********************************************************************************************
*      This file is part of X-Force, A Brute Force Execution Approach for Malware Analysis    *
*                                                                                             *
*      X-Force is owned and copyright (C) by Lab FRIENDS at Purdue University, 2009-2011.     *
*      All rights reserved.                                                                   *
*      Do not copy, disclose, or distribute without explicit written                          *
*      permission.                                                                            *
*                                                                                             *
*      Author: Zhiqiang Lin <zlin@cs.purdue.edu>                                              *
**********************************************************************************************/



/*--------------------------------------------------------------------*/
/*--- A hash table implementation.            hash_helper.h       ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of REDS, A Data Structure Reverse Engineering System.

   Copyright (C) 2008 Zhiqiang Lin
      zlin@cs.purdue.edu

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef _HASH_HELPER_H
#define _HASH_HELPER_H 1

/* Always 8 bits. */
typedef  unsigned char   UChar;
typedef    signed char   Char;
typedef           char   HChar; /* signfulness depends on host */
                                /* Only to be used for printf etc */

/* Always 16 bits. */
typedef  unsigned short  UShort;
typedef    signed short  Short;

/* Always 32 bits. */
typedef  unsigned int    UInt;
typedef  unsigned int    UINT;
typedef    signed int    Int;

/* Always 64 bits. */
typedef  unsigned long long int   ULong;
typedef    signed long long int   Long;

typedef  float   Float;    /* IEEE754 single-precision (32-bit) value */
typedef  double  Double;   /* IEEE754 double-precision (64-bit) value */

/* Bool is always 8 bits. */
typedef  unsigned char  Bool;
#define  True   ((Bool)1)
#define  False  ((Bool)0)

typedef  unsigned int HWord;
typedef  unsigned int Addr;


typedef signed int            Word;      // 32             64
typedef unsigned int          UWord;     // 32             64


typedef UWord                  AddrH;     // 32             64

typedef UWord                  SizeT;     // 32             64
typedef  Word                 SSizeT;     // 32             64

typedef  Word                   OffT;     // 32             64

typedef ULong                 Off64T;     // 64             64



#if !defined(NULL)
#  define NULL ((void*)0)
#endif


typedef struct _HashNode {
      struct _HashNode * next;
      UWord              key;
} HashNode;

struct _BasicBlockHashTable {
   UInt        n_chains;      // should be prime
   HashNode* iterNode;      // current iterator node
   UInt        iterChain;     // next chain to be traversed by the iterator
   HashNode* chains[0];     // must be last field in the struct!
};

typedef struct _BasicBlockHashTable * BasicBlockHashTable;


#define CHAIN_NO(key,tbl) (((UWord)(key)) % tbl->n_chains)

extern BasicBlockHashTable HT_construct(UInt n_chains);
extern Int HT_count_nodes ( BasicBlockHashTable table );
extern void HT_add_node ( BasicBlockHashTable table, void* vnode );
extern void* HT_get_node ( BasicBlockHashTable table, UWord key,HashNode*** next_ptr );


extern void* HT_lookup ( BasicBlockHashTable table, UWord key );
extern void* HT_remove( BasicBlockHashTable table, UWord key );
extern void HT_ResetIter(BasicBlockHashTable table);
extern void* HT_Next(BasicBlockHashTable table);
extern void HT_destruct(BasicBlockHashTable table);

#endif
