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
#include "hash_helper.h"
#include <stdlib.h>

#undef DEBUG_HASH
//#define DEBUG_HASH 1

BasicBlockHashTable HT_construct(UInt n_chains)
{
   /* Initialises to zero, ie. all entries NULL */
   SizeT sz = sizeof(struct _BasicBlockHashTable) + n_chains*sizeof(HashNode*);
   BasicBlockHashTable table = (BasicBlockHashTable) calloc(1, sz);
   table->n_chains = n_chains;

   return table;
}


Int HT_count_nodes ( BasicBlockHashTable table )
{
   HashNode* node;
   UInt      chain;
   Int       n = 0;

   for (chain = 0; chain < table->n_chains; chain++)
      for (node = table->chains[chain]; node != NULL; node = node->next)
         n++;
   return n;
}

/* Puts a new, heap allocated HashNode, into the BasicBlockHashTable.  Prepends
   the node to the appropriate chain. */
void HT_add_node ( BasicBlockHashTable table, void* vnode )
{
   HashNode* node     = (HashNode*)vnode;
   UInt chain           = CHAIN_NO(node->key, table);

   #ifdef DEBUG_HASH
   printf("\n%d node->key = %x chain in HT\n",chain, node->key);
   #endif

   node->next           = table->chains[chain];
   table->chains[chain] = node;

   #ifdef DEBUG_HASH
   printf("inserted node->key = %x chain in HT\n",table->chains[chain]->key);
   #endif
}

/* Looks up a HashNode in the table.  Also returns the address of
   the previous node's 'next' pointer which allows it to be removed from the
   list later without having to look it up again.  */
void* HT_get_node ( BasicBlockHashTable table, UWord key,
                         /*OUT*/HashNode*** next_ptr )
{
   HashNode *prev, *curr;
   Int       chain;

   chain = CHAIN_NO(key, table);

   prev = NULL;
   curr = table->chains[chain];
   while (True) {
      if (curr == NULL)
         break;
      if (key == curr->key)
         break;
      prev = curr;
      curr = curr->next;
   }

   if (NULL == prev)
      *next_ptr = & (table->chains[chain]);
   else
      *next_ptr = & (prev->next);

   return curr;
}

/* Looks up a HashNode in the table.  Returns NULL if not found. */
void* HT_lookup ( BasicBlockHashTable table, UWord key )
{
   HashNode* curr = table->chains[ CHAIN_NO(key, table) ];

   while (curr) {

      #ifdef DEBUG_HASH
	  printf("chain no: %d key=%x curr-key=%x\n",CHAIN_NO(key, table), key, curr->key);
      #endif

      if (key == curr->key) {
         return curr;
      }
      curr = curr->next;
   }
   return NULL;
}

/* Removes a HashNode from the table.  Returns NULL if not found. */
void* HT_remove( BasicBlockHashTable table, UWord key )
{
   Int          chain         = CHAIN_NO(key, table);
   HashNode*  curr          =   table->chains[chain];
   HashNode** prev_next_ptr = &(table->chains[chain]);

   while (curr) {
      if (key == curr->key) {
         *prev_next_ptr = curr->next;
         free(curr);
         return curr;
      }
      prev_next_ptr = &(curr->next);
      curr = curr->next;
   }
   return NULL;
}



void HT_ResetIter(BasicBlockHashTable table)
{
   table->iterNode  = NULL;
   table->iterChain = 0;
}

void* HT_Next(BasicBlockHashTable table)
{
   Int i;

   if (table->iterNode && table->iterNode->next) {
      table->iterNode = table->iterNode->next;
      return table->iterNode;
   }

   for (i = table->iterChain; i < table->n_chains; i++) {
      if (table->chains[i]) {
         table->iterNode  = table->chains[i];
         table->iterChain = i + 1;  // Next chain to be traversed
         return table->iterNode;
      }
   }
   return NULL;
}

void HT_destruct(BasicBlockHashTable table)
{
   UInt       i;
   HashNode *node, *node_next;

   for (i = 0; i < table->n_chains; i++) {
      for (node = table->chains[i]; node != NULL; node = node_next) {
         node_next = node->next;
         free(node);
      }
   }
   free(table);
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
