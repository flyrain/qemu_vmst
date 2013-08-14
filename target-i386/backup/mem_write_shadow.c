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




#include "hash_helper.h"
#include "mem_write_shadow.h"
#include <stdlib.h>
/*---------------------shadow memory----------------------*/
#define PAGE_SIZE 65536
#define PAGE_NUM 262144

#define IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(map, addr)                              \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[(addr) >> 16])) {       \
         map[(addr) >> 16] = alloc_secondary_map; \
      }                                                           \
   } while(0)

#define ENSURE_MAPPABLE_BYTE_GRANUITY(map,addr)         \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[(addr)&0x03][(addr) >> 16])) {    \
          map[(addr)&0x03][(addr) >> 16] = alloc_secondary_map(); \
      }                                                           \
   } while(0)



typedef struct {
   UChar byte[PAGE_SIZE];
} SecMap;

static SecMap distinguished_secondary_map;

static SecMap * ii_primary_map[4][PAGE_NUM];

unsigned int shadow_bytes;


void init_shadow_mem_write_memory(void)
{
    Int i,j;

    for (i = 0; i< PAGE_SIZE; i++)
       distinguished_secondary_map.byte[i] = VGM_BYTE_INVALID; //0xff

    for (j=0;j<4; j++)
      for (i = 0; i < PAGE_NUM; i++) {
        ii_primary_map[j][i] = &distinguished_secondary_map;
      }
}

void free_shadow_mem_write_memory(void)
{
    Int i,j;

    for (j=0;j<4; j++)
      for (i = 0; i < PAGE_NUM; i++) {
        if(ii_primary_map[j][i] != &distinguished_secondary_map)
        {
			free(ii_primary_map[j][i]);
        }
      }
}


static SecMap* alloc_secondary_map ()
{
   SecMap* map;
   UInt  i;

   /* Mark all bytes as invalid access and invalid value. */
   map = (SecMap *)malloc(sizeof(SecMap));
   shadow_bytes+=sizeof(SecMap);
   for (i = 0; i < 65536; i++)
      map->byte[i] = VGM_BYTE_INVALID; /* Invalid Value */

   return map;
}

UInt  get_mem_write_time_stamp( Addr a )
{

   SecMap* sm;
   sm= ii_primary_map[a&0x3][a>>16];

   UInt    sm_off = a & 0xFFFF;
   return ((UInt*)(sm->byte))[sm_off >> 2];
}


void  set_mem_write_time_stamp( Addr a, UInt bytes )
{
   SecMap* sm;
   UInt    sm_off;
   ENSURE_MAPPABLE_BYTE_GRANUITY(ii_primary_map, a);
   sm     = ii_primary_map[a&0x03][a >> 16];

   sm_off = a & 0xFFFF;
   ((UInt*)(sm->byte))[sm_off >> 2] = bytes;
}

/******************************************************************
* Shadow for heap
******************************************************************/

