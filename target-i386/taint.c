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




#include "taint.h"
#include <stdlib.h>
#include "qemu-common.h"
/*---------------------shadow memory----------------------*/
#define PAGE_BITS 16
#define PAGE_SIZE (1<<PAGE_BITS)
#define PAGE_NUM  (1<<16)

#define IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(map, addr)                              \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[addr >> 16])) {       \
         map[addr >> 16] = alloc_secondary_map; \
      }                                                           \
   } while(0)

#define ENSURE_MAPPABLE_BYTE_GRANUITY(map,addr)         \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[addr >> 16])) {    \
          map[addr >> 16] = alloc_secondary_map(); \
      }                                                           \
   } while(0)



typedef struct {
   UChar byte[PAGE_SIZE];
} SecMap;

static SecMap distinguished_secondary_map;

static SecMap * ii_primary_map[PAGE_NUM];

unsigned int shadow_bytes;


void init_shadow_memory(void)
{
    Int i,j;

    for (i = 0; i< PAGE_SIZE; i++)
       distinguished_secondary_map.byte[i] = UNTAINTED; //0xff

      for (i = 0; i < PAGE_NUM; i++) {
        ii_primary_map[i] = &distinguished_secondary_map;
      }
}

void free_shadow_memory(void)
{
    Int i,j;

      for (i = 0; i < PAGE_NUM; i++) {
        if(ii_primary_map[i] != &distinguished_secondary_map)
        {
			free(ii_primary_map[i]);
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
   for (i = 0; i < PAGE_SIZE; i++)
      map->byte[i] = UNTAINTED; /* Invalid Value */

   return map;
}

UChar  get_mem_taint( Addr a )
{
   
   SecMap* sm;
   sm= ii_primary_map[a>>16];

   UInt    sm_off = a & 0xFFFF;
   return  sm->byte[sm_off];
}

extern FILE * vmmi_log;
void  set_mem_taint( Addr a, UChar bytes)
{

//   if(qemu_log_enabled())
//	   qemu_log("set taint:(%x, %x)", a, bytes);
   SecMap* sm;
   UInt    sm_off;
   ENSURE_MAPPABLE_BYTE_GRANUITY(ii_primary_map, a);
   sm    = ii_primary_map[a >> 16];

   sm_off = a & 0xFFFF;

   sm->byte[sm_off] = bytes;

}

void  set_mem_taint_bysize( Addr a, UChar bytes, UInt size)
{
	UInt i;

	for(i=0; i<size;i++)
		set_mem_taint(a+i, bytes);

}
/******************************************************************
* Shadow for register
******************************************************************/
UChar regTaint[XED_REG_LAST];
UChar FDregTaint[XED_REG_LAST];
void regUntainted()
{
	int i;

	for( i=0; i< XED_REG_LAST;i++)
		regTaint[i]=UNTAINTED;


	regTaint[XED_REG_ESP]=TAINTED;
	regTaint[XED_REG_EBP]=TAINTED;
}
void regUntainted_fd()
{
	int i;

	for( i=0; i< XED_REG_LAST;i++)
		FDregTaint[i]=UNTAINTED;

}

UChar get_reg_taint(xed_reg_enum_t reg)
{

	return regTaint[reg];
}
UChar get_reg_taint_fd(xed_reg_enum_t reg)
{

	return FDregTaint[reg];
}

void set_reg_taint(xed_reg_enum_t reg, UChar bytes)
{
	regTaint[reg]=bytes;


#ifdef DEBUG_VMMI
  if(is_ins_log())
	   qemu_log("Reg: %u  taint %x", reg, bytes);
#endif
	
   //eax
	if(XED_REG_EAX == reg) {
		regTaint[(UInt)XED_REG_AX]=bytes;
		regTaint[(UInt)XED_REG_AH]=bytes;
		regTaint[(UInt)XED_REG_AL]=bytes;
    }
    //ebx
    else if(XED_REG_EBX == reg) {
		regTaint[(UInt)XED_REG_BX]=bytes;
		regTaint[(UInt)XED_REG_BH]=bytes;
		regTaint[(UInt)XED_REG_BL]=bytes;
	}
    //ecx
    else if(XED_REG_ECX == reg) {
		regTaint[(UInt)XED_REG_CX]=bytes;
		regTaint[(UInt)XED_REG_CH]=bytes;
		regTaint[(UInt)XED_REG_CL]=bytes;
	}
    //edx
	else if(XED_REG_EDX == reg) {
		regTaint[(UInt)XED_REG_DX]=bytes;
		regTaint[(UInt)XED_REG_DH]=bytes;
		regTaint[(UInt)XED_REG_DL]=bytes;
    }
}
void set_reg_taint_fd(xed_reg_enum_t reg, UChar bytes)
{
	FDregTaint[reg]=bytes;

#ifdef DEBUG_VMMI
  if(is_ins_log())
	   qemu_log("Fd Reg: %u  taint %x", reg, bytes);
#endif
	
   //eax
	if(XED_REG_EAX == reg) {
		FDregTaint[(UInt)XED_REG_AX]=bytes;
		FDregTaint[(UInt)XED_REG_AH]=bytes;
		FDregTaint[(UInt)XED_REG_AL]=bytes;
    }
    //ebx
    else if(XED_REG_EBX == reg) {
		FDregTaint[(UInt)XED_REG_BX]=bytes;
		FDregTaint[(UInt)XED_REG_BH]=bytes;
		FDregTaint[(UInt)XED_REG_BL]=bytes;
	}
    //ecx
    else if(XED_REG_ECX == reg) {
		FDregTaint[(UInt)XED_REG_CX]=bytes;
		FDregTaint[(UInt)XED_REG_CH]=bytes;
		FDregTaint[(UInt)XED_REG_CL]=bytes;
	}
    //edx
	else if(XED_REG_EDX == reg) {
		FDregTaint[(UInt)XED_REG_DX]=bytes;
		FDregTaint[(UInt)XED_REG_DH]=bytes;
		FDregTaint[(UInt)XED_REG_DL]=bytes;
    }
}


void taintInit()
{
	init_shadow_memory();
	regUntainted();
	regUntainted_fd();
}

void	mem_taint_format()
{
	Int i,j;

	for (i =0; i< PAGE_NUM; i++)
		for(j=0;j< PAGE_SIZE;j++)
			if(ii_primary_map[i]->byte[j]>TAINTED)
				ii_primary_map[i]->byte[j]=UNTAINTED;

}
