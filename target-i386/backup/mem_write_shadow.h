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


#ifndef __UTILITY_H
#define __UTILITY_H

#define VGM_BYTE_INVALID   0xFF
#include "hash_helper.h"


#ifdef CPLUSPLUS
extern "C" {
#endif

void init_shadow_mem_write_memory(void);
void free_shadow_mem_write_memory(void);
UInt  get_mem_write_time_stamp( Addr a );
void  set_mem_write_time_stamp( Addr a, UInt bytes );

#ifdef CPLUSPLUS
}
#endif


#endif
