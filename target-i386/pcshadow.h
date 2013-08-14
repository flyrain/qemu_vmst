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


#ifndef __UTILITY2_H
#define __UTILITY2_H

#define VGM_BYTE_INVALID   0xFF
#define TAINTED 1
#define UNTAINTED 0
#define FDTAINTED 2

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
typedef  unsigned int Addr;


#endif
