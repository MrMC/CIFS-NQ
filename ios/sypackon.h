/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Compile-dependent definitions for the SY module
 *                 This file is expected to be modified during porting
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

/* This file contains pre-processor code for structure packing.
   It assumes that compiler supports #pragma pack or its equivalent
   This code is included before a packed structure like:

   #include "sypackon.h"

   typdef struct {
     ...
   };

   #include "sypackof.h"
*/

#ifdef SY_PRAGMAPACK_DEFINED
#pragma pack(1)
#endif
