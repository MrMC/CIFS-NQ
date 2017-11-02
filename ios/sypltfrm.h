/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   :  Platfor-dependent definitions
 *                  This file is expected to be modified during porting
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYPLTFRM_H_
#define _SYPLTFRM_H_

/* accuracy (non-accuracy) of the system timer
   is defined in 100 nanosec units of the minimum time interval that this hardware may
   measure (clock tick) */

#define syGetTimeAccuracy() 556000L  /* 18 times in second for PC */

/* byte order on the target machine */

/*#if defined(__LittleEndian) || defined(LittleEndian)
#define SY_LITTLEENDIANHOST
#elif defined(__BigEndian) || defined(BigEndian)
#define SY_BIGENDIANHOST
#else
#error "Target byte order has to be defined, check compilation flags"
#endif*/ /* (defined(__LittleEndian) || defined(LittleEndian)) */

#define SY_LITTLEENDIANHOST

#endif  /* _SYPLTFRM_H_ */
