/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Trace definitions
 *--------------------------------------------------------------------
 * MODULE        : SY - System dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYTRACE_H_
#define _SYTRACE_H_

#include <assert.h>

/* define preferred log output */
#define SY_CONSOLE_LOG
/*#define SY_FILE_LOG*/
#define SY_REMOTE_LOG
#define SY_REMOTE_LOG_BROADCAST


#if defined(SY_REMOTE_LOG_BROADCAST) && !defined(SY_REMOTE_LOG)
#error "SY_REMOTE_LOG must be defined"
#endif

#ifdef SY_FILE_LOG
#define SY_LOG_FILENAME  "/etc/log" 
#endif 

#ifdef SY_REMOTE_LOG
#define SY_LOG_SRV_PORT 12121
#ifdef SY_REMOTE_LOG_BROADCAST
#define SY_LOG_SRV_IP "255.255.255.255"
#else
//#define SY_LOG_SRV_IP "127.0.0.1"
#define SY_LOG_SRV_IP "192.168.15.70"
#endif /* SY_REMOTE_LOG_BROADCAST */
#endif /* SY_REMOTE_LOG */


void syWriteTrace(char* buffer, unsigned long size);

#define SY_LOG_FUNCTION     __FUNCTION__
#define SY_LOG_LINE         __LINE__
#define SY_LOG_FILE         __FILE__

#endif  /* _SYTRACE_H_ */

