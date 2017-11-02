/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : OS-dependent includes
 *                 This file is expected to be modified during porting
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 27-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYINCLUD_H_
#define _SYINCLUD_H_

#include <errno.h>
#include <unistd.h>
#include <utime.h>
#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/sysctl.h>
//#include <sys/vfs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <arpa/inet.h>
#ifdef UD_NQ_USETRANSPORTIPV6
#include <ifaddrs.h>
#endif

/*
    Common constants
    ----------------

    These definitions are defined here because they should be defined on the SY level.
    However, they are system-independent and user is not supposed to modify this
    section.
 */

#ifndef NULL
#define NULL    ((void*)(0))
#endif

#ifndef TRUE
#define TRUE     (1)
#endif

#ifndef FALSE
#define FALSE    (0)
#endif

#ifndef OK
#define OK       (0)
#endif

#ifndef ERROR
#define ERROR    (-1)
#endif

#ifndef NQ_SUCCESS
#define NQ_SUCCESS  (0)
#endif

#ifndef NQ_FAIL
#define NQ_FAIL     (-1)
#endif

#endif  /* _SYINCLUD_H_ */
