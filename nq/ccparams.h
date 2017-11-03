/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client configuration definitions
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 17-Aug-2001
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CCCONFIG_H_
#define _CCCONFIG_H_

#include "ccapi.h"
#include "amcredentials.h"

/* -- Constants -- */
/* Number of reconnects. 
   Description
   This value defines how many times NQ attempts to reestablish a server connection. 
   NQ applies this count when it detects the following combination of conditions:
   * SMB operation failed;
   * Socket becomes disconnected;  
 */
#ifdef UD_CC_CLIENTRETRYCOUNT
#define CC_CONFIG_RETRYCOUNT UD_CC_CLIENTRETRYCOUNT
#else
#define CC_CONFIG_RETRYCOUNT 3
#endif

#ifdef UD_CC_BROWSERETRYCOUNT
#define CC_BROWSE_RETRYCOUNT UD_CC_BROWSERETRYCOUNT
#else
#define CC_BROWSE_RETRYCOUNT 1
#endif

/* max number of credits for client to request */
#define SMB2_CLIENT_MAX_CREDITS_TO_REQUEST 128

/* extends the timeout period when STATUS PENDING is sent (multiplies the timeout time by this define) */
#define PENDING_TIMEOUT_EXTENTION 2
/* -- API functions -- */

/* Description
   Initialize this module.
   Returns 
   None.
 */
void ccConfigInit(void);

/* Description
   Release resources used by this module.
   Returns 
   None.
 */
void ccConfigShutdown(void);

#endif /* _CCCONFIG_H_ */
