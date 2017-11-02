/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client configuration
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Aug-2001
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmcrypt.h"

#include "ccapi.h"
#include "ccconfig.h"
#include "cmthread.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* static data */
static NQ_TIME timeout = UD_CC_CLIENTRESPONSETIMEOUT;

void ccConfigInit(void)
{
	sySetRand();
    timeout = UD_CC_CLIENTRESPONSETIMEOUT;
}

void ccConfigShutdown(void)
{
}

void ccConfigSetTimeout(NQ_TIME secs)
{
	timeout = secs == 0? UD_CC_CLIENTRESPONSETIMEOUT: secs;
}

NQ_TIME ccConfigGetTimeout(void)
{
	return timeout;
}

void ccThreadSubscribe(void)
{
    cmThreadSubscribe();
}

void ccThreadUnsubscribe(void)
{
    cmThreadUnsubscribe();
}

#endif
