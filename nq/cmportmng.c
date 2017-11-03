/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#include "cmportmng.h"

/* -- Static data -- */
static NQ_UINT16 nextPort;	/* next port number to use */
static NQ_PORT freePort;	/* last released port */
static SYMutex portGoard;	/* running threads, not including internal*/

/* -- API Functions */

NQ_BOOL cmPortManageStart(void)
{
    syMutexCreate(&portGoard);
	nextPort = UD_NS_INTERNALNSPORT + 10;
	freePort = nextPort;
	return TRUE;
}

NQ_PORT cmPortManage(void)
{
	NQ_COUNT maxPort = 10000;		/* max number of ports to use */
    NQ_PORT res = 0;            /* the result */

    if(maxPort > nextPort)
    {
        syMutexTake(&portGoard);
	    res = freePort;
	    if (freePort == nextPort)
	    {
		    nextPort++;
	    }
	    freePort = nextPort;
        syMutexGive(&portGoard);
    }

    if(maxPort == nextPort)
    {
        syMutexTake(&portGoard);
    	nextPort = UD_NS_INTERNALNSPORT + 10;
    	freePort = nextPort;
    	res = freePort;
    	syMutexGive(&portGoard);
    }

    return res;
}

void cmManageFreePort(NQ_PORT port)
{
	freePort = port;
}


