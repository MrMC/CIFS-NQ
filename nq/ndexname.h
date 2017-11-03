/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Name Service functions for external names
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 1-September-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDEXNAME_H_
#define _NDEXNAME_H_

#include "cmapi.h"

#include "ndadaptr.h"

/* Initialize the list of names */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndExternalNameInit(
    void
    );

/* release internal data */

void
ndExternalNameStop(
    void
    );

/* Start querying external name over all adapters */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndExternalNameQuery(
    NDAdapterInfo* response,       /* adapter to response to "dummy" */
    const CMNetBiosName name       /* name entry to process */
    );

/* Process Positive Query Response */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
ndExternalNamePositiveQuery(
    const NDAdapterInfo* adapter,   /* adapter to response to "dummy" */
    const CMNetBiosName name,       /* name found */
    const NQ_BYTE* addData             /* the rest of the packet after the name */
    );

/* Process Negative Query Response */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
ndExternalNameNegativeQuery(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name not found */
    );

/* Process Wack Response */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
ndExternalNameWack(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name,       /* name mentioned */
    const NQ_BYTE* addData          /* the rest of the packet after the name */
    );

/* Process timeout on external names */

NQ_COUNT                            /* timeout */
ndExternalNameTimeout(
    NQ_INT delta                    /* elapsed time in seconds */
    );

#endif  /* _NDEXNAME_H_ */
