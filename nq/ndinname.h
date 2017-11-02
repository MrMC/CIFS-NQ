/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Name Service functions for internal names
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 1-Sep-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDINNAME_H_
#define _NDINNAME_H_

#include "cmapi.h"
#include "ndadaptr.h"

/* special return value */

#define ND_NOINTERNALNAME -1    /* name was not found */

/* initialize this code */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameInit(
    void
    );

/* release internal data */

void
ndInternalNameStop(
    void
    );

/* Get port binding of an internal name */

NQ_INT16                              /* port (in NBO) or ND_NOINTERNALNAME */
ndInternalNameGetPort(
    const CMNetBiosName name          /* name to look for */
    );

/* Set a binding of an internal name */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL when name was not found */
ndInternalNameSetPort(
    const CMNetBiosName name,       /* name to look for */
    NQ_UINT16 port                     /* the bound port (in NBO) */
    );

/* Start registering all existing internal names over a specific adapter */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameRegisterAllNames(
    const NDAdapterInfo* response,  /* adapter to response to "dummy" */
    const NDAdapterInfo* adapter    /* adapter to register over: may be either NEW or OLD */
    );

/* Start registering internal name over all adapters */

NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameRegisterAllAdapters(
    const NDAdapterInfo* response,      /* adapter to response to "dummy" */
    const CMNetBiosNameInfo* nameInfo   /* name to register */
    );

/* Release all names */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameReleaseAllNames(
    const NQ_BOOL doFreeEntry          /* TRUE to remove entry */ 
    );

/* Start releasing internal name over all adapters */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameReleaseAllAdapters(
    const NDAdapterInfo* response,  /* adapter to response to "dummy" */
    const CMNetBiosName name,       /* name entry to process */
    const NQ_BOOL doFreeEntry       /* TRUE to remove entry */ 
    );

/* Query internal name or node status */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameWhateverQuery(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name,       /* name registered */
    const NQ_BYTE* addData             /* the rest of the packet (after name) */
    );

/* Process Positive Registration Response */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNamePositiveRegistration(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name,       /* name registered */
    const NQ_BYTE* addData             /* the rest of the response packet (after name) */
    );

/* Process Negative Registration Response */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameNegativeRegistration(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name registered */
    );

/* Process Positive Query Response */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNamePositiveQuery(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name,       /* name registered */
    const NQ_BYTE* addData          /* the rest of the response packet (after name) */
    );

/* Process Name Registration Request from outside */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameCheckNameConflict(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name to check */
    );

/* Process Negative Query Response */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameNegativeQuery(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name registered */
    );

/* Process Positive Release Response */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNamePositiveRelease(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name registered */
    );

/* Process Negative Release Response */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameNegativeRelease(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name registered */
    );

/* Process WACK */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameWack(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name,       /* name registered */
    const NQ_BYTE* addData             /* the rest of the response packet (after name) */
    );

/* Send Refresh Request for all names whose TTL expired */

NQ_COUNT                              /* TRUE to count timeout */
ndInternalNameTimeout(
    NQ_INT delta                    /* elapsed time in seconds */
    );

/* processing of queries for internal names */

NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalProcessNameQuery(
    const NDAdapterInfo* response,  /* adapter to send response to */
    const CMNetBiosName name,       /* queried name */
    NQ_BOOL sendNegativeResponse    /* flag requiring sending of a negative name query response */
    );

#endif  /* _NDINNAME_H_ */
