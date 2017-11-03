/*********************************************************************
 *
 *           Copyright (c) 2001 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS pass-through authentication library
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 24-Aug-2004
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSAUTH_H_
#define _CSAUTH_H_

#include "csdataba.h"

/*
  Pass-through authentication library initialization and shutdown
*/

NQ_BOOL
csAuthInit(
    void
    );

void
csAuthShutdown(
    void
    );

/*
 * Returns pointer to the PDC host name or NULL of not initialized
 */

const NQ_CHAR*
csAuthGetPDCName(
    void
    );


/* Perform user authentication */
NQ_UINT32                                           /* error code or zero */
csAuthenticateUser(
    const NQ_BYTE* pReq,                            /* request pointer */
    CSSession* pSession,                            /* session pointer */
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    NQ_BYTE* pBlob,                                 /* place to generate response blob */
    NQ_COUNT* blobLength,                           /* pointer to blob length */
#endif /* UD_CS_INCLUDEEXTENDEDSECURITY */
    NQ_BOOL unicodeRequired,                        /* TRUE when client sends UNICODE strings */
    CSUser** pUser,                                 /* pointer to user descriptor will be placed here */
    const NQ_BYTE** pOsName                         /* pointer to the OS name */
    );

#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
/* Fill user token  */
NQ_BOOL                         /* TRUE if succeeded */
csFillUserToken(
    CSUser* pUser,              /* pointer to the user structure */
    NQ_BOOL unicodeRequired     /* TRUE when client sends UNICODE strings */
    );
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

NQ_BOOL
csChangeEncryptionLevel(
		NQ_UINT mask
		);
#endif /* _CSAUTH_H_ */
