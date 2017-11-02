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

#ifdef UD_CS_INCLUDEPASSTHROUGH

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

/*
  Returns TRUE if the PDC authorization required.
*/

NQ_BOOL
csIsPassthroughRequired(
    void
    );

/*
  Exchange negotiate command with PDC and get the encryption key from it
  May connect to PDC and negotiate if there is no connection yet
*/

NQ_BOOL
csPassthroughNegotiate(
    NQ_BYTE *buffer
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
    ,
    NQ_BOOL extendedSecurity
#endif    
    );

/*
  Send supplied user credentials to the PDC and get the authorization
  response. Then the connection to PDC is closed.
  Return codes:
    CC_AUTH_USER_OK        - authorization ok
    CC_AUTH_NETWORK_ERROR  - net work error (PDC failure)
    CC_AUTH_ACCESS_DENIED  - PDC denied access for the user
    CC_AUTH_IN_PROCESS     - more processing required (extended security) 
*/

#define CC_AUTH_USER_OK        0
#define CC_AUTH_ACCESS_DENIED  1
#define CC_AUTH_NETWORK_ERROR  2
#define CC_AUTH_IN_PROCESS     3

NQ_UINT
csPassthroughAuthorizeUser(
    const NQ_TCHAR *user,
    const NQ_BYTE *pwdLM,
    NQ_INT pwdLMLength,
    const NQ_BYTE *pwdNTLM,
    NQ_INT pwdNTLMLength,
    const NQ_CHAR *domain
    );
    
#ifdef UD_CS_INCLUDEEXTENDEDSECURITY
NQ_BOOL
csPassthroughNegotiate();
#endif

#endif /* UD_CS_INCLUDEPASSTHROUGH */

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
