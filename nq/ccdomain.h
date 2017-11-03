/*********************************************************************
 *
 *           Copyright (c) 2009 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client domain related operations
 *--------------------------------------------------------------------
 * MODULE        : CC
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 14-Jul-2009
 ********************************************************************/

#include "udapi.h"
#include "amapi.h"

#ifdef UD_CM_UNICODEAPPLICATION
    #define ccNetLogon ccNetLogonW
#else
    #define ccNetLogon ccNetLogonA
#endif

NQ_BOOL ccDomainStart();

void ccDomainShutdown();

/* net logon (Ansi)*/

NQ_BOOL ccNetLogonA(                    /* TRUE if succeded, FAIL otherwise */
    const NQ_CHAR *domain,                    /* domain name */
    const NQ_CHAR *username,                  /* username */
    const NQ_CHAR *workstation,               /* computer name */
    const NQ_BYTE serverChallenge[8],         /* server challenge */
    const NQ_BYTE *lmPasswd,                  /* pointer to LM password */
    NQ_UINT16 lmPasswdLen,                    /* LM password length */
    const NQ_BYTE *ntlmPasswd,                /* pointer to NTLM password */
    NQ_UINT16 ntlmPasswdLen,                  /* NTLM password length */
    const AMCredentialsA *admin,              /* domain administrator credentials */
    const NQ_BYTE secret[16],                 /* domain secret */ 
    NQ_BOOL isExtendedSecurity,               /* whether extended security is used */
    NQ_BYTE userSessionKey[16],               /* user session key */
	NQ_UINT32 * userRid,					  /* user rid*/
	NQ_UINT32 * groupRid                      /* user group rid */
	);

/* net logon (Unicode)*/

NQ_BOOL ccNetLogonW(                    /* TRUE if succeded, FAIL otherwise */
    const NQ_WCHAR *domain,                   /* domain name */
    const NQ_WCHAR *username,                 /* username */
    const NQ_WCHAR *workstation,              /* computer name */
    const NQ_BYTE serverChallenge[8],         /* server challenge */
    const NQ_BYTE *lmPasswd,                  /* pointer to LM password */
    NQ_UINT16 lmPasswdLen,                    /* LM password length */
    const NQ_BYTE *ntlmPasswd,                /* pointer to NTLM password */
    NQ_UINT16 ntlmPasswdLen,                  /* NTLM password length */
    const AMCredentialsW *admin,              /* domain administrator credentials*/
    const NQ_BYTE secret[16],                 /* domain secret */     
    NQ_BOOL isExtendedSecurity,               /* whether extended security is used */
	NQ_BYTE userSessionKey[16],               /* user session key */
	NQ_UINT32 * userRid,					  /* user rid*/
	NQ_UINT32 * groupRid                      /* user group rid */
	);

