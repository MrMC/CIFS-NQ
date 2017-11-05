/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Abstract GSASL interface
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Feb-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYSASL_H_
#define _SYSASL_H_

#include "udparams.h"
#include "udapi.h"
#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS)
#include <sasl/sasl.h>

/*
 * SASL context definitions and calls
 *
 */


/* Check SASL context */
NQ_BOOL
sySaslContextIsValid(
    NQ_BYTE* c
    );

/* Invalidate SASL context */
void
sySaslContextInvalidate(
    NQ_BYTE* c
    ); 
    
/* credentials callback */
typedef void SYSaslCallback(
    void* resouce,      /* credentaisl context */
    NQ_WCHAR* user,     /* user name */
    NQ_WCHAR* password, /* password */
    NQ_WCHAR* domain    /* domain */
    );

/* Security mechanism ID */

const NQ_CHAR*
sySaslGetSecurityMechanism(
    void
    );

/* start SASL client */
NQ_BOOL                     /* TRUE on success, FALSE on error */
sySaslClientInit(
    void* callback          /* credentials callback */
    );

/* stop SASL client */
NQ_BOOL                     /* TRUE on success, FALSE on error */
sySaslClientStop(
    void
    );

/* create SASL context */
NQ_BYTE*                       /* newly created context */
sySaslContextCreate(
    const NQ_CHAR* principal,  /* principal name */
    NQ_BOOL isSmb2,            /* is smb2 */
    NQ_BOOL signingOn          /* is signing on */
    );

/* dispose SASL context */
NQ_BOOL
sySaslContextDispose(
    NQ_BYTE* context           /* context to dispose */
    );

/*
 * Client calls
 *
 */

/* set security mechanism for this context */
NQ_BOOL                         /* TRUE on success, FALSE on fail */
sySaslClientSetMechanism(
    NQ_BYTE* context,           /* context to use */
    const NQ_CHAR* name         /* security mechanism name */
    );

/* generate first client blob */
NQ_BOOL                         /* TRUE on success, FALSE on fail */
sySaslClientGenerateFirstRequest(
    NQ_BYTE* context,           /* context to use */
    const NQ_CHAR* mechList,    /* list of security mechanisms */
    NQ_BYTE** blob,             /* buffer for blob pointer */
    NQ_COUNT* blobLen           /* buffer for blob length */
    );

/* generate next client blob */
NQ_BOOL                         /* TRUE on success, FALSE on fail */
sySaslClientGenerateNextRequest(
    NQ_BYTE* context,           /* context to use */
    const NQ_BYTE* inBlob,      /* server response */
    const NQ_COUNT inBlobLen,   /* server response length */
    NQ_BYTE** outBlob,          /* buffer for request blob pointer */
    NQ_COUNT* outBlobLen,       /* buffer for request blob length */
    NQ_BYTE* con                /* connection pointer (no use) */
    );

/* get session key */
NQ_BOOL
sySaslGetSessionKey(
    NQ_BYTE* context,           /* context to use */
    NQ_BYTE* buffer,            /* output buffer */
    NQ_COUNT* len               /* IN: buffer length, OUT: key length */
    );

#endif /* UD_CC_INCLUDEEXTENDEDSECURITY && UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */

#endif /* _SYSASL_H_ */
