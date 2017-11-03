/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Message signing
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 27-July-2010
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSSIGNIN_H_
#define _CSSIGNIN_H_

#include "cmapi.h"
#include "csdataba.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_MESSAGESIGNINGPOLICY)

NQ_BOOL                                     /* TRUE for valid signature, FALSE otherwise */
csCheckMessageSignatureSMB(
    CSSession *pSession,                    /* pointer to session structure */
    CSUser *pUser,                          /* pointer to user structure */
    NQ_BYTE *pHeaderIn,                     /* pointer to packet header */
    NQ_COUNT dataLength                     /* packet length */
    );


void
csCreateMessageSignatureSMB(
    CSSession *pSession,                    /* pointer to session structure */
    CSUser *pUser,                          /* pointer to user structure */
    NQ_BYTE *pHeaderOut,                    /* pointer to packet header */
    NQ_COUNT dataLength                     /* packet length */
    );


#ifdef UD_NQ_INCLUDESMB2

NQ_BOOL                                     /* TRUE for valid signature, FALSE otherwise */
csCheckMessageSignatureSMB2(
    CSUser *pUser,                          /* pointer to user structure */
    NQ_BYTE *pHeaderIn,                     /* pointer to packet header */
    NQ_COUNT dataLength,                    /* packet length */
    NQ_UINT32 flags                        /* header flags */
    );


void
csCreateMessageSignatureSMB2(
    NQ_UINT32 sid,
    NQ_BYTE *pHeaderOut,                    /* pointer to packet header */
    NQ_COUNT dataLength                     /* packet length */
    );

#endif /* UD_NQ_INCLUDESMB2 */

NQ_BOOL
csCheckMessageSignatureSMB3(
    CSUser *pUser,
    NQ_BYTE *pHeaderIn,
    NQ_COUNT dataLength,
    NQ_UINT32 flags
    );

void
csCreateMessageSignatureSMB3(
    NQ_UINT32 sid,
    NQ_BYTE *pHeaderOut,
    NQ_COUNT dataLength 
    );

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_CS_MESSAGESIGNINGPOLICY) */


#endif /* _CSSIGNIN_H_ */

