
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Proceesing incoming message and timeouts for Session Service
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 31-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndsespro.h"
#include "ndinname.h"

#ifdef UD_ND_INCLUDENBDAEMON

#ifdef UD_NB_RETARGETSESSIONS

/*
 *====================================================================
 * PURPOSE: External message processing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT origin adapter (dummy)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   parse message, call processing and change the state
 *====================================================================
 */


NQ_STATUS
ndSessionProcessExternalMessage(
    NDAdapterInfo* adapter
    )
{
    CMNetBiosSessionMessage* pHdr;  /* pointer to the header */
    CMNetBiosName calledName;       /* called name after parsing */
    NQ_INT16 port;                  /* retarget port */
    NQ_UINT msgLen;                 /* length of the outgoing message */
    NQ_INT retValue;                /* result of the send operation */
    NQ_STATIC NQ_CHAR scopeId[255]; /* buffer for parsed scope ID */


    TRCB();

    pHdr = (CMNetBiosSessionMessage*)adapter->inMsg;

    /* the only allowed operation if SESSION_REQUEST */

    if (pHdr->type != CM_NB_SESSIONREQUEST)
    {
        TRCE();
        return NQ_FAIL;
    }

    /* extract the Called name and loose the pointer to the calling name */

    cmNetBiosParseName(
        adapter->inMsg,
        pHdr + 1,
        calledName,
        scopeId,
        sizeof(scopeId)
        );

    /* find called name */

    if (cmNetBiosIsHostAlias(calledName))
    {
        cmNetBiosNameCopy(calledName, cmNetBiosGetHostNameZeroed());
    }

    port = ndInternalNameGetPort(calledName);

    if (port == ND_NOINTERNALNAME)
    {
        TRCERR("Name not found");
        TRC1P("  name: %s", calledName);
    }

    /* form the response */

    if (port != 0 && port != ND_NOINTERNALNAME)
    {
        CMNetBiosSessionRetarget* pRetarget;    /* casted pointer */

        /* generate a RETARGET SESSION RESPONSE packet */

        pRetarget = (CMNetBiosSessionRetarget*)adapter->outMsg;
        pRetarget->header.type = CM_NB_SESSIONRETARGETRESPONSE;
        pRetarget->header.flags = 0;
        cmPutSUint16(pRetarget->header.length, syHton16(sizeof(*pRetarget) - sizeof(*pHdr)));
        cmPutSUint32(pRetarget->ip, adapter->ip);
        cmPutSUint16(pRetarget->port, port);
        msgLen = sizeof(*pRetarget);
    }
    else
    {
        /*  generate a NEGATIVE SESSION RESPONSE packet */

        pHdr = (CMNetBiosSessionMessage*)adapter->outMsg;

        pHdr->type = CM_NB_NEGATIVESESSIONRESPONSE;
        pHdr->flags = 0;
        cmPutSUint16(pHdr->length, syHton16(sizeof(NQ_BYTE)));
        *(NQ_BYTE*)(pHdr + 1) = (port == 0)? CM_NB_SESSIONERROR_NOTLISTENINGON:
                                             CM_NB_SESSIONERROR_NONAME;
        msgLen = sizeof(*pHdr) + sizeof(NQ_BYTE);
    }

    retValue = sySendSocket(
        adapter->newSocket,
        adapter->outMsg,
        msgLen
        );
    if (retValue < 0)
    {
        TRCERR("Failed to send SESSION ... RESPONSE");
        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
}

#endif /* UD_NB_RETARGETSESSIONS */

#endif /* UD_ND_INCLUDENBDAEMON */

