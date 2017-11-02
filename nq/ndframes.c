/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Sending different ND frames
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBIOS Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 2-September-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndframes.h"

#ifdef UD_ND_INCLUDENBDAEMON

/*
 This file contains functions for generating the most common NetBIOS messages used in
 ND only. Messages are composed according to RFC-1002

 Functions whose start with ndFrameFramesSendFrame are sending packets outside
 Functions whose start with ndFrameFramesReturn are sending packets back to an internal
 apprlication
 */

/*
 *====================================================================
 * PURPOSE: Generate NAME <whatever> REQUEST packet
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN name to place into the packet
 *          IN name's IP to place into ADDR ENTRY (in NBO)
 *          IN TRUE for B node, FALSE for H node
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   The opcode and the transaction ID are expected to be filled later
 *====================================================================
 */

NQ_INT
ndGenerateNameWhateverRequest(
    CMNetBiosHeader* msgHdr,
    const CMNetBiosName name,
    NQ_UINT32 ip,
    NQ_BOOL nodeTypeB
    )
{
    NQ_BYTE*            questionName;   /* pointer to the target question name */
    CMNetBiosQuestion*  questionBody;   /* question entry trailer */
    NQ_BYTE*            resName;        /* pointer to the target RR name */
    CMNetBiosResourceRecord* resBody;   /* pointer to the target RR body */
    CMNetBiosAddrEntry* addrEntry;      /* pointer to an ADDR ENTRY structure */
    NQ_UINT              shift;          /* various shifts in the message */

    TRCB();

    /* fill in the frame buffer header */

    cmPutSUint16(msgHdr->qdCount, syHton16(1));
    cmPutSUint16(msgHdr->anCount, syHton16(0));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(1));

    /* fill in the question entry */

    questionName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    shift = cmNetBiosEncodeName(name, questionName);

    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Unable to encode name");
        TRC1P("Illegal name: %s", name);
        TRCE();
        return -1;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,  syHton16(CM_NB_RTYPE_NB));      /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    /* fill in the resource record */

    resName = (NQ_BYTE*)(questionBody + 1);

    shift = cmNetBiosEncodeNamePointer((void*)msgHdr, (void*)resName, questionName);

    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Unable to encode a name pointer");
        TRC1P("Illegal name: %s", name);
        TRCE();
        return NQ_FAIL;
    }

    resBody = (CMNetBiosResourceRecord*)(resName + shift);

    cmPutSUint16(resBody->rrType,   syHton16(CM_NB_RTYPE_NB));         /* type */;
    cmPutSUint16(resBody->rrClass,  syHton16(CM_NB_RCLASS_IN));        /* class */;
    cmPutSUint32(resBody->ttl,      0);
    cmPutSUint16(resBody->rdLength, syHton16(sizeof(CMNetBiosAddrEntry)));

    /* add an AddrEntry for RR data */

    {
        NQ_UINT16 temp;     /* for composing flags */
        CMNetBiosName domain;
        
        cmNetBiosNameCreate(domain, cmNetBiosGetDomain()->name,CM_NB_POSTFIX_WORKSTATION);
        addrEntry = (CMNetBiosAddrEntry*)(resBody + 1);
        temp = (NQ_BYTE)((nodeTypeB)? CM_NB_NAMEFLAGS_ONT_B : CM_NB_NAMEFLAGS_ONT_M);
        if (0 == cmAStricmp(name, domain))
        {
            temp |= CM_NB_NAMEFLAGS_G;
        }
        cmPutSUint16(addrEntry->flags, syHton16(temp));
        cmPutSUint32(addrEntry->ip, ip);
    }

    TRCE();
    return (NQ_INT)((NQ_BYTE*)(addrEntry + 1) - (NQ_BYTE*)msgHdr);
}

/*
 *====================================================================
 * PURPOSE: Generate NAME <whatever> RESPONSE packet
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN: name to place into the packet
 *          IN resource type as in the RR RECORD
 *          IN: more data after the resource record
 *          IN: this data length
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   The opcode and the transaction ID are expected to be filled later
 *          moreData is not too long and always fits into the buffer
 *====================================================================
 */

NQ_INT
ndGenerateNameWhateverResponse(
    CMNetBiosHeader* msgHdr,
    const CMNetBiosName name,
    NQ_UINT16 type,
    const NQ_BYTE* moreData,
    NQ_UINT moreLength
    )
{
    NQ_BYTE*               answerName;     /* pointer to the target answer name */
    CMNetBiosResourceRecord* resBody;   /* pointer to the target RR body */
    NQ_UINT                shift;          /* various shifts in the message */

    TRCB();

    /* fill in the frame buffer header */

    cmPutSUint16(msgHdr->qdCount, syHton16(0));
    cmPutSUint16(msgHdr->anCount, syHton16(1));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(0));

    /* fill in the question entry */

    answerName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    shift = cmNetBiosEncodeName(name, answerName);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Unable to encode name");
        TRC1P("Illegal name: %s", name);
        TRCE();
        return -1;
    }

    /* fill in the resource record */

    resBody = (CMNetBiosResourceRecord*) (answerName + shift);
    cmPutSUint16(resBody->rrType,    syHton16(type));                     /* type */;
    cmPutSUint16(resBody->rrClass,   syHton16(CM_NB_RCLASS_IN));          /* class */;
    cmPutSUint32(resBody->ttl,       0);
    cmPutSUint16(resBody->rdLength,  syHton16((NQ_UINT16)moreLength));
    if (moreLength > 0)
        syMemcpy((NQ_BYTE*)(resBody + 1), moreData, moreLength);

    TRCE();
    return (NQ_INT)(((NQ_BYTE*)(resBody + 1) - (NQ_BYTE*)msgHdr) + moreLength);
}

/*
 *====================================================================
 * PURPOSE: Generate NAME Query REQUEST packet
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN name to place into the packet
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
ndGenerateNameQueryRequest(
    CMNetBiosHeader* msgHdr,
    const CMNetBiosName name
    )
{
    NQ_BYTE*               questionName;   /* pointer to the target question name */
    CMNetBiosQuestion*  questionBody;   /* question entry trailer */
    NQ_COUNT               shift;          /* various shifts in the message */

    TRCB();

    /* fill in the frame buffer header */

    cmPutSUint16(msgHdr->qdCount, syHton16(1));
    cmPutSUint16(msgHdr->anCount, syHton16(0));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(0));

    /* fill in the question entry */

    questionName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    shift = cmNetBiosEncodeName(name, questionName);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Unable to encode name");
        TRC1P("Illegal name: %s", name);
        TRCE();
        return -1;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,   syHton16(CM_NB_RTYPE_NB));      /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    TRCE();
    return (NQ_INT)((NQ_BYTE*)(questionBody + 1) - (NQ_BYTE*)msgHdr);
}

#endif /* UD_ND_INCLUDENBDAEMON */

