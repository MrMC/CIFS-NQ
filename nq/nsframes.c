/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Management of common NS frames
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"

#include "nsframes.h"
#include "nsbuffer.h"
#include "nssocket.h"

/*
 This file contains functions for generating the most common NetBIOS messages used in
 NS only. Messages are composed according to RFC-1002

 TODO: some functions are subjects to be moved to CMNetBios when used by ND or DD too.
 */

/*
    Statis data & functions
    -----------------------
 */

static const CMNetBiosNameInfo ddName = /* NetBIOS name of DD */
{
    CM_DDNAME,                          /* DD name */
    FALSE                               /* not a group name */
};

/* generates common frame for NAME REGISTRATION REQUEST or NAME RELEASE REQUEST
   without specifying the packet code */

static NQ_INT                           /* returns the message length */
generateInternalNameWhateverRequest(
    CMNetBiosHeader* msgHdr,            /* pointer to the buffer of enough length */
    const CMNetBiosNameInfo* name       /* name to use in the request */
    );

/*
 *====================================================================
 * PURPOSE: Parse an incoming Datagram Service message
 *--------------------------------------------------------------------
 * PARAMS:  IN  message buffer
 *          IN number of bytes in the message
 *          OUT buffer to place a parsed calling name (may be NULL, then do not parse)
 *          OUT buffer for user data
 *          IN this buffer length
 *          IN expected destination name - will be checked agains the actual destionation name
 *
 * RETURNS: number of bytes transferred to user or NQ_FAIL on error
 *
 * NOTES:   if the user buffer is too small - data will be truncated. The following
 *          conditions are check upon:
 *          1) the datagram to parse is Direct Unique
 *          2) it has an expected destination name
 *          3) datagram is of a valid format (RFC-1002)
 *====================================================================
 */

NQ_INT
frameParseDatagram(
    const NQ_BYTE *receiveBuf,
    NQ_UINT bytesRead,
    CMNetBiosName sourceName,
    NQ_BYTE *userBuf,
    NQ_UINT userLen,
    const CMNetBiosName expectedName
    )
{
    NQ_INT resultLen = NQ_FAIL;                 /* number of bytes transferred to user so far */
    CMNetBiosDatagramMessage* datagramHeader;   /* pointer to a Datagram Service header */
    void* pSourceName;              /* pointer to source (calling) name in the message */
    void* pParse;                   /* pointer to the currently parsed clause */
    CMNetBiosName destinationName;  /* decoded destination name */
    NQ_CHAR scopeId[10];               /* buffer for scope id (not used) */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "receiveBuf:%p bytesRead:%u sourceName:%p userBuf:%p userLen:%u expectedName:%s", receiveBuf, bytesRead, sourceName, userBuf, userLen, expectedName ? expectedName : "");

    /* point to the packet header */

    datagramHeader = (CMNetBiosDatagramMessage*) receiveBuf;

    if ( datagramHeader->type != CM_NB_DATAGRAM_DIRECTUNIQUE && datagramHeader->type != CM_NB_DATAGRAM_DIRECTGROUP )
    {
        sySetLastError(CM_NBERR_ILLEGALDATAGRAMTYPE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal datagram type");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " value = 0x%x", datagramHeader->type);
        goto Exit;
    }

    /* skip to the source name and decode it it */

    pSourceName = (void*)(datagramHeader + 1);

    if (sourceName == NULL)     /* the calling function is not interested in the source name */
    {
        pParse = cmNetBiosSkipName(receiveBuf, pSourceName);
    }
    else                        /* copy the decoded name into the calling function */
    {
        pParse = cmNetBiosParseName(
                            receiveBuf,
                            (void*)(datagramHeader + 1),
                            sourceName,
                            scopeId,
                            sizeof(scopeId)
                            );
    }

    if (pParse == NULL)         /* source name has invalid format */
    {
        sySetLastError(CM_NBERR_ILLEGALDATAGRAMSOURCE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal source name");
        goto Exit;
    }

    /* decode the destionation (called) name */

    pParse = cmNetBiosParseName(
                        receiveBuf,
                        pParse,
                        destinationName,
                        scopeId,
                        sizeof(scopeId)
                        );
    if (pParse == NULL)         /* destination name has invalid format */
    {
        sySetLastError(CM_NBERR_ILLEGALDATAGRAMDESTINATION);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal destination name");
        goto Exit;
    }

    /* compare the destination with the expected destination */

    if (!cmNetBiosSameNames(expectedName, destinationName))
    {
        sySetLastError(CM_NBERR_ILLEGALDATAGRAMDESTINATION);
        LOGERR(CM_TRC_LEVEL_ERROR, "Datagram is not for this socket");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " socket name - %s, destination name - %s", expectedName, destinationName);
        goto Exit;
    }

    resultLen = (NQ_INT)(bytesRead - syNtoh16(cmGetSUint16(datagramHeader->dataOffset)));

    /* check if buffer size supplied is     */
    /* less than amount received        */

    if (resultLen > (NQ_INT)userLen)
    {
        resultLen = (NQ_INT)userLen;
    }

    /* copy user data */

    syMemcpy(userBuf, pParse, resultLen);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", resultLen);
    return resultLen;
}

/*
 *====================================================================
 * PURPOSE: Compose a datagram
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          OUT buffer for the datagram message
 *          IN datagram type
 *          IN source name
 *          IN destination name
 *          IN pointer to the user data
 *          In user data length
 *
 * RETURNS: Datagram message length
 *
 * NOTES:   this functions assumes that user data together with the header and names
 *          will fit in one buffer. Otherwise user data will be truncated. The header and
 *          the names should fit anyway - otherwise an error happens.
 *====================================================================
 */

NQ_INT
frameComposeDatagram(
    CMNetBiosDatagramMessage* msgBuf,
    const SocketSlot* pSock,
    NQ_BYTE type,
    const CMNetBiosName callingName,
    const CMNetBiosName calledName,
    const NQ_BYTE* data,
    NQ_UINT dataLen
    )
{
    NQ_UINT scopeLen;           /* length of the scope id field */
    NQ_UINT msgLen;             /* number of bytes to send */
    NQ_BYTE* curPtr;           /* pointer to the current place in the message */
    NQ_COUNT shift;            /* shift after name encoding */
    NQ_INT result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p pSock:%p type:%d callingName:%s calledName:%s data:%p dataLen:%u", msgBuf, pSock, type, callingName ? callingName : "", calledName ? calledName : "", data, dataLen);

    msgBuf->type = type;
    msgBuf->flags = cmNetBiosSetDatagramFlags(CM_NB_DATAGRAM_FIRSTFLAG);
    cmPutSUint16(msgBuf->datagramID, syHton16(cmNetBiosGetNextTranId()));
    cmPutSUint32(msgBuf->sourceIP, CM_IPADDR_GET4(pSock->ip));       /* already in NBO */
    cmPutSUint16(msgBuf->sourcePort, pSock->port);   /* already in NBO */

        /* calculate datagram length without the header and the entire message length
           truncate user data on overflow */

    scopeLen = (NQ_UINT)syStrlen(cmNetBiosGetScope());
    if (scopeLen > 0)
        scopeLen++;     /* add another byte for the label length */
    msgLen = 2 * (CM_NB_ENCODEDNAMELEN + 1 + scopeLen + 1)  /* source name + dest name */
             + dataLen;                                     /* + user data */
    msgLen += (NQ_INT)sizeof(CMNetBiosDatagramMessage);    /* add header length */
    if (msgLen > UD_NS_BUFFERSIZE)  /* overflow */
    {
        dataLen -= (msgLen - UD_NS_BUFFERSIZE);
    }

#if SY_DEBUGMODE
    if ((NQ_INT)dataLen < 0)    /* critical overflow - even names do not fit */
    {
        sySetLastError(CM_NBERR_BUFFEROVERFLOW);
        LOGERR(CM_TRC_LEVEL_ERROR, "Datagram names do not fit inside a buffer");
        goto Exit;
    }
#endif

    cmPutSUint16(msgBuf->dataLen, syHton16((NQ_UINT16)(msgLen - sizeof(CMNetBiosDatagramMessage))));
    cmPutSUint16(msgBuf->dataOffset, 0);         /* no offset */

    /* place source name and destination name */

    curPtr = (NQ_BYTE*)(msgBuf + 1);    /* point after the header */

    shift = cmNetBiosEncodeName(callingName, curPtr);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode the calling name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name %s: ", callingName);
        goto Exit;
    }

    curPtr += shift;

    shift = cmNetBiosEncodeName(calledName, curPtr);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode the called name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", calledName);
        goto Exit;
    }

    /* place the user data, truncating it if necessary */

    curPtr += shift;

    syMemcpy(curPtr, data, dataLen);
    result = (NQ_INT)msgLen;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Generate NAME QUERY REQUEST packet
 *          for internal use with the ND
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN NetBIOS name to query
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   this message is used internally with the ND. However, it conforms to
 *          RFC-1002
 *====================================================================
 */

NQ_INT
frameInternalNameQueryRequest(
    NQ_BYTE* msgBuf,
    const CMNetBiosNameInfo* name
    )
{
    CMNetBiosHeader*    msgHdr;            /* pointer to the message header */
    NQ_BYTE*            questionName;      /* pointer to the target question name */
    CMNetBiosQuestion*  questionBody;      /* question entry trailer */
    NQ_COUNT            shift;             /* various shifts in the message */
    NQ_UINT16           hostShort;         /* temprary keeping a 16-bit value */
    NQ_INT              result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p name:%p", msgBuf, name);

    msgHdr = (CMNetBiosHeader*) msgBuf;

    /* fill in the frame buffer header */

    hostShort = cmNetBiosGetNextTranId();

    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_NAMEQUERYREQUEST | CM_NB_NAMEFLAGS_RD));
    cmPutSUint16(msgHdr->tranID, syHton16(hostShort));

    cmPutSUint16(msgHdr->qdCount, syHton16(1));
    cmPutSUint16(msgHdr->anCount, syHton16(0));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(0));

    /* fill in the question entry */

    questionName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    shift = cmNetBiosEncodeName(name->name, questionName);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", name->name);
        goto Exit;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,  syHton16(CM_NB_RTYPE_NB));      /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    result = (NQ_INT)((NQ_BYTE*)(questionBody + 1) - (NQ_BYTE*)msgHdr);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Generate NAME REQISTRATION REQUEST packet
 *          for internal use with the ND
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN NetBIOS name to register
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   this message is used internally with the ND. However, it conforms to
 *          RFC-1002 except for that we send task PID in place of IP address (NB_ADDRESS)
*====================================================================
 */

NQ_INT
frameInternalNameRegistrationRequest(
     NQ_BYTE* msgBuf,
     const CMNetBiosNameInfo* name
     )
{
    NQ_INT result;     /* the resulted length */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p name:%p", msgBuf, name);

    result = generateInternalNameWhateverRequest((CMNetBiosHeader*)msgBuf, name);

    if (result > 0)
    {
        cmPutSUint16(((CMNetBiosHeader*)msgBuf)->packCodes, syHton16(CM_NB_NAMEREGISTRATIONREQUEST));
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);

    return result;
}

/*
 *====================================================================
 * PURPOSE: Generate NAME RELEASE REQUEST packet
 *          for internal use with the ND
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN NetBIOS name to release
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   this message is used internally with the ND. However, it conforms to
 *          RFC-1002 except for that we send task PID in place of IP address (NB_ADDRESS)
 *====================================================================
 */

NQ_INT
frameInternalNameReleaseRequest(
    NQ_BYTE* msgBuf,
    const CMNetBiosNameInfo* name
    )
{
    NQ_INT    result;     /* the resulted length */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p name:%p", msgBuf, name);

    result = generateInternalNameWhateverRequest((CMNetBiosHeader*)msgBuf, name);

    if (result > 0)
    {
        cmPutSUint16(((CMNetBiosHeader*)msgBuf)->packCodes, syHton16(CM_NB_NAMERELEASEREQUEST));
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);

    return result;
}

/*
 *====================================================================
 * PURPOSE: Generate SESSION REQUEST packet
 *          for internal use with the DD
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN NetBIOS name to connect
 *          IN socket that requires this operation
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   calling name is withdrawn from the socket name
 *====================================================================
 */

NQ_INT
frameInternalSessionRequest(
     NQ_BYTE* msgBuf,
     const CMNetBiosNameInfo* calledName,
     const SocketSlot* pSock
     )
 {
    NQ_INT result = NQ_FAIL;               /* return value */
    CMNetBiosSessionMessage* msgHdr;       /* pointer to the beginning of the message buffer */
    NQ_BYTE* curPtr;                       /* pointer to the current position in the buffer */
    NQ_UINT shift;                         /* shift in the buffer after name encoding */
    NQ_UINT length;                        /* the entire length of the trailer (including the
                                           extension (E) bit */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON,"msgBuf:%p calledName:%p pSock:%p", msgBuf, calledName, pSock);

    msgHdr = (CMNetBiosSessionMessage*)msgBuf;

    /* fill in names (skipping the header) */

    curPtr = (NQ_BYTE*)(msgHdr + 1);    /* start of the called name */

    shift = cmNetBiosEncodeName(calledName->name, curPtr);

    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode the called name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", calledName->name);
        goto Exit;
    }

    curPtr += shift;        /* start of the calling name */

    shift = cmNetBiosEncodeName(pSock->name.name, curPtr);  /* calling name = socket name */

    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode the calling name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", pSock->name.name);
        goto Exit;
    }

    curPtr += shift;        /* just after the end of the message */

    /* fill in the frame header */

    msgHdr->type = CM_NB_SESSIONREQUEST;

    length = (NQ_UINT)((NQ_UINT)(curPtr - (NQ_BYTE*)msgHdr) - (NQ_UINT)sizeof(*msgHdr));

    msgHdr->flags = (NQ_BYTE) (length >> 16) & CM_NB_SESSIONLENGTHEXTENSION;   /* extension bit */
    cmPutSUint16(msgHdr->length, syHton16((NQ_UINT16)length));    /* possible trancation of the 17th bit - extension */
    result = (NQ_INT)(curPtr - (NQ_BYTE*)msgHdr);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Generate POSITIVE SESSION RESPONSE packet
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *
 * RETURNS: Message length
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
framePositiveSessionResponse(
    NQ_BYTE* msgBuf
    )
{
    CMNetBiosSessionMessage* msgHdr;    /* pointer to the header of the message */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p", msgBuf);

    msgHdr = (CMNetBiosSessionMessage*)msgBuf;

    /* compose the header */

    msgHdr->type = CM_NB_POSITIVESESSIONRESPONSE;
    msgHdr->flags = 0;
    cmPutSUint16(msgHdr->length, 0);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", sizeof(CMNetBiosSessionMessage));

    return sizeof(CMNetBiosSessionMessage);
}

#ifdef UD_NB_CHECKCALLEDNAME

/*
 *====================================================================
 * PURPOSE: Generate NEGATIVE SESSION RESPONSE packet
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *
 * RETURNS: Message length
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
frameNegativeSessionResponse(
    NQ_BYTE* msgBuf
    )
{
    CMNetBiosSessionMessage* msgHdr;    /* pointer to the header of the message */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p", msgBuf);

    msgHdr = (CMNetBiosSessionMessage*)msgBuf;

    /* compose the header */

    msgHdr->type = CM_NB_NEGATIVESESSIONRESPONSE;
    msgHdr->flags = 0;
    cmPutSUint16(msgHdr->length, syHton16(sizeof(NQ_BYTE)));
    *(NQ_BYTE*)(msgHdr + 1) = CM_NB_SESSIONERROR_NONAME;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", sizeof(CMNetBiosSessionMessage) + sizeof (NQ_BYTE));

    return sizeof(CMNetBiosSessionMessage) + sizeof (NQ_BYTE);
}

#endif /* UD_NB_CHECKCALLEDNAME */

/*
 *====================================================================
 * PURPOSE: Generate SESSION MESSAGE packet
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN user data
 *          IN user data length
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   User data may be truncated if does no fit into the buffer
 *====================================================================
 */

NQ_UINT
frameSessionMessage(
    NQ_BYTE* msgBuf,
    const NQ_BYTE* data,
    NQ_UINT dataLen
    )
{
    CMNetBiosSessionMessage* msgHdr;    /* pointer to the header of the message */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p data:%p dataLen:%u ", msgBuf, data, dataLen);

    msgHdr = (CMNetBiosSessionMessage*)msgBuf;

    /* compose the header */

    msgHdr->type = CM_NB_SESSIONMESSAGE;
    msgHdr->flags = (NQ_BYTE) (dataLen >> 16)
                    & CM_NB_SESSIONLENGTHEXTENSION; /* extension bit is set if
                                                       length does not fit in 16 bits */
    cmPutSUint16(msgHdr->length, syHton16((NQ_UINT16)dataLen));     /* possible trancation of the 17th bit -
                                                       extension */

    /* place the user data, truncating it if too long */

    if (dataLen > UD_NS_BUFFERSIZE - sizeof(CMNetBiosSessionMessage))
    {
        dataLen = UD_NS_BUFFERSIZE - sizeof(CMNetBiosSessionMessage);
    }

    syMemcpy(((NQ_BYTE*)msgHdr + sizeof(CMNetBiosSessionMessage)), data, dataLen);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%u", (NQ_UINT)(dataLen + sizeof(CMNetBiosSessionMessage)));
    return (NQ_UINT)(dataLen + sizeof(CMNetBiosSessionMessage));
}

/*
 *====================================================================
 * PURPOSE: Generate LISTEN REQUEST packet
 *          for internal use with the DD
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN socket that requires this operation
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   this packet has a proprietary Visuality format (VIPC)
 *          we send task PID in place of IP address (NB_ADDRESS)
 *          we fill in a VIPC message and then askframeComposeDatagram() to
 *          do the rest of the work using the VIPC message as user data
 *====================================================================
 */

NQ_INT
frameInternalListenRequest(
    NQ_BYTE* msgBuf,
    const SocketSlot* pSock
    )
{
    CMNetBiosDatagramMessage* msgHdr;   /* pointer to the header of the message */
    NQ_INT length;                      /* packet length */
    CMNetBiosVIPCListen  listenMsg;     /* pointer to the VIPC structure */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p pSock:%p", msgBuf, pSock);

    /* fill in the VIPC message */

    cmPutSUint16(listenMsg.header.protocolVersion, CM_NB_VIPCVERSION);
    cmPutSUint16(listenMsg.header.code, CM_NB_LISTENREQUEST);

    if (pSock->type == NS_SOCKET_STREAM)
    {
        cmPutSUint16(listenMsg.type, CM_NB_VIPCREQUESTSESSION);
    }
    else
    {
        cmPutSUint16(listenMsg.type, CM_NB_VIPCREQUESTDATAGRAM);
    }
    cmPutSUint16(listenMsg.port, pSock->port);       /* already in NBO */
    cmNetBiosNameCopy(listenMsg.name, CM_NB_NETBIOSANYNAME);
    cmPutSUint32(listenMsg.pid, (NQ_UINT32)syGetPid());

    msgHdr = (CMNetBiosDatagramMessage*)msgBuf;

    /* compose the datagram */

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " listen request with source %s destination %s", pSock->name.name, ddName.name);

    length = frameComposeDatagram(
                msgHdr,
                pSock,
                CM_NB_DATAGRAM_DIRECTUNIQUE,
                pSock->name.name,
                CM_DDNAME,
                (NQ_BYTE*)&listenMsg,
                sizeof(listenMsg)
                );

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", length);
    return length;
}

/*
 *====================================================================
 * PURPOSE: Generate CANCEL LISTEN packet
 *          for internal use with the DD
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN socket that requires this operation
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   this packet has a proprietary Visuality format (VIPC)
 *          we send task PID in place of IP address (NB_ADDRESS)
 *          we fill in a VIPC message and then askframeComposeDatagram() to
 *          do the rest of the work using the VIPC message as user data
 *====================================================================
 */

NQ_INT
frameInternalCancelListen(
     NQ_BYTE* msgBuf,
     const SocketSlot* pSock
     )
 {
    NQ_INT length;                      /* packet length */
    CMNetBiosVIPCCancel  cancelMsg;     /* pointer to the VIPC structure */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p pSock:%p", msgBuf, pSock);

    /* fill in the VIPC message */

    cmPutSUint16(cancelMsg.header.protocolVersion, CM_NB_VIPCVERSION);
    cmPutSUint16(cancelMsg.header.code, CM_NB_CANCELLISTEN);
    if (pSock->type == NS_SOCKET_STREAM)
    {
        cmPutSUint16(cancelMsg.type, CM_NB_VIPCCANCELSESSION);
    }
    else
    {
        cmPutSUint16(cancelMsg.type, CM_NB_VIPCCANCELDATAGRAM);
    }
    cmPutSUint32(cancelMsg.pid, (NQ_UINT32)syGetPid());

    /* compose the datagram */

    length = frameComposeDatagram(
                (CMNetBiosDatagramMessage*)msgBuf,
                pSock,
                CM_NB_DATAGRAM_DIRECTUNIQUE,
                pSock->name.name,
                ddName.name,
                (NQ_BYTE*)&cancelMsg,
                sizeof(cancelMsg)
                );

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", length);
    return length;
}

/*
 *====================================================================
 * PURPOSE: Generate NAME <whatever> REQUEST packet
 *          for internal use with the ND
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT packet buffer of enough length
 *          IN NetBIOS name to place into the packet
 *
 * RETURNS: Message length or NQ_FAIL
 *
 * NOTES:   this message is used internally with the ND. However it conforms to
 *          RFC-1002 except for that we send task PID in place of IP address (NB_ADDRESS)
 *====================================================================
 */

static
NQ_INT
generateInternalNameWhateverRequest(
    CMNetBiosHeader* msgHdr,
    const CMNetBiosNameInfo* name
    )
{
    NQ_BYTE* questionName;              /* pointer to the target question name */
    CMNetBiosQuestion* questionBody;    /* question entry trailer */
    NQ_BYTE* resName;                   /* pointer to the target RR name */
    CMNetBiosResourceRecord* resBody;   /* pointer to the target RR body */
    CMNetBiosAddrEntry* addrEntry;      /* pointer to an ADDR ENTRY structure */
    NQ_COUNT               shift;       /* various shifts in the message */
    NQ_INT result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgHdr:%p, name:%p", msgHdr, name);

    /* fill in the frame buffer header */

    cmPutSUint16(msgHdr->tranID, syHton16(cmNetBiosGetNextTranId()));

    cmPutSUint16(msgHdr->qdCount, syHton16(1));
    cmPutSUint16(msgHdr->anCount, syHton16(0));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(1));

    /* fill in the question entry */

    questionName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    shift = cmNetBiosEncodeName(name->name, questionName);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", name->name);
        goto Exit;
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode a name pointer");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", name->name);
        goto Exit;
    }

    resBody = (CMNetBiosResourceRecord*)(resName + shift);

    cmPutSUint16(resBody->rrType,   syHton16(CM_NB_RTYPE_NB));         /* type */;
    cmPutSUint16(resBody->rrClass,  syHton16(CM_NB_RCLASS_IN));        /* class */;
    cmPutSUint32(resBody->ttl, syHton32(CM_NB_UNICASTREQRETRYTIMEOUT));
    cmPutSUint16(resBody->rdLength, sizeof(CMNetBiosAddrEntry));

    /* add an AddrEntry for RR data */

    {
        NQ_UINT16 temp;    /* for composing flags */

        addrEntry = (CMNetBiosAddrEntry*)(resBody + 1);
        temp = cmNetBiosGetNodeType();

        if (name->isGroup)  /* group name */
        {
            temp |= CM_NB_NAMEFLAGS_G;
        }

        cmPutSUint16(addrEntry->flags, syHton16(temp));
        cmPutSUint32(addrEntry->ip, syHton32((NQ_UINT)syGetPid()));       /* pass PID to ND instead of IP */
    }
    result = (NQ_INT)((NQ_BYTE*)(addrEntry + 1) - (NQ_BYTE*)msgHdr);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}
