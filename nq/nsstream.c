/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of session data transfer functions
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 1-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"
#include "cmapi.h"
#include "nssocket.h"
#include "nsbuffer.h"
#include "nscommon.h"
#include "nsframes.h"

/*
 This file implements r/w functions for a not connected NetBIOS socket.

 Data is packed into a Session Message as in RFC-1002 with the following restrictions:
    nsSendFromBuffer - data should reside in one message. A message that does not fit in a buffer
              is truncated
    nsRecvIntoBuffer -  only the 1st fragment is accepted. All subsequent fragments of a multi-fragment
              message are discarded

 These calls work for not NetBIOS (pure Internet) sockets too. In this case a call is
 delegated to the underlying socket
*/

/*
 *====================================================================
 * PURPOSE: Skip space for a session header
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN buffer to use
 *
 * RETURNS: pointer to the user data in the buffer
 *====================================================================
 */


NQ_BYTE*
nsSkipHeader(
    NSSocketHandle socket,
    NQ_BYTE *buf
    )
{
    SocketSlot* pSock;                      /* actual pointer to a socket slot */
    NQ_BYTE* pResult = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "socket:%p buf:%p", socket, buf);

    pSock = (SocketSlot*)socket;

    if (pSock != NULL && !pSock->isNetBios) /* socket is not NetBIOS */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_SOME, "Not a NetBIOS socket");
        pResult = buf;
        goto Exit;
    }
    pResult = buf + sizeof(CMNetBiosSessionMessage);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_TOOL, "result:%p", pResult);
    return pResult;
}

/*
 *====================================================================
 * PURPOSE: Write to a stream
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer to send (including space for header)
 *          IN packetlen length of the NBT packet
 *          IN dataCount data length - may include the entire packet data or
 *                       just headers without payload
 *
 *
 * RETURNS: TRUE or FALSE
 * NOTES:
 *====================================================================
 */

NQ_COUNT
nsPrepareNBBuffer(
    NQ_BYTE *buf,	            /* buffer to use */
    NQ_UINT packetLen,          /* packet length */
    NQ_UINT dataCount           /* data length (may the entire packet data or just headers with no payload) */
    )
{
	NQ_COUNT res = 0;
    CMNetBiosSessionMessage* msgHdr;    /* casted pointer to the outgoing message */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "buf:%p packetLen:%u dataCount:%u" , buf, packetLen, dataCount);


    if (packetLen <= 0)
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid data length");
        goto Exit;
    }

    msgHdr = (CMNetBiosSessionMessage*) buf;    /* cast the pointer */

    /* create a session message */

    msgHdr->type = CM_NB_SESSIONMESSAGE;
    msgHdr->flags = (NQ_BYTE)(packetLen / 0x10000);
    packetLen = packetLen % 0x10000;
    /* possible transaction of the 17th bit - extension */
    cmPutSUint16(msgHdr->length, (NQ_UINT16)syHton16((NQ_UINT16)packetLen));
    res = (NQ_COUNT)(dataCount + sizeof(CMNetBiosSessionMessage));

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_TOOL, "result:%d", res);
	return res;
}

/*
 *====================================================================
 * PURPOSE: Write to a stream
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN buffer to send (including space for header)
 *          IN packetlen length of the packet
 *          IN dataCount data length - may include the entire packet data or
 *                       just headers without payload
 *          IN callback function releasing the buffer
 *
 * RETURNS: Number of bytes written into the stream
 *
 * NOTES:   deallocates the buffer
 *====================================================================
 */

NQ_INT
nsSendFromBuffer(
    NSSocketHandle socketHandle,
    NQ_BYTE *buf,
    NQ_UINT packetLen,          
    NQ_UINT dataCount,          
    NSReleaseCallback release
    )
{
    SocketSlot* pSock;                  /* actual pointer to a socket slot */
    NQ_INT msgLen;                      /* this message length */
    NQ_INT dataSent;
    NQ_UINT dataToSend, offset;
    NQ_INT result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "socketHandle:%p buf:%p packetLen:%u dataCount:%u release:%p", socketHandle, buf, packetLen, dataCount, release);

    if (packetLen <= 0)
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid data length");
        goto Error;
    }

    pSock = (SocketSlot*)socketHandle;
    if (pSock == NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        goto Error;
    }

    /* send the message */

#ifdef UD_NS_ASYNCSEND
    if (release == NULL)
    {
    	msgLen = sySendSocket(
            pSock->socket,
            buf,
           dataCountn
        );
    }
    else
    {
    	msgLen = sySendSocketAsync(
            pSock->socket,
            buf,
			dataCountn,
            release
        );
    }
#else
    if (pSock->isAccepted)
    	syMutexTake(&pSock->guard);

    for (dataSent = 0, offset = 0, dataToSend = dataCount; dataToSend > 0; dataToSend -= (NQ_UINT)dataSent, offset += (NQ_UINT)dataSent)
    {
        if (NQ_FAIL == (dataSent = sySendSocket(pSock->socket, buf + offset, dataToSend)))
            break;
    }
    msgLen = (NQ_INT)(dataCount - dataToSend);

    if (pSock->isAccepted)
    	syMutexGive(&pSock->guard);

    if (NULL != release)
    {
        (*release)(buf);        /* immediately release the buffer */
    }
#endif /* UD_NS_ASYNCSEND */

    if (msgLen == NQ_FAIL) /* error */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error while sending message");
        goto Exit;
    }

    result = msgLen;
    goto Exit;

Error:
    if (NULL != release)
    {
        (*release)(buf);
    }

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_TOOL, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Prepare reading from an NBT stream
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          OUT pointer to the receive descriptor
 *
 * RETURNS: Number of bytes available for receive in the NBT packet
 *
 * NOTES:   This function should be called prior to nsRecvFRomBuffer 
 *====================================================================
 */

NQ_INT
nsStartRecvIntoBuffer(
	NSSocketHandle socket,  
	NSRecvDescr * descr		 
    )
{
    SocketSlot* pSock;                      /* actual pointer to a socket slot */
    NQ_INT bytesToRead;                     /* number of bytes to receive */
    NQ_UINT32 packetLen;                    /* packet length, including the extension (E) bit */
    CMNetBiosSessionMessage buffer;			/* to read NBT header */
    NQ_BYTE * pBuf;                         /* pointer into this buffer */
    NQ_INT result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "socket: %p, descr: %p", socket, descr);

    pSock = (SocketSlot*)socket;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        goto Exit;
    }
#endif

    descr->socket = pSock;
    bytesToRead = sizeof(CMNetBiosSessionMessage);
    pBuf = (NQ_BYTE*)&buffer;
    while (bytesToRead > 0)
    {
        NQ_INT res;

        res = syRecvSocket(pSock->socket, pBuf, (NQ_COUNT)bytesToRead);

        /* if no bytes received this means that the remote end died */
        if (res == 0 || res == NQ_FAIL)
        {
            if (res == 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "0 bytes read (header)");
                goto Exit;
            }

            LOGERR(CM_TRC_LEVEL_ERROR, "Error during reading header");
            goto Exit;
        }

        if (buffer.type == CM_NB_SESSIONKEEPALIVE)
            break;
        
        bytesToRead -= res;
        pBuf += res;
    }
    /* check for a control message */
    if (buffer.type != CM_NB_SESSIONMESSAGE)
    {
        switch (buffer.type)
        {
        case CM_NB_SESSIONKEEPALIVE:
            /* discard */
            result = 0;
            goto Exit;
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet type 0x%x", buffer.type);
			goto Exit;
        }
    }

    packetLen = (NQ_UINT32)(syHton16(cmGetSUint16((NQ_UINT16)buffer.length)) & 0xFFFF);
    packetLen += ((NQ_UINT32) buffer.flags) * 0x10000;
	if (packetLen == 0)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected zero length");
		goto Exit;
	}
/*    packetLen |= (((NQ_UINT32) buffer.flags) & CM_NB_SESSIONLENGTHEXTENSION) << 16; */
    descr->remaining = (NQ_COUNT)packetLen;
    result = (NQ_INT)packetLen;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_TOOL, "result: %d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Prepare reading from an Rpc over Tcp stream
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          OUT pointer to the receive descriptot
 *
 * RETURNS: Number of bytes available for receive in the Rpc packet
 *
 * NOTES:   This function should be called prior to nsRecvFRomBuffer
 *====================================================================
 */

NQ_INT
nsStartRecvIntoRpcBuffer(
	NSSocketHandle socket,
	NSRecvDescr * descr,
	NQ_BYTE * pBuf
    )
{
    SocketSlot* pSock;                      /* actual pointer to a socket slot */
    NQ_INT bytesToRead;                     /* number of bytes to receive */
    NQ_UINT16 packetLen;                    /* packet length */
    NQ_INT result = NQ_FAIL;
    NQ_INT res = 0;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket: %p, descr: %p", socket, descr);

    pSock = (SocketSlot*)socket;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        goto Exit;
    }
#endif

    descr->socket = pSock;
    bytesToRead = 10;

    while (bytesToRead > 0)
    {
        res = syRecvSocket(pSock->socket, &pBuf[res], (NQ_COUNT)bytesToRead);

        /* if no bytes received this means that the remote end died */
        if (res == 0 || res == NQ_FAIL)
        {
            if (res == 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "0 bytes read (header)");
                goto Exit;
            }

            LOGERR(CM_TRC_LEVEL_ERROR, "Error during reading header");
            goto Exit;
        }

        bytesToRead -= res;
    }


    packetLen = *(NQ_UINT16 *)&pBuf[8];
	if (packetLen == 0)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected zero length");
		goto Exit;
	}
    descr->remaining = (NQ_COUNT)packetLen;
    result = (NQ_INT)packetLen;

    Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result: %d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: End reading from an NBT stream
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Usually this call does nothing. On possible buffer overflow it
 * 			may discard the tail of the NBT packet 
 *====================================================================
 */

NQ_STATUS
nsEndRecvIntoBuffer(
		NSRecvDescr * descr		 
    )
{
    SocketSlot* pSock;                      /* actual pointer to a socket slot */
    NQ_INT bytesRead;                       /* number of bytes received */
    NQ_UINT32 lenToRead;                    /* data length we can read, may be less on buffer limits */
#ifndef CM_NQ_STORAGE
    SYSocketSet socketSet;  				/* set for reading from this socket */
#endif
    static NQ_BYTE buffer[200];				/* buffer for discarded bytes */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "descr: %p", descr);

    pSock = (SocketSlot*)descr->socket;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        goto Exit;
    }
#endif

    if (descr->remaining != 0)
    { 
        while (descr->remaining > 0)
        {
#ifndef CM_NQ_STORAGE
            syClearSocketSet(&socketSet);
            syAddSocketToSet(pSock->socket, &socketSet);
            result = sySelectSocket(&socketSet, 25);
            if (result == NQ_FAIL)                 /* error the select failed  */
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Error during select");
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NQ_FAIL;
            }
            if (result == 0)                /* timeout  */
            {
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NQ_FAIL;
            }
#endif

            lenToRead = (NQ_UINT32)(descr->remaining > sizeof(buffer) ? sizeof(buffer) : descr->remaining);
#ifndef CM_NQ_STORAGE
            bytesRead = syRecvSocket(pSock->socket, buffer, (NQ_COUNT)lenToRead);
#else
            bytesRead = syRecvSocketWithTimeout(pSock->socket, buffer, (NQ_COUNT)lenToRead, 25);
#endif
            if (bytesRead == 0 || bytesRead == NQ_FAIL)
            {
                if (bytesRead == 0)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "0 bytes read (message body)");
                    goto Exit;
                }
                LOGERR(CM_TRC_LEVEL_ERROR, "Error reading message body, code: %d", syGetLastError());
                goto Exit;
            }
            descr->remaining -= (NQ_COUNT)bytesRead;
        }
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL, "result: %d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Read from a stream into a preallocated buffer
 *--------------------------------------------------------------------
 * PARAMS:  IN receive descriptor
 *          OUT buffer for incoming user data
 *          IN maximum number of bytes to read
 *
 * RETURNS: Number of bytes read into the user buffer or NQ_FAIL
 *
 * NOTES:   
 *====================================================================
 */

NQ_INT
nsRecvIntoBuffer(
    NSRecvDescr  * descr,
    NQ_BYTE *buf,
    NQ_COUNT len
    )
{
    SocketSlot* pSock;                      /* actual pointer to a socket slot */
    NQ_INT bytesRead;                       /* number of bytes received */
    NQ_INT totalBytesRead;                  /* number of bytes received */
#ifndef CM_NQ_STORAGE
    SYSocketSet socketSet;  /* set for reading from this socket */
#endif
    NQ_INT dataToRead;
    NQ_INT result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL, "descr: %p, buf: %p, len: %d", descr, buf, len);

    dataToRead = len < descr->remaining ? (NQ_INT)len : (NQ_INT)descr->remaining;
    pSock = (SocketSlot*)descr->socket;

    if (pSock == NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        goto Exit;
    }

    if (!pSock->isNetBios) /* socket is not NetBIOS */
    {
		LOGMSG(CM_TRC_LEVEL_MESS_SOME, "Not a NetBIOS socket");

        bytesRead = syRecvSocket(
            pSock->socket,
            buf,
            (NQ_UINT)dataToRead
            );

        result = bytesRead;
        goto Exit;
    }

    if (pSock->isAccepted)
    	syMutexTake(&pSock->guard);

    totalBytesRead = 0;
    while (len > 0 && descr->remaining > 0)
    {
#ifndef CM_NQ_STORAGE
        syClearSocketSet(&socketSet);
        syAddSocketToSet(pSock->socket, &socketSet);

        /* on a busy network the response may be as late as
         * a couple of seconds */
        result = sySelectSocket(&socketSet, 25);
        if (result == NQ_FAIL)                 /* error the select failed  */
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error during select");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
        }
        if (result == 0)                /* timeout  */
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
        }

        bytesRead = syRecvSocket(
            pSock->socket,
            buf,
            (NQ_UINT)dataToRead
            );
#else
    	bytesRead = syRecvSocketWithTimeout(pSock->socket, buf, (NQ_UINT)dataToRead, 25);
#endif
        if (bytesRead == 0 || bytesRead == NQ_FAIL)
        {
            if (pSock->isAccepted)
            	syMutexGive(&pSock->guard);
            if (bytesRead == 0)
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "0 bytes read (message body)");
                goto Exit;
            }
            LOGERR(CM_TRC_LEVEL_ERROR, "Error reading message body, code: %d", syGetLastError());
            goto Exit;
        }

        buf += bytesRead;
        totalBytesRead += bytesRead;
        len -= (NQ_COUNT)bytesRead;
        dataToRead -= bytesRead;
        descr->remaining -= (NQ_COUNT)bytesRead;
    }

    if (pSock->isAccepted)
    	syMutexGive(&pSock->guard);

    result = (NQ_INT)totalBytesRead;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_TOOL, "result: %d", result);
    return result;
}

