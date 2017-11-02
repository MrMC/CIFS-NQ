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

    TRCB();

    pSock = (SocketSlot*)socket;

    if (pSock != NULL && !pSock->isNetBios) /* socket is not NetBIOS */
    {
        TRC("Not a NetBIOS socket");

        TRCE();
        return buf;
    }

    TRCE();
    return buf + sizeof(CMNetBiosSessionMessage);
}

/*
 *====================================================================
 * PURPOSE: Write to a stream
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN buffer to send (including space for header)
 *          IN packetlen length of the NBT packet
 *          IN dataCount data length - may incldue the entire packet data or 
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
    CMNetBiosSessionMessage* msgHdr;    /* casted pointer to the outgoing message */
    NQ_INT msgLen;                      /* this message length */

    TRCB();

    pSock = (SocketSlot*)socketHandle;

    if (packetLen <= 0)
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        if (release != NULL)
        {
            (*release)(buf);
        }
        TRCERR("Invalid data length");
        TRCE();
        return NQ_FAIL;
    }

    if (pSock == NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        if (release != NULL)
        {
            (*release)(buf);
        }
        TRCERR("Illegal socket descriptor");
        TRCE();
        return NQ_FAIL;
    }

    if (!pSock->isNetBios) /* socket is not NetBIOS */
    {
        TRC("Not a NetBIOS socket");

        msgLen = sySendSocket(
            pSock->socket,
            buf,
            dataCount
            );

        if (release != NULL)
        {
            (*release)(buf);
        }

        TRCE();
        return msgLen;
    }

    msgHdr = (CMNetBiosSessionMessage*) buf;    /* cast the pointer */

    /* create a session message */

    msgHdr->type = CM_NB_SESSIONMESSAGE;
    msgHdr->flags = (NQ_BYTE) (packetLen >> 16)
                    & CM_NB_SESSIONLENGTHEXTENSION; /* extension bit is set if
                                                       length does not fit in 16 bits */ 
    cmPutSUint16(msgHdr->length, syHton16((NQ_UINT16)packetLen));  /* possible trancation of the 17th bit -
                                                       extension */

    msgLen = (NQ_INT)(dataCount + sizeof(CMNetBiosSessionMessage));

    /* send the message */

#ifdef UD_NS_ASYNCSEND
    if (release == NULL)
    {
        msgLen = sySendSocket(
            pSock->socket,
            (NQ_BYTE*)msgHdr,
            (NQ_UINT)msgLen
        );
    }
    else
    {
        msgLen = sySendSocketAsync(
            pSock->socket,
            (NQ_BYTE*)msgHdr,
            (NQ_UINT)msgLen,
            release
        );
    }
#else
    msgLen = sySendSocket(
        pSock->socket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen
    );
    if (release != NULL)
    {
        (*release)(buf);        /* immediately release the buffer */
    }
#endif /* UD_NS_ASYNCSEND */

    if (msgLen == NQ_FAIL) /* error */
    {
        TRCERR("Error while sending message");

        TRCE();
        return NQ_FAIL;
    }

    msgLen -= (NQ_INT)sizeof(CMNetBiosSessionMessage);

    TRCE();
    return msgLen;
}

/*
 *====================================================================
 * PURPOSE: Prepare reading from an NBT stream
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          OUT pointer to the receive descriptot
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

    TRCB();

    pSock = (SocketSlot*)socket;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        TRCE();
        return NQ_FAIL;
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
                TRCERR("0 bytes read (header)");
                TRCE();
                return NQ_FAIL;
            }
            
            LOGERR(CM_TRC_LEVEL_ERROR, "Error during reading header");
            TRCE();
            return NQ_FAIL;
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
            TRCE();
            return 0;
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet type %x", buffer.type);
            TRCE();
        }
    }

    packetLen = syHton16(cmGetSUint16(buffer.length)) & 0xFFFF;
    packetLen |= (((NQ_UINT32) buffer.flags) & CM_NB_SESSIONLENGTHEXTENSION) << 16;
    descr->remaining = (NQ_COUNT)packetLen;

    TRCE();
    return (NQ_INT)packetLen;
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
    NQ_INT result;          				/* result of the select operation */
    SYSocketSet socketSet;  				/* set for reading from this socket */
    static NQ_BYTE buffer[200];				/* buffer for discarded bytes */

    TRCB();

    pSock = (SocketSlot*)descr->socket;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        TRCERR("Illefgal socket descriptor");
        TRCE();
        return NQ_FAIL;
    }
#endif

    if (descr->remaining != 0)
    {       
        while (descr->remaining > 0)
        {
            syClearSocketSet(&socketSet);
            syAddSocketToSet(pSock->socket, &socketSet);
            result = sySelectSocket(&socketSet, 25);
            if (result == NQ_FAIL)                 /* error the select failed  */
            {
                TRCERR("Error during select");
                TRCE();
                return NQ_FAIL;
            }
            if (result == 0)                /* timeout  */
            {
                TRCE();
                return NQ_FAIL;
            }

            lenToRead = (NQ_UINT32)(descr->remaining > sizeof(buffer) ? sizeof(buffer) : descr->remaining);
            bytesRead = syRecvSocket(pSock->socket, buffer, (NQ_COUNT)lenToRead);
            if (bytesRead == 0 || bytesRead == NQ_FAIL)
            {
                if (bytesRead == 0)
                {
                    TRCERR("0 bytes read (message body)");
                    TRCE();
                    return NQ_FAIL;
                }
                TRCERR("Error reading message body");
                TRC1P(" error code: %d", syGetLastError());
                TRCE();
                return NQ_FAIL;
            }
            descr->remaining -= (NQ_COUNT)bytesRead;
        }
    }

    TRCE();
    return NQ_SUCCESS;
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
    NQ_INT result;          /* result of the select operation */
    SYSocketSet socketSet;  /* set for reading from this socket */
    NQ_INT dataToRead;

    TRCB();

    dataToRead = len < descr->remaining ? (NQ_INT)len : (NQ_INT)descr->remaining;
    pSock = (SocketSlot*)descr->socket;

    if (pSock == NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        TRCERR("Illegal socket descriptor");
        TRCE();
        return NQ_FAIL;
    }

    if (!pSock->isNetBios) /* socket is not NetBIOS */
    {
        TRC("Not a NetBIOS socket");

        bytesRead = syRecvSocket(
            pSock->socket,
            buf,
            (NQ_UINT)dataToRead
            );

        TRCE();
        return bytesRead;
    }

    totalBytesRead = 0;
    while (len > 0 && descr->remaining > 0)
    {
        syClearSocketSet(&socketSet);
        syAddSocketToSet(pSock->socket, &socketSet);

        /* on a busy network the response may be as late as
         * a couple of seconds */
        result = sySelectSocket(&socketSet, 25);
        if (result == NQ_FAIL)                 /* error the select failed  */
        {
            TRCERR("Error during select");
            TRCE();
            return NQ_FAIL;
        }
        if (result == 0)                /* timeout  */
        {
            TRCE();
            return NQ_FAIL;
        }

        bytesRead = syRecvSocket(
            pSock->socket,
            buf,
            (NQ_UINT)dataToRead
            );
        if (bytesRead == 0 || bytesRead == NQ_FAIL)
        {
            if (bytesRead == 0)
            {
                TRCERR("0 bytes read (message body)");
                TRCE();
                return NQ_FAIL;
            }
            TRCERR("Error reading message body");
            TRC1P(" error code: %d", syGetLastError());
            TRCE();
            return NQ_FAIL;
        }

        buf += bytesRead;
        totalBytesRead += bytesRead;
        len -= (NQ_COUNT)bytesRead;
        dataToRead -= bytesRead;
        descr->remaining -= (NQ_COUNT)bytesRead;
    }

    TRCE();
    return (NQ_INT)totalBytesRead;
}

