/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of message-oriented data transfer functions
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"
#include "cmapi.h"

#include "nscommon.h"
#include "nssocket.h"
#include "nsinsock.h"
#include "nsbuffer.h"
#include "nsframes.h"

/*
  This file implements r/w operations for connected/unconnected sockets according
  to RFC-1002.

  The functions in this file are intended for UDP sockets and expect an exchange of
  NetBIOS datagrams. nsSend and nsRecv work also for TCP sockets as yet another
  equivalent to nsWrite() and nsRead().

  These calls work also for not NetBIOS (pure Internet) sockets. In this case a call
  is delegated directly to the underlying socket.

  Restrictions:
  - datagram defragmentation is not supported - a NetBIOS DATAGRAM should fit in one
    UDP datagram
  - too long data (not fitting into the user buffer) is discarded

  When this file is compiled for no daemon (#ifndef UD_ND_INCLUDENBDAEMON) it also contains
  code for:
  - discovering the adapter configuration
  - broadcasting
 */

/* check illegal combination of compilation parameters */

#ifndef UD_ND_INCLUDENBDAEMON
#ifdef UD_NB_RETARGETSESSIONS
#error illegal combination of parameters UD_ND_INCLUDENBDAEMON (not defined) and UD_NB_RETARGETSESSIONS (defined)
#endif
#ifdef UD_NB_INCLUDENAMESERVICE
#error illegal combination of parameters UD_ND_INCLUDENBDAEMON (not defined) and UD_NB_INCLUDENAMESERVICE (defined)
#endif


/* adapter structure */
typedef struct
{
    NQ_IPADDRESS ip;            /* this adapter address (in NBO) */
    NQ_IPADDRESS bcast;         /* broadcast address already in NBO */
    NQ_IPADDRESS wins;          /* WINS address already in NBO */
    NQ_BOOL typeB;              /* broadcast registration (otherwise - use WINS) */
    NQ_BOOL empty;              /* TREU when this slot is empty */
}
AdapterInfo;
#endif /* UD_ND_INCLUDENBDAEMON */

typedef struct
{
    NQ_BYTE sendBuffer[CM_NB_DATAGRAMBUFFERSIZE]; /* buffer for sending datagrams */
#ifndef UD_ND_INCLUDENBDAEMON
    AdapterInfo adapters[UD_NS_MAXADAPTERS];
    SYMutex adapterGuard;
#endif /* UD_ND_INCLUDENBDAEMON */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

#ifndef UD_ND_INCLUDENBDAEMON
/*
 *====================================================================
 * PURPOSE: Load the list of adapters
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   read adapter configuration
 *====================================================================
 */

void
ndNotifyConfigurationChange(
    )
{
    NQ_INDEX idx;              /* index in the list of adapters */
    const CMSelfIp * nextIp;   /* next host IP */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMutexTake(&staticData->adapterGuard);

    /* mark all slots as emtry */

    for (idx = 0; idx < sizeof(staticData->adapters)/sizeof(staticData->adapters[0]); idx++)
    {
        staticData->adapters[idx].empty = TRUE;
    }

    /* get new adapters and determine its status */

    cmSelfipIterate();
    for (idx = 0; NULL != (nextIp = cmSelfipNext()) && idx < UD_NS_MAXADAPTERS; )
    {
        if (CM_IPADDR_IPV4 != CM_IPADDR_VERSION(nextIp->ip))
            continue;

        staticData->adapters[idx].ip = nextIp->ip;
        CM_IPADDR_ASSIGN4(staticData->adapters[idx].bcast, nextIp->bcast);
        CM_IPADDR_ASSIGN4(staticData->adapters[idx].wins, udGetWins());
        staticData->adapters[idx].typeB = (CM_IPADDR_EQUAL4(staticData->adapters[idx].wins, 0));
        staticData->adapters[idx].empty = FALSE;
        idx++;
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Adapter found, ip=0x%08lx bcast=0x%08lx wins=0x%08lx", staticData->adapters[idx].ip, staticData->adapters[idx].bcast, staticData->adapters[idx].wins);
    }
    cmSelfipTerminate();
    syMutexGive(&staticData->adapterGuard);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#endif /* UD_ND_INCLUDENBDAEMON */


/*
 *====================================================================
 * PURPOSE: Initialize this file data
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   Starts mutex
 *====================================================================
 */

NQ_STATUS
nsInitMessage(
    void
    )
{
    NQ_STATUS result = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate adapter information in nsMessage");
        result = NQ_FAIL;
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

#ifndef UD_ND_INCLUDENBDAEMON
    syMutexCreate(&staticData->adapterGuard);
    ndNotifyConfigurationChange();
#endif /* UD_ND_INCLUDENBDAEMON */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release this file resources
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   release mutex
 *====================================================================
 */

void
nsExitMessage(
    void
    )
{
#ifndef UD_ND_INCLUDENBDAEMON
    syMutexDelete(&staticData->adapterGuard);
#endif /* UD_ND_INCLUDENBDAEMON*/
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * PURPOSE: Receive a message from a connected socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket
 *          OUT buffer for incoming data
 *          IN this buffer length
 *
 * RETURNS: number of bytes received or NQ_FAIL on error
 *
 * NOTES:   On TCP socket we expect a SESSION MESSAGE. Since this is a srtream, we read
 *          it in the most appropriate portions:
 *           1) the header
 *           2) data, but not more then fits into the user buffer
 *           3) the reminder if any (this is discarded)
 *          On UDP socket we expect exactly one DIRECT UNIQUE DATAGRAM
 *====================================================================
 */

NQ_INT
nsRecv(
    NSSocketHandle socketHandle,
    NQ_BYTE* buf,
    NQ_UINT bufLen
    )
{
    SocketSlot* pSock;          /* actual pointer to a socket slot */
    NQ_BYTE* receiveBuf;        /* receive buffer */
    NQ_INT bytesRead;           /* number of bytes received */
    NQ_INT resultLen;           /* number of bytes transferred to user */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socketHandle:%p buf:%p bufLen:%u", socketHandle, buf, bufLen);

    receiveBuf = nsGetRecvDatagramBuffer();    /* allocate a buffer */
    pSock = (SocketSlot*)socketHandle;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illefgal socket descriptor");
        resultLen = NQ_FAIL;
        goto Exit;
    }
#endif

    if (!pSock->isNetBios) /* socket is not NetBIOS */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Not a NetBIOS socket");

        resultLen = syRecvSocket(
            pSock->socket,
            buf,
            bufLen
            );

        goto Exit;
    }

    if (pSock->type == NS_SOCKET_STREAM)    /* a TCP (stream) socket */
    {
        NQ_UINT32 packetLen;       /* packet length, including the extension (E) bit */
        CMNetBiosSessionMessage* sessionHeader; /* pointer to the Session message header */

        /* A SESSION MESSAGE expected over a TCP socket. Since this is a srtream, we read
          it in the most appropriate portions: 1) the header 2) data */

        /* receive the header */

        bytesRead = syRecvSocket(pSock->socket, (NQ_BYTE*)receiveBuf, sizeof(CMNetBiosSessionMessage));

        /* if data length is zero that means that the remote client
           has died silently (abnormally)
         */

        if (bytesRead == 0)
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Abnormal termination - data truncated");
            resultLen = (NQ_INT)bufLen;
            goto Exit;
        }
        else if (bytesRead < 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Read error on socket");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " error code - %d", syGetLastError());
            resultLen = NQ_FAIL;
            goto Exit;
        }

        /* extract the session message data length from the header */

        sessionHeader = (CMNetBiosSessionMessage*) receiveBuf;
        packetLen = syHton16(cmGetSUint16(sessionHeader->length)) & 0xFFFF;
            /* add extension (E) flag from the byte of flags */
        if (pSock->isNetBios)
        {
        	packetLen |= (((NQ_UINT32) sessionHeader->flags) & CM_NB_SESSIONLENGTHEXTENSION) << 16;
        }
        else
        {
        	packetLen += ((NQ_UINT32) sessionHeader->flags) * 0x10000;
        }

        /* receive the rest of the message
         *
         * we are receiving directly into the user buffer
         * even if message size is greater than the user buffer
         * we still read (virtually) the entire message
         * the user, nowever, will get a
         * trancated message */

        if (packetLen <= bufLen)
            resultLen = (NQ_INT)packetLen;
        else
            resultLen = (NQ_INT)bufLen;

        bytesRead = syRecvSocket(pSock->socket, buf, (NQ_UINT)resultLen);

        /* receive the reminder that did not fit in the user buffer */

        if (bytesRead > 0 && packetLen > bufLen)    /* prevous redv succeeded and we have a
                                                       a reminder to receive */
        {
            bytesRead = syRecvSocket(pSock->socket, buf, (NQ_UINT)resultLen);
        }

        if (bytesRead == 0)
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Abnormal termination - data truncated");
            resultLen = (NQ_INT)bufLen;
            goto Exit;
        }
        else if (bytesRead < 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Read error on socket");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " error code - %d", syGetLastError());
            resultLen = NQ_FAIL;
            goto Exit;
        }
    }
    else        /* a UDP socket */
    {
        NQ_UINT16 port;         /* dummy value get from syRecvFromSocket */
        NQ_IPADDRESS ip;        /* dummy value get from syRecvFromSocket */

        /* DATAGRAM MESSAGE expected */

        /* receive the entire message */

        bytesRead = syRecvFromSocket(
            pSock->socket,
            (NQ_BYTE*)receiveBuf,
            CM_NB_DATAGRAMBUFFERSIZE,
            &ip,
            &port
            );
        if (bytesRead <= 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Read error on socket");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " error code - %d", syGetLastError());
            resultLen = NQ_FAIL;
            goto Exit;
        }

        /* parse the message */

        resultLen = frameParseDatagram(
            (const NQ_BYTE*)receiveBuf,
            (NQ_UINT)bytesRead,
            NULL,
            buf,
            bufLen,
            pSock->name.name
            );

    }/* end if/else */

Exit:
    nsPutRecvDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", resultLen);
    return resultLen;
}

/*
 *====================================================================
 * PURPOSE: Receive a message from a datagram socket regardless of
 *          whether connected or not
 *--------------------------------------------------------------------
 * PARAMS:  IN socket
 *          OUT buffer for incoming data
 *          IN this buffer length
 *          OUT pointer to a buffer for the calling name
 *
 * RETURNS: number of bytes received or NQ_FAIL on error
 *
 * NOTES:   we expect exactly one DIRECT UNIQUE DATAGRAM
 *====================================================================
 */

NQ_INT
nsRecvFromName(
    NSSocketHandle socketHandle,
    NQ_BYTE* buf,
    NQ_UINT bufLen,
    CMNetBiosNameInfo* sourceName
    )
{
    SocketSlot* pSock;          /* actual pointer to a socket slot */
    NQ_BYTE* receiveBuf;        /* receive buffer */
    NQ_INT bytesRead;           /* number of bytes received */
    NQ_INT resultLen = NQ_FAIL; /* number of bytes transferred to user */
    NQ_UINT16 port;             /* dummy value get from syRecvFromSocket */
    NQ_IPADDRESS ip;            /* dummy value get from syRecvFromSocket */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socketHandle:%p buf:%p bufLen:%u sourceName:%p", socketHandle, buf, bufLen, sourceName);

    receiveBuf = nsGetRecvDatagramBuffer();    /* allocate a buffer */
    pSock = (SocketSlot*)socketHandle;

#if SY_DEBUGMODE
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illefgal socket descriptor");
        goto Exit;
    }
    if (pSock->type!=NS_SOCKET_DATAGRAM)        /* not a stream socket - error */
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Not a stream socket passed");
        goto Exit;
    }
#endif

    bytesRead = syRecvFromSocket(
            pSock->socket,
            (NQ_BYTE*)receiveBuf,
            CM_NB_DATAGRAMBUFFERSIZE,
            &ip,
            &port
            );
    if (bytesRead <= 0) /*error*/
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error during receive");
        goto Exit;
    }

    resultLen = frameParseDatagram(
        (const NQ_BYTE*)receiveBuf,
        (NQ_UINT)bytesRead,
        sourceName->name,
        buf,
        bufLen,
        pSock->name.name
        );

    /* resolve the calling IP and port */

Exit:
    nsPutRecvDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", resultLen);
    return resultLen;
}

/*
 *====================================================================
 * PURPOSE: Send data over a socket regradless of whether connected or not
 *--------------------------------------------------------------------
 * PARAMS:  IN socket handle
 *          IN pointer to the user data
 *          IN user data length
 *          IN IP address in NBO
 *
 * RETURNS: Number of bytes sent or NQ_FAIL on error
 *
 * NOTES:   When the destination is a unique name - we resolve the destimation
 *          and send a DIRECT UNIQUE DATAGRAM to the destionation IP on the
 *          Datagram Service (DD) port.
 *          For a group address we ask our DD to broadcast by transferring
 *          it the data in a DIRECT GROUP DATAGRAM
 *====================================================================
 */

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_INT
nsSendTo(
    NSSocketHandle socketHandle,
    const NQ_BYTE* data,
    NQ_UINT dataLen,
    const CMNetBiosNameInfo* calledName,
    NQ_IPADDRESS *ip
    )
{
    SocketSlot* pSock;              /* actual pointer to a socket slot */
    NQ_BYTE* msgBuf;                /* outgoing message buffer */
    NQ_INT msgLen;                  /* number of bytes to send (the entire message) */
    NQ_INT resultLen;               /* number of user bytes sent */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socketHandle:%p data:%p dataLen:%u calledName:%p ip:%p", socketHandle, data, dataLen, calledName, ip);

    pSock = (SocketSlot*)socketHandle;

#if SY_DEBUGMODE
    if (dataLen <= 0)
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid data length");
        resultLen = NQ_FAIL;
        goto Exit;
    }
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illefgal socket descriptor");
        resultLen = NQ_FAIL;
        goto Exit;
    }
#endif

    if (!pSock->isNetBios)/* socket is not NetBIOS */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Not a NetBIOS socket");

        resultLen = sySendToSocket(
            pSock->socket,
            data,
            dataLen,
            ip,
            syHton16(CM_NB_SESSIONSERVICEPORT)
            );

        goto Exit;
    }

    /* inspect the called name */

    if (!cmNetBiosCheckName(calledName))       /* valid NetBIOS name? */
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send to a broacast name");
        resultLen = NQ_FAIL;
        goto Exit;
    }

    msgBuf = staticData->sendBuffer;    /* allocate a buffer */

    if (ip == 0L)
    {
        sySetLastError(CM_NBERR_HOSTNAMENOTRESOLVED);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to resolve called name");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        resultLen = NQ_FAIL;
        goto Exit;
    }

    msgLen = frameComposeDatagram(
                (CMNetBiosDatagramMessage*)msgBuf,
                pSock,
                CM_NB_DATAGRAM_DIRECTGROUP,
                pSock->name.name,
                calledName->name,
                data,
                dataLen
                );

    if (msgLen <= 0)
    {
        sySetLastError(CM_NBERR_INTERNALERROR);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to compose a Datagram Message");
        resultLen = NQ_FAIL;
        goto Exit;
    }

    resultLen = sySendToSocket(
        pSock->socket,
        msgBuf,
        (NQ_COUNT)msgLen,
        ip,
        syHton16(CM_NB_DATAGRAMSERVICEPORT)
        );

    if (resultLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send a datagram");
        resultLen = NQ_FAIL;
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", resultLen);
    return resultLen;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: Send data over a socket regradless of whether connected or not
 *--------------------------------------------------------------------
 * PARAMS:  IN socket handle
 *          IN pointer to the user data
 *          IN user data length
 *          IN IP address in NBO
 *
 * RETURNS: Number of bytes sent or NQ_FAIL on error
 *
 * NOTES:   When the destination is a unique name - we resolve the destimation
 *          and send a DIRECT UNIQUE DATAGRAM to the destionation IP on the
 *          Datagram Service (DD) port.
 *          For a group address we ask our DD to broadcast by transferring
 *          it the data in a DIRECT GROUP DATAGRAM
 *====================================================================
 */

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_INT
nsSendToName(
    NSSocketHandle socketHandle,
    const NQ_BYTE* data,
    NQ_UINT dataLen,
    CMNetBiosNameInfo* calledName
    )
{
    SocketSlot* pSock;              /* actual pointer to a socket slot */
#ifdef UD_ND_INCLUDENBDAEMON
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    InternalSocket* internalSock;   /* socket for communication with DD */
#endif
    NQ_BYTE* msgBuf;                /* outgoing message buffer */
    NQ_INT msgLen;                  /* number of bytes to send (the entire message) */
    NQ_INT resultLen = 0;           /* number of user bytes sent */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socketHandle:%p data:%p dataLen:%u calledName:%p", socketHandle, data, dataLen, calledName);

    pSock = (SocketSlot*)socketHandle;

#if SY_DEBUGMODE
    if (dataLen <= 0)
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid data length");
        resultLen = NQ_FAIL;
        goto Exit;
    }
    if (pSock==NULL || !syIsValidSocket(pSock->socket))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal socket descriptor");
        resultLen = NQ_FAIL;
        goto Exit;
    }
#endif

    if (!pSock->isNetBios)/* socket is not NetBIOS */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Not a NetBIOS socket");
        resultLen = NQ_FAIL;
        goto Exit;
    }

    /* inspect the called name */

    if (!cmNetBiosCheckName(calledName))       /* valid NetBIOS name? */
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send to a broadcast name");
        resultLen = NQ_FAIL;
        goto Exit;
    }

    if (calledName->isGroup)    /*  group name - broadcasts are handled by DD */
    {
        msgBuf = staticData->sendBuffer;    /* allocate a buffer */

        msgLen = frameComposeDatagram(
                    (CMNetBiosDatagramMessage*)msgBuf,
                    pSock,
                    CM_NB_DATAGRAM_DIRECTGROUP,
                    pSock->name.name,
                    calledName->name,
                    data,
                    dataLen
                    );

        if (msgLen <= 0)
        {
            sySetLastError(CM_NBERR_INTERNALERROR);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to compose a Datagram Message");
            resultLen = NQ_FAIL;
            goto Exit;
        }

#ifdef UD_ND_INCLUDENBDAEMON
        /* send to DD and do not wait for response */

        internalSock = getInternalSocketDD();

        if (internalSock == NULL)
        {
            sySetLastError(CM_NBERR_INTERNALERROR);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to get an internal socket to DD");
            resultLen = NQ_FAIL;
            goto Exit;
        }

        resultLen = sySendToSocket(
            internalSock->socket,
            (const NQ_BYTE*)msgBuf,
            (NQ_COUNT)msgLen,
            &localhost,
            syHton16(CM_IN_INTERNALDSPORT)
            );

        putInternalSocketDD(internalSock);

        if (resultLen < 0)
        {
            sySetLastError(CM_NBERR_DDCOMMUNICATIONERROR);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send a message to DD");
            resultLen = NQ_FAIL;
            goto Exit;
        }

#else /* UD_ND_INCLUDENBDAEMON */
        {
            NQ_INT idx;     /* adapter index */

            /* broadcast on each of adapters */

            for (idx = 0; idx < sizeof(staticData->adapters)/sizeof(staticData->adapters[0]); idx++)
            {
                if (staticData->adapters[idx].empty)
                {
                    break;
                }

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Adapter found on %d ip=0x%08lx bcast=0x%08lx", idx, CM_IPADDR_GET4(staticData->adapters[idx].ip), CM_IPADDR_GET4(staticData->adapters[idx].bcast));
                /* regardless of the node type, datagram is broadcasted since a
                   host is treated as a NBDD for itself */

                cmPutSUint32(((CMNetBiosDatagramMessage*)msgBuf)->sourceIP, CM_IPADDR_GET4(staticData->adapters[idx].ip));
                cmPutSUint16(((CMNetBiosDatagramMessage*)msgBuf)->sourcePort, syHton16(CM_NB_DATAGRAMSERVICEPORT));

                /* send the response */

                resultLen = sySendToSocket(
                    pSock->socket,
                    (NQ_BYTE*)msgBuf,
                    (NQ_COUNT)msgLen,
                    &staticData->adapters[idx].bcast,
                    syHton16(CM_NB_DATAGRAMSERVICEPORT)
                    );
                if (resultLen < 0)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to broadcast message");
                    resultLen = NQ_FAIL;
                    goto Exit;
                }
            }
        }
#endif /* UD_ND_INCLUDENBDAEMON */

        resultLen = (NQ_INT)dataLen;        /* we do not know the final result just count on */
    }
    else /* a unique name */
    {
        NQ_IPADDRESS ip;       /* destination IP address */

        if (nsGetHostByName(&ip, calledName) == NQ_FAIL)
        {
            sySetLastError(CM_NBERR_HOSTNAMENOTRESOLVED);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to resolve called name");
            resultLen = NQ_FAIL;
            goto Exit;
        }

        resultLen = nsSendTo(socketHandle, data, dataLen, calledName, &ip);
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", resultLen);
    return resultLen;
}
#endif /* UD_NQ_USETRANSPORTNETBIOS */
