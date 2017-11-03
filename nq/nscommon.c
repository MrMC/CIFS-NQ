/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Module-internal routines and data
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 24-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"

#include "nsapi.h"
#include "nscommon.h"   /* self-include */

#include "nsbuffer.h"
#include "nssocket.h"
#include "nsinsock.h"
#include "nsframes.h"
#include "nssessio.h"
#include "cmresolver.h"

/*
 This file contains those NS functions that do not fit in other categories
 */

/* structure used to release NS resources  */
typedef struct
{
    NQ_BOOL initSocketPool;         /* TRUE if SocketPool initialized */
    NQ_BOOL initInternalSockets;    /* TRUE if InternalSockets initialized */
    NQ_BOOL initSession;            /* TRUE if Session initialized */
    NQ_BOOL initMessageBufferPool;  /* TRUE if MessageBufferPool initialized */
    NQ_BOOL initMessage;            /* TRUE if Message initialized */
#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
    NQ_BOOL initDns;               /* TRUE if Dns initialized */
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
} NsReleaseParams;

/*
    Static data and functions
    -------------------------
 */

static NQ_COUNT initCount = 0;                      /* number of calls to nsInit() */
static NSSocketHandle commonDatagramSocket = NULL;  /* common datagram socket bound to the "local host name<0>" */
static SYMutex initGuard;                           /* for exclusive access to resources */


static
NQ_BOOL
createCommonDatagramSocket(
    void
    );

static void
releaseData(
    NsReleaseParams *params
    );

/*
 *====================================================================
 * PURPOSE: Initialize mutex
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   This function should be called only once on initialization.
 *          Its aim is to initialize mutex fo exclusive access to nsInit
 *====================================================================
 */

void
nsInitGuard(
    void
    )
{
    syMutexCreate(&initGuard);
}

/*
 *====================================================================
 * PURPOSE: Delete mutex
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   
 *
 *====================================================================
 */

void
nsExitGuard(
    void
    )
{
    syMutexDelete(&initGuard);
}

/*
 *====================================================================
 * PURPOSE: Initialize NS module
 *--------------------------------------------------------------------
 * PARAMS:  IN TRUE to create "common" socket
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   DD and ND treat tasks as resources holders and are capable to do
 *          resource clean-up on per-task basis. Tasks identify themselves on
 *          nsInit by specifying a TRUE value in the parameter.
 *          Drivers should use FALSE, application tasks - TRUE
 *          NS register a task by sending its PID to ND in an internal Name
 *          Registration Request
 *====================================================================
 */

NQ_STATUS
nsInit(
    NQ_BOOL createSocket
    )
{
    NsReleaseParams params;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "createSocket:%s", createSocket ? "TRUE" : "FALSE");

    /* now we are allocating internal NS resources
       here we assume that this function is never interrupted.
       it may be entered more then once, but this will have no effect on the next block */

    syMutexTake(&initGuard);

    if (initCount == 0)
    {
        if (NQ_FAIL == cmInit())   /* initialize common routines */
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Common initialization failed");
            goto Exit;
        }

        /* Initialize:
         *  pool of socket slots
         *  pools of precreated sockets for internal communication
         *  pool of buffers and predefined buffers
         *  Message module
         *  DNS client
         */
        initCount++; 
        syMemset(&params, 0, sizeof(params));
        if (   !(params.initSocketPool = (nsInitSocketPool() == NQ_SUCCESS)) 
            || !(params.initInternalSockets = (nsInitInternalSockets() == NQ_SUCCESS))   
            || !(params.initSession = (nsInitSession() == NQ_SUCCESS))                  
            || !(params.initMessageBufferPool = (nsInitMessageBufferPool() == NQ_SUCCESS))
            || !(params.initMessage = (nsInitMessage() == NQ_SUCCESS))  
#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
            || !(params.initDns = (nsDnsInit() == NQ_SUCCESS))  
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
            )               
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to initialize NS library");
            goto Error;
        }
    }
	else
		initCount++;

#if defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE)

    /* register with Resolver */
    {
        CMResolverMethodDescriptor method;          /* method descriptor */
        CMResolverMethodDescriptor methodDC;        /* method descriptor for DC resolution */
        NQ_UINT32 wins;                             /* WINS IPv4 */             

        method.type = NQ_RESOLVER_NETBIOS;
        method.isMulticast = TRUE;  /* broadcast */
        method.activationPriority = 4;
        method.timeout.low = 2000; /* milliseconds */
        method.timeout.high = 0;   /* milliseconds */
        method.waitAnyway = FALSE;
        method.requestByName = nsRequestByNameBcast;
        method.responseByName = nsResponseByName;
        method.requestByIp = nsRequestByIp;
        method.responseByIp = nsResponseByIp;
        cmResolverRegisterMethod(&method, NULL);
        wins = udGetWins();
        if (0L != wins)
        {
            NQ_IPADDRESS ip;            /* IP address */
            method.isMulticast = FALSE;  /* unicast */
            method.activationPriority = 2;
            method.timeout.low = 1000; /* milliseconds */
            method.timeout.high = 0;   /* milliseconds */
            method.waitAnyway = TRUE;
            method.requestByName = nsRequestByNameWins;
            method.responseByName = nsResponseByName;
            method.requestByIp = nsRequestByIp;
            method.responseByIp = nsResponseByIp;
            CM_IPADDR_ASSIGN4(ip, wins);
            cmResolverRegisterMethod(&method, &ip);
        }

#ifndef UD_NQ_AVOIDDCRESOLUTIONNETBIOS
        methodDC.type = NQ_RESOLVER_NETBIOS_DC;
        methodDC.isMulticast = TRUE;  /* broadcast */
        methodDC.activationPriority = 4;
        methodDC.timeout.low = 2000; /* milliseconds */
        methodDC.timeout.high = 0;	 /* milliseconds */
        methodDC.waitAnyway = FALSE;
        methodDC.requestByName = nsRequestByNameBcastDC;
        methodDC.responseByName = nsResponseByName;
        methodDC.requestByIp = nsRequestByIp;
        methodDC.responseByIp = nsResponseByIp;
        cmResolverRegisterMethod(&methodDC, NULL);
#endif /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */
        if (0L != wins)
        {
            NQ_IPADDRESS ip;            /* IP address */

            methodDC.type = NQ_RESOLVER_NETBIOS_DC;
            methodDC.isMulticast = FALSE;  /* unicast */
            methodDC.activationPriority = 2;
            methodDC.timeout.low = 1000; /* milliseconds */
            methodDC.timeout.high = 0; 	 /* milliseconds */
            methodDC.waitAnyway = FALSE;
            methodDC.requestByName = nsRequestByNameWinsDC;
            methodDC.responseByName = nsResponseByName;
            methodDC.requestByIp = nsRequestByIp;
            methodDC.responseByIp = nsResponseByIp;
            CM_IPADDR_ASSIGN4(ip, wins);
            cmResolverRegisterMethod(&methodDC, &ip);
        }
    }

#endif /* defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE) */

    if (NULL == commonDatagramSocket && createSocket && !createCommonDatagramSocket())
    {
        syMemset(&params, 1, sizeof(params));
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create the common datagram socket");
        goto Error;
    }
    /* initialization totally succeded */
    result = NQ_SUCCESS;
    goto Exit;

Error:
    releaseData(&params);

Exit:
    syMutexGive(&initGuard);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Shutdown NS module
 *--------------------------------------------------------------------
 * PARAMS:  IN should be TRUE if this task called nsInit with TRUE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   the parameter says whether to release resources or not
 *          to release resources we send Name Release Request internally
 *          to the ND
 *====================================================================
 */

NQ_STATUS nsExit(
    NQ_BOOL reg
    )
{
    NsReleaseParams params;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "reg:%s", reg ? "TRUE" : "FALSE");

    syMutexTake(&initGuard);
  
#ifdef UD_ND_INCLUDENBDAEMON
    if (reg && commonDatagramSocket != NULL)
    {  
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Closing the common 'host_name<0>' datagram socket");

        nsClose(commonDatagramSocket);
        commonDatagramSocket = NULL;
    }
#endif

    /* if we reached nsExit all param flags must be TRUE. so set all to 1 */
    syMemset(&params, 1, sizeof(params));
    releaseData(&params);

    syMutexGive(&initGuard);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", NQ_SUCCESS);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Check a socket
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to the result buffer at least 17 byte long
 *
 * RETURNS: TRUE for an "alive" socket, FALSE for A "dead" socket
 *
 * NOTE:    we delegate this call to the underlying socket system
 *====================================================================
 */

NQ_BOOL
nsIsSocketAlive(
    NSSocketHandle socketHandle
    )
{
    SYSocketHandle sock;

    if (NULL == socketHandle)
    	return FALSE;

    sock = ((SocketSlot*)socketHandle)->socket;

    return syIsValidSocket(sock) && syIsSocketAlive(sock);
}

/*
 *====================================================================
 * PURPOSE: Share single datagram socket bound to 'local host name<0>'
 *--------------------------------------------------------------------
 * PARAMS:  none
 *
 * RETURNS: common datagram socket
 *
 * NOTE:
 *====================================================================
 */

NSSocketHandle
nsGetCommonDatagramSocket(
    void
    )
{
    return commonDatagramSocket;
}

static
NQ_BOOL
createCommonDatagramSocket(
    void
    )
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

#ifdef UD_NQ_USETRANSPORTNETBIOS
    if (commonDatagramSocket == NULL)
    {
        CMNetBiosNameInfo addr;

		if (cmNetBiosGetHostNameInfo()->name[0] == '\0')
		{
		    /* avoid null socket name */
			syMemcpy(&addr.name, cmNetBiosGetHostNameSpaced(), sizeof(addr.name));
		}
		else
    	{
        	syMemcpy(&addr, cmNetBiosGetHostNameInfo(), sizeof(addr));
	    }
        cmNetBiosNameFormat(addr.name, CM_NB_POSTFIX_WORKSTATION);
        addr.isGroup = FALSE;

        if ((commonDatagramSocket = nsSocket(NS_SOCKET_DATAGRAM, NS_TRANSPORT_NETBIOS)) != NULL)
        {
            if (nsBindNetBios(commonDatagramSocket, &addr , NS_BIND_DEAMON) != NQ_FAIL)
            {
                if (nsListen(commonDatagramSocket, 3) != NQ_FAIL)
                {
                    result = TRUE;
                    goto Exit;
                }
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Can't listen");
                }
            }
            else
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Can't bind to port");
            }
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Can't create DATAGRAM socket");
        }
    }
    else
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Socket is already initialized");
        result = TRUE;
        goto Exit;
    }

    if (NULL != commonDatagramSocket)
    {
        nsClose(commonDatagramSocket);
        commonDatagramSocket = NULL;
    }
#else /* UD_NQ_USETRANSPORTNETBIOS */
    result = TRUE;
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTNETBIOS
Exit:
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send request to the Name Daemon
 *--------------------------------------------------------------------
 * PARAMS:  IN socket to use
 *          IN message to send
 *          IN this message length
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 *====================================================================
 */

NQ_STATUS
nsSendRequestToND(
    SYSocketHandle socket, 
    const NQ_BYTE * msg,  
    NQ_UINT msgLen      
    )
{
    NQ_STATUS res;

#ifdef UD_ND_INCLUDENBDAEMON
    const NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT result;              /* various results */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d msg:%p msgLen:%u", socket, msg, msgLen);

    /* send message to the ND */

    result = sySendToSocket(
        socket,
        msg,
        msgLen,
        &localhost,
        syHton16(CM_IN_INTERNALNSPORT)
        );
    if (result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send to ND");
        res = NQ_FAIL;
        goto Exit;
    }

    res = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", msgLen);
#else /* UD_ND_INCLUDENBDAEMON */
    res = (NQ_STATUS)msgLen;
#endif /* UD_ND_INCLUDENBDAEMON */
    return res;
}

/*
 *====================================================================
 * PURPOSE: Receive a response from the Name Daemon
 *--------------------------------------------------------------------
 * PARAMS:  IN  Socket to use
 *          OUT buffer for the response ADDR ENTRY or NULL if no ADDR ENTRY 
 *              expected
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 *====================================================================
 */

NQ_STATUS                   
nsReceiveResponseFromND(
    SYSocketHandle socket,
    void * addrEntry
    )
{
#ifdef UD_ND_INCLUDENBDAEMON
    CMNetBiosHeader* resHdr;        /* pointer to the response header */
    NQ_INT result;                  /* various results */
    NQ_IPADDRESS ip;                /* response IP */
    NQ_PORT port;                   /* responding port */
    NQ_UINT16 codes;                /* OPCODE, RCODE, etc. */
    NQ_STATUS res = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%p addrEntry:%p", socket, addrEntry);

    /* cast pointer to the response message header */

    resHdr = (CMNetBiosHeader*) nsGetRecvDatagramBuffer();

    /* retry operation several times */

    result = syRecvFromSocket(
        socket,
        (NQ_BYTE*)resHdr,
        CM_NB_DATAGRAMBUFFERSIZE,
        &ip,
        &port
        );
    if (result == 0 || result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Receive error");
        goto Exit;
    }

    /* inspect packet type: response flag, error code */

    codes = syNtoh16(cmGetSUint16(resHdr->packCodes));

    if (!(codes & CM_NB_RESPONSE))
    {
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet - not a response");
        goto Exit;
    }

    if ((codes & CM_NB_RCODE_MASK) != CM_NB_RCODE_NOERR)
    {
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Negative response: RCODE: %d", codes & CM_NB_RCODE_MASK);
        goto Exit;
    }

    /* proceed by OPCODE */

    codes = codes & (NQ_UINT16)CM_NB_OPCODE;
    switch (codes)
    {
        case CM_NB_OPCODE_QUERY:    /* the response match the request - this is a
                                           positive response */
        {
            if (addrEntry != NULL)      /* ADDR ENTRY expected in the response
                                           we will parse the message until ADDR ENTRY */
            {
                NQ_BYTE* curPtr;   /* pointer for parsing */

                curPtr = cmNetBiosSkipName(resHdr, resHdr + 1);     /* skip RR name */

                if (curPtr == NULL) /* parse error */
                {
                    sySetLastError(CM_NBERR_NOTNETBIOSNAME);
                    LOGERR(CM_TRC_LEVEL_ERROR, "Error while parsing the NB name in the response");
                    goto Exit;
                }

                curPtr += sizeof(CMNetBiosResourceRecord);          /* skip RR */
                syMemcpy(addrEntry, curPtr, sizeof(CMNetBiosAddrEntry));
            }
            res = NQ_SUCCESS;
            goto Exit;
        }
        case CM_NB_OPCODE_REGISTRATION: 
        {
            res = NQ_SUCCESS;
            goto Exit;
        }
        case CM_NB_OPCODE_WACK:                     /* wait for acknowledge */
        {
            sySetLastError(CM_NBERR_TIMEOUT);
            LOGERR(CM_TRC_LEVEL_ERROR, "WACK received");
            goto Exit;
        }
        case CM_NB_OPCODE_RELEASE:
        {
            res = NQ_SUCCESS;
            goto Exit;
        }
        default:
            break;
    }
    LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet code: received opcode: 0x%x", codes);

Exit:
    nsPutRecvDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
#else /* UD_ND_INCLUDENBDAEMON */
    return NQ_FAIL;
#endif /* UD_ND_INCLUDENBDAEMON */
}

/*
 *====================================================================
 * PURPOSE: Send request to the Name Daemon and get a response
 *--------------------------------------------------------------------
 * PARAMS:  IN message to send
 *          IN this message length
 *          OUT buffer for the response ADDR ENTRY or NULL if no
 *              ADDR ENTRY expected
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This routine may be called in a case when a response should bring
 *          (e.g. - name resolution). Then, the data will be an ADD ENTRY chunk
 *          in the Resource Record data.
 *          We try to send the message several times until a response will appear:
 *            Negative Response fails the operation
 *            WACK changes the timeout value
 *            Positive Response successfully completes the operation
 *====================================================================
 */

NQ_STATUS
nsProceedRequestToND(
    const NQ_BYTE* msgBuf,
    NQ_UINT msgLen,
    void * addrEntry
    )
{
#ifdef UD_ND_INCLUDENBDAEMON
    InternalSocket * pSock; /* socket for communication with ND */
    SYSocketSet  socketSet; /* set for reading from this socket */
    NQ_COUNT retryCount;    /* number of retries */
    NQ_UINT32 timeOut;        /* timeout in seconds, may change as the result of a WACK response */
    NQ_STATUS result = NQ_FAIL; /* operation status */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p msgLen:%u addrEntry:%p", msgBuf, msgLen, addrEntry);

    pSock = getInternalSocketND();
    if (NULL == pSock)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable allocate internal socket");
        goto Exit;
    }

    timeOut = CM_NB_UNICASTREQRETRYTIMEOUT + 100;        /* initial timeout */

    /* retry operation several times */

    for (retryCount = CM_NB_UNICASTREQRETRYCOUNT; retryCount>0; retryCount--)
    {
        /* send message to the ND */

        result = nsSendRequestToND(pSock->socket, msgBuf, msgLen);
        if (NQ_FAIL == result)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send to ND");
            goto Exit;
        }

        /* wait for response */

        syClearSocketSet(&socketSet);
        syAddSocketToSet(pSock->socket, &socketSet);

        result = sySelectSocket(
            &socketSet,
            timeOut
            );

        if (result == NQ_FAIL)                 /* error the select failed  */
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error during select. Unable to read from ND");
            goto Exit;
        }

        if (result == 0)                /* timeout  */
        {
            sySetLastError(CM_NBERR_TIMEOUT);
            LOGERR(CM_TRC_LEVEL_ERROR, "select timed out");
            goto Exit;
        }

        /* socket is ready to read from */
        result = nsReceiveResponseFromND(pSock->socket, addrEntry);
        if (NQ_FAIL == result)
        {
            continue;
        }
        result = NQ_SUCCESS;
        goto Exit;
    }

Exit:
    if (NULL != pSock)
        putInternalSocketND(pSock);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
#else /* UD_ND_INCLUDENBDAEMON */
    return (NQ_STATUS)msgLen;
#endif /* UD_ND_INCLUDENBDAEMON */
}

/*
 *====================================================================
 * PURPOSE: Send request to the Datagram Daemon and get a response
 *--------------------------------------------------------------------
 * PARAMS:  IN message to send
 *          IN this message length
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This routine sends an internal message to ND. A message is a DIRECT UNIQUE
 *          DATAGRAM with has a proprietary (VIPC) structure in the data trailer.
 *          We try to send the message several times until a response appears.
 *          Any response but a positive one (CM_NB_VIPCOK) will fail the operation
 *====================================================================
 */

NQ_STATUS
nsProceedRequestToDD(
    const NQ_BYTE* msgBuf,
    NQ_UINT msgLen,
    const CMNetBiosName socketName
    )
{
    InternalSocket* pSock;         /* socket for communication with ND */
    NQ_COUNT retryCount;           /* number of retries */
    NQ_BYTE* responseBuf = NULL;   /* buffer for the response message */
    CMNetBiosName sourceName;      /* expected DD name */
    NQ_STATUS res = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msgBuf:%p msgLen:%u socketName:%p", msgBuf, msgLen, socketName);

    pSock = getInternalSocketDD();
    if (NULL == pSock)
    {
        sySetLastError(CM_NBERR_INTERNALERROR);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to get an internal socket to DD");
        goto Exit;
    }

    responseBuf = nsGetRecvDatagramBuffer();

    for (retryCount = CM_NB_UNICASTREQRETRYCOUNT; retryCount>0; retryCount--)
    {
        SYSocketSet  socketSet;            /* set for reading from this socket */
        NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
        NQ_INT result;                     /* various results */
        NQ_IPADDRESS ip;                   /* response IP (placeholder) */
        NQ_PORT port;                      /* responding port (placeholder) */
        CMNetBiosVIPCResponse vipcHdr;     /* a VIPC Listen Response structure
                                              from the incoming datagram */
        /* send message to DD */

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "sending to DD using socket %d, buffer %p", pSock->socket, (void*)msgBuf);

        result = sySendToSocket(
            pSock->socket,
            msgBuf,
            msgLen,
            &localhost,
            syHton16(CM_IN_INTERNALDSPORT)
            );
        if (result == NQ_FAIL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send to DD Daemon");
            goto Exit;
        }

        /* wait for response */

        syClearSocketSet(&socketSet);
        syAddSocketToSet(pSock->socket, &socketSet);

        result = sySelectSocket(
            &socketSet,
            CM_NB_UNICASTREQRETRYTIMEOUT + 100
            );
        if (result == 0)      /* no input */
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Select timeout");
            continue;
        }
        if (result == NQ_FAIL) /* error */
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error during select. Unable to read from ND");
            continue;
        }

        /* socket is ready to read from */

        result = syRecvFromSocket(
            pSock->socket,
            (NQ_BYTE*)responseBuf,
            CM_NB_DATAGRAMBUFFERSIZE,
            &ip,
            &port
            );
        if (result == 0 || result == NQ_FAIL) /* error */
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Receive error");
            continue;
        }
        /* Parse the result and extract the VIPC response.
           Note that the real source name resides in the place of the destination name */

        result = frameParseDatagram(
                    (const NQ_BYTE*)responseBuf,
                    (NQ_UINT)result,
                    sourceName,
                    (NQ_BYTE*)&vipcHdr,
                    sizeof(vipcHdr),
                    socketName
                    );

        if (result == NQ_FAIL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Error while parsing the response");
            continue;
        }

        /* check names */

        if (!cmNetBiosSameNames(sourceName, CM_DDNAME))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Response from unexpected source");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " name: %s", sourceName);
            continue;
        }

        /* inspect the response */

        if ((cmGetSUint16(vipcHdr.status)) == CM_NB_VIPCOK)     /* its is HBO and mask is applied because of a bug in DD - TODO */
        {
            res = NQ_SUCCESS;
            goto Exit;
        }
        else
        {
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Negative response from DD");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " response code: %d", cmGetSUint16(vipcHdr.status));
            goto Exit;
        }

    } /* for loop end */
    sySetLastError(CM_NBERR_TIMEOUT);
    LOGERR(CM_TRC_LEVEL_ERROR, "Operation timed out");

Exit:
    nsPutRecvDatagramBuffer();
    if (NULL != pSock)
        putInternalSocketDD(pSock);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

/*
 *====================================================================
 * PURPOSE: Release memory and clean up resources
 *--------------------------------------------------------------------
 * PARAMS:  IN release parameter
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
releaseData(
    NsReleaseParams *params
    )
{
    initCount--;
    if (initCount == 0)
    {
        if (params->initMessage)            nsExitMessage();
        if (params->initMessageBufferPool)  nsReleaseMessageBufferPool();
#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
        if (params->initDns)                nsDnsExit();
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */
        if (params->initInternalSockets)    nsExitInternalSockets();
        if (params->initSocketPool)         nsExitSocketPool();
        if (params->initSession)            nsExitSession();
        cmExit();
    }
}


