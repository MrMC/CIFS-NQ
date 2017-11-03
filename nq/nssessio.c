/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of session framework functions
 *                  (common for the both types of sockets)
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"
#include "nssessio.h"
#include "nsbuffer.h"
#include "nssocket.h"
#include "nsinsock.h"
#include "nscommon.h"
#include "nsframes.h"
#include "ndapi.h"

/*
  This file implements NS calls for establishing connections for both server side and
  client side.

  A user may create either a TCP/UDP or a NetBIOS socket. We implement separate Bind and
  Connect functions for TCP/UDP and NetBIOS (nsBindInet(), nsBindNetBios(), nsConnectInt(),
  nsConnectNetBios). The "Inet" functions just delegate control to the underlying sockets.

  A socket has two NetBIOS names - socket name and remote socket name.
    1) A listening server socket gets name on nsBindNetBios() and has no remote name
    2) A session socket on the server side gets its names on nsAccept(). It has
       the same name as the respective listening socket and the remote name of the client
       socket that has connected it.
    3) A client socket has an empty socket name and the remote name of the server socket
       it is connected to (on nsConnect())
    4) A bound unconnected socket gets name on nsBindNetBios()
 */

#define SESSION_BUFFER_SIZE 128

 /*
    Static functions and data
    -------------------------
 */

typedef struct
{
    NQ_BOOL domainRegistered;   /* TRUE when domain name was registered */
    NQ_IPADDRESS winsServers[UD_NQ_MAXWINSSERVERS * UD_NS_MAXADAPTERS];
    NQ_COUNT numServers;        /* number of WINS servers */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* Updates the DNS record for socket */

#ifdef UD_NQ_USETRANSPORTIPV4
static NQ_COUNT ip4Count = 0;
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
static NQ_COUNT ip6Count = 0;
#endif /* UD_NQ_USETRANSPORTIPV6 */

/* Release the DNS record for socket*/

static
NQ_STATUS
releaseDnsName(
    SocketSlot* pSock
    );

/* send Session Request and get the response
   this function comes to solve SESSION RETARGET RESPONSE by recursively calling itself */

static
NQ_STATUS
doConnect(
    SocketSlot* slot,
    CMNetBiosNameInfo* name,
    NQ_IPADDRESS *ip,
    NQ_PORT port,
    NQ_UINT16 level
    );

#ifdef UD_NQ_USETRANSPORTNETBIOS

static
NQ_STATUS
recreateSocket(     /* on error, close a socket, then create a new one with the same
                       parameters - this is the only way to unbind a socket on error */
    SocketSlot* pSock
    );
#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: Initialize "static" memory
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

NQ_STATUS
nsInitSession(
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate socket pool");
        result = NQ_FAIL;
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->domainRegistered = FALSE;
    staticData->numServers = 0;

#if defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE)
    {
		NQ_IPADDRESS4 wins;

		if (0L != (wins = udGetWins()))
		{
			NQ_IPADDRESS ip;

			CM_IPADDR_ASSIGN4(ip, wins);
			staticData->winsServers[staticData->numServers++] = ip;
		}
    }

#endif /* defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE) */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release "static" memory
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

void
nsExitSession(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: Register a name on the network as a NetBIOS name
 *--------------------------------------------------------------------
 * PARAMS:  IN  name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name is registered as a workstation and as a server name
 *====================================================================
 */

NQ_STATUS
nqRegisterNetBiosName(
    const NQ_CHAR* name   /* pointer to name to register as NetBIOS name */
    )
{
    NQ_STATUS         result = NQ_FAIL;
    CMNetBiosNameInfo nameWrkst;
    CMNetBiosNameInfo nameSrv;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p", name);

    nameWrkst.isGroup = FALSE;
    cmNetBiosNameCreate(nameWrkst.name, name, CM_NB_POSTFIX_WORKSTATION);
    if (nsRegisterName(&nameWrkst) == NQ_FAIL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_GEN,
			UD_LOG_GEN_NAMEREGFAIL,
			NULL,
			NULL,
			0,
			NULL
		);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        goto Exit;
    }   
    
    nameSrv.isGroup = FALSE;
    cmNetBiosNameCreate(nameSrv.name, name, CM_NB_POSTFIX_SERVER);    
    if (nsRegisterName(&nameSrv) == NQ_FAIL)
    {
#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_GEN,
			UD_LOG_GEN_NAMEREGFAIL,
			NULL,
			NULL,
			0,
			NULL
		);
#endif /* UD_NQ_INCLUDEEVENTLOG */
        nsReleaseName(&nameWrkst);
        goto Exit;
    }

    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release a name on the network as a NetBIOS name
 *--------------------------------------------------------------------
 * PARAMS:  IN  name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name should be a workstation name and a server name
 *====================================================================
 */

NQ_STATUS
nqReleaseNetBiosName(
    const NQ_CHAR* name   /* pointer to name to release as NetBIOS name */
    )
{
    CMNetBiosNameInfo nameInfo;
    NQ_STATUS status;

    nameInfo.isGroup = FALSE;
    cmNetBiosNameCreate(nameInfo.name, name, CM_NB_POSTFIX_WORKSTATION);
    status = nsReleaseName(&nameInfo);
    cmNetBiosNameCreate(nameInfo.name, name, CM_NB_POSTFIX_SERVER);
    return nsReleaseName(&nameInfo) == NQ_SUCCESS ? status : NQ_FAIL;
}

/*
 *====================================================================
 * PURPOSE: Register a name on the network as a NetBIOS name (extended)
 *--------------------------------------------------------------------
 * PARAMS:  IN  name
 *          IN  flags (combination of flags designating group or unique name 
 *              and postfix, e.g. CM_NB_UNIQUE|CM_NB_POSTFIX_SERVER)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This is an extended version of nqRegisterNetBiosName()
 *====================================================================
 */
NQ_STATUS nqRegisterNetBiosNameEx(const NQ_CHAR* name, const NQ_BYTE flags)
{
    CMNetBiosNameInfo nameToRegister;

    nameToRegister.isGroup = flags & CM_NB_GROUP;
    cmNetBiosNameCreate(nameToRegister.name, name, flags & CM_NB_POSTFIXMASK);

    return nsRegisterName(&nameToRegister);
}

/*
 *====================================================================
 * PURPOSE: Release a name on the network as a NetBIOS name (extended)
 *--------------------------------------------------------------------
 * PARAMS:  IN  name
 *          IN  flags (combination of flags designating group or unique name 
 *              and postfix, e.g. CM_NB_UNIQUE|CM_NB_POSTFIX_SERVER)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This is an extended version of nqReleaseNetBiosName()
 *====================================================================
 */

NQ_STATUS nqReleaseNetBiosNameEx(const NQ_CHAR* name, const NQ_BYTE flags)
{
    CMNetBiosNameInfo nameToRelease;

    nameToRelease.isGroup = flags & CM_NB_GROUP;
    cmNetBiosNameCreate(nameToRelease.name, name, flags & CM_NB_POSTFIXMASK);
    return nsReleaseName(&nameToRelease);
}

/*
 *====================================================================
 * PURPOSE: Create a socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket type - TCP or UDP
 *          IN socket transport - NetBIOS, TCPv4 or TCPv6
 *
 * RETURNS: Socket slot
 *
 * NOTES:   Information about a new socket is stored in a socket slot structure
 *====================================================================
 */

NSSocketHandle
nsSocket(
        NQ_UINT type,
        NQ_UINT transport
        )
{
    SocketSlot* pSock;      /* pointer to NS socket descriptor */
    NSSocketHandle resultHdl = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "type:%u transport:%u", type, transport);

    /* check parameters */

#if SY_DEBUGMODE
    switch (type)
    {
    case NS_SOCKET_DATAGRAM:
    case NS_SOCKET_STREAM:
        break;
    default:
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown socket type value %i", type);
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        goto Exit;
    }

    switch (transport)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
    case NS_TRANSPORT_NETBIOS:
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_USETRANSPORTIPV4
    case NS_TRANSPORT_IPV4:
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    case NS_TRANSPORT_IPV6:
#endif /* UD_NQ_USETRANSPORTIPV6 */
        break;
    default:
        LOGERR(CM_TRC_LEVEL_ERROR, "Unknown socket transport value %i", transport);
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        goto Exit;
    }
#endif /* SY_DEBUGMODE */

    /* allocate and initialize a socket descriptor */
    if ((pSock=getSocketSlot()) == NULL)        /* Get a slot for socket info */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate socket slot");
        sySetLastError(CN_NBERR_SOCKETOVERFLOW);    /* no more slots */
        goto Exit;
    }

    /* create the socket in the underlying socket system */
    pSock->socket =
        syCreateSocket(
            (type==NS_SOCKET_STREAM),
#ifdef UD_NQ_USETRANSPORTIPV6
            (transport == NS_TRANSPORT_IPV6) ? CM_IPADDR_IPV6 :
#endif /* UD_NQ_USETRANSPORTIPV6 */
            CM_IPADDR_IPV4
            );
    if (!syIsValidSocket(pSock->socket))
    {
        putSocketSlot(pSock);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create socket");
        sySetLastError(NQ_ERR_SOCKETCREATE);
        goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Created NS socket %d", pSock->socket);

    /* fill initial socket information */
    pSock->transport = transport;
    pSock->isListening = FALSE;
    pSock->port = 0;
    pSock->type = type;
    pSock->isBind = FALSE;
	pSock->isAccepted = FALSE;

    /* set the default caller name to the own NETBIOS name */
    cmNetBiosNameCopy(pSock->name.name, cmNetBiosGetHostNameInfo()->name);
    cmNetBiosNameFormat(pSock->name.name, CM_NB_POSTFIX_WORKSTATION);
    cmNetBiosNameCopy(pSock->remoteName.name, cmNetBiosGetEmptyName());
    pSock->name.isGroup = FALSE;
    pSock->remoteName.isGroup = FALSE;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Socket created with fd=%d, type=%s", pSock->socket, (type==NS_SOCKET_STREAM)?"stream":"datagram");
    resultHdl = pSock;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", resultHdl);
    return resultHdl;
} /* nsSocket() */

/*
 *====================================================================
 * PURPOSE: Bind a TCP or UDP socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN IP   (in NBO)
 *          IN port (in NBO)
 *
 * RETURNS: SUSSESS or NQ_FAIL
 *
 * NOTES:   Delegates this call to the underlying socket system
 *====================================================================
 */

NQ_STATUS
nsBindInet(
      NSSocketHandle sockHandle,
      NQ_IPADDRESS *ip,
      NQ_PORT port
      )
{
    NQ_STATUS res = NQ_SUCCESS;         /* return value */
    SocketSlot* pSock;  /* the same as sockHandle but properly casted */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sockHandle:%p ip:%p port:%u", sockHandle, ip, port);

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        res = NQ_FAIL;
        goto Exit;
    }
#endif

    pSock->isNetBios = FALSE;   /* Not NB socket */

    res = syBindSocket(pSock->socket, ip, port);
    if (NQ_FAIL == res)
    {
        syCloseSocket(pSock->socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to bind socket");
        res = NQ_FAIL;
        goto Exit;
    }

    /* for a case when port was zero (dynamically allocated port) - get socket port
       number by reading the value from the underlying socket layer */

    syGetSocketPortAndIP(pSock->socket, &pSock->ip, &pSock->port);
    if (pSock->port == 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to obtain a dynamically bind port");
        res = NQ_FAIL;
        goto Exit;
    }

    pSock->isBind = TRUE;

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
    /* register all host addresses in DNS servers */
    if (nsDnsSetTargetAddresses() != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to update DNS record");
    }
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

/*
 *====================================================================
 * PURPOSE: Register a NetBIOS name on the network
 *--------------------------------------------------------------------
 * PARAMS:  IN NetBIOS name
 *
 * RETURNS: SUSSESS or NQ_FAIL
 *
 * NOTES:   A name should be registered with the ND
 *====================================================================
 */

NQ_STATUS
nsRegisterName(
      const CMNetBiosNameInfo* name
      )
{
    NQ_BYTE*   msgBuf;             /* buffer for REGISTRATION REQUEST message */
    NQ_INT     msgLen;             /* message length */
    NQ_STATUS  result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p", name);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "name = %s", name->name);

    msgBuf = nsGetSendDatagramBuffer();

    if (!cmNetBiosCheckName(name) )                     /* valid NetBIOS name? */
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Not a NetBIOS name");
        goto Exit;
    }
    /* we assume that the name is not registered yet
       we generate a NAME REGISTRATION PACKET for registration with the ND */

    if ((msgLen = frameInternalNameRegistrationRequest((NQ_BYTE*)msgBuf, name)) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Registration Request");
        goto Exit;
    }

    /* send the request and wait for a response */

    if (nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, NULL) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to register the name");
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    nsPutSendDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Unregister a NetBIOS name on the network
 *--------------------------------------------------------------------
 * PARAMS:  IN NetBIOS name
 *
 * RETURNS: SUSSESS or NQ_FAIL
 *
 * NOTES:   A name should be registered with the ND
 *====================================================================
 */

NQ_STATUS
nsReleaseName(
      const CMNetBiosNameInfo* name
      )
{
    NQ_BYTE* msgBuf;        /* buffer for Cancel Listen and Name Release Request packet */
    NQ_INT msgLen;          /* length of the message in this buffer */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p", name);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "name = %s", name->name);
    
    /* allocate buffer for Name Release Request */

    msgBuf = nsGetSendDatagramBuffer();

    if (   (msgLen = frameInternalNameReleaseRequest((NQ_BYTE*)msgBuf, name)) == NQ_FAIL
        || nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, NULL) == NQ_FAIL
       )
     {
         sySetLastError(CM_NBERR_RELEASENAMEFAIL);
         LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create Name Release Request packet");
         goto Exit;
     }
     result = NQ_SUCCESS;

Exit:
     nsPutSendDatagramBuffer();
     LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
     return result;
}

/*
 *====================================================================
 * PURPOSE: Bind a socket to a NetBIOS name
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN NetBIOS name
 *          IN type of binding
 *
 * RETURNS: SUSSESS or NQ_FAIL
 *
 * NOTES:   A name should be registered with the ND
 *====================================================================
 */

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_STATUS
nsBindNetBios(
      NSSocketHandle sockHandle,
      const CMNetBiosNameInfo* localName,
      NQ_UINT16	type
      )
{
    NQ_IPADDRESS anyIp = CM_IPADDR_ANY4 , localHost = CM_IPADDR_LOCAL;
    SocketSlot*        pSock;      /* the same as sockHandle but properly casted */
    NQ_STATUS          result;     /* result of socket operations */
    NQ_STATUS    res = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sockHandle:%p localName:%p type:%u", sockHandle, localName, type);

    pSock = (SocketSlot*)sockHandle;

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        goto Exit;
    }
#endif

    pSock->isNetBios = TRUE;                                /* an NB socket */
    syMemcpy(&pSock->name, localName, sizeof(*localName));  /* give name to the socket */

    /* bind socket in the underlying socket system to any port on any available IP
       if we can assume that the only server application on the target machine is
       the CIFS server, then we may bind this socket directly to the Session Service
       port. Otherwise we bind it to any port and the Daemon will retarget session to
       this port. */

#ifdef UD_NB_RETARGETSESSIONS
    result = syBindSocket(pSock->socket, type == NS_BIND_DEAMON ? &localHost : &anyIp, 0);
#else
    result = syBindSocket(pSock->socket, type == NS_BIND_DEAMON ? &localHost : &anyIp, (NQ_PORT)((pSock->type == NS_SOCKET_DATAGRAM) ? 0 : syHton16(CM_IN_SESSIONSERVICEPORT)));
#endif

    if (NQ_FAIL == result)
    {
        syCloseSocket(pSock->socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to bind");
        sySetLastError(NQ_ERR_SOCKETBIND);
        goto Exit;
    }
    if (NQ_FAIL == nsRegisterName(localName))
    {
        if (syGetLastError() != CM_NBERR_NEGATIVERESPONSE && syGetLastError() != CM_NBERR_TIMEOUT)
        {
            recreateSocket(pSock);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Registration Request");
            goto Exit;
        }
        LOGERR(CM_TRC_LEVEL_ERROR, " Name Registration Failed");

#ifdef UD_NQ_INCLUDEEVENTLOG
		udEventLog(
			UD_LOG_MODULE_CS,
			UD_LOG_CLASS_GEN,
			UD_LOG_GEN_NAMECONFLICT,
			NULL,
			NULL,
			0,
			NULL
		);
#endif /* UD_NQ_INCLUDEEVENTLOG */
		goto Exit;
    }

    if (!staticData->domainRegistered)
    {
        CMNetBiosNameInfo domain;

        syStrcpy(domain.name, cmNetBiosGetDomain()->name);
        cmNetBiosNameFormat(domain.name, CM_NB_POSTFIX_WORKSTATION);
        domain.isGroup = TRUE;
        staticData->domainRegistered = (NQ_SUCCESS == nsRegisterName(&domain));
    }

    syGetSocketPortAndIP(pSock->socket, &pSock->ip, &pSock->port);
    if (pSock->port == 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to obtain a dynamically bind port");
        sySetLastError(NQ_ERR_SOCKETNAME);
        goto Exit;
    }

    pSock->isBind = TRUE;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Socket %d bound to name: %s", pSock->socket, pSock->name.name);
    res = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: Connect to a remote host by its name
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN IP of the remote host (NBO)
 *          IN calling name
 *
 * RETURNS: SUSSESS or NQ_FAIL
 *
 * NOTES:   1) resolve NetBIOS name and find the remote server IP
 *          2) an UDP socket is really connected on the socket level
 *          3) for a TCP socket we send SESSION REQUEST to the remote server
 *             thus a connection happens on the NetBIOS level while both side
 *             sockets remain unconnected. SESSION REQUEST may cause SESSION
 *             RETARGET RESPONSE. Then the operation is repeated with a new
 *             (retarget) socket.
 *====================================================================
 */

NQ_STATUS
nsConnect(
    NSSocketHandle sockHandle,
    NQ_IPADDRESS *ip,
    CMNetBiosNameInfo* calledName
    )
{
    SocketSlot* pSock;       /* the same as sockHandle but properly casted */
    NQ_STATUS res = NQ_FAIL; /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sockHandle:%p ip:%p calledName:%p", sockHandle, ip, calledName);

    pSock = (SocketSlot*)sockHandle;

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        goto Exit;
    }
#endif

    /* check parameters */

    if (pSock->transport == NS_TRANSPORT_NETBIOS && !cmNetBiosCheckName(calledName)) /* valid netBIOS name? */
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Not a NetBIOS name");
        goto Exit;
    }

    pSock->isNetBios = TRUE;   /* is an NB socket */

    switch (pSock->transport)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
        case NS_TRANSPORT_NETBIOS:
            pSock->remotePort = CM_NB_SESSIONSERVICEPORT;
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NS_TRANSPORT_NETBIOS, port: %d", pSock->remotePort);
            res = doConnect(pSock, calledName, ip, syHton16(pSock->remotePort), 0);
            break;
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
        case NS_TRANSPORT_IPV4:
        case NS_TRANSPORT_IPV6:
            pSock->remotePort = CM_NB_SESSIONSERVICEPORTIP;
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NS_TRANSPORT_IPV4, port: %d", pSock->remotePort);
            res = doConnect(pSock, calledName, ip, syHton16(pSock->remotePort), 0);
            break;
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

      default:
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transport value");
        goto Exit;
    }

    /* copy the remote name and ip */
    syMemcpy(&pSock->remoteName, calledName, sizeof(*calledName));
    pSock->remoteIP = *ip;

    /* determine self IP address and port */
    syGetSocketPortAndIP(pSock->socket, &pSock->ip, &pSock->port);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

/*
 *====================================================================
 * PURPOSE: Close a socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN address IP
 *          IN port
 *
 * RETURNS: SUSSESS or NQ_FAIL
 *
 * NOTES:   release resources by this socket:
 *          1) socket name in ND
 *          2) listening request in DD (if any)
 *====================================================================
 */

NQ_STATUS nsClose(
    NSSocketHandle sockHandle
    )
{
    SocketSlot* pSock;      /* pointer to the socket descriptor */
#ifdef UD_NB_RETARGETSESSIONS
    NQ_BYTE* msgBuf;        /* buffer for Cancel Listen and Name Release Request packet */
    NQ_INT msgLen;          /* length of the message in this buffer */
    NQ_INT res;             /* various results (bytes sent, status returned) */
#endif
    NQ_BOOL isBind;         /* whether a bound socket */
    NQ_STATUS result = NQ_FAIL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "Closing socket: 0x%x", sockHandle);

    if (NULL == sockHandle)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Socket handle is NULL");
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        goto Exit;
    }

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {        
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot: %p", pSock);
        if (pSock != NULL)
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "socket: %d", pSock->socket);
        }
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        goto Exit;
    }
#endif

    if (NQ_SUCCESS != releaseDnsName(pSock))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to clear DNS record");
    }

    isBind = pSock->isBind;

	LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Closing socket (fid) %d", pSock->socket);

    putSocketSlot(pSock);

#ifdef UD_NB_RETARGETSESSIONS
    /* allocate buffer for Cancel Listen and Name Release Request */
    msgBuf = nsGetSendDatagramBuffer();

    /* release listening */
    if (pSock->isListening)
    {
        InternalSocket* internalSock;   /* socket for communication with DD */
        NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;

        if ((msgLen = frameInternalCancelListen((NQ_BYTE*)msgBuf, pSock)) == NQ_FAIL)
        {
            sySetLastError(CM_NBERR_CANCELLISTENFAIL);
            nsPutSendDatagramBuffer();
        }

        /* send the Cancel Listen packet to the DD  */
        internalSock = getInternalSocketDD();   /* should never fail but may block the task */
#if SY_DEBUGMODE
        if (internalSock==NULL || !syIsValidSocket(internalSock->socket))
        {
            if (internalSock != NULL)
                putInternalSocketDD(internalSock);
            nsPutSendDatagramBuffer();
            LOGERR("Unable to get an internal socket to DD");
            TRCE();
            return NQ_FAIL;
        }
#endif

        res = sySendToSocket (
                    internalSock->socket,
                    (const NQ_BYTE*)msgBuf,
                    (NQ_COUNT)msgLen,
                    &localhost,
                    syHton16(CM_IN_INTERNALDSPORT)
                    );

        putInternalSocketDD(internalSock);
        if (res == NQ_FAIL)
        {
            nsPutSendDatagramBuffer();
            LOGERR("Unable to send Cancel Listen");
            sySetLastError(CM_NBERR_CANCELLISTENFAIL);
        }

    } /* end of if (pSock->isListening) */

    nsPutSendDatagramBuffer();

#endif /* UD_NB_RETARGETSESSIONS */

    if (isBind && pSock->transport == NS_TRANSPORT_NETBIOS)
    {
        /* release the socket name */
        if (NQ_FAIL == nsReleaseName(&pSock->name))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create Name Release Request packet");
            sySetLastError(CM_NBERR_RELEASENAMEFAIL);
            goto Exit;
        }

#ifndef CM_NQ_STORAGE
		/* now release the domain registration */
        if (staticData->domainRegistered)
        {
            CMNetBiosNameInfo domain;

            syStrcpy(domain.name, cmNetBiosGetDomain()->name);
            cmNetBiosNameFormat(domain.name, CM_NB_POSTFIX_WORKSTATION);
            domain.isGroup = TRUE;
            if (NQ_FAIL == nsReleaseName(&domain))
            {
            	LOGERR(CM_TRC_LEVEL_ERROR, "Unable to Release domain name registration.");
                sySetLastError(CM_NBERR_RELEASENAMEFAIL);
            }
        }
#endif /* CM_NQ_STORAGE */
    }
    result = NQ_SUCCESS;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result: %d", result);
    return result;
}

 
/*
 *====================================================================
 * PURPOSE: Resolve host name and get its IP
 *--------------------------------------------------------------------
 * PARAMS:  IN name to resolve
 *
 * RETURNS: IP Address (in NBO) or zero on error
 *
 * NOTES:   This is a "socket-less" call
 *          We resolve a name by sending a Name Query Response to the ND
 *          IP address is returned in Network Byte Order (NBO)
 *          Besides, the group flag is revealed in the name info
 *====================================================================
 */

#ifdef UD_NQ_USETRANSPORTNETBIOS
NQ_STATUS
nsGetHostByName(
    NQ_IPADDRESS *hostIp,
    CMNetBiosNameInfo* destName
    )
{
    NQ_STATUS result = NQ_FAIL;

#ifdef UD_NB_INCLUDENAMESERVICE
    NQ_IPADDRESS zero = CM_IPADDR_ZERO;
    NQ_BYTE* msgBuf;                /* buffer for Name Query Request */
    NQ_INT msgLen;                  /* this message length */
    CMNetBiosAddrEntry addrEntry;   /* buffer for the response */
#else /* UD_NB_INCLUDENAMESERVICE */
    NQ_IPADDRESS4 ip;               /* IP address */
#endif /* UD_NB_INCLUDENAMESERVICE */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "hostIp:%p destName:%p", hostIp, destName);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Trying to resolve NETBIOS name: %s", destName->name);

#ifndef UD_NB_INCLUDENAMESERVICE
    ip = syGetHostByName(destName->name);
    if (ip == 0xFFFFFFFF || ip == SY_ZEROIP4)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid host IP");
        goto Exit;
    }
    else
    {
        CM_IPADDR_ASSIGN4(*hostIp, ip);
        result = NQ_SUCCESS;
        goto Exit;
    }
#else /* UD_NB_INCLUDENAMESERVICE */
    msgBuf = nsGetSendDatagramBuffer();

    *hostIp = zero;

#if SY_DEBUGMODE
     /* Check the passed pointer */
    if (NULL == destName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid host name");
        goto Exit;
    }
#endif /* SY_DEBUGMODE */

    if (destName->name[0] == '*' )
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid host name");
        goto Exit;
    }

    /* generate a Name Query Request */

    if (NQ_FAIL == (msgLen = frameInternalNameQueryRequest((NQ_BYTE*)msgBuf, destName)))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        goto Exit;
    }

    /* send the request and wait for a response */

    if (nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, &addrEntry) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
        goto Exit;
    }

    destName->isGroup = (syNtoh16(cmGetSUint16(addrEntry.flags)) & CM_NB_NAMEFLAGS_G) != 0;
    CM_IPADDR_ASSIGN4( *hostIp, cmGetSUint32(addrEntry.ip));          /* NBO */
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved ip: %s", cmIPDump(hostIp));
#endif /* UD_NB_INCLUDENAMESERVICE */

    result = NQ_SUCCESS;

Exit:
#ifdef UD_NB_INCLUDENAMESERVICE
    nsPutSendDatagramBuffer();
#endif /* UD_NB_INCLUDENAMESERVICE */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}
#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: Get host name by its IP
 *--------------------------------------------------------------------
 * PARAMS:  IN socket to report on
 *          IN IP address
 *          OUT netbios name
 *
 * RETURNS: NQ_SUCCESS on success
 *
 * NOTES:
 *====================================================================
 */

#ifdef UD_NQ_USETRANSPORTNETBIOS

NQ_STATUS
nsGetHostName(
    NQ_IPADDRESS *calledIp,
    CMNetBiosNameInfo* hostName
    )
{
    NQ_IPADDRESS anyIp = CM_IPADDR_ANY4;/* address to bind to */
    SYSocketHandle socket;              /* socket for exchanging datagrams with remote NBNS */
    NQ_COUNT retryCount;                /* number of retries */
    NQ_UINT msgLen;                     /* this message length */
    NQ_UINT16 hostShort;                /* temporary variable */
    NQ_BYTE* questionName;              /* pointer to the target question name */
    CMNetBiosQuestion* questionBody;    /* question entry trailer */
    NQ_COUNT shift;                     /* various shifts in the message */
    SYSocketSet  socketSet;             /* set for reading from this socket */
    CMNetBiosHeader* resHdr = NULL;     /* pointer to the response header */
    CMNetBiosHeader* msgHdr = NULL;     /* pointer to the response header */
    NQ_UINT32 timeOut;                    /* timeout in seconds, may change as the result of a WACK
                                           response */
    NQ_UINT16 savedTranId;              /* transaction ID in the request */
    CMNetBiosName calledName;           /* place "*" into this name */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "calledIp:%p hostName:%p", calledIp, hostName);

    msgHdr = (CMNetBiosHeader*)nsGetSendDatagramBuffer();
    resHdr = (CMNetBiosHeader*)nsGetRecvDatagramBuffer();

    /* allocate a UDP socket  */
    socket = syCreateSocket(FALSE, CM_IPADDR_IPV4);   /* datagram socket */
    if(!syIsValidSocket(socket))      /* error */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create datagram socket");
        goto Exit;
    }

    if(syBindSocket(socket, &anyIp, 0) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to bind datagram socket");
        goto Exit;
    }

#if SY_DEBUGMODE
    /* Check the passed pointer */
    if (NULL == hostName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid host name");
        goto Exit;
    }
#endif

    /* generate a Node Status Query Request */

    hostShort = cmNetBiosGetNextTranId();

    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_NAMEQUERYREQUEST));
    cmPutSUint16(msgHdr->tranID, syHton16(hostShort));
    savedTranId = cmGetSUint16(msgHdr->tranID);

    cmPutSUint16(msgHdr->qdCount, syHton16(1));
    cmPutSUint16(msgHdr->anCount, syHton16(0));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(0));

    /* fill in the question entry */

    questionName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    syMemset(calledName, 0, sizeof(calledName));
    calledName[0] = '*';

    shift = cmNetBiosEncodeName(calledName, questionName);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Illegal name: %s", hostName->name);
        goto Exit;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,  syHton16(CM_NB_RTYPE_NBSTAT));  /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    msgLen = (NQ_UINT)((NQ_BYTE*)(questionBody + 1) - (NQ_BYTE*)msgHdr);

    timeOut = CM_NB_UNICASTREQRETRYTIMEOUT;        /* initial timeout */

    for (retryCount = CM_NB_UNICASTREQRETRYCOUNT; retryCount>0; retryCount--)
    {
        NQ_INT res;                 /* various results */
        NQ_UINT16 codes;            /* response codes */
        NQ_PORT port;               /* response codes */
        NQ_IPADDRESS resIp;         /* response IP */

        /* send message to a remote host */

        res = sySendToSocket(
            socket,
            (const NQ_BYTE*)msgHdr,
            msgLen,
            calledIp,
            syHton16(CM_NB_NAMESERVICEPORT)
            );
        if (NQ_FAIL == res)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send Host Status Request");
            goto Exit;
        }

        /* wait for response */

        syClearSocketSet(&socketSet);
        syAddSocketToSet(socket, &socketSet);

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
            LOGERR(CM_TRC_LEVEL_ERROR, "Select timed out");
            continue;
        }

        /* socket is ready to read from */

        result = syRecvFromSocket(
            socket,
            (NQ_BYTE*)resHdr,
            CM_NB_DATAGRAMBUFFERSIZE,
            &resIp,
            &port
            );
        if (result == 0 || result == NQ_FAIL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Receive error");
            continue;
        }

        /* inspect packet type: response flag, error code */

        codes = syNtoh16(cmGetSUint16(resHdr->packCodes));

        if (!(codes & CM_NB_RESPONSE))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet - not a response");
            continue;
        }

        if ((codes & CM_NB_RCODE_MASK) != CM_NB_RCODE_NOERR)
        {
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Negative response");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " RCODE: %d", codes & CM_NB_RCODE_MASK);
            goto Exit;
        }

        /* proceed by OPCODE */

        codes = codes & (NQ_UINT16)CM_NB_OPCODE;

        if ((codes & CM_NB_OPCODE) == CM_NB_OPCODE_QUERY)
            /* the response match the request - this is a positive response */
        {
            CMNetBiosName    name;          /* called name after parsing */
            NQ_STATIC NQ_CHAR scopeId[255]; /* buffer for parsed scope ID */
            CMNetBiosQuestion* pQuestion;   /* pointer to the question record */
            NQ_BYTE* pData;                 /* pointer to arbitrary data */
            NQ_INT numNames;                /* number of names in the response */

            /* parse the response */

            if (cmGetSUint16(resHdr->tranID) != savedTranId)
            {
                sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected tran ID");
                goto Exit;
            }

            pQuestion = (CMNetBiosQuestion*)cmNetBiosParseName(
                            resHdr,
                            resHdr + 1,
                            name,
                            scopeId,
                            sizeof(scopeId)
                            );

            if (pQuestion == NULL)
            {
                sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing name in the response");
                goto Exit;
            }

            if (syNtoh16(cmGetSUint16(pQuestion->questionType)) != CM_NB_RTYPE_NBSTAT)
            {
                sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                LOGERR(CM_TRC_LEVEL_ERROR, "Unepected question record");
                goto Exit;
            }

            pData = (NQ_BYTE*)(pQuestion + 1);
            pData += 4 + 2;

            for (numNames = *pData++; numNames>0; numNames--)
            {
                /* pData points to the next name */

                if (*(pData + CM_NB_POSTFIXPOSITION) == CM_NB_POSTFIX_SERVER)
                {
                    NQ_UINT16 flags;   /* name flags */

                    flags = cmGetUint16((NQ_UINT16*)(pData + 16));
                    flags = syNtoh16(flags);
                    if ((flags & CM_NB_NAMESTATUS_ACT) != 0)
                    {
                        syStrncpy(hostName->name, (NQ_CHAR*)pData, 16);
                        result = NQ_SUCCESS;
                        goto Exit;
                    }
                }

                pData += 16 + 2;
            }
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unepected question record");
            goto Exit;
        }

        if (codes == CM_NB_OPCODE_WACK)                     /* wait for acknowledge */
        {
            CMNetBiosResourceRecord* rrPtr;  /* resource record in the response */

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "WACK received");

            rrPtr = (CMNetBiosResourceRecord*)cmNetBiosSkipName(resHdr, resHdr + 1);
                                                            /* skip the name */
            if (cmGetSUint32(rrPtr->ttl) != 0)                            /* try to use the recommended timeout */
            {
                timeOut = syNtoh32(cmGetSUint32((NQ_UINT)rrPtr->ttl));
            }
            continue;
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet code");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "opcode: 0x%x", codes);
            continue;
        }

    } /* end for */

    sySetLastError(CM_NBERR_TIMEOUT);
    LOGERR(CM_TRC_LEVEL_ERROR, "Operation timed out");

Exit:
    if (syIsValidSocket(socket))
        syCloseSocket(socket);
    nsPutSendDatagramBuffer();
    nsPutRecvDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: Releases the DNS record for socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket slot
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   if socket is bound, A or AAAA record is cleared from
 *          DNS server.
 *====================================================================
 */

static
NQ_STATUS
releaseDnsName(
    SocketSlot* pSock
    )
{
    NQ_STATUS result = NQ_FAIL;
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pSock:%p", pSock);

    if (!pSock->isBind)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "not bind:%d", pSock->isBind);
        result = NQ_SUCCESS;
        goto Exit;
    }

    switch (pSock->transport)
    {
        case NS_TRANSPORT_NETBIOS:
            result = NQ_SUCCESS;
            break;

#ifdef UD_NQ_USETRANSPORTIPV4
        case NS_TRANSPORT_IPV4:
            if (--ip4Count == 0)
                result = nsDnsClearTargetAddress(NS_DNS_A);
            else
                result = NQ_SUCCESS;
            break;
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
        case NS_TRANSPORT_IPV6:
            if (--ip6Count == 0)
                result = nsDnsClearTargetAddress(NS_DNS_AAAA);
            else
                result = NQ_SUCCESS;
            break;
#endif /* UD_NQ_USETRANSPORTIPV6 */

        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transport used");
            break;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Connect a host by its IP and port
 *--------------------------------------------------------------------
 * PARAMS:  IN socket slot
 *          IN called name
 *          IN called IP    (already in NBO)
 *          IN called port  (already in NBO)
 *          IN current retarget level (recursion depth)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   sends Session Request and processes the response
 *          this function may recursively call itself on Session Retarget
 *====================================================================
 */

static
NQ_STATUS
doConnect(
    SocketSlot* slot,
    CMNetBiosNameInfo* name,
    NQ_IPADDRESS *ip,
    NQ_PORT port,
    NQ_UINT16 level
    )
{
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "slot:%p name:%p ip:%p port:%u level:%u", slot, name, ip, port, level);

    sySetStreamSocketOptions(slot->socket);

#ifdef UD_NQ_USETRANSPORTNETBIOS
    if ((port == syHton16(CM_NB_SESSIONSERVICEPORT)) || ((port != syHton16(CM_NB_SESSIONSERVICEPORTIP)) && level > 0))
    {
        /* limit the number of retargets to 1 by checking the recursion level */
        if (level < 2 && syConnectSocket(slot->socket, ip, port) != NQ_FAIL)
        {
            NQ_UINT16 retries;

            /* send session request & wait for response */
            for (retries = 0; retries < CM_NB_UNICASTREQRETRYCOUNT; retries++)
            {
#ifndef CM_NQ_STORAGE
                SYSocketSet socketSet;     /* read set */
#endif
                NQ_BYTE     buffer[SESSION_BUFFER_SIZE];
                NQ_INT      length, sent;

                if ((length = frameInternalSessionRequest(buffer, name, slot)) <= 0)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Failed to generate a request");
					goto Exit;
                }
                sent = sySendSocket(slot->socket, buffer, (NQ_UINT)length);

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Session request sent - size: %d(%d)", sent, length);

                /* send the Session Request packet to the remote node */
                if (sent > 0)
                {
#ifndef CM_NQ_STORAGE
                    syClearSocketSet(&socketSet);
                    syAddSocketToSet(slot->socket, &socketSet);

                    switch (sySelectSocket(&socketSet, CM_NB_UNICASTREQRETRYTIMEOUT))
                    {
                        case 0:  /* set not changed (no incoming data) - try again */
                            TRC("Select timed out. Retrying...");
                            continue;

                        case NQ_FAIL: /* error the select failed  */
                            TRCERR("Select failed");
                            TRCE();
                            return NQ_FAIL;

                        default: /* data ready for reading */
                            if ((length = syRecvSocket(slot->socket, buffer, SESSION_BUFFER_SIZE)) > 0)
#else
                    if ((length = syRecvSocketWithTimeout(slot->socket, buffer, SESSION_BUFFER_SIZE, CM_NB_UNICASTREQRETRYTIMEOUT)) > 0)
#endif
                    {
                        CMNetBiosSessionRetarget* retarget;
                        CMNetBiosSessionMessage* message;

                        /* process different packets */
                        message = (CMNetBiosSessionMessage*)buffer;
                        switch (message->type)
                        {
                        case CM_NB_POSITIVESESSIONRESPONSE:     /* the work is done */
                            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Success: Positive SSN response of size %d received", length);
                            result = NQ_SUCCESS;
                            goto Exit;

                        case CM_NB_NEGATIVESESSIONRESPONSE:     /* total failure, close connection and fail */
                            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                            LOGERR(CM_TRC_LEVEL_ERROR, "Negative response");
                            goto Exit;

                        case CM_NB_SESSIONRETARGETRESPONSE:     /* close this connection and try with
                                                                    new IP and port by calling this function
                                                                    recursively */
                            retarget = (CMNetBiosSessionRetarget*)buffer;
                            port = (NQ_PORT)cmGetSUint16(retarget->port);                 /* in NBO */
                            CM_IPADDR_ASSIGN4(*ip, cmGetSUint32(retarget->ip));  /* in NBO */

                            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Retargetting to - ip %s", cmIPDump(ip));
                            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Retargetting to - port: %d", syNtoh16(port));

                            syCloseSocket(slot->socket);
                            slot->socket = syCreateSocket(NS_SOCKET_STREAM, CM_IPADDR_IPV4);

                            if (syIsValidSocket(slot->socket))
                            {
                                /* go to the next recursion level */
                                result = doConnect(slot, name, ip, port, (NQ_UINT16)(level + 1));
                                goto Exit;
                            }
                            else
                            {
                                LOGERR(CM_TRC_LEVEL_ERROR, "Unable to re-create socket");
                                goto Exit;
                            }
                        } /* switch (buffer->type) */
                        } /* if (syRecv) */
                        else
                        {
                            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Error: sysRecvfrom() returned %d. Retrying...", length);
                            continue;
                        }
#ifndef CM_NQ_STORAGE
                    } /* switch (sySelect) */
#endif
                }  /* if (sySend) */
                else
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send a message");
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " error: %d", syGetLastError());
                }
            } /* for (retries) */

            sySetLastError(CM_NBERR_TIMEOUT);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect - session response timed out");
        }
        else
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Connect failed");
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " ip - %s", cmIPDump(ip));
        }
    }
#endif 
#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
    if (port == syHton16(CM_NB_SESSIONSERVICEPORTIP))
    {
        if (syConnectSocket(slot->socket, ip, port) == NQ_SUCCESS)
        {
            result = NQ_SUCCESS;
            goto Exit;
        }
    
        LOGERR(CM_TRC_LEVEL_ERROR, "Connect failed");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " ip - %s", cmIPDump(ip));
    }
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Unbind a socket on error by recreating it
 *--------------------------------------------------------------------
 * PARAMS:  IN socket slot
 *
 * RETURNS: Socket descriptor
 *
 * NOTES:   the only way to unbind a socket is to recreate it
 *          we assume that the socket was bound but it is not listening
 *          yet - this assumption is correct in the framework of this
 *          source file
 *====================================================================
 */

#ifdef UD_NQ_USETRANSPORTNETBIOS

static
NQ_STATUS
recreateSocket(
    SocketSlot* pSock
    )
{
    NQ_STATUS sts; /* operation status */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pSock:%p", pSock);

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        goto Exit;
    }
#endif

    sts = syCloseSocket(pSock->socket);
    if (NQ_FAIL == sts)     /* error on close */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to close socket");
        goto Exit;
    }

    /* create the socket in the underlying socket system */

    pSock->socket = syCreateSocket(
            (pSock->type==NS_SOCKET_STREAM),
#ifdef UD_NQ_USETRANSPORTIPV6
            (pSock->transport == NS_TRANSPORT_IPV6) ? CM_IPADDR_IPV6 :
#endif /* UD_NQ_USETRANSPORTIPV6 */
            CM_IPADDR_IPV4);

    if (!syIsValidSocket(pSock->socket))
    {
        putSocketSlot(pSock);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create socket");
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Socket recreated created with fd=%d", pSock->socket);
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */


NQ_IPADDRESS4 cmNetBiosGetWins(NQ_COUNT winsID)
{
    if (winsID > staticData->numServers)
        return 0;

    return CM_IPADDR_GET4(staticData->winsServers[winsID]);
}

NQ_COUNT cmNetBiosGetNumWinsServers(void)
{
    return staticData->numServers;
}

/********************************************************************
 *  Resolver callbacks
 ********************************************************************/

#if defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE)
static 
NQ_STATUS 
    requestByNameWins(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp, 
    NQ_BYTE postfix
    )
{
    NQ_BYTE* msgBuf = NULL;         /* buffer for Name Query Request */
    NQ_INT msgLen;                  /* this message length */
    CMNetBiosNameInfo destName;     /* NetBIOS name */            
    NQ_CHAR * nameA = NULL;         /* server name in ASCII */
    NQ_STATUS result;               /* operation result */
    NQ_STATUS res = NQ_FAIL;        /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d name:%s context:%p serverIp:%p postfix:%d", socket, cmWDump(name), context, serverIp, postfix);

    /* create NetBIOS name */
    nameA = cmMemoryCloneWStringAsAscii(name);
    if (NULL == nameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        goto Exit;
    }
    cmNetBiosNameCreate(destName.name, nameA, postfix);
    destName.isGroup = FALSE;
    cmMemoryFree(nameA);

    msgBuf = nsGetSendDatagramBuffer();

    /* generate a Name Query Request */
    if (NQ_FAIL == (msgLen = frameInternalNameQueryRequest((NQ_BYTE*)msgBuf, &destName)))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        goto Exit;
    }

    /* send the request and wait for a response */
    result = sySendToSocket(socket, (const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, serverIp, syHton16(CM_NB_NAMESERVICEPORT));
    if (result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
    }

    res = (result > 0 ? NQ_SUCCESS : NQ_FAIL);

Exit:
    if (NULL != msgBuf)
        nsPutSendDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;
}

NQ_STATUS nsRequestByNameWinsDC(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{
    NQ_STATUS result;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d name:%s context:%p serverIp:%p", socket, cmWDump(name), context, serverIp);

    result = requestByNameWins(socket, name, context, serverIp, CM_NB_POSTFIX_DOMAINCONTROLLER);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

NQ_STATUS nsRequestByNameWins(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{    
    NQ_STATUS result;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d name:%s context:%p serverIp:%p", socket, cmWDump(name), context, serverIp);

    result = requestByNameWins(socket, name, context, serverIp, CM_NB_POSTFIX_SERVER);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

static
NQ_STATUS requestByNameBcast(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp,
    NQ_BYTE postfix
    )
{
    NQ_BYTE* msgBuf;                /* buffer for Name Query Request */
    NQ_INT msgLen;                  /* this message length */
    CMNetBiosNameInfo destName;     /* NetBIOS name */            
    NQ_CHAR * nameA = NULL;         /* server name in ASCII */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d name:%s context:%p serverIp:%p postfix:%d", socket, cmWDump(name), context, serverIp, postfix);

    msgBuf = nsGetSendDatagramBuffer();

    /* create NetBIOS name */
    nameA = cmMemoryCloneWStringAsAscii(name);
    if (NULL == nameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        goto Exit;
    }
    cmNetBiosNameCreate(destName.name, nameA, postfix);
    cmMemoryFree(nameA);
    destName.isGroup = FALSE;

    /* generate a Name Query Request */
    if (NQ_FAIL == (msgLen = frameInternalNameQueryRequest((NQ_BYTE*)msgBuf, &destName)))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        goto Exit;
    }

    /* send the request and wait for a response */
    if (NQ_FAIL == nsSendRequestToND(socket, (const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
        goto Exit;
    }

    result = NQ_SUCCESS;

Exit:
    nsPutSendDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#ifndef UD_NQ_AVOIDDCRESOLUTIONNETBIOS
NQ_STATUS nsRequestByNameBcastDC(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{
    NQ_STATUS result;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    result = requestByNameBcast(socket, name, context, serverIp, CM_NB_POSTFIX_DOMAINMASTERBROWSER);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}
#endif /* UD_NQ_AVOIDDCRESOLUTIONNETBIOS */

NQ_STATUS nsRequestByNameBcast(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{
    NQ_STATUS result;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    result = requestByNameBcast(socket, name, context, serverIp, CM_NB_POSTFIX_SERVER);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d",result);
    return result;
}

NQ_STATUS nsResponseByName(
    SYSocketHandle socket, 
    NQ_IPADDRESS ** pAddressArray, 
    NQ_INT * numIps, 
    void ** pContext
    )
{
    CMNetBiosAddrEntry addrEntry;   /* buffer for the response */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d pAddressArray:%p pNumIps:%p pContext:%p", socket, pAddressArray, numIps, pContext);

    *pAddressArray = NULL;
    if (nsReceiveResponseFromND(socket, &addrEntry) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
        goto Exit;
    }

    *pAddressArray = (NQ_IPADDRESS *)cmMemoryAllocate(sizeof(NQ_IPADDRESS));
    if (NULL == *pAddressArray)
    {
        sySetLastError(CM_NBERR_INTERNALERROR);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate IP buffer");
        goto Exit;
    }

    /* NBO */
    CM_IPADDR_ASSIGN4(**pAddressArray, cmGetSUint32(addrEntry.ip));
    *numIps = 1;
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d, numIPs: %d", result, *numIps);
    return result;
}

NQ_STATUS nsRequestByIp(
    SYSocketHandle socket, 
    const NQ_IPADDRESS * ip, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{
    NQ_UINT msgLen;                     /* this message length */
    NQ_UINT16 hostShort;                /* temporary variable */
    NQ_BYTE* questionName;              /* pointer to the target question name */
    CMNetBiosQuestion* questionBody;    /* question entry trailer */
    NQ_COUNT shift;                     /* various shifts in the message */
    CMNetBiosHeader* msgHdr;            /* pointer to the request header */
    CMNetBiosName calledName;           /* place "*" into this name */
    NQ_STATUS result = NQ_FAIL;         /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d ip:%p context:%p serverIp:%p", socket, ip, context, serverIp);

    msgHdr = (CMNetBiosHeader*) nsGetSendDatagramBuffer();

    /* generate a Node Status Query Request */
    hostShort = cmNetBiosGetNextTranId();

    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_NAMEQUERYREQUEST));
    cmPutSUint16(msgHdr->tranID, syHton16(hostShort));

    cmPutSUint16(msgHdr->qdCount, syHton16(1));
    cmPutSUint16(msgHdr->anCount, syHton16(0));
    cmPutSUint16(msgHdr->nsCount, syHton16(0));
    cmPutSUint16(msgHdr->arCount, syHton16(0));

    /* fill in the question entry */

    questionName = (NQ_BYTE*) (msgHdr + 1);   /* question entry goes just after the header */

    syMemset(calledName, 0, sizeof(calledName));
    calledName[0] = '*';

    shift = cmNetBiosEncodeName(calledName, questionName);
    if (shift <= 0)
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode name - illegal name: %s", calledName);
        goto Exit;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,  syHton16(CM_NB_RTYPE_NBSTAT));  /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    msgLen = (NQ_UINT)((NQ_BYTE*)(questionBody + 1) - (NQ_BYTE*)msgHdr);

    result = sySendToSocket(socket, (const NQ_BYTE*)msgHdr, (NQ_UINT)msgLen, ip, syHton16(CM_NB_NAMESERVICEPORT));
    if (NQ_FAIL == result)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
    }

    result = ( result >= 0 ? NQ_SUCCESS : NQ_FAIL );

Exit:
    nsPutSendDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

NQ_STATUS nsResponseByIp(
    SYSocketHandle socket, 
    const NQ_WCHAR ** pName, 
    void ** pContext
    )
{
    CMNetBiosHeader* resHdr;            /* pointer to the response header */
    NQ_INT res;                         /* various results */
    NQ_UINT16 codes;                    /* response codes */
    NQ_PORT port;                       /* response port */
    NQ_IPADDRESS resIp;                 /* response IP */
    NQ_STATUS result = NQ_FAIL;         /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "socket:%d pName:%p pContext:%p", socket, pName, pContext);

    resHdr = (CMNetBiosHeader*)nsGetRecvDatagramBuffer();

    res = syRecvFromSocket(
        socket,
        (NQ_BYTE*)resHdr,
        CM_NB_DATAGRAMBUFFERSIZE,
        &resIp,
        &port
        );

    if (0 == res || NQ_FAIL == res)
    {
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to receive response");
        goto Exit;
    }

    /* inspect packet type: response flag, error code */
    codes = syNtoh16(cmGetSUint16(resHdr->packCodes));

    if (!(codes & CM_NB_RESPONSE))
    {
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
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

    if ((codes & CM_NB_OPCODE) == CM_NB_OPCODE_QUERY)
        /* the response match the request - this is a positive response */
    {
        CMNetBiosName    name;          /* called name after parsing */
        NQ_CHAR scopeId[255]; 			/* buffer for parsed scope ID */
        CMNetBiosQuestion* pQuestion;   /* pointer to the question record */
        NQ_BYTE* pData;                 /* pointer to arbitrary data */
        NQ_INT numNames;                /* number of names in the response */

        /* parse the response */
        pQuestion = (CMNetBiosQuestion*)cmNetBiosParseName(
                        resHdr,
                        resHdr + 1,
                        name,
                        scopeId,
                        sizeof(scopeId)
                        );
        if (pQuestion == NULL)
        {
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing name in the response");
            goto Exit;
        }

        if (syNtoh16(cmGetSUint16(pQuestion->questionType)) != CM_NB_RTYPE_NBSTAT)
        {
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected question record");
            goto Exit;
        }

        pData = (NQ_BYTE*)(pQuestion + 1);
        pData += 4 + 2;

        for (numNames = *pData++; numNames>0; numNames--)
        {
            /* pData points to the next name */
            if (*(pData + CM_NB_POSTFIXPOSITION) == CM_NB_POSTFIX_SERVER)
            {
                NQ_UINT16 flags;   /* name flags */

                flags = cmGetUint16((NQ_UINT16*)(pData + 16));
                flags = syNtoh16(flags);
                if ((flags & CM_NB_NAMESTATUS_ACT) != 0)
                {
                    /* netbios name */
                    CMNetBiosName nbName;
                    NQ_INT* num;

                    syStrncpy(nbName, (NQ_CHAR*)pData, 16);
                    cmNetBiosNameClean(nbName);
                    *pName = cmMemoryCloneAString(nbName);

                    if (NULL != *pName)
                    {
                    	result = NQ_SUCCESS;

                    	result = ( NULL != *pName? NQ_SUCCESS : NQ_ERR_NOMEM );
                    	*pContext = num = (NQ_INT *)cmMemoryAllocate(sizeof(num));
                        if (NULL == num)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                            res = NQ_ERR_NOMEM;
                            goto Exit;
                        }
                        *num = 1;
                    }
                    else
                    {
                    	result = NQ_ERR_NOMEM;
                    }
                    goto Exit;
                }
            }
            pData += 16 + 2;
        }

        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        goto Exit;
    }

    if (codes == CM_NB_OPCODE_WACK)                     /* wait for acknowledge */
    {
        sySetLastError(CM_NBERR_TIMEOUT);
        LOGERR(CM_TRC_LEVEL_ERROR, "WACK received");
    }
    else
    {
        sySetLastError(CM_NBERR_TIMEOUT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet code: opcode: 0x%x", codes);
    }

Exit:
    nsPutRecvDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

static void parseServerList(NQ_WCHAR * list)
{
    CMResolverMethodDescriptor method;                      /* next method descriptor */
    NQ_WCHAR * curServer;                                   /* pointer to the current server IP */
    NQ_WCHAR * nextServer;                                  /* pointer to the next server IP */
    NQ_CHAR aServer[CM_IPADDR_MAXLEN];                      /* the same in ASCII */

    method.type = NQ_RESOLVER_NETBIOS;
    method.isMulticast = FALSE;  /* unicast */
    method.activationPriority = 2;
    method.timeout.low = 1000; /* milliseconds */
    method.timeout.high = 0;   /* milliseconds */
    method.waitAnyway = TRUE;
    method.requestByName = nsRequestByNameWins;
    method.responseByName = nsResponseByName;
    method.requestByIp = nsRequestByIp;
    method.responseByIp = nsResponseByIp;

    /* parse servers string */
    for (curServer = list, staticData->numServers = 0;
        staticData->numServers < sizeof(staticData->winsServers) / sizeof(staticData->winsServers[0]);
        curServer = nextServer + 1
        )
    {
        NQ_STATUS res;                      /* operation status */
        NQ_IPADDRESS ip;                    /* next IP */

        nextServer = cmWStrchr(curServer, cmWChar(';'));
        if (NULL != nextServer)
        {
            *nextServer = cmWChar('\0');
        }
        if (cmWStrlen(curServer) < CM_IPADDR_MAXLEN)
        {
        	cmUnicodeToAnsiN(aServer, curServer, CM_IPADDR_MAXLEN * 2);
            res = cmAsciiToIp(aServer, &ip);
            if (NQ_SUCCESS == res)
            {
            	staticData->winsServers[staticData->numServers] = ip;
                /* register WINS with Resolver */
            	if (TRUE == cmResolverRegisterMethod(&method, &staticData->winsServers[staticData->numServers]))
            		staticData->numServers++;
            }
        }

        if (NULL == nextServer)
            break;
    }
}

void cmNetBiosSetWinsA(const NQ_CHAR * servers)
{
    const NQ_WCHAR * serversW;      /* unicode copy */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "servers:%s", servers ? servers : "");

    if (NULL == servers)
    {
        cmNetBiosSetWinsW(NULL);
        goto Exit;
    }
    serversW = cmMemoryCloneAString(servers);
    if (NULL != serversW)
        cmNetBiosSetWinsW(serversW);
    cmMemoryFree(serversW);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void cmNetBiosSetWinsW(const NQ_WCHAR * servers)
{
    NQ_INT idx;                             /* index in servers */
    CMResolverMethodDescriptor descriptor;  /* method descriptor */
    NQ_WCHAR * aCopy;                       /* server list copy */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "servers:%s", cmWDump(servers));

    /* remove per WINS server methods */
    descriptor.type = NQ_RESOLVER_NETBIOS;  /* only type and multicast flag are required */
    descriptor.isMulticast = FALSE;

    for (idx = 0; idx < (NQ_INT)staticData->numServers; idx++)
    {
        cmResolverRemoveMethod(&descriptor, &staticData->winsServers[idx]);
    }
    if (NULL == servers || 0 == syWStrlen(servers))
    {
        staticData->numServers = 0;
        goto Exit;
    }
    aCopy = cmMemoryCloneWString(servers);
    if (NULL != aCopy)
    {
        parseServerList(aCopy);
        cmMemoryFree(aCopy);
    }
    nsRefreshNetBios(servers);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void ndSetWinsW(const NQ_WCHAR * servers)
{
    NQ_INT idx;                             /* index in servers */
    CMResolverMethodDescriptor descriptor;  /* method descriptor */
    NQ_WCHAR * aCopy;                       /* server list copy */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "servers:%s", cmWDump(servers));

    /* remove per WINS server methods */
    descriptor.type = NQ_RESOLVER_NETBIOS;  /* only type and multicast flag are required */
    descriptor.isMulticast = FALSE;

    for (idx = 0; idx < (NQ_INT)staticData->numServers; idx++)
    {
        cmResolverRemoveMethod(&descriptor, &staticData->winsServers[idx]);
    }
    if (NULL == servers || 0 == syWStrlen(servers))
    {
        staticData->numServers = 0;
        goto Exit;
    }
    aCopy = cmMemoryCloneWString(servers);
    if (NULL != aCopy)
    {
        parseServerList(aCopy);
        cmMemoryFree(aCopy);
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


void nsRefreshNetBios(const NQ_WCHAR * servers)
{
	NQ_BYTE*   	msgBuf;             /* buffer for INTERNALREFRESHLIST REQUEST message */
	NQ_UINT		msgLen = 0;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "servers:%s", cmWDump(servers));

	msgBuf = nsGetSendDatagramBuffer();

	cmPutSUint16(((CMNetBiosHeader*)msgBuf)->tranID, syHton16(cmNetBiosGetNextTranId()));
	cmPutSUint16(((CMNetBiosHeader*)msgBuf)->qdCount, syHton16(1));
	cmPutSUint16(((CMNetBiosHeader*)msgBuf)->anCount, syHton16(0));
	cmPutSUint16(((CMNetBiosHeader*)msgBuf)->nsCount, syHton16(0));
	cmPutSUint16(((CMNetBiosHeader*)msgBuf)->arCount, syHton16(1));
	cmPutSUint16(((CMNetBiosHeader*)msgBuf)->packCodes, syHton16(CM_NB_INTERNALREFRESHLIST));

	/* send the request and wait for a response */
	syMemcpy(msgBuf+sizeof(CMNetBiosHeader) , servers , (syWStrlen(servers) + 1) * sizeof(NQ_WCHAR));
	msgLen = (NQ_UINT)(sizeof(CMNetBiosHeader) + (syWStrlen(servers) + 1) * sizeof(NQ_WCHAR));
	if (nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, NULL) == NQ_FAIL)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to refresh the name");
	}
	nsPutSendDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#endif /* defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE) */
