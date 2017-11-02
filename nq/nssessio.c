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
                       params - this is the only way to unbind a socket on error */
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
    TRCB();
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate socket pool");
        TRCE();
        return NQ_FAIL;
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
    TRCE();
    return NQ_SUCCESS;
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
    TRCB();
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    TRCE();
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
    CMNetBiosNameInfo nameWrkst;
    CMNetBiosNameInfo nameSrv;

    nameWrkst.isGroup = FALSE;
    cmNetBiosNameCreate(nameWrkst.name, name, CM_NB_POSTFIX_WORKSTATION);
    if (nsRegisterName(&nameWrkst) == NQ_FAIL)
    {
        return NQ_FAIL;
    }   
    
    nameSrv.isGroup = FALSE;
    cmNetBiosNameCreate(nameSrv.name, name, CM_NB_POSTFIX_WORKSTATION);    
    if (nsRegisterName(&nameSrv) == NQ_FAIL)
    {
        nsReleaseName(&nameWrkst);
        return NQ_FAIL;
    }
    return NQ_SUCCESS;
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

    TRCB();

    /* check parameters */

#if SY_DEBUGMODE
    switch (type)
    {
    case NS_SOCKET_DATAGRAM:
    case NS_SOCKET_STREAM:
        break;
    default:
        TRCERR("Unknown socket type");
        TRC1P(" value %i", type);
        TRCE();
        return NULL;
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
        TRCERR("Unknown socket transport");
        TRC1P(" value %i", transport);
        TRCE();
        return NULL;
    }
#endif

    /* allocate and initalize a socket descriptor */

    if ((pSock=getSocketSlot()) == NULL)        /* Get a slot for socket info */
    {
        sySetLastError(CN_NBERR_SOCKETOVERFLOW);    /* no more slots */

        TRCERR("Unable to allocate socket slot");
        TRCE();
        return NULL;
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

        TRCERR("Unable to create socket");
        TRCE();
        return NULL;
    }

    TRC1P("Created NS socket %d", pSock->socket);

    /* fill initial socket information */

    pSock->transport = transport;
    pSock->isListening = FALSE;
    pSock->port = 0;
    pSock->type = type;
    pSock->isBind = FALSE;

    /* set the default caller name to the own NETBIOS name */
    cmNetBiosNameCopy(pSock->name.name, cmNetBiosGetHostNameInfo()->name);
    cmNetBiosNameFormat(pSock->name.name, CM_NB_POSTFIX_WORKSTATION);

    cmNetBiosNameCopy(pSock->remoteName.name, cmNetBiosGetEmptyName());

    pSock->name.isGroup = FALSE;
    pSock->remoteName.isGroup = FALSE;

    TRC2P("Socket created with fd=%d, type=%s", pSock->socket, (type==NS_SOCKET_STREAM)?"stream":"datagram");

    TRCE();
    return  pSock;
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
    NQ_STATUS res;         /* return value */
    SocketSlot* pSock;  /* the same as sockHandle but properly casted */

    TRCB();

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
    }
#endif

    pSock->isNetBios = FALSE;   /* Not NB socket */

    res = syBindSocket(pSock->socket, ip, port);
    if (res==NQ_FAIL)
    {
        syCloseSocket(pSock->socket);
        TRCERR("Unable to bind socket");
        TRCE();
        return NQ_FAIL;
    }

    /* for a case when port was zero (dynamically allocated port) - get socket port
       number by reading the value from the underlying socket layer */

    syGetSocketPortAndIP(pSock->socket, &pSock->ip, &pSock->port);
    if (pSock->port == 0)
    {
        TRCERR("Unable to obtain a dynamically bind port");
        TRCE();
        return NQ_FAIL;
    }

    pSock->isBind = TRUE;

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
    /* register all host addresses in DNS servers */
    if (nsDnsSetTargetAddresses() != NQ_SUCCESS)
    {
        TRCERR("Unable to update DNS record");
    }
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();
    TRC1P("name = %s", name->name);
    
    if (!cmNetBiosCheckName(name) )                     /* valid NetBIOS name? */
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Not a NetBIOS name");
        TRCE();
        return NQ_FAIL;
    }
    /* we assume that the name is not registered yet
       we generate a NAME REGISTRATION PACKET for registration with the ND */

    msgBuf = nsGetSendDatagramBuffer();
    if ((msgLen = frameInternalNameRegistrationRequest((NQ_BYTE*)msgBuf, name)) == NQ_FAIL)
    {
        nsPutSendDatagramBuffer();
        TRCERR("Unable to generate Name Registration Request");
        TRCE();
        return NQ_FAIL;
    }

    /* send the request and wait for a response */

    if (nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, NULL) == NQ_FAIL)
    {
        nsPutSendDatagramBuffer();
        TRCERR("ND failed to register the name");
        TRCE();
        return NQ_FAIL;
    }

    nsPutSendDatagramBuffer();

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();
    TRC1P("name = %s", name->name);
    
    /* allocate buffer for Name Release Request */

    msgBuf = nsGetSendDatagramBuffer();

    if (   (msgLen = frameInternalNameReleaseRequest((NQ_BYTE*)msgBuf, name)) == NQ_FAIL
        || nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, NULL) == NQ_FAIL
       )
     {
         sySetLastError(CM_NBERR_RELEASENAMEFAIL);
         nsPutSendDatagramBuffer();

         TRCERR("Unable to create Name Release Request packet");
         TRCE();
         return NQ_FAIL;
     }

     nsPutSendDatagramBuffer();

     TRCE();
     return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Bind a socket to a NetBIOS name
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN NetBIOS name
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
      const CMNetBiosNameInfo* localName
      )
{
    NQ_IPADDRESS anyIp = CM_IPADDR_ANY4;
    SocketSlot*        pSock;      /* the same as sockHandle but properly casted */
    NQ_STATUS          result;     /* result of socket operations */

    TRCB();

    pSock = (SocketSlot*)sockHandle;

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
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
    result = syBindSocket(pSock->socket, &anyIp, 0);
#else
    result = syBindSocket(pSock->socket, &anyIp, (NQ_PORT)((pSock->type == NS_SOCKET_DATAGRAM) ? 0 : syHton16(CM_IN_SESSIONSERVICEPORT)));
#endif

    if (result == NQ_FAIL)
    {
        syCloseSocket(pSock->socket);
        TRCERR("Unable to bind");
        TRCE();
        return NQ_FAIL;
    }
    if (NQ_FAIL == nsRegisterName(localName))
    {
        if (syGetLastError() != CM_NBERR_NEGATIVERESPONSE && syGetLastError() != CM_NBERR_TIMEOUT)
        {
            recreateSocket(pSock);
            TRCERR("Unable to generate Name Registration Request");
            TRCE();
            return NQ_FAIL;
        }
        TRCERR(" Name Registration Failed");

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
        TRCERR("Unable to obtain a dynamically bind port");
        TRCE();
        return NQ_FAIL;
    }

    pSock->isBind = TRUE;

    TRC2P("Socket %d bound to name: %s", pSock->socket, pSock->name.name);

    TRCE();
    return NQ_SUCCESS;
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
    SocketSlot* pSock;      /* the same as sockHandle but properly casted */
    NQ_STATUS res;          /* operation result */

    TRCB();

    pSock = (SocketSlot*)sockHandle;

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
    }
#endif

    /* check parameters */

    if (pSock->transport == NS_TRANSPORT_NETBIOS && !cmNetBiosCheckName(calledName)) /* valid netBIOS name? */
    {
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Not a NetBIOS name");
        TRCE();
        return NQ_FAIL;
    }

    pSock->isNetBios = TRUE;   /* is an NB socket */

    switch (pSock->transport)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
        case NS_TRANSPORT_NETBIOS:
            TRC("NS_TRANSPORT_NETBIOS, port 139");
            res = doConnect(pSock, calledName, ip, syHton16(CM_NB_SESSIONSERVICEPORT), 0);
            break;
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
        case NS_TRANSPORT_IPV4:
        case NS_TRANSPORT_IPV6:
            TRC("NS_TRANSPORT_IPV4, port 445");
            res = doConnect(pSock, calledName, ip, syHton16(CM_NB_SESSIONSERVICEPORTIP), 0);
            break;
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

      default:
        sySetLastError(CM_NBERR_INVALIDPARAMETER);
        TRCERR("Invalid transport value");
        TRCE();
        return NQ_FAIL;
    }

    /* copy the remote name and ip */
    syMemcpy(&pSock->remoteName, calledName, sizeof(*calledName));
    pSock->remoteIP = *ip;

    /* determine self IP address */

    syGetSocketPortAndIP(pSock->socket, &pSock->ip, &pSock->port);

    TRCE();
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

    TRCB();

    if (sockHandle == NULL)
    {
        TRCERR("Socket handle is NULL");
        TRCE();
        return NQ_FAIL;
    }

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRC1P("slot: %p", pSock);
        if (pSock != NULL)
        {
            TRC1P("socket: %d", pSock->socket);
        }
        TRCE();
        return NQ_FAIL;
    }
#endif

    if (releaseDnsName(pSock) != NQ_SUCCESS)
    {
        TRCERR("Unable to clear DNS record");
    }

    isBind = pSock->isBind;

    TRC1P("Closing socket %d", pSock->socket);

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

            TRCERR("Unable to create Cancel Listen packet");
            TRCE();
            return NQ_FAIL;
        }

        /* send the Cancel Listen packet to the DD  */

        internalSock = getInternalSocketDD();   /* should never fail but may block the task */
#if SY_DEBUGMODE
        if (internalSock==NULL || !syIsValidSocket(internalSock->socket))
        {
            if (internalSock != NULL)
                putInternalSocketDD(internalSock);
            nsPutSendDatagramBuffer();
            TRCERR("Unable to get an internal socket to DD");
            TRCE();
            return NQ_FAIL;
        }
#endif

        res = sySendToSocket (
                    internalSock->socket,
                    (const NQ_BYTE*)msgBuf,
                    msgLen,
                    &localhost,
                    syHton16(CM_IN_INTERNALDSPORT)
                    );

        putInternalSocketDD(internalSock);

        if (res == NQ_FAIL)
        {
            nsPutSendDatagramBuffer();
            TRCERR("Unable to send Cancel Listen");
            TRCE();
            return NQ_FAIL;
        }

    } /* end of if (pSock->isListening) */

    nsPutSendDatagramBuffer();

#endif /* UD_NB_RETARGETSESSIONS */

    if (isBind && pSock->transport == NS_TRANSPORT_NETBIOS)
    {
        /* release the socket name */

        if (NQ_FAIL == nsReleaseName(&pSock->name))
        {
            sySetLastError(CM_NBERR_RELEASENAMEFAIL);

            TRCERR("Unable to create Name Release Request packet");
            TRCE();
            return NQ_FAIL;
        }
    }

    /* release socket descriptor */

    TRCE();
    return NQ_SUCCESS;
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
#ifdef UD_NB_INCLUDENAMESERVICE
    NQ_IPADDRESS zero = CM_IPADDR_ZERO;
    NQ_BYTE* msgBuf;                /* buffer for Name Query Request */
    NQ_INT msgLen;                  /* this message length */
    CMNetBiosAddrEntry addrEntry;   /* buffer for the response */
#else
    NQ_IPADDRESS4 ip;               /* ip address */
#endif

    TRCB();

    TRC1P("Trying to resolve NETBIOS name: %s", destName->name);

#ifndef UD_NB_INCLUDENAMESERVICE
    ip = syGetHostByName(destName->name);
    if (ip == 0xFFFFFFFF || ip == SY_ZEROIP4)
    {
        TRCERR("Invalid host IP");
        TRCE();
        return NQ_FAIL;
    }
    else
    {
        CM_IPADDR_ASSIGN4(*hostIp, ip);
        TRCE();
        return NQ_SUCCESS;
    }
#else /* UD_NB_INCLUDENAMESERVICE */

    *hostIp = zero;

#if SY_DEBUGMODE

     /* Check the passed pointer */

    if (destName == NULL)
    {
        TRCERR("Invalid host name");
        TRCE();
        return NQ_FAIL;
    }
#endif

    if (destName->name[0] == '*' )
    {
       TRCERR("Invalid host name");
       TRCE();
       return NQ_FAIL;
    }

    msgBuf = nsGetSendDatagramBuffer();

    /* generate a Name Query Request */

    if (NQ_FAIL == (msgLen = frameInternalNameQueryRequest((NQ_BYTE*)msgBuf, destName)))
    {
        nsPutSendDatagramBuffer();

        TRCERR("Unable to generate Name Query Request");
        TRCE();
        return NQ_FAIL;
    }

    /* send the request and wait for a response */

    if (nsProceedRequestToND((const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, &addrEntry) == NQ_FAIL)
    {
        nsPutSendDatagramBuffer();

        TRCERR("ND failed to resolve the name");
        TRCE();

        return NQ_FAIL;
    }

    nsPutSendDatagramBuffer();

    destName->isGroup = (syNtoh16(cmGetSUint16(addrEntry.flags)) & CM_NB_NAMEFLAGS_G) != 0;
    CM_IPADDR_ASSIGN4( *hostIp, cmGetSUint32(addrEntry.ip));          /* NBO */
    TRC("Resolved ip: %s", cmIPDump(hostIp));
    TRCE();
    return NQ_SUCCESS;
#endif /* UD_NB_INCLUDENAMESERVICE */
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
    CMNetBiosHeader* resHdr;            /* pointer to the response header */
    CMNetBiosHeader* msgHdr;            /* pointer to the response header */
    NQ_TIME timeOut;                    /* timeout in seconds, may change as the result of a WACK
                                           response */
    NQ_UINT16 savedTranId;              /* transaction ID in the request */
    CMNetBiosName calledName;           /* place "*" into this name */

    TRCB();

#if SY_DEBUGMODE

    /* Check the passed pointer */

    if (hostName == NULL)
    {
        TRCERR("Invalid host name");
        TRCE();
        return NQ_FAIL;
    }
#endif

    msgHdr = (CMNetBiosHeader*) nsGetSendDatagramBuffer();

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
        nsPutSendDatagramBuffer();

        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        TRCERR("Unable to encode name");
        TRC1P("Illegal name: %s", hostName->name);
        TRCE();
        return NQ_FAIL;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,  syHton16(CM_NB_RTYPE_NBSTAT));  /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    msgLen = (NQ_UINT)((NQ_BYTE*)(questionBody + 1) - (NQ_BYTE*)msgHdr);

    /* allocate a UDP socket  */

    socket = syCreateSocket(FALSE, CM_IPADDR_IPV4);   /* datagram socket */
    if(!syIsValidSocket(socket))      /* error */
    {
        nsPutSendDatagramBuffer();
        TRCERR("Unable to create datagram socket");
        TRCE();
        return NQ_FAIL;
    }

    if(syBindSocket(socket, &anyIp, 0) == NQ_FAIL)
    {
        nsPutSendDatagramBuffer();
        syCloseSocket(socket);
        TRCERR("Unable to bind datagram socket");
        TRCE();
        return NQ_FAIL;
    }

    resHdr = (CMNetBiosHeader*)nsGetRecvDatagramBuffer();

    timeOut = CM_NB_UNICASTREQRETRYTIMEOUT;        /* initial timeout */

    for (retryCount = CM_NB_UNICASTREQRETRYCOUNT; retryCount>0; retryCount--)
    {
        NQ_INT result;              /* various results */
        NQ_UINT16 codes;            /* reponse codes */
        NQ_PORT port;               /* reponse codes */
        NQ_IPADDRESS resIp;         /* reposen IP */

        /* send message to a remote host */

        result = sySendToSocket(
            socket,
            (const NQ_BYTE*)msgHdr,
            msgLen,
            calledIp,
            syHton16(CM_NB_NAMESERVICEPORT)
            );
        if (result == NQ_FAIL)
        {
            syCloseSocket(socket);
            nsPutSendDatagramBuffer();
            nsPutRecvDatagramBuffer();

            TRCERR("Unable to send Host Status Request");
            TRCE();
            return NQ_FAIL;
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
            syCloseSocket(socket);
            nsPutSendDatagramBuffer();
            nsPutRecvDatagramBuffer();

            TRCERR("Error during select. Unable to read from ND");
            TRCE();
            return NQ_FAIL;
        }

        if (result == 0)                /* timeout  */
        {
            TRC("Select timed out");
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
            TRCERR("Receive error");
            continue;
        }

        /* inspect packet type: response flag, error code */

        codes = syNtoh16(cmGetSUint16(resHdr->packCodes));

        if (!(codes & CM_NB_RESPONSE))
        {
            TRCERR("Unexpected packet - not a response");
            continue;
        }

        if ((codes & CM_NB_RCODE_MASK) != CM_NB_RCODE_NOERR)
        {
            syCloseSocket(socket);
            nsPutSendDatagramBuffer();
            nsPutRecvDatagramBuffer();

            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            TRCERR("Negative response");
            TRC1P(" RCODE: %d", codes & CM_NB_RCODE_MASK);
            TRCE();
            return NQ_FAIL;
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
                syCloseSocket(socket);
                nsPutSendDatagramBuffer();
                nsPutRecvDatagramBuffer();

                sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                TRCERR("Unexpected tran ID");
                TRCE();
                return NQ_FAIL;
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
                syCloseSocket(socket);
                nsPutSendDatagramBuffer();
                nsPutRecvDatagramBuffer();

                sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                TRCERR("Error parsing name in the response");
                TRCE();
                return NQ_FAIL;
            }

            if (syNtoh16(cmGetSUint16(pQuestion->questionType)) != CM_NB_RTYPE_NBSTAT)
            {
                syCloseSocket(socket);
                nsPutSendDatagramBuffer();
                nsPutRecvDatagramBuffer();

                sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                TRCERR("Unepected question record");
                TRCE();
                return NQ_FAIL;
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
                        syCloseSocket(socket);
                        nsPutSendDatagramBuffer();
                        nsPutRecvDatagramBuffer();

                        TRCE();
                        return NQ_SUCCESS;
                    }
                }

                pData += 16 + 2;
            }

            syCloseSocket(socket);
            nsPutSendDatagramBuffer();
            nsPutRecvDatagramBuffer();

            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            TRCERR("Unepected question record");
            TRCE();
            return NQ_FAIL;
        }

        if (codes == CM_NB_OPCODE_WACK)                     /* wait for acknowledge */
        {
            CMNetBiosResourceRecord* rrPtr;  /* resource record in the response */

            TRC("WACK received");

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
            TRCERR("Unexpected packet code");
            TRC1P("opcode: 0x%x", codes);
            continue;
        }

    } /* end for */

    syCloseSocket(socket);
    nsPutSendDatagramBuffer();
    nsPutRecvDatagramBuffer();

    sySetLastError(CM_NBERR_TIMEOUT);
    TRCERR("Operation timed out");
    TRCE();

    return NQ_FAIL;
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
    if (!pSock->isBind)
        return NQ_SUCCESS;

    switch (pSock->transport)
    {
        case NS_TRANSPORT_NETBIOS:
            return NQ_SUCCESS;

#ifdef UD_NQ_USETRANSPORTIPV4
        case NS_TRANSPORT_IPV4:
            if (--ip4Count == 0)
                return nsDnsClearTargetAddress(NS_DNS_A);
            else
                return NQ_SUCCESS;
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
        case NS_TRANSPORT_IPV6:
            if (--ip6Count == 0)
                return nsDnsClearTargetAddress(NS_DNS_AAAA);
            else
                return NQ_SUCCESS;
#endif /* UD_NQ_USETRANSPORTIPV6 */

        default:
            TRCERR("Invalid transport used");
            return NQ_FAIL;
    }
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
    TRCB();

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
                SYSocketSet socketSet;     /* read set */
                NQ_BYTE     buffer[SESSION_BUFFER_SIZE];
                NQ_INT      length = frameInternalSessionRequest(buffer, name, slot);
                NQ_INT      sent = sySendSocket(slot->socket, buffer, (NQ_UINT)length);

                TRC2P("Session request sent - size: %d(%d)", sent, length);

                /* send the Session Request packet to the remote node */
                if (sent > 0)
                {
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
                            {
                                CMNetBiosSessionRetarget* retarget;
                                CMNetBiosSessionMessage* message;
                                
                                /* process different packets */
                                message = (CMNetBiosSessionMessage*)buffer;
                                switch (message->type)
                                {
                                    case CM_NB_POSITIVESESSIONRESPONSE:     /* the work is done */
                                        TRC1P("Success: Positive SSN response of size %d received", length);
                                        TRCE();
                                        return NQ_SUCCESS;

                                    case CM_NB_NEGATIVESESSIONRESPONSE:     /* total failure, close connection and fail */
                                        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
                                        TRCERR("Negative response");
                                        TRCE();
                                        return NQ_FAIL;

                                    case CM_NB_SESSIONRETARGETRESPONSE:     /* close this connection and try with
                                                                               new IP and port by calling this function
                                                                               recursively */
                                        retarget = (CMNetBiosSessionRetarget*)buffer;
                                        port = (NQ_PORT)cmGetSUint16(retarget->port);                 /* in NBO */
                                        CM_IPADDR_ASSIGN4(*ip, cmGetSUint32(retarget->ip));  /* in NBO */

                                        TRC1P("Retargetting to - ip %s", cmIPDump(ip));
                                        TRC1P("Retargetting to - port: %d", syNtoh16(port));

                                        syCloseSocket(slot->socket);
                                        slot->socket = syCreateSocket(NS_SOCKET_STREAM, CM_IPADDR_IPV4);

                                        if (syIsValidSocket(slot->socket))
                                        {
                                            /* go to the next recursion level */
                                            NQ_STATUS res = doConnect(slot, name, ip, port, (NQ_UINT16)(level + 1));
                                            TRCE();
                                            return res;
                                        }
                                        else
                                        {
                                            TRCERR("Unable to re-create socket");
                                            TRCE();
                                            return NQ_FAIL;
                                        }
                                } /* switch (buffer->type) */
                            } /* if (syRecv) */
                            else
                            {
                                TRC1P("Error: sysRecvfrom() returned %d. Retrying...", length);
                                continue;
                            }
                    } /* switch (sySelect) */
                }  /* if (sySend) */
                else
                {
                    TRCERR("Failed to send a message");
                    TRC1P(" error: %d", syGetLastError());
                }
            } /* for (retries) */


            sySetLastError(CM_NBERR_TIMEOUT);
            TRCERR("Unable to connect - session response timed out");
        }
        else
        {
            TRCERR("Connect failed");
            TRC1P(" ip - %s", cmIPDump(ip));
        }
    }
#endif 
#if defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6)
    if (port == syHton16(CM_NB_SESSIONSERVICEPORTIP))
    {
        if (syConnectSocket(slot->socket, ip, port) == NQ_SUCCESS)
        {
            TRCE();
            return NQ_SUCCESS;
        }
    
        TRCERR("Connect failed");
        TRC1P(" ip - %s", cmIPDump(ip));
    }
#endif /* defined(UD_NQ_USETRANSPORTIPV4) || defined(UD_NQ_USETRANSPORTIPV6) */

    TRCE();
    return NQ_FAIL;
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

    TRCB();

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
    }
#endif

    sts = syCloseSocket(pSock->socket);
    if (sts == NQ_FAIL)     /* error on close */
    {
        TRCERR("Unable to close socket");
        TRCE();
        return NQ_FAIL;
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

        TRCERR("Unable to create socket");
        TRCE();
        return NQ_FAIL;
    }

    TRC1P("Socket recreated created with fd=%d", pSock->socket);
    TRCE();
    return  NQ_SUCCESS;
}

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/********************************************************************
 *  Resolver callbacks
 ********************************************************************/

#if defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE)

NQ_STATUS nsRequestByNameWins(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{
    NQ_BYTE* msgBuf;                /* buffer for Name Query Request */
    NQ_INT msgLen;                  /* this message length */
    CMNetBiosNameInfo destName;     /* NetBIOS name */            
    NQ_CHAR * nameA;                /* server name in ASCII */
    NQ_STATUS result;               /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* create NetBIOS name */
    nameA = cmMemoryCloneWStringAsAscii(name);
    if (NULL == nameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    cmNetBiosNameCreate(destName.name, nameA, CM_NB_POSTFIX_SERVER);
    destName.isGroup = FALSE;

    cmMemoryFree(nameA);
    msgBuf = nsGetSendDatagramBuffer();

    /* generate a Name Query Request */
    if (NQ_FAIL == (msgLen = frameInternalNameQueryRequest((NQ_BYTE*)msgBuf, &destName)))
    {
        nsPutSendDatagramBuffer();
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* send the request and wait for a response */

    result = sySendToSocket(socket, (const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, serverIp, syHton16(CM_NB_NAMESERVICEPORT));
    if (result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
        LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    }

    nsPutSendDatagramBuffer();

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result > 0 ? NQ_SUCCESS : NQ_FAIL;
}

NQ_STATUS nsRequestByNameBcast(
    SYSocketHandle socket, 
    const NQ_WCHAR * name, 
    void * context, 
    const NQ_IPADDRESS * serverIp
    )
{
    NQ_BYTE* msgBuf;                /* buffer for Name Query Request */
    NQ_INT msgLen;                  /* this message length */
    CMNetBiosNameInfo destName;     /* NetBIOS name */            
    NQ_CHAR * nameA;                /* server name in ASCII */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* create NetBIOS name */
    nameA = cmMemoryCloneWStringAsAscii(name);
    if (NULL == nameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    cmNetBiosNameCreate(destName.name, nameA, CM_NB_POSTFIX_SERVER);
    cmMemoryFree(nameA);
    destName.isGroup = FALSE;

    msgBuf = nsGetSendDatagramBuffer();

    /* generate a Name Query Request */
    if (NQ_FAIL == (msgLen = frameInternalNameQueryRequest((NQ_BYTE*)msgBuf, &destName)))
    {
        nsPutSendDatagramBuffer();
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to generate Name Query Request");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* send the request and wait for a response */

    if (nsSendRequestToND(socket, (const NQ_BYTE*)msgBuf, (NQ_UINT)msgLen) == NQ_FAIL)
    {
        nsPutSendDatagramBuffer();
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
        LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

        return NQ_FAIL;
    }

    nsPutSendDatagramBuffer();

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
}

NQ_STATUS nsResponseByName(
    SYSocketHandle socket, 
    NQ_IPADDRESS ** pAddressArray, 
    NQ_INT * numIps, 
    void ** pContext
    )
{
    CMNetBiosAddrEntry addrEntry;   /* buffer for the response */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    *pAddressArray = NULL;
    if (nsReceiveResponseFromND(socket, &addrEntry) == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    *pAddressArray = cmMemoryAllocate(sizeof(NQ_IPADDRESS));
    if (NULL == pAddressArray)
    {
        sySetLastError(CM_NBERR_INTERNALERROR);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate IP buffer");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }
    CM_IPADDR_ASSIGN4(**pAddressArray, cmGetSUint32(addrEntry.ip));          /* NBO */
    *numIps = 1;

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_SUCCESS;
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
    NQ_STATUS result;                   /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
        nsPutSendDatagramBuffer();
        sySetLastError(CM_NBERR_NOTNETBIOSNAME);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to encode name - illegal name: %s", calledName);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    questionBody = (CMNetBiosQuestion*) (questionName + shift);

    cmPutSUint16(questionBody->questionType,  syHton16(CM_NB_RTYPE_NBSTAT));  /* type */;
    cmPutSUint16(questionBody->questionClass, syHton16(CM_NB_RCLASS_IN));     /* class */;

    msgLen = (NQ_UINT)((NQ_BYTE*)(questionBody + 1) - (NQ_BYTE*)msgHdr);

    result = sySendToSocket(socket, (const NQ_BYTE*)msgHdr, (NQ_UINT)msgLen, ip, syHton16(CM_NB_NAMESERVICEPORT));
    if (result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "ND failed to resolve the name");
    }
    nsPutSendDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return result >= 0 ? NQ_SUCCESS:NQ_FAIL;
}

NQ_STATUS nsResponseByIp(
    SYSocketHandle socket, 
    const NQ_WCHAR ** pName, 
    void ** pContext
    )
{
    CMNetBiosHeader* resHdr;            /* pointer to the response header */
    NQ_INT result;                      /* various results */
    NQ_UINT16 codes;                    /* response codes */
    NQ_PORT port;                       /* response port */
    NQ_IPADDRESS resIp;                 /* response IP */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    resHdr = (CMNetBiosHeader*)nsGetRecvDatagramBuffer();

    result = syRecvFromSocket(
        socket,
        (NQ_BYTE*)resHdr,
        CM_NB_DATAGRAMBUFFERSIZE,
        &resIp,
        &port
        );
    if (result == 0 || result == NQ_FAIL)
    {
        nsPutRecvDatagramBuffer();
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to receive response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    /* inspect packet type: response flag, error code */
    codes = syNtoh16(cmGetSUint16(resHdr->packCodes));

    if (!(codes & CM_NB_RESPONSE))
    {
        nsPutRecvDatagramBuffer();
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected packet - not a response");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    if ((codes & CM_NB_RCODE_MASK) != CM_NB_RCODE_NOERR)
    {
        nsPutRecvDatagramBuffer();
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Negative response: RCODE: %d", codes & CM_NB_RCODE_MASK);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
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
        pQuestion = (CMNetBiosQuestion*)cmNetBiosParseName(
                        resHdr,
                        resHdr + 1,
                        name,
                        scopeId,
                        sizeof(scopeId)
                        );
        if (pQuestion == NULL)
        {
            nsPutRecvDatagramBuffer();
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Error parsing name in the response");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
        }

        if (syNtoh16(cmGetSUint16(pQuestion->questionType)) != CM_NB_RTYPE_NBSTAT)
        {
            nsPutRecvDatagramBuffer();
            sySetLastError(CM_NBERR_NEGATIVERESPONSE);
            LOGERR(CM_TRC_LEVEL_ERROR, "Unepected question record");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NQ_FAIL;
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
                    CMNetBiosName nbName;       /* netbios name */    
                    
                    syStrncpy(nbName, (NQ_CHAR*)pData, 16);
                    cmNetBiosNameClean(nbName);
                    *pName = cmMemoryCloneAString(nbName);

                    nsPutRecvDatagramBuffer();
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return NULL != *pName? NQ_SUCCESS : NQ_ERR_NOMEM;
                }
            }
            pData += 16 + 2;
        }

        nsPutRecvDatagramBuffer();
        sySetLastError(CM_NBERR_NEGATIVERESPONSE);
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected question record");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NQ_FAIL;
    }

    nsPutRecvDatagramBuffer();

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
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NQ_FAIL;
}

static void parseServerList(NQ_WCHAR * list)
{
    CMResolverMethodDescriptor method;                      /* next method descriptor */
    NQ_WCHAR * curServer;                                   /* pointer to the current server IP */
    NQ_WCHAR * nextServer;                                  /* pointer to the next server IP */
    NQ_CHAR aServer[CM_IPADDR_MAXLEN];                      /* the same in ASCII */
    
    method.type = NQ_RESOLVER_NETBIOS;
    method.isMulticast = FALSE;  /* unicast */
    method.timeout = 1; /* seconds */
    method.waitAnyway = TRUE;
    method.requestByName = nsRequestByNameWins;
    method.responseByName = nsResponseByName;
    method.requestByIp = nsRequestByIp;
    method.responseByIp = nsResponseByIp;

    /* parse servers string */
    for(curServer = list, staticData->numServers = 0; 
        staticData->numServers < sizeof(staticData->winsServers) / sizeof(staticData->winsServers[0]); 
        )
    {
        NQ_STATUS res;                      /* operation status */
        NQ_IPADDRESS ip;                    /* next IP */

        nextServer = cmWStrchr(curServer, cmWChar(';'));
        if (NULL != nextServer)
        {
            *nextServer = cmWChar('\0');
        }
        cmUnicodeToAnsi(aServer, curServer);
        res = cmAsciiToIp(aServer, &ip);
        staticData->winsServers[staticData->numServers] = ip;
        curServer = nextServer + 1;
        /* register WINS with Resolver */
        res = cmResolverRegisterMethod(&method, &staticData->winsServers[staticData->numServers]);
        if (TRUE == res)
            staticData->numServers++; 
        if (NULL == nextServer)
        {
            break;
        }
    }
}

void cmNetBiosSetWinsA(const NQ_CHAR * servers)
{
    const NQ_WCHAR * serversW;      /* unicode copy */

    if (NULL == servers)
    {
        cmNetBiosSetWinsW(NULL);
        return;
    }
    serversW = cmMemoryCloneAString(servers);
    if (NULL != serversW)
        cmNetBiosSetWinsW(serversW);
    cmMemoryFree(serversW);
}

void cmNetBiosSetWinsW(const NQ_WCHAR * servers)
{
    NQ_INT idx;                             /* index in servers */
    CMResolverMethodDescriptor descriptor;  /* method descriptor */
    NQ_WCHAR * aCopy;                       /* server list copy */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return;
    }
    aCopy = cmMemoryCloneWString(servers);
    if (NULL != aCopy)
    {
        parseServerList(aCopy);
        cmMemoryFree(aCopy);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#endif /* defined(UD_NQ_USETRANSPORTNETBIOS) && defined(UD_NB_INCLUDENAMESERVICE) */
