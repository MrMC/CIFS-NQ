/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : The main loop of the CIFS server
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 17-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csapi.h"
#include "nsapi.h"

#include "csbrowse.h"
#include "csnotify.h"
#include "csdispat.h"
#ifdef UD_NQ_INCLUDESMB2
#include "cs2disp.h"
#endif /* UD_NQ_INCLUDESMB2 */
#include "csdataba.h"
#include "csutils.h"
#include "csauth.h"
#include "csdcerpc.h"
#include "cmsdescr.h"
#include "cscontrl.h"
#include "cmbuf.h"
#ifdef UD_CS_INCLUDEPASSTHROUGH
#include "ccdcerpc.h"
#include "ccsamrpc.h"
#include "cclsarpc.h"
#include "ccapi.h"
#endif /*UD_CS_INCLUDEPASSTHROUGH*/

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements the main loop of the server
 */

/*
    Static data
    -----------
 */

/* abstract response parser - returns a pointer to the 
 * static parameter structure for this command */
typedef NQ_BOOL (*CommandProcessor)(
    CMBufferReader * reader, 
    CMBufferWriter * writer
    ); 

typedef struct          /* descriptor for a control command */
{
    NQ_UINT32 code;             /* command code */
    CommandProcessor processor; /* command processor */
}
ControlCommand;

/* command processors */
static NQ_BOOL stopServer(CMBufferReader * reader, CMBufferWriter * writer); 
static NQ_BOOL restartServer(CMBufferReader * reader, CMBufferWriter * writer); 
static NQ_BOOL addShare(CMBufferReader * reader, CMBufferWriter * writer); 
static NQ_BOOL removeShare(CMBufferReader * reader, CMBufferWriter * writer); 
static NQ_BOOL enumShares(CMBufferReader * reader, CMBufferWriter * writer);
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
static NQ_BOOL addUser(CMBufferReader * reader, CMBufferWriter * writer); 
static NQ_BOOL removeUser(CMBufferReader * reader, CMBufferWriter * writer); 
static NQ_BOOL cleanUserCons(CMBufferReader * reader, CMBufferWriter * writer);
static NQ_BOOL enumUsers(CMBufferReader * reader, CMBufferWriter * writer);
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
static NQ_BOOL enumClients(CMBufferReader * reader, CMBufferWriter * writer);
static NQ_BOOL changeEncryptLevel(CMBufferReader * reader, CMBufferWriter * writer);
#ifdef UD_CS_MESSAGESIGNINGPOLICY
static NQ_BOOL changeMsgSign(CMBufferReader * reader, CMBufferWriter * writer);
#endif /*UD_CS_MESSAGESIGNINGPOLICY*/

static const ControlCommand controlCommands[] = 
{
    { CS_CONTROL_STOP, stopServer },    
    { CS_CONTROL_RESTART, restartServer },  
    { CS_CONTROL_ADDSHARE, addShare },  
    { CS_CONTROL_REMOVESHARE, removeShare },    
    { CS_CONTROL_ENUMSHARES, enumShares },    
#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT
    { CS_CONTROL_ADDUSER, addUser },    
    { CS_CONTROL_REMOVEUSER, removeUser }, 
    { CS_CONTROL_CLEANUSERCONS, cleanUserCons },
    { CS_CONTROL_ENUMUSERS, enumUsers },
#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */
    { CS_CONTROL_ENUMCLIENTS , enumClients},
    { CS_CONTROL_CHANGEENCRYPTION , changeEncryptLevel},
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    { CS_CONTROL_CHANGEMSGSIGN , changeMsgSign}
#endif /*UD_CS_MESSAGESIGNINGPOLICY*/
};

typedef struct
{
    NSSocketHandle serverSocketUDP;     /* server internal UDP socket used to signal server to stop its execution */
    NQ_BOOL restart;                    /* when TRUE - restart the server cycle */
#if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDEPASSTHROUGH)
    CMSdDomainSid domainSid;            /* SID of the configured domain */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS && UD_CS_INCLUDEPASSTHROUGH */
#ifdef UD_NQ_USETRANSPORTNETBIOS
    NQ_TIME nextAnnouncementInterval;   /* next interval between announcements, this value wil
                                           raise up to CM_FS_MINHOSTANNOUNCEMENTINTERVAL */
    NQ_TIME lastTimeout;                /* time of the last timeout */
    NSSocketHandle serverSocketNB;      /* server NetBIOS TCP socket */
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_USETRANSPORTIPV4
    NSSocketHandle serverSocketV4;      /* server TCPv4 socket */
#endif /* UD_NQ_USETRANSPORTIPV4 */
#ifdef UD_NQ_USETRANSPORTIPV6
    NSSocketHandle serverSocketV6;      /* server TCPv6 socket */
#endif /* UD_NQ_USETRANSPORTIPV6 */
    NSSocketSet socketSet;              /* for nsSelect() */
    CSSocketDescriptor clientSockets[UD_FS_NUMSERVERSESSIONS];     /* list of client sockets */
    SYMutex dbGuard;                    /* mutex for access to the database */
#ifdef UD_CS_INCLUDEPASSTHROUGH
    NQ_WCHAR domain[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE + 1)];
                                        /* buffer for client domain name in TCHAR */
    NQ_WCHAR pdcName[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE + 1)];
                                        /* buffer for PDC name in TCHAR */
    NQ_BOOL pdcNameFlag;                /* flag for this name */
#endif /* UD_CS_INCLUDEPASSTHROUGH */
    NQ_TCHAR nameT[CM_BUFFERLENGTH(NQ_TCHAR, 256)]; /* buffer for username in TCHAR */
    NQ_TCHAR fullNameT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];   /* buffer for full name in TCHAR */
    NQ_TCHAR descriptionT[CM_BUFFERLENGTH(NQ_TCHAR, 256)];/* buffer for description in TCHAR */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/*
    Forward definitions
 */
static NQ_STATUS
serverCycle(
    void
    );

static void
closeServerSockets(
    void
    );

/* accept incoming connection and processes it */
static NQ_BOOL
acceptSocket(
    NSSocketHandle serverSocket,
    NQ_BOOL isNetBios,
    NQ_TIME time
    );

/* pause server for performing changes in the database */
static void
pauseServer(
    void
    );

/* resume server after database changes are over */
static void
resumeServer(
    void
    );

/* release allocated memory */
static void
releaseResources(
    void
    );

/* prepare internal UDP server socket */    
static NSSocketHandle
prepareUdpServerSocket(
    void
    );

/* perform a control command */
NQ_BOOL     /* TRUE - continue, FALSE - exit server */
doControl(
    SYSocketHandle sock     /* socket with pending command UDP */ 
    );

/*
 *====================================================================
 * PURPOSE: main server loop
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   As any other server, this one implements a listening loop
 *          we listen to one "server" socket (TCP) and several "client" sockets.
 *          The "server" socket accepts new connections, while "client" sockets
 *          represent those connections.
 *====================================================================
 */

NQ_STATUS
csStart(
    void
    )
{
    NQ_STATUS res;
    TRCB();

    TRC("CIFS is starting up");

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate server data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */
    
    staticData->restart = FALSE;
    do
    {
        res = serverCycle();
        if (res == NQ_FAIL)
            break;
    }
    while (staticData->restart);

#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
       syFree(staticData);
    staticData = NULL;   
#endif /* SY_FORCEALLOCATION */

    TRCE();
    return res;
}


/*
 *====================================================================
 * PURPOSE: main server loop
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   As any other server, this one implements a listening loop
 *          we listen to one "server" socket (TCP) and several "client" sockets.
 *          The "server" socket accepts new connections, while "client" sockets
 *          represent those connections.
 *====================================================================
 */

static NQ_STATUS
serverCycle(
    void
    )
{
    NQ_INT ret;                 /* value returned from various calls */
    NQ_UINT idx;                /* index in the table of client sockets */
    NQ_TIME curTime;            /* current system time */
    
    TRCB();

    TRC("CIFS restarting");

    if (!staticData->restart)
    {
    #if defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDEPASSTHROUGH)
        staticData->pdcNameFlag = FALSE;
    #endif /* defined(UD_CS_INCLUDESECURITYDESCRIPTORS) && defined(UD_CS_INCLUDEPASSTHROUGH) */
    #ifdef UD_NQ_USETRANSPORTIPV4
        staticData->serverSocketV4 = NULL;
    #endif /* UD_NQ_USETRANSPORTIPV4 */
    #ifdef UD_NQ_USETRANSPORTIPV6
        staticData->serverSocketV6 = NULL;
    #endif /* UD_NQ_USETRANSPORTIPV6 */
    #ifdef UD_NQ_USETRANSPORTNETBIOS
        staticData->serverSocketNB = NULL;
    #endif /* UD_NQ_USETRANSPORTNETBIOS */
        staticData->serverSocketUDP = NULL;
    }

    syMutexCreate(&staticData->dbGuard);
#ifdef UD_NQ_USETRANSPORTNETBIOS
    staticData->lastTimeout = (NQ_TIME)syGetTime();
#endif
    /* clean up section is essential when this task is re-entered after csStop():
        - zero sockets
        - close server socket if still open */

    if (!staticData->restart)
    {
        closeServerSockets();
    }

    for (idx = 0; idx <UD_FS_NUMSERVERSESSIONS; idx++)
    {
        staticData->clientSockets[idx].socket = NULL;
    }

    /* Initialization:
        - Database
        - NetBIOS
        - socket set
        - stream server socket bound to the name of the machine */
	if (!staticData->restart)
	{
		if (NQ_FAIL == nsInit(TRUE))        /* we are initializing a task - not a driver */
		{
			syMutexDelete(&staticData->dbGuard);    
			udCifsServerClosed();
			TRC("ns initialization failed");
			TRCE();
			return NQ_FAIL;
		}
	}

    if (NQ_FAIL == csInitDatabase(&pauseServer, &resumeServer))
    {
        releaseResources();
        TRCE();
        return NQ_FAIL;
    }

#ifdef UD_CS_INCLUDERPC
    if (NQ_FAIL == csDcerpcInit())
    {
        releaseResources();
        TRCE();
        return NQ_FAIL;
    }
#endif /* UD_CS_INCLUDERPC */

#ifdef UD_NQ_USETRANSPORTNETBIOS
    if (csInitBrowse() == NQ_FAIL)
    {
        releaseResources();
        TRCERR("browser initialization failed");
        TRCE();
        return NQ_FAIL;
    }
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    if (NQ_FAIL == csFnamesInit())
    {
        releaseResources();
        TRCERR("Failed to start file enumeration tools");
        TRCE();
        return NQ_FAIL;
    }
#ifdef UD_CS_INCLUDEPASSTHROUGH    
    if (!csAuthInit())
    {
        releaseResources();
        TRCERR("Pass through authentication failed to initialize");
        TRCE();
        return NQ_FAIL;
    }
#endif /* UD_CS_INCLUDEPASSTHROUGH */
    if (NQ_FAIL == csDispatchInit())
    {
        releaseResources();
        TRC("Dispatcher failed to initialize");
        TRCE();
        return NQ_FAIL;
    }

#ifdef UD_NQ_INCLUDESMB2
    if (NQ_FAIL == cs2DispatchInit())
    {
        releaseResources();
        TRCERR("SMB2 Dispatcher failed to initialiaze");
        TRCE();
        return NQ_FAIL;
    }
#endif /* UD_NQ_INCLUDESMB2 */

    if (NQ_FAIL == csNotifyInit())
    {
        releaseResources();
        TRCERR("Notify failed to initialize");
        TRCE();
        return NQ_FAIL;
    }
    TRC1P("Host name registered: %s", cmNetBiosGetHostNameZeroed());

    /* setup random number generator for creating encryption keys */
    sySetRand();

    if (!staticData->restart)
    {
        if ((staticData->serverSocketUDP = prepareUdpServerSocket()) == NULL)
        {
            releaseResources();
            TRCERR("Server internal UDP socket initialization failed");
            TRCE();
            return NQ_FAIL;
        }
        
#ifdef UD_NQ_USETRANSPORTNETBIOS
        if (udGetTransportPriority(NS_TRANSPORT_NETBIOS) &&
            (staticData->serverSocketNB = csPrepareSocket(NS_SOCKET_STREAM, NS_TRANSPORT_NETBIOS)) == NULL)
        {
            releaseResources();
            TRCERR("NetBIOS socket initialization failed");
            TRCE();
            return NQ_FAIL;
        }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTIPV4
        if (udGetTransportPriority(NS_TRANSPORT_IPV4) &&
            (staticData->serverSocketV4 = csPrepareSocket(NS_SOCKET_STREAM, NS_TRANSPORT_IPV4)) == NULL)
        {
            releaseResources();
            TRCERR("IPv4 socket initialization failed");
            TRCE();
            return NQ_FAIL;
        }
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
        if (udGetTransportPriority(NS_TRANSPORT_IPV6) &&
            (staticData->serverSocketV6 = csPrepareSocket(NS_SOCKET_STREAM, NS_TRANSPORT_IPV6)) == NULL)
        {
            releaseResources();
            TRCERR("IPv6 socket initialization failed");
            TRCE();
            return NQ_FAIL;
        }
#endif /* UD_NQ_USETRANSPORTIPV6 */

#ifdef UD_NQ_USETRANSPORTNETBIOS
        /* announce our host to the domain for the first time and start
           the announcement timeout */

        if ((NQ_INT)(staticData->nextAnnouncementInterval = csAnnounceServer()) == NQ_FAIL)
        {
            releaseResources();
            TRCERR("call to csAnnounceServer failed");
            TRCE();
            return NQ_FAIL;
        }
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    }

#ifdef UD_CS_INCLUDEPASSTHROUGH
    /* resolve this domain SID on DC */
    if (!cmNetBiosGetDomainAuth()->isGroup)
    {
        const NQ_CHAR * pdcName;            /* pointer to PDC name in CHAR */

        if (!staticData->pdcNameFlag)
        {
            pdcName = csAuthGetPDCName();

            if (NULL != pdcName)
            {
            	CCLsaPolicyInfoDomain	domainInfo;
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
                NQ_HANDLE sam;                      /* pipe handle for SAMR */
                NQ_STATUS status;                   /* operation status */
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

                staticData->pdcNameFlag = TRUE;
                cmAnsiToUnicode(staticData->pdcName, pdcName);
                cmAnsiToUnicode(staticData->domain, cmNetBiosGetDomainAuth()->name);
#ifdef UD_CS_INCLUDESECURITYDESCRIPTORS
                sam = ccDcerpcConnect(staticData->pdcName, NULL, ccSamGetPipe(), FALSE);
                if (NULL == sam)
                {
                    TRCERR("Unable to open SAMR on PDC");
                }
                else
                {
                    status = ccSamGetDomainSid(sam, staticData->domain, &staticData->domainSid);

                    ccDcerpcDisconnect(sam);

                    if (status == NQ_SUCCESS && !cmSdIsDomainSidSet())
                        cmSdSetDomainSid(&staticData->domainSid);
                }
#endif /* UD_CS_INCLUDESECURITYDESCRIPTORS */

                if (NQ_SUCCESS == ccLsaDsRoleGetPrimaryDomainInformation(staticData->pdcName, &domainInfo))
                {
                	cmNetBiosSetDomainAuth(domainInfo.name);
                }
            }
            else
            {
                TRCERR("Pass through authentication is not initialized yet");
            }
        }
    }
#endif /* UD_CS_INCLUDEPASSTHROUGH */

#ifdef UD_NQ_INCLUDEEVENTLOG
    udEventLog(
        UD_LOG_MODULE_CS,
        UD_LOG_CLASS_GEN,
        UD_LOG_GEN_START,
        NULL,
        NULL,
        0,
        NULL
    );
#endif /* UD_NQ_INCLUDEEVENTLOG */

    /* from here we accept incoming client connections */

    udCifsServerStarted();

    TRC("Entering the main loop ");

    while (TRUE)
    {
        /* compose the set of sockets for select:
           1) the server listening socket
           2) client session sockets */

        nsClearSocketSet(&staticData->socketSet);
                
        nsAddSocketToSet(&staticData->socketSet, staticData->serverSocketUDP);        /* add internal UDP server socket */
#ifdef UD_NQ_USETRANSPORTNETBIOS
        if (udGetTransportPriority(NS_TRANSPORT_NETBIOS))
            nsAddSocketToSet(&staticData->socketSet, staticData->serverSocketNB);     /* add NetBIOS server socket */
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTIPV4
        if (udGetTransportPriority(NS_TRANSPORT_IPV4))
            nsAddSocketToSet(&staticData->socketSet, staticData->serverSocketV4);     /* add v4 server socket */
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
        if (udGetTransportPriority(NS_TRANSPORT_IPV6))
            nsAddSocketToSet(&staticData->socketSet, staticData->serverSocketV6);     /* add v6 server socket */
#endif /* UD_NQ_USETRANSPORTIPV6 */

        for (idx = 0; idx < UD_FS_NUMSERVERSESSIONS; idx++)
        {
            if (staticData->clientSockets[idx].socket != NULL)
            {
                /* if the socket actually was closed inside the server clear it here as well */
                if (!nsAddSocketToSet(&staticData->socketSet, staticData->clientSockets[idx].socket))
                    staticData->clientSockets[idx].socket = NULL;
            }
        }

#ifdef UD_NQ_USETRANSPORTNETBIOS
        TRC1P("SERVER --->> Select, next timeout = %ld sec", staticData->nextAnnouncementInterval);
        ret = nsSelect(&staticData->socketSet, staticData->nextAnnouncementInterval);
#else /* UD_NQ_USETRANSPORTNETBIOS */
        TRC("SERVER --->> Select, infinite");
        ret = nsSelect(&staticData->socketSet, SMB_MAX_SERVER_ANNOUNCEMENT_INTERVAL);
#endif /* UD_NQ_USETRANSPORTNETBIOS */

        TRC1P("select returned: %d", ret);

        /* call user defined processing */

        udServerDataIn();

        curTime = (NQ_TIME)syGetTime();
#ifdef UD_NQ_USETRANSPORTNETBIOS
        /* Check for timeout and calculate the time to announce the server*/

        if (ret == 0 || curTime >= (staticData->lastTimeout + staticData->nextAnnouncementInterval))       /* timeout */
        {
            staticData->lastTimeout = curTime;
            if ((NQ_INT)(staticData->nextAnnouncementInterval = csAnnounceServer()) == NQ_FAIL)
            {
                TRC("call to csAnnounceServer failed");
                break;
            }
        }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

        /* on timeout do not continue */
        if (ret == 0)
            continue;

        /* if select failed - one of sockets has disconnected:
           clean up the list of client sockets */

        if (ret == NQ_FAIL)
        {
            TRCERR("Select failed");

            if (FALSE
#ifdef UD_NQ_USETRANSPORTNETBIOS
                  || (!nsIsSocketAlive(staticData->serverSocketNB))
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTIPV4
                  || (!nsIsSocketAlive(staticData->serverSocketV4))
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
                  || (!nsIsSocketAlive(staticData->serverSocketV6))
#endif /* UD_NQ_USETRANSPORTIPV6 */
            )
            {
                TRC(" server socket failed");
                TRCE();
                break;
            }
            for (idx = 0; idx < UD_FS_NUMSERVERSESSIONS; idx++)
            {
                if (staticData->clientSockets[idx].socket != NULL)
                {
                    if (!nsIsSocketAlive(staticData->clientSockets[idx].socket))
                    {
                        TRC(" a dead session socket found, cleaning up");

                        csReleaseSessions(staticData->clientSockets[idx].socket , FALSE);
                        nsClose(staticData->clientSockets[idx].socket);
                        staticData->clientSockets[idx].socket = NULL;
                    }
                }
            }
            
            continue;
        }
        
        /* if data arrived on internal UDP server socket it means a command was sent */
        if (nsSocketInSet(&staticData->socketSet, staticData->serverSocketUDP))
        {
            if (!doControl(nsGetSySocket(staticData->serverSocketUDP)))
            {
                TRC("Exit from the server cycle");
                break;          /* exit server */
            }
        }

        /* if new client connecting: accept new socket */
#ifdef UD_NQ_USETRANSPORTNETBIOS
        if (nsSocketInSet(&staticData->socketSet, staticData->serverSocketNB))
            acceptSocket(staticData->serverSocketNB, TRUE, curTime);
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTIPV4
        if (nsSocketInSet(&staticData->socketSet, staticData->serverSocketV4))
            acceptSocket(staticData->serverSocketV4, FALSE, 0);
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
        if (nsSocketInSet(&staticData->socketSet, staticData->serverSocketV6))
            acceptSocket(staticData->serverSocketV6, FALSE, 0);
#endif /* UD_NQ_USETRANSPORTIPV6 */

        /* if a session packet has arrived at an already accepted socket,
           this means a CIFS message */

        TRC("checking accepted sockets");

        for (idx = 0; idx < UD_FS_NUMSERVERSESSIONS; idx++)
        {
            if (staticData->clientSockets[idx].socket != NULL)
            {
                if (!nsIsSocketAlive(staticData->clientSockets[idx].socket))
                {
                    TRC(" a dead session socket found, cleaning up");

                    csReleaseSessions(staticData->clientSockets[idx].socket , TRUE);
                    nsClose(staticData->clientSockets[idx].socket);
                    staticData->clientSockets[idx].socket = NULL;
                }
                else if (nsSocketInSet(&staticData->socketSet, staticData->clientSockets[idx].socket))
                {
#ifdef UD_NQ_USETRANSPORTNETBIOS
                    /* process NBT Session Request */
                    if (staticData->clientSockets[idx].requestExpected)
                    {
                        staticData->clientSockets[idx].requestExpected = (NQ_SUCCESS != nsPostAccept(&staticData->clientSockets[idx].socket));
                        continue;
                    }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

                    syMutexTake(&staticData->dbGuard);
                    ret = csDispatchRequest(
                        &staticData->clientSockets[idx]
                        );    /* process CIFS message */
                    syMutexGive(&staticData->dbGuard);
                    
                    staticData->clientSockets[idx].lastActivityTime = curTime;

                    if (ret == NQ_FAIL)
                    {
                        TRCERR("Error in performing the command");

                        csReleaseSessions(staticData->clientSockets[idx].socket , FALSE);
                        nsClose(staticData->clientSockets[idx].socket);
                        staticData->clientSockets[idx].socket = NULL;
                    }
                }
#ifdef UD_NQ_USETRANSPORTNETBIOS
                else
                {
                    /* clean up sockets with NBT Session Request timeed out */
                    if (staticData->clientSockets[idx].requestExpected &&
                      ((curTime - staticData->clientSockets[idx].requestTimeout) > CM_NB_UNICASTREQRETRYTIMEOUT)
                       )
                    {
                        nsClose(staticData->clientSockets[idx].socket);
                        staticData->clientSockets[idx].socket = NULL;
                    }
                }
#endif /* UD_NQ_USETRANSPORTNETBIOS */
            }
        }
    }/* end of main loop */

    
    /* close all sockets */
    if (!staticData->restart)
        closeServerSockets();

    for (idx = 0; idx < UD_FS_NUMSERVERSESSIONS; idx++)
    {
        if (staticData->clientSockets[idx].socket != NULL)
        {
            csReleaseSessions(staticData->clientSockets[idx].socket , TRUE);
            if (nsIsSocketAlive(staticData->clientSockets[idx].socket))
            {
                nsClose(staticData->clientSockets[idx].socket);
                staticData->clientSockets[idx].socket = NULL;
            }
        }
    }

    TRC("Exiting the CIFS server");

#ifdef UD_NQ_INCLUDEEVENTLOG
    udEventLog(
        UD_LOG_MODULE_CS,
        UD_LOG_CLASS_GEN,
        UD_LOG_GEN_STOP,
        NULL,
        NULL,
        0,
        NULL
    );
#endif /* UD_NQ_INCLUDEEVENTLOG */

    releaseResources();

    TRCE();
    return NQ_SUCCESS;

}  

/*
 *====================================================================
 * PURPOSE: create a UDP socket and bind it to any port
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: socket handle or NULL on error
 *
 * NOTES:   This internal UDP server socket is used to signal server to
 *          exit the main execution loop.
 *====================================================================
 */

static NSSocketHandle
prepareUdpServerSocket(
    void
    )
{
    NSSocketHandle socket; 
    NQ_INT 	i;
    NQ_UINT transArr[] = {
#ifdef UD_NQ_USETRANSPORTIPV6
       NS_TRANSPORT_IPV6,
#endif
#ifdef UD_NQ_USETRANSPORTIPV4
       NS_TRANSPORT_IPV4,
#endif
#ifdef UD_NQ_USETRANSPORTNETBIOS
       NS_TRANSPORT_NETBIOS
#endif
    			}; /* array to check transports*/
#ifndef UD_NQ_USETRANSPORTIPV6
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
#else
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_IPADDRESS localhostv6 = CM_IPADDR_LOCAL6;
#endif

    TRCB();

    for (i = 0; i < sizeof(transArr)/sizeof(transArr[0]) ; i++)
    {
    	if (!udGetTransportPriority(transArr[i]))
    			continue;

		/* create a UDP socket */
		if ((socket = nsSocket(NS_SOCKET_DATAGRAM, transArr[i])) == NULL)
		{
			TRCERR("Unable to create internal UDP server socket with transport %d " , transArr[i]);
			continue;
		}
#ifdef UD_NQ_USETRANSPORTIPV6
		if (transArr[i] == NS_TRANSPORT_IPV6)
		    		localhost = localhostv6;
#endif /*UD_NQ_USETRANSPORTIPV6*/

		/* bind to any port */
		if (nsBindInet(socket, &localhost, syHton16(CS_CONTROL_PORT)) == NQ_FAIL)
		{
			nsClose(socket);
			TRCERR("Unable to bind internal UDP server socket to any port with transport %d " , transArr[i]);
			continue;
		}

		TRCE();
		return socket;
    }
    TRCERR("Unable to create or bind internal UDP server socket");
	TRCE();
	return NULL;
}

/*
 *====================================================================
 * PURPOSE: close server sockets
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void
closeServerSockets(
    void
    )
{
    TRCB();

    if (staticData != NULL)
    {
#ifdef UD_NQ_USETRANSPORTNETBIOS
        if (staticData->serverSocketNB != NULL)
        {
            nsClose(staticData->serverSocketNB);
            staticData->serverSocketNB = NULL;
        }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_NQ_USETRANSPORTIPV4
        if (staticData->serverSocketV4 != NULL)
        {
            nsClose(staticData->serverSocketV4);
            staticData->serverSocketV4 = NULL;
        }
#endif /* UD_NQ_USETRANSPORTIPV4 */

#ifdef UD_NQ_USETRANSPORTIPV6
        if (staticData->serverSocketV6 != NULL)
        {
            nsClose(staticData->serverSocketV6);
            staticData->serverSocketV6 = NULL;
        }
#endif /* UD_NQ_USETRANSPORTIPV6 */
        
        if (staticData->serverSocketUDP != NULL)
        {
            nsClose(staticData->serverSocketUDP);  
            staticData->serverSocketUDP = NULL;
        }
    }

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: debug only
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

#if SY_DEBUGMODE

void
csDumpSockets(
    )
{
    NQ_UINT i;

    syPrintf("\n================ Sockets ==============\n");

    for (i = 0; i < UD_FS_NUMSERVERSESSIONS; i++)
    {
        syPrintf(
            "socket: %d, mapped on: %p, with peer IP: %s\n",
            i,
            staticData->clientSockets[i].socket,
            cmIPDump(&staticData->clientSockets[i].ip));
    }

    syPrintf("================         ==============\n\n");
}

#endif

/*
 *====================================================================
 * PURPOSE: pause server for performing changes in the database
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void
pauseServer(
    void
    )
{
    syMutexTake(&staticData->dbGuard);
}

/*
 *====================================================================
 * PURPOSE: resume server after changes in the database
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void
resumeServer(
    void
    )
{
    syMutexGive(&staticData->dbGuard);
}

/*
 *====================================================================
 * PURPOSE: accume new client socket
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE when done and FALSE on error
 *
 * NOTES:
 *====================================================================
 */

static NQ_BOOL
acceptSocket(
    NSSocketHandle serverSocket,
    NQ_BOOL isNetBios,
    NQ_TIME time
    )
{
    NSSocketHandle newSocket;           /* an accepted socket */
    NQ_UINT idx;                        /* index in the table of client sockets */
    NQ_IPADDRESS ip;                    /* IP on the next side of the socket */

    nsResetBufferPool();
    newSocket = nsAccept(serverSocket, &ip);
    if (newSocket == NULL)
    {
    #ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(UD_LOG_MODULE_CS,
            UD_LOG_CLASS_CONNECTION,
            UD_LOG_CONNECTION_CONNECT,
            NULL,
            &ip,
            (NQ_UINT32)syGetLastError(),
            NULL);
    #endif
        TRCERR("nsAccept failed");
        return FALSE;
    }
    /* save this socket in an empty record in the client socket table */

    for (idx = 0; idx < UD_FS_NUMSERVERSESSIONS; idx++)
    {
        if (staticData->clientSockets[idx].socket == NULL)
        {
            break;
        }
    }

    if (idx == UD_FS_NUMSERVERSESSIONS)
    {
#ifdef UD_CS_REFUSEONSESSIONTABLEOVERFLOW
    #ifdef UD_NQ_INCLUDEEVENTLOG
        udEventLog(UD_LOG_MODULE_CS,
            UD_LOG_CLASS_CONNECTION,
            UD_LOG_CONNECTION_CONNECT,
            NULL,
            &ip,
            (NQ_UINT32)SMB_STATUS_INSUFFICIENT_RESOURCES,
            NULL);
    #endif
        TRCERR(" Server Session Table Overflow - Refusing Connection");
        nsClose(newSocket);
        return FALSE;
#else
        NQ_UINT stepIdx = 0;        /* Index of the oldest inactive session so far */ 
        NQ_TIME stepTime = (NQ_TIME)-1;  /* Last activity time of the */  

        /* no more connections may be accepted - 
         * close the connection with the latest activity 
         */
        for (idx = 0; idx < UD_FS_NUMSERVERSESSIONS; idx++)
        {
            if (stepTime == -1 || stepTime > staticData->clientSockets[idx].lastActivityTime)
            {
                stepTime = staticData->clientSockets[idx].lastActivityTime;
                stepIdx = idx;
            }
        }

        csReleaseSessions(staticData->clientSockets[stepIdx].socket , FALSE);
        nsClose(staticData->clientSockets[stepIdx].socket);
        staticData->clientSockets[stepIdx].socket = NULL;
        idx = stepIdx;
#endif
        
    }
#ifdef UD_NQ_INCLUDEEVENTLOG
    udEventLog(UD_LOG_MODULE_CS,
        UD_LOG_CLASS_CONNECTION,
        UD_LOG_CONNECTION_CONNECT,
        NULL,
        &ip,
        NQ_SUCCESS,
        NULL);
#endif
    /* save the connection socket in an empty slot */
    staticData->clientSockets[idx].socket = newSocket;
    staticData->clientSockets[idx].ip = ip;
    staticData->clientSockets[idx].lastActivityTime = time;
#ifdef UD_NQ_USETRANSPORTNETBIOS
    staticData->clientSockets[idx].requestTimeout = time;
    staticData->clientSockets[idx].requestExpected = isNetBios;
#endif /* UD_NQ_USETRANSPORTNETBIOS */
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: release allocated memory
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

static void
releaseResources(
    void
    )
{
    csFnamesExit();
#ifdef UD_CS_INCLUDEPASSTHROUGH   
    csAuthShutdown();
#endif /* UD_CS_INCLUDEPASSTHROUGH */    
    csNotifyExit();
    csDispatchExit();
#ifdef UD_NQ_INCLUDESMB2
    cs2DispatchExit();
#endif /* UD_NQ_INCLUDESMB2 */
#ifdef UD_NQ_USETRANSPORTNETBIOS
    csStopBrowse();
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_CS_INCLUDERPC
    csDcerpcStop();
#endif /* UD_CS_INCLUDERPC */
    csCloseDatabase();
    syMutexDelete(&staticData->dbGuard);
	if (!staticData->restart)
		nsExit(TRUE);
    udCifsServerClosed(); 
}

/*
 *====================================================================
 * PURPOSE: perform a control command
 *--------------------------------------------------------------------
 * PARAMS:  IN socket with pending UDP 
 *
 * RETURNS: TRUE - continue, FALSE - exit server
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL     
doControl(
    SYSocketHandle sock      
    )
{
    NQ_IPADDRESS ip;            /* IP address */
    NQ_PORT port;               /* port number */
    NQ_BYTE buf[CS_CONTROL_MAXMSG]; /* command buffer */
    NQ_UINT32 code;             /* command code */
    CMBufferReader reader;      /* command parser */
    CMBufferReader writer;      /* command packer */
    NQ_INT i;                   /* just a counter */
    NQ_INT comLen;              /* command length */
    NQ_BOOL res = FALSE;        /* command result */
    
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* read command */
    comLen = syRecvFromSocket(sock, buf, sizeof(buf), &ip, &port);
    if (comLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error receiving control command");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return TRUE;
    }

    /* parse response code */
    cmBufferReaderInit(&reader, buf, (NQ_COUNT)comLen);
    cmBufferReadUint32(&reader, &code);
    
    /* find command */
    for (i = 0; i < sizeof(controlCommands)/sizeof(controlCommands[0]); i++)
    {
        if (controlCommands[i].code == code)
            break;
    }
    
    /* prepare packer */
    cmBufferWriterInit(&writer, buf, sizeof(buf));
    if (i < sizeof(controlCommands)/sizeof(controlCommands[0]))
    {
        res = (*controlCommands[i].processor)(&reader, &writer);
    }
    else
    {
        cmBufferWriteUint32(&writer, NQ_ERR_BADPARAM);
    }
    
    /* send response */
    comLen = sySendToSocket(sock, buf, (NQ_COUNT)(writer.current - buf), &ip, port);
    if (comLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error sending control response");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return TRUE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return res;
}

/*
 *====================================================================
 * PURPOSE: stop the server
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
csStop(
    void
    )
{
    NQ_UINT32 buf = CS_CONTROL_STOP;
#ifndef UD_NQ_USETRANSPORTIPV6     
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
#else   
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_IPADDRESS localhostv6 = CM_IPADDR_LOCAL6;
#endif
    SYSocketHandle sock = 0;                        /* for internal communication */
    NQ_IPADDRESS ip;                            /* server IP in response */
    NQ_PORT port;                               /* server port in response */
    NQ_INT result;                              /* sent/received/select result */
    SYSocketSet  socketSet;                     /* set for reading from this socket */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* create socket */
#ifndef UD_NQ_USETRANSPORTIPV6     
    sock = syCreateSocket(FALSE, CM_IPADDR_IPV4);    /* datagram socket */
#else   
    if (udGetTransportPriority(NS_TRANSPORT_IPV4))
    	 sock = syCreateSocket(FALSE, CM_IPADDR_IPV4);    /* datagram socket */

    if (udGetTransportPriority(NS_TRANSPORT_IPV6))
    {
    	sock = syCreateSocket(FALSE, CM_IPADDR_IPV6);    /* datagram socket */
    	localhost = localhostv6;
    }
#endif      

    if(!syIsValidSocket(sock))       /* error */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create internal communication socket");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return;
    }
    
    /* send command */
    result = sySendToSocket(
            sock, 
            (NQ_BYTE*)&buf, 
            sizeof(buf), 
            &localhost, 
            syHton16(CS_CONTROL_PORT)
            );
    if (result <= 0)
    {
           LOGERR(CM_TRC_LEVEL_ERROR, "Command not sent");
           syCloseSocket(sock);
           LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
           return;
    }
    
    /* receive response */
    syClearSocketSet(&socketSet);
    syAddSocketToSet(sock, &socketSet);
    result = sySelectSocket(
        &socketSet,
        15
        );
    if (result == NQ_FAIL)                 /* error the select failed  */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Select failed");
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return;
    }
    if (result == 0)                /* timeout  */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Select timed out");
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return;
    }
    result = syRecvFromSocket(
        sock,
        (NQ_BYTE*)&buf,
        sizeof(buf),
        &ip,
        &port
        );

    if (result == 0 || result == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Receive failed with result: %d", result);
        syCloseSocket(sock);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return;
    }

    /* close socket */
    syCloseSocket(sock);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return;
}

/* 
 * command processors 
 */

static NQ_BOOL stopServer(CMBufferReader * reader, CMBufferWriter * writer)
{
    cmBufferWriteUint32(writer, NQ_SUCCESS);
    staticData->restart = FALSE;
    return FALSE;
}

static NQ_BOOL restartServer(CMBufferReader * reader, CMBufferWriter * writer)
{
    cmBufferWriteUint32(writer, NQ_SUCCESS);
    staticData->restart = TRUE;
    return FALSE;
}

static NQ_BOOL addShare(CMBufferReader * reader, CMBufferWriter * writer)
{
    const NQ_TCHAR * name;      /* share name */
    const NQ_TCHAR * path;      /* share mapping */
    const NQ_TCHAR * comment;   /* share comment */
    NQ_BOOL isPrinter;          /* TRUE for printer */
    NQ_UINT16 len;              /* string length */
    NQ_STATUS res;              /* result status */
    
    /* parse the command */
    cmBufferReadUint16(reader, &len);
    name = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    cmBufferReadUint16(reader, &len);
    path = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    cmBufferReadUint16(reader, &len);
    isPrinter = len == 1? TRUE : FALSE;
    cmBufferReadUint16(reader, &len);
    comment = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    
    /* perform */
    res = nqAddShare(name, path, isPrinter, comment, NULL);

    /* pack response */
    cmBufferWriteUint32(writer, res == NQ_SUCCESS? NQ_SUCCESS : NQ_ERR_ERROR);
    
    return TRUE;
}

static NQ_BOOL removeShare(CMBufferReader * reader, CMBufferWriter * writer)
{
    const NQ_TCHAR * name;      /* share name */
    NQ_UINT16 len;              /* string length */
    NQ_STATUS res;              /* result status */
    
    /* parse the command */
    cmBufferReadUint16(reader, &len);
    name = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    
    /* perform */
    res = nqRemoveShare(name);

    /* pack response */
    cmBufferWriteUint32(writer, res == NQ_SUCCESS? NQ_SUCCESS : NQ_ERR_ERROR);
    
    return TRUE;
}

static NQ_BOOL enumShares(CMBufferReader * reader, CMBufferWriter * writer)
{
    NQ_UINT32 res;              /* result status */
    NQ_UINT16 index;            /* index */
    const CSShare *share;       /* pointer to share slot */

    TRCB();
    
    /* parse the command */
    cmBufferReadUint16(reader, &index);
        
    /* perform */
    res = (share = csGetShareByIndex(index)) != NULL ? NQ_SUCCESS : NQ_ERR_ERROR;

    /* pack response */
    cmBufferWriteUint32(writer, res);
    if (res == NQ_SUCCESS)
    {
        cmBufferWriteUint16(writer, (NQ_UINT16)cmTStrlen(share->name));
        cmBufferWriteTString(writer, share->name);
        cmBufferWriteUint16(writer, (NQ_UINT16)cmTStrlen(share->map));
        cmBufferWriteTString(writer, share->map);
        cmBufferWriteUint16(writer, share->isPrintQueue ? 1 : 0);
        cmBufferWriteUint16(writer, (NQ_UINT16)cmTStrlen(share->description));
        cmBufferWriteTString(writer, share->description);
    }
    TRCE();
    return TRUE;
}

#ifdef UD_CS_INCLUDELOCALUSERMANAGEMENT

static NQ_BOOL addUser(CMBufferReader * reader, CMBufferWriter * writer)
{
    const NQ_TCHAR* name;       /* logon name */
    const NQ_TCHAR* fullName;   /* full name */
    const NQ_TCHAR* description;/* user descripton */
    const NQ_TCHAR* password;   /* password */
    NQ_BOOL isAdmin;            /* TRUE for Admistrator rights */
    NQ_UINT16 len;              /* string length */
    NQ_STATUS res;              /* result status */
    NQ_UINT32 rid;              /* user RID */
    NQ_WCHAR passwordW[CM_BUFFERLENGTH(NQ_WCHAR, 256)];

    
    /* parse the command */
    cmBufferReadUint16(reader, &len);
    name = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    cmBufferReadUint16(reader, &len);
    fullName = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    cmBufferReadUint16(reader, &len);
    description = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    cmBufferReadUint16(reader, &len);
    password = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    cmBufferReadUint16(reader, &len);
    isAdmin = len == 1? TRUE : FALSE;
    
    /* perform */
    res = udCreateUser(name, fullName, description);
    if (res)
    {
        res = udGetUserRidByName(name, &rid);
    }
    if (res)
    {
        cmTcharToUnicode(passwordW, password);
        res = udSetUserInfo(rid, name, fullName, description, passwordW);
    }
    if (res)
    {
        res = udSetUserAsAdministrator(rid, isAdmin);
    }

    /* pack response */
    cmBufferWriteUint32(writer, res? NQ_SUCCESS : NQ_ERR_ERROR);
    
    return TRUE;
}

static NQ_BOOL removeUser(CMBufferReader * reader, CMBufferWriter * writer)
{
    const NQ_TCHAR * name;      /* user name */
    NQ_UINT16 len;              /* string length */
    NQ_STATUS res;              /* result status */
    NQ_UINT32 rid;              /* user RID */
    NQ_UINT i;                  /* user counter */
    
    /* parse the command */
    cmBufferReadUint16(reader, &len);
    name = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));
    
    /* perform */
    res = udGetUserRidByName(name, &rid);
    if (res)
    {
        res = udDeleteUserByRid(rid);
    }
    
    /* release user from the database */
    for (i = 0; ; i++)
    {
        CSUser* pUser = csGetUserByIndex(i); /* pointer to user descriptor */
        if (NULL == pUser)
            break;
        if (pUser->token.rids[0] == rid)
        {
            csReleaseUser(pUser->uid, TRUE);
            break;
        }
    }
    
    /* pack response */
    cmBufferWriteUint32(writer, res? NQ_SUCCESS : NQ_ERR_ERROR);
    
    return TRUE;
}

static NQ_BOOL cleanUserCons(CMBufferReader * reader, CMBufferWriter * writer)
{
    const NQ_TCHAR * name;      /* user name */
    NQ_UINT16 len;              /* string length */
    NQ_STATUS res;              /* result status */
    NQ_UINT16 isDomainUser;     /* user type */

    /* parse the command */
    cmBufferReadUint16(reader, &isDomainUser);
    cmBufferReadUint16(reader, &len);
    name = (const NQ_TCHAR*)cmBufferReaderGetPosition(reader);
    cmBufferReaderSkip(reader, (NQ_UINT)((NQ_UINT)(len + 1) * sizeof(NQ_TCHAR)));

    /* perform */
    res = nqCleanUserServerConnections(name, isDomainUser);
    
    /* pack response */
    cmBufferWriteUint32(writer, res == NQ_SUCCESS ? NQ_SUCCESS : NQ_ERR_ERROR);
    return TRUE;
}


static NQ_BOOL enumUsers(CMBufferReader * reader, CMBufferWriter * writer)
{
    NQ_UINT16 index;            /* index */
    NQ_UINT32 rid;              /* user RID */
    
    /* parse the command */
    cmBufferReadUint16(reader, &index);
        
    /* perform */
    if (udGetUserInfo(index, &rid, staticData->nameT, staticData->fullNameT, staticData->descriptionT))
    {
        /* pack response */
        cmBufferWriteUint32(writer, NQ_SUCCESS);
        cmBufferWriteUint16(writer, (NQ_UINT16)cmTStrlen(staticData->nameT));
        cmBufferWriteTString(writer, staticData->nameT);
        cmBufferWriteUint16(writer, (NQ_UINT16)cmTStrlen(staticData->fullNameT));
        cmBufferWriteTString(writer, staticData->fullNameT);
        cmBufferWriteUint16(writer, (NQ_UINT16)cmTStrlen(staticData->descriptionT));
        cmBufferWriteTString(writer, staticData->descriptionT);
        cmBufferWriteUint16(writer, ((NQ_INT)rid) < 0 ? 1 : 0);
    }
    else
    {
        /* pack response */
        cmBufferWriteUint32(writer, NQ_ERR_ERROR);
    }

    return TRUE;
}

#endif /* UD_CS_INCLUDELOCALUSERMANAGEMENT */

static NQ_BOOL enumClients(CMBufferReader * reader, CMBufferWriter * writer)
{
	NQ_UINT16 	index;		/* index*/
	NQ_UINT16	count;
	NQ_INT		i;

	cmBufferReadUint16(reader , &index);
	count = index;

	for (i = 0; i < UD_FS_NUMSERVERSESSIONS ; i++)
	{
		CSSession *	pSession;

		pSession = csGetSessionById((CSSessionKey)i);
		if (pSession != NULL)
		{
			if (count == 0 && pSession->key != CS_ILLEGALID)
			{
				NQ_CHAR * ip;
				NQ_WCHAR * ipW;
				ip = (NQ_CHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN* sizeof(NQ_CHAR));
				ipW = (NQ_WCHAR *)cmMemoryAllocate(CM_IPADDR_MAXLEN* sizeof(NQ_WCHAR));
				if (ip == NULL || ipW == NULL)
				{
					cmMemoryFree(ip); /* can handle NULL */
					cmMemoryFree(ipW); /* can handle NULL */
					break;
				}
				cmIpToAscii(ip , &pSession->ip);
				cmAnsiToUnicode(ipW, ip);
				cmBufferWriteUint32(writer, NQ_SUCCESS);
				cmBufferWriteUint16(writer , (NQ_UINT16)syWStrlen(ipW));
				cmBufferWriteUnicode(writer , ipW);
				cmBufferWriteUint16(writer , pSession->smb2);
				cmMemoryFree(ip);
				cmMemoryFree(ipW);
				return TRUE;
			}
			if (pSession->key != CS_ILLEGALID)
				count == 0 ? count = 0 : count--;
		}

	}
	cmBufferWriteUint32(writer, NQ_ERR_ERROR);

	return TRUE;
}

static NQ_BOOL changeEncryptLevel(CMBufferReader * reader, CMBufferWriter * writer)
{
	NQ_UINT16 newLevel;

	cmBufferReadUint16(reader , &newLevel);
	csChangeEncryptionLevel(newLevel);

	cmBufferWriteUint32(writer, NQ_SUCCESS);

	return TRUE;
}

#ifdef UD_CS_MESSAGESIGNINGPOLICY
static NQ_BOOL changeMsgSign(CMBufferReader * reader, CMBufferWriter * writer)
{
	NQ_UINT16 newPolicy;

	cmBufferReadUint16(reader , &newPolicy);
	csSetMessageSigningPolicy((NQ_INT)newPolicy);

	cmBufferWriteUint32(writer, NQ_SUCCESS);

	return TRUE;
}
#endif /*UD_CS_MESSAGESIGNINGPOLICY*/
#endif /* UD_NQ_INCLUDECIFSSERVER */

