/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : The main loop of the Name Daemon
 *--------------------------------------------------------------------
 * MODULE        : ND - Name Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndapi.h"
#include "nsapi.h"

#include "ndnampro.h"
#include "ndadaptr.h"
#include "nddatpro.h"
#include "ndsespro.h"
#include "ndinname.h"
#include "ndexname.h"

#ifdef UD_ND_INCLUDENBDAEMON

/* This code implements the main loop of the Name Daemon and also the start-up and the
   shut-down routines

   The Daemon implements three NetBIOS services: Name, Session and Datagram.
   The Session Service, however may be implemented outside the daemon, providing that
   there is only one server application on the target machine (CUFS server). This options
   is controlled by the UD_NB_RETARGETSESSIONS definition. When not defined, the Session
   Service code is not compiled. */

/*
    Static data & functions
    -----------------------
 */

/* service types */

#define ST_EXTERNALNAME      0   /* external name service */
#define ST_EXTERNALDATAGRAM  1   /* external datagram service */
#define ST_EXTERNALSESSION   2   /* external session service */
#define ST_INTERNALNAME      3   /* internal name service */
#define ST_INTERNALDATAGRAM  4   /* internal datagram service */

/* service information */

typedef struct
{
    SYSocketHandle socket;
    NQ_UINT type;
    NQ_BOOL tcp;
}
Service;

#define MAX_NUMOFSERVICES  5

/* we use only one receive buffer and only one send buffer since all daemon operations
   are synchronous */

typedef struct
{
    NQ_BOOL exitNow;                        /* TRUE signals to the daemon to stop execution */
    NQ_BOOL configurationChanged;           /* signal that the list of adapters has changed */
    NDAdapterInfo internalAdapter;          /* "dummy" adapter for internal communications  */
    NQ_UINT numOfServices;                  /* actual number of services */
    NQ_BYTE recv[CM_NB_DATAGRAMBUFFERSIZE]; /* receive buffer */
    NQ_BYTE send[CM_NB_DATAGRAMBUFFERSIZE]; /* send buffer */
    Service services[MAX_NUMOFSERVICES];    /* service table */
    NQ_COUNT nextTimeout;                   /* next Select timeout */
    NQ_TIME lastTime;                       /* timestamp before select */
    SYMutex mutex;                          /* mutex for cleanup synchronization */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/*
 *====================================================================
 * PURPOSE: create service
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeded, FALSE otherwise
 *
 * NOTES:   create service socket, bind and optionally listen on it
 *====================================================================
 */

static NQ_BOOL
createService(
    NQ_UINT index,
    NQ_UINT type,
    NQ_IPADDRESS *ip,
    NQ_UINT port,
    NQ_BOOL tcp
    )
{
    Service *s = &staticData->services[index];

    TRCB();

    s->type = type;
    s->tcp = tcp;

    s->socket = syCreateSocket(tcp, CM_IPADDR_IPV4);
    if (!syIsValidSocket(s->socket))
    {
        TRCERR("NBD: unable to create socket");
        TRCE();
        return FALSE;
    }

    if (syBindSocket(s->socket, ip, syHton16((NQ_UINT16)port)) == NQ_FAIL)
    {
        syCloseSocket(s->socket);
        TRCERR("Error binding socket");
        /* this socket will be closed by calling cleanup() if this function returns FALSE */
        TRC1P("NBD: unable to bind socket on port %d", port);
        TRCE();
        return FALSE;
    }

    if (tcp && syListenSocket(s->socket, 10) == NQ_FAIL)
    {
        TRC1P("NBD: unable to start listening on port %d", port);
        TRCE();
        return FALSE;
    }

    TRC3P("NBD: [%1d] service of type %d, socket %d", index, s->type, s->socket);
    TRC2P("NBD:     TCP flag: %d, port: %d", s->tcp, port);

    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: clean up daemon resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeded, FALSE otherwise
 *
 * NOTES:   close service sockets, release names
 *====================================================================
 */

static void
cleanup(
    void
    )
{
    NQ_UINT i;

    TRCB();
    
    if (NULL == staticData)
    {
        TRCE();
        return;
    }

    /* synchronize: this code should allow ndStop() to finish before
       the execution flow will reach beyond this point */
    syMutexTake(&staticData->mutex);
    syMutexGive(&staticData->mutex);

    if (staticData->exitNow == TRUE)    /* otherwise - already done */
    { 
        ndInternalNameReleaseAllNames(TRUE);
    
        /* close open sockets for all active services */
        for (i = 0; i < staticData->numOfServices; i++)
            if (staticData->services[i].socket != syInvalidSocket())
            {
                syCloseSocket(staticData->services[i].socket);
                staticData->services[i].socket = syInvalidSocket();
            }
    
        staticData->numOfServices = 0;
    }

    ndAdapterListStop();

    udNetBiosDaemonClosed();

    ndDatagramStop();
    ndNameStop();
    syMutexDelete(&staticData->mutex);

    nsExit(FALSE);
	
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
 * PURPOSE: process configuration change by reloading list of adapters
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeded, FALSE otherwise
 *
 * NOTES:   called when configurationChanged set to TRUE
 *====================================================================
 */

static NQ_BOOL
processConfigChange(
    void
    )
{
    NDAdapterInfo *adapter;

    TRCB();
    /* load/relload the list of adapters */

    TRC("Loading list of adapters:");

    staticData->configurationChanged = FALSE;

    if (ndAdapterListLoad() == NQ_FAIL)
    {
        TRCERR("Unable to load the list of adapters");
        TRCE();
        return FALSE;
    }

    /* compose origins: 1) adapter sockets 2) internal communication
       sockets */

    /* adapter sockets (server listening sockets) */

    while ((adapter = ndAdapterGetNext()) != NULL)
    {
        adapter->inMsg = staticData->recv;
        adapter->outMsg = staticData->send;
        adapter->nsSocket = staticData->services[ST_EXTERNALNAME].socket;
        adapter->dsSocket = staticData->services[ST_EXTERNALDATAGRAM].socket;
#ifdef UD_NB_RETARGETSESSIONS
        adapter->ssSocket = staticData->services[ST_EXTERNALSESSION].socket;
#endif /* UD_NB_RETARGETSESSIONS */

        /* register all internal names over a new adapter: NDINNAME will deside
           whether to register a name (NEW) or just to reorganize structures
           (OLD) */
        ndInternalNameRegisterAllNames(NULL, adapter);
    }

    TRCE();    
    return TRUE;
}


/*
 *====================================================================
 * PURPOSE: initialize the daemon
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeded, FALSE otherwise
 *
 * NOTES:   creates all the services, initializes names
 *====================================================================
 */

static NQ_BOOL
initialize(
    void
    )
{
    NQ_IPADDRESS anyIP = CM_IPADDR_ANY4;
    NQ_UINT i;

    TRCB();

    nsInit(FALSE);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));

    if (NULL == staticData)
    {
        TRCERR("Unable to allocate NetBIOS daemon tables");
        TRCE();
        return FALSE;
    }
#endif /* SY_FORCEALLOCATION */

    syMutexCreate(&staticData->mutex);

    staticData->numOfServices = 0;
    staticData->configurationChanged = TRUE;
    staticData->nextTimeout = UD_ND_DAEMONTIMEOUT;

    for (i = 0; i < MAX_NUMOFSERVICES; i++)
        staticData->services[i].socket = syInvalidSocket();

    if (ndDatagramInit() == NQ_FAIL || ndNameInit() == NQ_FAIL || ndAdapterListInit() == NQ_FAIL)
    {
        TRCERR("Unable to initialize datagram datagram, name or adapter module");
        TRCE();
        return FALSE;
    }

    TRC("NBD: creating services");

    if (createService(staticData->numOfServices++, ST_EXTERNALNAME, &anyIP, CM_IN_NAMESERVICEPORT, FALSE) &&
        createService(staticData->numOfServices++, ST_EXTERNALDATAGRAM, &anyIP, CM_IN_DATAGRAMSERVICEPORT, FALSE) &&
#ifdef UD_NB_RETARGETSESSIONS
        createService(staticData->numOfServices++, ST_EXTERNALSESSION, &anyIP, CM_IN_SESSIONSERVICEPORT, TRUE) &&
#endif /* UD_NB_RETARGETSESSIONS */
        createService(staticData->numOfServices++, ST_INTERNALNAME, &anyIP, CM_IN_INTERNALNSPORT, FALSE) &&
        createService(staticData->numOfServices++, ST_INTERNALDATAGRAM, &anyIP, CM_IN_INTERNALDSPORT, FALSE))
    {
        staticData->internalAdapter.inMsg = staticData->recv;
        staticData->internalAdapter.outMsg = staticData->send;
        staticData->internalAdapter.nsSocket = staticData->services[staticData->numOfServices - 2].socket;
        staticData->internalAdapter.dsSocket = staticData->services[staticData->numOfServices - 1].socket;
#ifdef UD_NB_RETARGETSESSIONS
        staticData->internalAdapter.ssSocket = staticData->services[staticData->numOfServices - 3].socket;
#endif /* UD_NB_RETARGETSESSIONS */

        TRC("NBD: initializing names");

        staticData->exitNow = FALSE;
        
        if (!processConfigChange())
        {
            TRCERR("Unable to load adapters");
            TRCE();
            return FALSE;
        }

        TRC("NBD: calling user processing: udNetBiosDaemonStarted()");

        udNetBiosDaemonStarted();

        TRCE();
        return TRUE;
    }

    TRCE();
    return FALSE;
}

/*
 *====================================================================
 * PURPOSE: main daemon loop
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
ndStart(
    void
    )
{
    SYSocketSet sockset;       /* the socket set to select from */
    NQ_UINT i;

    TRCB();

    TRC("====> Name Daemon is starting up");

    /* One-time initialization */

    if (!initialize())
    {
        cleanup();
        TRCERR("NBD: initialization failed");
        TRCE();
        return NQ_FAIL;
    }

    /* infinite loop until the application is shut down */

    while (!staticData->exitNow)
    {       
        if (staticData->configurationChanged && !processConfigChange())
        {
            cleanup();
            udNetBiosDaemonClosed();
            TRCE();
            return NQ_FAIL;
        }

        /* build socket set */

        syClearSocketSet(&sockset);

        for (i = 0; i < staticData->numOfServices; i++)
            syAddSocketToSet(staticData->services[i].socket, &sockset);

        /* SELECT on the socket set */

        staticData->lastTime = (NQ_TIME)syGetTime();

        TRC1P("NBDaemon select (timeout - %d)", staticData->nextTimeout);
        switch (sySelectSocket(&sockset, staticData->nextTimeout))
        {
            /* error */
            case NQ_FAIL:
                cleanup();
                
                TRCERR("Select error");
                TRCE();
                return NQ_FAIL;

            /* timeout */
            case 0:
                /* process timeout in name resolving and TTLs */
                staticData->nextTimeout = ndNameProcessTimeout((NQ_INT)((NQ_TIME)syGetTime() - staticData->lastTime));
                break;

            /* data in or socket to accept */
            default:
                /* call user defined processing */
                udNetBiosDataIn();
                
                if (syGetTime() >= (staticData->lastTime + staticData->nextTimeout))
                {
                    /* time expired - process timeout in name resolving and TTLs */
                    staticData->nextTimeout = ndNameProcessTimeout((NQ_INT)((NQ_TIME)syGetTime() - staticData->lastTime));
                }
                else
                {
                    staticData->nextTimeout -= (NQ_TIME)syGetTime() - staticData->lastTime; 
                }
                staticData->nextTimeout = UD_ND_DAEMONTIMEOUT;
                for (i = 0; i < staticData->numOfServices; i++)
                {
                    Service *s = &staticData->services[i];

                    if (syIsSocketSet(s->socket, &sockset))
                    {
                        NQ_IPADDRESS ip;       /* sender IP */
                        NQ_UINT16 port;        /* sender port */
                        NQ_INT received;       /* number of bytes received from a socket */

#ifdef UD_NB_RETARGETSESSIONS
                        if (s->tcp)
                        {
                            SYSocketHandle h = syAcceptSocket(s->socket, &ip, &port);

                            if (h == syInvalidSocket())
                            {
                                TRCERR("Error in accept");
                                continue;
                            }

                            if ((received = syRecvSocket(h, staticData->recv, sizeof(staticData->recv))) > 0)
                            {
                                NDAdapterInfo *a = ndFindAdapter(CM_IPADDR_GET4(ip), &staticData->internalAdapter);

                                a->newSocket = h;
                                a->inIp = CM_IPADDR_GET4(ip);
                                a->inPort = port;
                                a->inLen = received;
                                a->bcastDest = FALSE;

                                TRC1P("TCP: %d bytes received", received);

                                switch (s->type)
                                {
                                    case ST_EXTERNALSESSION:
                                        TRC("TCP: external session service packet");
                                        ndSessionProcessExternalMessage(a);
                                        break;

                                    default:
                                        TRC1P("TCP: service type %d", s->type);
                                        break;
                                }

                                if (syCloseSocket(h) == NQ_FAIL)
                                {
                                    cleanup();

                                    TRCERR("Unable to close accepted socket");
                                    TRCE();
                                    return NQ_FAIL;
                                }
                            }
                        }
                        else
#endif /* UD_NB_RETARGETSESSIONS */
                        {
                            if ((received = syRecvFromSocket(s->socket, staticData->recv, sizeof(staticData->recv), &ip, &port)) > 0)
                            {
                                NDAdapterInfo *a = ndFindAdapter(CM_IPADDR_GET4(ip), &staticData->internalAdapter);

                                a->inIp = CM_IPADDR_GET4(ip);
                                a->inPort = port;
                                a->inLen = (NQ_UINT)received;
                                a->bcastDest = FALSE;

                                switch (s->type)
                                {
                                    case ST_EXTERNALNAME:
                                        TRC2P("NBD: UDP external name packet, %d bytes from %s", received, cmIPDump(&ip));
                                        ndNameProcessExternalMessage(a);
                                        break;

                                    case ST_EXTERNALDATAGRAM:
                                        TRC2P("NBD: UDP external datagram packet, %d bytes from %s", received, cmIPDump(&ip));
                                        ndDatagramProcessExternalMessage(a);
                                        break;

                                    case ST_INTERNALNAME:
                                        TRC2P("NBD: UDP internal name packet, %d bytes from %s", received, cmIPDump(&ip));
                                        ndNameProcessInternalMessage(a);
                                        break;
                                    case ST_INTERNALDATAGRAM:
                                        TRC2P("NBD: UDP internal datagram packet, %d bytes from %s", received, cmIPDump(&ip));
                                        ndDatagramProcessInternalMessage(a);
                                        break;

                                    default:
                                        TRC1P("NBD: UDP service type %d", s->type);
                                        break;
                                }
                            }
                        }
                    }
                }
        }
    }

    cleanup();
        
    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: stop the daemon
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ndStop(
    void
    )
{
    NQ_INDEX i;     /* just an index */

    TRCB();

    if (staticData != NULL)
    {
        syMutexTake(&staticData->mutex);

        staticData->exitNow = TRUE;

        ndInternalNameReleaseAllNames(TRUE);

        /* close daemon sockets */
        for (i = 0; i < staticData->numOfServices; i++)
        {
            syCloseSocket(staticData->services[i].socket);
            staticData->services[i].socket = syInvalidSocket();
        }

        staticData->numOfServices = 0;

        syMutexGive(&staticData->mutex);
    }
    
    TRCE();
}

/*
 *====================================================================
 * PURPOSE: Tell the ND that the adapter configuration has changed
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ndNotifyConfigurationChange(
    )
{
     /* release all names */
    ndInternalNameReleaseAllNames(FALSE);

    staticData->configurationChanged = TRUE;
}

#endif /* UD_ND_INCLUDENBDAEMON */

