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
#include "ndllmnr.h"

#ifdef UD_ND_INCLUDENBDAEMON

/* This code implements the main loop of the Name Daemon and also the start-up and the
   shut-down routines

   The Daemon implements three NetBIOS services: Name, Session and Datagram. */

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
#define ST_LLMNR_RESPONDER	 5

/* service information */

typedef struct
{
    SYSocketHandle socket;
    NQ_UINT type;
    NQ_BOOL tcp;
}
Service;

#define MAX_NUMOFSERVICES  6

/* we use only one receive buffer and only one send buffer since all daemon operations
   are synchronous */

typedef struct
{
    NQ_BOOL exitNow;                        /* TRUE signals to the daemon to stop execution */
    NQ_BOOL configurationChanged;           /* signal that the list of adapters has changed */
    NDAdapterInfo configChangeRequestorAdapter; /* Adapter info of the requestor requestion configuration change */
    NDAdapterInfo internalAdapter;          /* "dummy" adapter for internal communications  */
    NQ_UINT numOfServices;                  /* actual number of services */
    NQ_BYTE recv[CM_NB_DATAGRAMBUFFERSIZE]; /* receive buffer */
    NQ_BYTE send[CM_NB_DATAGRAMBUFFERSIZE]; /* send buffer */
    Service services[MAX_NUMOFSERVICES];    /* service table */
    NQ_COUNT nextTimeout;                   /* next Select timeout */
    NQ_UINT32 lastTime;                       /* timestamp before select */
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
    NQ_BOOL result = FALSE;
    Service *s = &staticData->services[index];

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "index:%u type:%u ip:%p port:%u tcp:%s", index, type, ip, port, tcp ? "TRUE" : "FALSE");

    s->type = type;
    s->tcp = tcp;

    s->socket = syCreateSocket(tcp, CM_IPADDR_IPV4);
    if (!syIsValidSocket(s->socket))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "NBD: unable to create socket");
        goto Exit;
    }

    if (syBindSocket(s->socket, ip, syHton16((NQ_UINT16)port)) == NQ_FAIL)
    {
        syCloseSocket(s->socket);
        LOGERR(CM_TRC_LEVEL_ERROR, "Error binding socket");
        /* this socket will be closed by calling cleanup() if this function returns FALSE */
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: unable to bind socket on port %d", port);
        goto Exit;
    }
#ifdef UD_NQ_USETRANSPORTIPV4
    if (type == ST_LLMNR_RESPONDER)
    {
    	NQ_IPADDRESS	llmnrIP4;

    	cmAsciiToIp((NQ_CHAR *)"224.0.0.252", &llmnrIP4);
		sySubscribeToMulticast(s->socket , &llmnrIP4);
		ndLLMNRSetSocket(s->socket);
    }
#endif /* UD_NQ_USETRANSPORTIPV4 */
    if (tcp && syListenSocket(s->socket, 10) == NQ_FAIL)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: unable to start listening on port %d", port);
        goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: [%1d] service of type %d, socket %d", index, s->type, s->socket);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD:     TCP flag: %d, port: %d", s->tcp, port);
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    if (NULL == staticData)
    {
        goto Exit;
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

    /* release memory before nsExit which closes memory module */
#ifdef SY_FORCEALLOCATION
	if (NULL != staticData)
		cmMemoryFree(staticData);

	staticData = NULL;
#endif /* SY_FORCEALLOCATION */
    
    nsExit(FALSE);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: process configuration change by reloading list of adapters
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeeded, FALSE otherwise
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
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    /* load/reload the list of adapters */

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Loading list of adapters:");

    staticData->configurationChanged = FALSE;

    if (ndAdapterListLoad() == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to load the list of adapters");
        goto Exit;
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
    }

    /* Register all names over a new adapter, or new WINS servers:
     * NDINNAME will decide whether to register a name (NEW) or just to
     * reorganize structures (OLD) */
    ndConfigChangeRegisterAllNames(&staticData->configChangeRequestorAdapter);

    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}



/*
 *====================================================================
 * PURPOSE: initialize the daemon
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: TRUE if succeeded, FALSE otherwise
 *
 * NOTES:   creates all the services, initializes names
 *====================================================================
 */

static NQ_BOOL
initialize(
    void
    )
{
    NQ_IPADDRESS anyIP = CM_IPADDR_ANY4 , localHost = CM_IPADDR_LOCAL;
    NQ_UINT i;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	if (NQ_FAIL == nsInit(FALSE))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "NS initialization failed");
		goto Exit;
	}

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));

    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate NetBIOS daemon tables");
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    syMutexCreate(&staticData->mutex);

    staticData->numOfServices = 0;
    staticData->configurationChanged = TRUE;
    staticData->nextTimeout = UD_ND_DAEMONTIMEOUT;
    staticData->exitNow = FALSE;

    for (i = 0; i < MAX_NUMOFSERVICES; i++)
        staticData->services[i].socket = syInvalidSocket();

    if (ndDatagramInit() == NQ_FAIL || ndNameInit() == NQ_FAIL || ndAdapterListInit() == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to initialize datagram, name or adapter module");
        goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: creating services");

    if (createService(staticData->numOfServices++, ST_EXTERNALNAME, &anyIP, CM_IN_NAMESERVICEPORT, FALSE) &&
        createService(staticData->numOfServices++, ST_EXTERNALDATAGRAM, &anyIP, CM_IN_DATAGRAMSERVICEPORT, FALSE) &&
#ifdef UD_NB_RETARGETSESSIONS
        createService(staticData->numOfServices++, ST_EXTERNALSESSION, &anyIP, CM_IN_SESSIONSERVICEPORT, TRUE) &&
#endif /* UD_NB_RETARGETSESSIONS */
        createService(staticData->numOfServices++, ST_INTERNALNAME, &localHost, CM_IN_INTERNALNSPORT, FALSE) &&
        createService(staticData->numOfServices++, ST_INTERNALDATAGRAM, &localHost, CM_IN_INTERNALDSPORT, FALSE)
#ifdef UD_NQ_USETRANSPORTIPV4
        &&	createService(staticData->numOfServices++, ST_LLMNR_RESPONDER, &anyIP , LLMNR_PORT, FALSE)
#endif /* UD_NQ_USETRANSPORTIPV4 */
    	)
    {
    	staticData->internalAdapter.ip = 0;
        staticData->internalAdapter.inMsg = staticData->recv;
        staticData->internalAdapter.outMsg = staticData->send;
        staticData->internalAdapter.nsSocket = staticData->services[staticData->numOfServices - 2].socket;
        staticData->internalAdapter.dsSocket = staticData->services[staticData->numOfServices - 1].socket;
#ifdef UD_NB_RETARGETSESSIONS
        staticData->internalAdapter.ssSocket = staticData->services[staticData->numOfServices - 3].socket;
#endif /* UD_NB_RETARGETSESSIONS */

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: initializing names");

        if (!processConfigChange())
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to load adapters");
            goto Exit;
        }

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: calling user processing: udNetBiosDaemonStarted()");

        udNetBiosDaemonStarted();

        result = TRUE;
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/*
*====================================================================
* PURPOSE: main daemon loop
*--------------------------------------------------------------------
* PARAMS:  pointer to semaphore
*
* RETURNS: NQ_SUCCESS or NQ_FAIL
*
* NOTES:
*====================================================================
*/

NQ_STATUS
ndStart(
	SYSemaphore * sem
)
{
	SYSocketSet sockset;       				/* the socket set to select from */
	NQ_UINT i;
	NQ_STATUS result = NQ_FAIL;
	NQ_BOOL exitNowflg = FALSE;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sem:%p", sem);

	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "====> Name Daemon is starting up");

	/* One-time initialization */

	if (!initialize())
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "NBD: initialization failed");
		if (NULL != sem)
		{
			sySemaphoreGive(*sem);
		}
		goto Exit;
	}
	if (NULL != sem)
	{
		sySemaphoreGive(*sem);
	}

	/* infinite loop until the application is shut down */

    while(1)
    {
        syMutexTake(&staticData->mutex);
        exitNowflg = staticData->exitNow;
        syMutexGive(&staticData->mutex);

        if (exitNowflg)
        {
            goto Exit;
        }

        if (staticData->configurationChanged && !processConfigChange())
        {
            udNetBiosDaemonClosed();
            goto Exit;
        }

        /* build socket set */
        syClearSocketSet(&sockset);

        for (i = 0; i < staticData->numOfServices; i++)
            syAddSocketToSet(staticData->services[i].socket, &sockset);

        /* SELECT on the socket set */

        staticData->lastTime = (NQ_UINT32)syGetTimeInSec();

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBDaemon select (timeout - %d)", staticData->nextTimeout);
        switch (sySelectSocket(&sockset, staticData->nextTimeout))
        {
            /* error */
            case NQ_FAIL:
                LOGERR(CM_TRC_LEVEL_ERROR, "Select error");
                goto Exit;

            /* timeout */
            case 0:
                /* process timeout in name resolving and TTLs */
                staticData->nextTimeout = ndNameProcessTimeout((NQ_INT)((NQ_UINT32)syGetTimeInSec() - staticData->lastTime));
                staticData->lastTime = (NQ_UINT32)syGetTimeInSec();
                break;

            /* data in or socket to accept */
            default:
                /* call user defined processing */
                udNetBiosDataIn();
                
                if (syGetTimeInSec() >= (NQ_UINT32)(staticData->lastTime + staticData->nextTimeout))
                {
                    /* time expired - process timeout in name resolving and TTLs */
                    staticData->nextTimeout = ndNameProcessTimeout((NQ_INT)((NQ_UINT32)syGetTimeInSec() - staticData->lastTime));
                    staticData->lastTime = (NQ_UINT32)syGetTimeInSec();
                }
                else
                {
                    staticData->nextTimeout -= (NQ_COUNT)((NQ_UINT32)syGetTimeInSec() - staticData->lastTime);
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
                                a->inLen = (NQ_UINT)received;
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
									LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: UDP external name packet, %d bytes from %s", received, cmIPDump(&ip));
									ndNameProcessExternalMessage(a);
									break;

								case ST_EXTERNALDATAGRAM:
									LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: UDP external datagram packet, %d bytes from %s", received, cmIPDump(&ip));
									ndDatagramProcessExternalMessage(a);
									break;

								case ST_INTERNALNAME:
									LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: UDP internal name packet, %d bytes from %s", received, cmIPDump(&ip));
									ndNameProcessInternalMessage(a);
									break;
								case ST_INTERNALDATAGRAM:
									LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: UDP internal datagram packet, %d bytes from %s", received, cmIPDump(&ip));
									ndDatagramProcessInternalMessage(a);
									break;
#ifdef UD_NQ_USETRANSPORTIPV4
								case ST_LLMNR_RESPONDER:
									LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: LLMNR UDP external name packet, %d bytes from %s", received, cmIPDump(&ip));
									ndLLMNRProcessExternalMessage(a);
									break;
#endif /* UD_NQ_USETRANSPORTIPV4 */

								default:
									LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NBD: UDP service type %d", s->type);
									break;
							}
						}
                    }
                }
        }
    }
    }

    result = NQ_SUCCESS;

Exit:
    cleanup();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", result);
    return result;
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
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (staticData != NULL)
    {
        syMutexTake(&staticData->mutex);
        staticData->exitNow = TRUE;
        syMutexGive(&staticData->mutex);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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
	NDAdapterInfo* adapter)
{
	staticData->configurationChanged = TRUE;
    staticData->configChangeRequestorAdapter = *adapter;
}

#endif /* UD_ND_INCLUDENBDAEMON */

