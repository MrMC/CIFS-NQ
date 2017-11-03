/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Name Service functions for internal names
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndinname.h"
#include "ndnampro.h"
#include "ndframes.h"
#include "nsapi.h"
#include "nssessio.h"

#ifdef UD_ND_INCLUDENBDAEMON

/* This source implements routines responsible for operations with internal names.
   Internal names are those registered by the host applications. */

typedef struct                  /* Name entry per adapter - used as a status for
                                   name registration/release process */
{
    const NDAdapterInfo* adapter;      	/* pointer to the adapter structure */
    NQ_INT status;                     	/* name registration/release status (see below) */
    NQ_UINT count;                     	/* repeat counter */
    NQ_UINT timeout;                   	/* time when the next operation on this entry times out -
                                          this value is measured in timeout counts as: <time> / <daemon timeout> and is decreased */
    NQ_UINT ttl;                       	/* the initial value for timeout field */
    NQ_UINT16 tranId;                  	/* last sent trans ID (host format), for comparing with a response in NBO */
    NQ_UINT16 firstTranId;              /* when num wins serveres > 1 we send a few messages and should know hte tran ID range */
    NQ_UINT numPendingRequestsPerAdapter;	/* how many requests sent on this adapter when wins servers > 1  we send additional requests */
} Operation;

/* values for the Status field */

#define OPERATION_NEW               0   /* nothing done yet */
#define OPERATION_REGISTERED_B      1   /* name registered over this adapter */
#define OPERATION_REGISTERED_H      2   /* name registered over this adapter with WINS */
#define OPERATION_RELEASED          3   /* name released over this adapter */
#define OPERATION_INREGISTRATION_H  4   /* ND is sending Name Registration Requests to WINS */
#define OPERATION_INREGISTRATION_B  5   /* ND is sending Name Registration Request broadcasts */
#define OPERATION_INRELEASE_H       6   /* ND is sending Name Release Requests to WINS */
#define OPERATION_INRELEASE_B       7   /* ND is sending Name Release Request broadcasts */
#define OPERATION_PENDINGBCAST		8 	/* failed h registration. will start B registration
											when all other H registrations fail. */
#define OPERATION_ENDNODECHALLENGE  9   /* ND is sending Name Query Requests to a presumed owner */
#define OPERATION_CLAIM             10  /* ND is sending Name Refresh Requests to claim a name */

/* maximum length of a buffer for composing node status, calculated as:
    1) one byte for number of names
    2) 16 byte of name + 2 bytes of flags for each name
    3) the statistics structure */

#define STATUS_DATA_LENGTH  (   \
    1 +                         \
    UD_ND_MAXINTERNALNAMES*(sizeof(CMNetBiosName) + 2) +   \
    sizeof(CMNetBiosNodeStatistics)                                     \
    )

typedef struct                              /* name entry structure */
{
    NQ_INT idx;                             /* index in the list */
    CMNetBiosNameInfo nameInfo;             /* NB name + group flag */
    NQ_UINT16 resPort;                      /* Requester port (internal) */
    NQ_UINT16 resTranId;                    /* Requester tranId */
    const NDAdapterInfo* resAdapter;        /* Requester adapter (dummy) */
    Operation operations[UD_NS_MAXADAPTERS];/* operations per adapter */
    NQ_COUNT regCount;                      /* registration count */
    NQ_COUNT numPendingRequests;			/* on wins registration, reply requester only after all requests were replied or timed out */
    NQ_BOOL isAnyPositiveResponse;			/* was any positivie registration repspose recieved for thie name */
    NQ_BOOL isHRegistrationFailed;		/* is h registration phase done and failed */
    NQ_BOOL increment;                      /* when TRUE regCount increment allowed */
    NQ_BOOL regName;                        /* whether to register this name on the network */
	CMList bindPorts;                       /* list of ports binded with the same name */
}
NameEntry;

typedef struct
{
    NameEntry names[UD_ND_MAXINTERNALNAMES]; /* list of names */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* find name in the list */

static NQ_INT         /* name index or NO_NAME */
findName(
    const CMNetBiosName name    /* the query name */
    );

/* find an empty entry in the list */

static NQ_INT         /* name index or NO_NAME */
findNoName(
    void
    );

/* process Node Status request */

static NQ_STATUS                               /* NQ_SUCCESS or NQ_FAIL */
processNodeStatus(
    const NDAdapterInfo* response,      /* adapter to respond on */
    const CMNetBiosName name            /* name to query */
    );

/* Send different packets:
    Functions whose name starts with "send" are sending packets outside
    Functions whose name starts with "return" are sending packets back to an internal
    Application */

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
sendRegistrationRequest(
    NameEntry* name,                /* name to register */
    const NDAdapterInfo* adapter,   /* adapter to use */
	NQ_BOOL isMultiHome				/* does the host have more than one IP */
    );

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
sendRefreshRequest(
    NameEntry* name,                /* name to register */
    const NDAdapterInfo* adapter    /* adapter to use */
    );

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
sendNegativeWhateverResponse(
    NameEntry* name,                /* name to register */
    const NDAdapterInfo* adapter,   /* adapter to use */
    NQ_UINT opcode,                 /* either QUERY or REGISTRATION */
    NQ_UINT error                   /* error code */
    );

static NQ_STATUS                            /* NQ_SUCCESS or NQ_FAIL */
sendPositiveQueryResponse(
    NameEntry* name,                        /* name to register */
    const NDAdapterInfo* adapter,           /* adapter to use */
    const CMNetBiosAddrEntry* addresses,    /* an array of ADDR ENTRY structures */
    NQ_UINT numAddr                         /* number of those structures */
    );

static NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
sendReleaseRequest(
    NameEntry* name,                /* name to register */
    const NDAdapterInfo* adapter    /* adapter to use */
    );

static NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
sendQueryRequest(
    NameEntry* name,                /* name to register */
    const NDAdapterInfo* adapter,   /* adapter to use */
    NQ_UINT32 ip                    /* the called IP */
    );

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
returnPositiveRegistrationResponse(
    NameEntry* name,                /* name to respond */
    const NDAdapterInfo* adapter    /* adapter whose IP to report on */
    );

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
returnNegativeRegistrationResponse(
    const NameEntry* name,          /* name to respond */
    const NDAdapterInfo* adapter,   /* adapter whose IP to report on */
    NQ_UINT error                   /* error code */
    );

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
returnPositiveReleaseResponse(
    const NameEntry* name,          /* name to respond */
    const NDAdapterInfo* adapter    /* adapter whose IP to report on */
    );

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
returnNegativeReleaseResponse(
    const CMNetBiosName name,       /* name to respond */
    const NDAdapterInfo* response,  /* response adapter */
    const NDAdapterInfo* adapter,   /* adapter whose IP to report on */
    NQ_UINT error                   /* error code */
    );

static NQ_STATUS
findNameAndAdapterForResponse(
	const CMNetBiosName name,		/* name to find */
	NQ_INT *idx,					/* return idx */
	const NDAdapterInfo* adapter,	/* recived adapter */
	const NDAdapterInfo** correctAdapter	/* new found adapter */
	);

/* special values, indicating no value */

#define NO_NAME -1  /* index of an empty name entry */
#define NO_TID 0    /* "no transaction" ID */

/* request operation timeouts measured in daemon cycles */

#define UNICAST_TIMEOUT \
        (CM_NB_UNICASTREQRETRYTIMEOUT + UD_ND_DAEMONTIMEOUT - 1) / UD_ND_DAEMONTIMEOUT
#define BCAST_TIMEOUT   1       /* this is as least as possible */

#if defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE)
static const NQ_CHAR *
formatName(
    const CMNetBiosName name
    )
{
    static NQ_CHAR buffer[(15 * 4) + 4 + 1];
    NQ_CHAR prefix = name[15];
    NQ_INT s, d;

    for (s = 0, d = 0; s < 15; s++)
    {
        if (name[s] != '\0' && name[s] != ' ')
        {
            if (name[s] >= '!')
                buffer[d++] = name[s];
            else
            {
                sySprintf(buffer + d, "<%02x>", (NQ_BYTE)name[s]);
                d += 4;
            }
        }
    }

    sySprintf(buffer + d, "<%02x>", (NQ_BYTE)prefix);

    return buffer;
}
#endif /* defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE) */

/*
 *====================================================================
 * PURPOSE: Initialize this code
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Mark all names as empty slots.
 *====================================================================
 */

NQ_STATUS
ndInternalNameInit(
    void
    )
{
    NQ_UINT idx;       /* index in the names */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate internal Names data");
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        NQ_UINT i;         /* index in operations */

        staticData->names[idx].idx = NO_NAME;
        staticData->names[idx].isAnyPositiveResponse = FALSE;
        staticData->names[idx].isHRegistrationFailed = FALSE;
        staticData->names[idx].numPendingRequests = 0;
        for (i = 0; i < UD_NS_MAXADAPTERS; i++)
        {
        	staticData->names[idx].operations[i].status = OPERATION_NEW;
            staticData->names[idx].operations[i].tranId = NO_TID;
            staticData->names[idx].operations[i].firstTranId = NO_TID;
            staticData->names[idx].operations[i].numPendingRequestsPerAdapter = 0;
	        cmListStart(&staticData->names[idx].bindPorts);
            staticData->names[idx].increment = FALSE;
            syMemset(staticData->names[idx].nameInfo.name, 0, sizeof(staticData->names[idx].nameInfo.name));
        }
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: release internal data
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ndInternalNameStop(
    void
    )
{
    NQ_UINT idx;       /* index in the names */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	for (idx = 0; idx < sizeof(staticData->names) / sizeof(staticData->names[0]); idx++)
	{
		cmListShutdown(&staticData->names[idx].bindPorts);
	}

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
 * PURPOSE: Find a port bound to an internal name
 *--------------------------------------------------------------------
 * PARAMS:  IN: name to look for
 *
 * RETURNS: port number (in NBO) or -1 when name was not found
 *
 * NOTES:   A name may either exist or not
 *====================================================================
 */
CMList *
ndInternalNameGetPort(
    const CMNetBiosName name
    )
{
    NQ_INT idx;           /* index in names */
    CMList *pResult = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s", formatName(name));

    /* find name in the list */
    idx = findName(name);
    if (idx == NO_NAME)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Name not found: %s", formatName(name));
        goto Exit;
    }
    pResult = &staticData->names[idx].bindPorts;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
	return pResult;
}

static void handlePositiveRegistration(
		NameEntry* name,
	    const NDAdapterInfo* adapter
	    )
{
	NQ_INT j;

	returnPositiveRegistrationResponse(name, adapter);
	/* switch all relevant adapters to registred state */
	for (j = 0; j < UD_NS_MAXADAPTERS; j++)
	{
		if (OPERATION_INREGISTRATION_H == name->operations[j].status ||
			OPERATION_PENDINGBCAST == name->operations[j].status ||
			OPERATION_INREGISTRATION_B == name->operations[j].status)
		{
			name->operations[j].status = OPERATION_REGISTERED_H;
			name->operations[j].tranId = name->operations[j].firstTranId = NO_TID;
			name->operations[j].timeout = name->operations[j].ttl;
		}
	}
}


/*
 *====================================================================
 * PURPOSE: Set a port bound to an internal name
 *--------------------------------------------------------------------
 * PARAMS:  IN: name to look for
 *          IN: bound port
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL when name was not found
 *
 * NOTES:   A name may either exist or not
 *====================================================================
 */

NQ_STATUS
ndInternalNameSetPort(
    const CMNetBiosName name,
    NQ_UINT16 port
    )
{
    NQ_INT idx;           /* index in names */
    BindPort *bindPort;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s port:%u", formatName(name), port);

    /* find name in the list */
    idx = findName(name);
    if (idx == NO_NAME)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Name not found: %s", formatName(name));
        goto Exit;
    }

    if (port != 0)
	{
		bindPort = (BindPort *)cmListItemCreateAndAdd(&staticData->names[idx].bindPorts, sizeof(BindPort), NULL, NULL, FALSE);
		if (NULL != bindPort)
		{
			bindPort->port = port;
		}
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Set port for name: %s, port: 0x%x", formatName(name), port);
	}
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Start registering a name over a specific adapter
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter to response to "dummy"
 *          IN: adapter to register over
 *          IN: name to register
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name may either exist or not. If not exist - we create it.
 *====================================================================
 */

static NQ_STATUS
ndInternalNameRegister(
    const NDAdapterInfo* response,
    const NDAdapterInfo* adapter,
    NQ_INDEX nameIndex,
	NQ_BOOL isMultiHome
    )
{
    NQ_STATUS result = NQ_SUCCESS;
    NameEntry *name = &staticData->names[nameIndex];
    Operation *operation = &name->operations[adapter->idx];

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p adapter:%p nameIndex:%u", response, adapter, nameIndex);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Registering name %s on adapter %d", formatName(name->nameInfo.name), adapter->idx);

    operation->adapter = adapter;
    name->resAdapter = response;

    if (NULL != response)
    {
        name->resPort = response->inPort;
        name->resTranId = response->inTranId;
    }

    /* check the name postfix and determine whether to register this name on the network */

#ifdef UD_NB_INCLUDENAMESERVICE
    switch ((NQ_BYTE)name->nameInfo.name[15])
    {
    case 0x20:
        name->regName = TRUE;
        break;
    case 0x1:
    case 0xFF:
        name->regName = FALSE;
        break;
    default:
        name->regName = TRUE;
        break;
    }
#else  /* UD_NB_INCLUDENAMESERVICE */
    name->regName = FALSE;
#endif /* UD_NB_INCLUDENAMESERVICE */
#ifdef UD_CM_DONOTREGISTERHOSTNAMENETBIOS
    name->regName = FALSE;
#endif

    if (syStrlen(name->nameInfo.name) == 0 || name->nameInfo.name[0] == ' ')
    {
    	name->regName = FALSE;
    	operation->status = OPERATION_REGISTERED_B;
    	returnNegativeRegistrationResponse(name, adapter, CM_NB_RCODE_NAMERR);
        goto Exit;
    }
    if (!name->regName)
    {
        /* do not register on the network: mark this name as virtually registered so far */
        operation->status = OPERATION_REGISTERED_B;
        returnPositiveRegistrationResponse(name, adapter);
        goto Exit;
    }

    switch (operation->status)
    {
    case OPERATION_NEW:
    case OPERATION_RELEASED:
        break;          /* valid status - send request */
    case OPERATION_REGISTERED_B:
    case OPERATION_REGISTERED_H:
        returnPositiveRegistrationResponse(name, adapter);
        goto Exit;
    case OPERATION_INRELEASE_H:
    case OPERATION_INRELEASE_B:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "An attempt to register a name (%s) that is being released", formatName(name->nameInfo.name));
        returnNegativeRegistrationResponse(name, adapter, CM_NB_RCODE_NAMERR);
        goto Exit;
    default:
        /* do nothing - operation already in progress */
        goto Exit;
    }

    if (adapter->typeB)
    {
        operation->status = OPERATION_INREGISTRATION_B;
        operation->timeout = BCAST_TIMEOUT;
    }
    else
    {
        operation->status = OPERATION_INREGISTRATION_H;
        operation->timeout = UNICAST_TIMEOUT;
    }

    operation->count = CM_NB_UNICASTREQRETRYCOUNT;
    operation->ttl = CM_NB_UNICASTREQRETRYTIMEOUT;

    sendRegistrationRequest(name, adapter, isMultiHome);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Start registering all existing internal names over a
 *          specific adapter
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter to response to "dummy"
 *          IN: adapter to register over
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   If the adapter is an old one - just reorganize the Operation array
 *          for this name. If it is a new one - start name registration
 *          This function should be called subsequently (and not interruptibly)
 *          for all adapters. Thus, these calls should reorganize the list
 *          operations for each of the names.
 *====================================================================
 */

NQ_STATUS
ndConfigChangeRegisterAllNames(
    const NDAdapterInfo* response
    )
{
    NQ_INDEX idx;       /* index in the names */
    NDAdapterInfo *adapter;
    NQ_BOOL isMultiHome;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p ", response);

    isMultiHome = ndGetNumAdapters() > 1;

    /* iterate and register all names  */
	for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
	{
		/* iterate and register each name per adapter */
		if (staticData->names[idx].idx != NO_NAME)
		{
			/* init name DB*/
			staticData->names[idx].isAnyPositiveResponse = FALSE;
			staticData->names[idx].isHRegistrationFailed = FALSE;
			staticData->names[idx].numPendingRequests = 0;

			while ((adapter = ndAdapterGetNext()) != NULL)
			{
				/* when registering on WINS (OPERATION_INREGISTRATION_H == specific IP Address) we register
				  each name per adapter = unicast else we send broadcast "registration" per adapter */
				const NDAdapterInfo* pResponse;

				/* init operation (adapter) DB */
				staticData->names[idx].operations[adapter->idx].numPendingRequestsPerAdapter = 0;

				/* Configuration change response (success or fail) will be sent when host name (non group) registration succeeds
				* for group name registration we will not send response
				*/
				if (staticData->names[idx].nameInfo.isGroup)
					pResponse = NULL;
				else
					pResponse = response;

				ndInternalNameRegister(pResponse, adapter, idx, isMultiHome);
			}
		}
	}

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", NQ_SUCCESS);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Start registering a name over all adapters
 *--------------------------------------------------------------------
 * PARAMS:  IN: name to register
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name may either  exist or not. For an existing name we
 *          register it only over those adapters that do not have this name
 *          registered yet
 *====================================================================
 */

NQ_STATUS
ndInternalNameRegisterAllAdapters(
    const NDAdapterInfo* response,
    const CMNetBiosNameInfo* nameInfo
    )
{
    NDAdapterInfo* adapter;
    NQ_INT n = findName(nameInfo->name);
    NQ_UINT regAdapterCount = 0; /* Counter of adapters if its 0 (no adapters) NQND will send a negative response */
    NDAdapterInfo fakeAdpt; /* fake adapter for the negative registration response*/
    NQ_STATUS result = NQ_FAIL;
    NQ_BOOL isMultiHome;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p nameInfo:%p", response, nameInfo);

    if (n == NO_NAME)
    {
        /* create name */
        n = findNoName();

        if (n == NO_NAME)
        {
            goto Exit;
        }

        staticData->names[n].regCount = 0;
        syMemcpy(&staticData->names[n].nameInfo, nameInfo, sizeof(CMNetBiosNameInfo));
    }

    /* init name DB */
    /****************/
    /* allow increasing registration count */
    staticData->names[n].increment = TRUE;
    staticData->names[n].isAnyPositiveResponse = FALSE;
    staticData->names[n].isHRegistrationFailed = FALSE;
    staticData->names[n].numPendingRequests = 0;


    isMultiHome = ndGetNumAdapters() > 1;
    while ((adapter = ndAdapterGetNext()) != NULL)
    {
    	staticData->names[n].operations[adapter->idx].numPendingRequestsPerAdapter = 0;
        ndInternalNameRegister(response, adapter, (NQ_INDEX)n, isMultiHome);
        regAdapterCount++;
    }

	if (regAdapterCount == 0)
	{
		staticData->names[n].resAdapter = response;
		staticData->names[n].resPort = response->inPort;
		staticData->names[n].resTranId = response->inTranId;
		fakeAdpt.ip = (NQ_IPADDRESS4)-1;
		fakeAdpt.typeB = FALSE;
		returnNegativeRegistrationResponse(&staticData->names[n], &fakeAdpt, CM_NB_RCODE_NAMERR);
	}
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Releasing all internal names over all adapters
 *--------------------------------------------------------------------
 * PARAMS:  IN whether to free entry
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Only for those adapters that this name is registered over them
 *====================================================================
 */

NQ_STATUS
ndInternalNameReleaseAllNames(
    const NQ_BOOL doFreeEntry
    )
{
    NQ_UINT idx;   /* index in names */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "doFreeEntry:%s", doFreeEntry ? "TRUE" : "FALSE");

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx != NO_NAME)
        {
            ndInternalNameReleaseAllAdapters(NULL, staticData->names[idx].nameInfo.name, doFreeEntry);
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", NQ_SUCCESS);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Start releasing internal name over all adapters
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter to response over (may be NULL - then no response)
 *          IN: name to release
 *          IN: whether to free entry 
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Only for those adapters that this name is registered over them
 *====================================================================
 */

NQ_STATUS
ndInternalNameReleaseAllAdapters(
    const NDAdapterInfo* response,
    const CMNetBiosName name,
    const NQ_BOOL doFreeEntry
    )
{
    NDAdapterInfo* adapter;    /* next adapter */
    NQ_INT idx;                /* index in names */
    NQ_UINT relAdapterCount = 0; /* Counter of adapters if its 0 (no adapters) nqnd will send a negative response */
    NQ_STATUS result = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p name:%p doFreeEntry:%s", response, name ? name : "", doFreeEntry ? "TRUE" : "FALSE");

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> An attempt to release a non-existing name: %s", formatName(name));

        if (response != NULL)
            returnNegativeReleaseResponse(name, response, response, CM_NB_RCODE_NAMERR);
        goto Exit;
    }

    if (response != NULL)
    {
        staticData->names[idx].resPort = response->inPort;
        staticData->names[idx].resTranId = response->inTranId;
        staticData->names[idx].resAdapter = response;
    }
    else
    {
        staticData->names[idx].resPort = 0;
    }

    if (staticData->names[idx].regCount > 0)
        staticData->names[idx].regCount--;
    
    if (staticData->names[idx].regCount > 0 && doFreeEntry)
    {
        if (response != NULL)
            returnPositiveReleaseResponse(&staticData->names[idx], response);
        goto Exit;
    }
    /* staticData->names[idx].regCount = 0;*/

    while ((adapter = ndAdapterGetNext()) != NULL)
    {
        NQ_INT 	opStatus;  /* operation status */
        NQ_BOOL	skip;
        relAdapterCount++;
        /* validate operation status */

        opStatus = staticData->names[idx].operations[adapter->idx].status;
        skip = FALSE;

        switch (opStatus)
        {
        case OPERATION_NEW:
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "An attempt to release a name (%s) that is not registered yet", formatName(name));

            if (response != NULL)
                returnNegativeReleaseResponse(name, response, adapter, CM_NB_RCODE_NAMERR);
            skip = TRUE;
            break;
        case OPERATION_RELEASED:
            if (response != NULL)
                returnPositiveReleaseResponse(&staticData->names[idx], adapter);
            skip = TRUE;
            break;
        case OPERATION_REGISTERED_B:
        case OPERATION_INREGISTRATION_B:
            opStatus = OPERATION_INRELEASE_B;
            break;          /* valid status */
        case OPERATION_REGISTERED_H:
        case OPERATION_INREGISTRATION_H:
            opStatus = OPERATION_INRELEASE_H;
            break;          /* valid status */
        default:
            skip = TRUE;
            break;
        }

        if (!skip)
        {
			staticData->names[idx].operations[adapter->idx].status = opStatus;

			if (staticData->names[idx].regName)
			{
				sendReleaseRequest(&staticData->names[idx], adapter);
			}

			staticData->names[idx].operations[adapter->idx].status = OPERATION_NEW;
        }
    }

    if (response != NULL)
    {
    	if (relAdapterCount > 0)
    	{
    		returnPositiveReleaseResponse(&staticData->names[idx], response);
    	}
    	else
    	{
    		returnNegativeReleaseResponse(name, response, response, CM_NB_RCODE_NAMERR);
    	}
    }


    /* free entry in names table for released name*/
    if (doFreeEntry)
        staticData->names[idx].idx = NO_NAME;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Process incoming query request to an internal name or node status
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the request
 *          IN: name to query
 *          IN: address of the data after the name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   We dispatch this request according to its question type
 *====================================================================
 */

NQ_STATUS
ndInternalNameWhateverQuery(
    const NDAdapterInfo* response,
    const CMNetBiosName name,
    const NQ_BYTE* addData
    )
{
    const CMNetBiosQuestion* pQuestion; /* casted pointer to a question record */
    NQ_STATUS ret = NQ_FAIL;            /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p name:%p addData:%p", response, name, addData);

    pQuestion = (CMNetBiosQuestion*)addData;

    switch (syNtoh16(cmGetSUint16(pQuestion->questionType)))
    {
    case CM_NB_RTYPE_NB:
        ret = ndInternalProcessNameQuery(response, name, FALSE);
        break;
    case CM_NB_RTYPE_NBSTAT:
        ret = processNodeStatus(response, name);
        break;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", ret);
    return ret;
}

/*
 *====================================================================
 * PURPOSE: Process Positive Registration Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the registered name
 *          IN: the rest of the response packet after the Name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Registration Request
 *          or an End-Node Challenge Response over the same adapter
 *====================================================================
 */

NQ_STATUS
ndInternalNamePositiveRegistration(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name,
    const NQ_BYTE* addData
    )
{
    NQ_INT idx;          /* index in names */
    NQ_STATUS opStatus;  /* operation status */
    NQ_STATUS result = NQ_SUCCESS;
    const NDAdapterInfo* correctAdapter = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p addData:%p", adapter, name, addData);

    /* find name in the list and find correct adapter*/
    if (NQ_FAIL == findNameAndAdapterForResponse(name, &idx, adapter, &correctAdapter))
    	goto Exit;

    /* validate operation status */
    opStatus = staticData->names[idx].operations[correctAdapter->idx].status;

    switch (opStatus)
    {
		case OPERATION_INREGISTRATION_H:
		case OPERATION_CLAIM:
			break;          /* valid status */
		default:
			LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Unexpected Pos Reg Response for name: %s on adapter: %d, state: %d",
					formatName(name), correctAdapter->idx, opStatus);
			goto Exit;
    }

    /* distinguish between Positive Registration Response and End-Node Challenge Response */

    if (syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->packCodes)) & CM_NB_NAMEFLAGS_RA)
    {
		/* calculate TTL */
		{
			const CMNetBiosResourceRecord* resourceRecord;     /* casting to the rest of the packet */
			NQ_UINT32 ttl;                                     /* ttl value */

			resourceRecord = (CMNetBiosResourceRecord*)addData;
			ttl = syNtoh32(cmGetSUint32(resourceRecord->ttl));
			staticData->names[idx].operations[correctAdapter->idx].ttl = (NQ_UINT)(ttl - 1)/UD_ND_DAEMONTIMEOUT;
		}

    	--(staticData->names[idx].operations[correctAdapter->idx].numPendingRequestsPerAdapter);

    	staticData->names[idx].isAnyPositiveResponse = TRUE;

		/* if we sent more then one regitration request for this name we should wait for the last one */
		if (--(staticData->names[idx].numPendingRequests) <= 0)
		{
			/* success */
			handlePositiveRegistration(&staticData->names[idx], correctAdapter);
		}
    }
    else
    {
        const CMNetBiosAddrEntry* addrEntry;         /* to discover the claiming IP */

        /* another node claims to own this name -  start end-node challenge */

        addrEntry = (const CMNetBiosAddrEntry*)(addData + sizeof(CMNetBiosResourceRecord));
        staticData->names[idx].operations[correctAdapter->idx].status = OPERATION_ENDNODECHALLENGE;
        staticData->names[idx].operations[correctAdapter->idx].count = UD_ND_REGISTRATIONCOUNT;
        sendQueryRequest(&staticData->names[idx], correctAdapter, cmGetSUint32(addrEntry->ip));
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Process WACK
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the waiting name
 *          IN: the rest of the response packet after the Name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Registration Request
 *          or an End-Node Challenge Response over the same adapter
 *====================================================================
 */

NQ_STATUS
ndInternalNameWack(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name,
    const NQ_BYTE* addData
    )
{
    NQ_INT idx;          /* index in names */
    NQ_STATUS opStatus;  /* operation status */
    NQ_STATUS result = NQ_SUCCESS;
    const NDAdapterInfo* correctAdapter = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p addData:%p", adapter, name, addData);

    /* find name in the list and find correct adapter*/
    if (NQ_FAIL == findNameAndAdapterForResponse(name, &idx, adapter, &correctAdapter))
    	goto Exit;

    /* validate operation status */

    opStatus = staticData->names[idx].operations[correctAdapter->idx].status;

    switch (opStatus)
    {
		case OPERATION_INREGISTRATION_H:
		case OPERATION_CLAIM:
			break;          /* valid status */
		default:
			LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Unexpected WACK for name: %s, state: %d", formatName(name), opStatus);
			goto Exit;
    }

    {
        const CMNetBiosResourceRecord* resourceRecord;     /* casting to the rest of the packet */
        NQ_UINT32 ttl;                                     /* ttl value */

        resourceRecord = (CMNetBiosResourceRecord*)addData;
        ttl = syNtoh32(cmGetSUint32(resourceRecord->ttl));
        staticData->names[idx].operations[correctAdapter->idx].ttl = (NQ_UINT)(ttl - 1)/UD_ND_DAEMONTIMEOUT;
        staticData->names[idx].operations[correctAdapter->idx].timeout = staticData->names[idx].operations[correctAdapter->idx].ttl;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Process Negative Registration Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the registered name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Registration Request
 *          over the same adapter
 *====================================================================
 */

NQ_STATUS
ndInternalNameNegativeRegistration(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name
    )
{
    NQ_INT idx;          /* index in names */
    NQ_STATUS opStatus;  /* operation status */
    NQ_STATUS result = NQ_SUCCESS;
    const NDAdapterInfo* correctAdapter = NULL;


    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p", adapter, name);

    /* find name in the list */

   if (NQ_FAIL == findNameAndAdapterForResponse(name, &idx, adapter, &correctAdapter))
	   goto Exit;

    /* validate operation status */

    opStatus = staticData->names[idx].operations[correctAdapter->idx].status;
    switch (opStatus)
    {
    case OPERATION_INREGISTRATION_H:
    case OPERATION_INREGISTRATION_B:
    case OPERATION_INRELEASE_B:
    case OPERATION_INRELEASE_H:
        break;          /* valid status */
    default:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Unexpected Neg Reg Response for name: %s, state: %d", formatName(name), opStatus);
        /* valid status - do nothing */
        goto Exit;
    }
    returnNegativeRegistrationResponse(&staticData->names[idx], adapter, CM_NB_RCODE_NAMERR);

    /* if name registration failed mark in release */
    staticData->names[idx].regName = FALSE;
    if (OPERATION_INREGISTRATION_H == opStatus)
    	staticData->names[idx].operations[correctAdapter->idx].status = OPERATION_INRELEASE_H;
    else if (OPERATION_INREGISTRATION_B == opStatus)
    	staticData->names[idx].operations[correctAdapter->idx].status = OPERATION_INRELEASE_B;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Process Positive Query Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the registered name
 *          IN: the rest of the response packet after the Name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Query Request
 *          issued as an end-node challenge
 *          This function may be also called on a response to an external
 *          name query. Then it will silently return.
 *====================================================================
 */

NQ_STATUS
ndInternalNamePositiveQuery(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name,
    const NQ_BYTE* addData
    )
{
    NQ_INT idx;          /* index in names */
    NQ_STATUS opStatus;  /* operation status */
    const NDAdapterInfo* correctAdapter = NULL;
    NQ_STATUS result = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p addData:%p", adapter, name, addData);

    /* find name in the list and find correct adapter*/
    if (NQ_FAIL == findNameAndAdapterForResponse(name, &idx, adapter, &correctAdapter))
       	goto Exit;

    /* validate operation status */

    opStatus = staticData->names[idx].operations[correctAdapter->idx].status;

    switch (opStatus)
    {
    case OPERATION_ENDNODECHALLENGE:
        break;          /* valid status */
    default:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Unexpected Pos Query Response for name: %s, state: %d", formatName(name), opStatus);
        /* valid status - do nothing */
        goto Exit;
    }

    staticData->names[idx].operations[correctAdapter->idx].status = OPERATION_RELEASED;
    returnNegativeRegistrationResponse(&staticData->names[idx], correctAdapter, CM_NB_RCODE_NAMERR);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Process Negative Query Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the registered name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Query Request
 *          issued as an end-node challenge
 *          This function may be also called on a response to an external
 *          name query. Then it will silently return.
 *====================================================================
 */

NQ_STATUS
ndInternalNameNegativeQuery(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name
    )
{
    NQ_INT idx;          /* index in names */
    NQ_STATUS opStatus;  /* operation status */
    NQ_STATUS result = NQ_SUCCESS;
    const NDAdapterInfo* correctAdapter = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p", adapter, name);

    /* find name in the list */

    if (NQ_FAIL == findNameAndAdapterForResponse(name, &idx, adapter, &correctAdapter))
    	goto Exit;

    /* validate operation status */

    opStatus = staticData->names[idx].operations[correctAdapter->idx].status;

    switch (opStatus)
    {
    case OPERATION_ENDNODECHALLENGE:
        break;          /* valid status */
    default:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Unexpected Neg Reg Response for name: %s, state: %d", formatName(name), opStatus);
        /* valid status - do nothing */
        goto Exit;
    }

    staticData->names[idx].operations[correctAdapter->idx].status = OPERATION_CLAIM;
    staticData->names[idx].operations[correctAdapter->idx].count = UD_ND_REGISTRATIONCOUNT;
    sendRefreshRequest(&staticData->names[idx], correctAdapter);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
 }

/*
 *====================================================================
 * PURPOSE: Process Positive Release Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the registered name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Registration Request
 *          over the same adapter
 *====================================================================
 */

NQ_STATUS
ndInternalNamePositiveRelease(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p", adapter, name);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", NQ_SUCCESS);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Process Negative Release Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the registered name
 *          IN: the rest of the response packet after the Name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This response should correspond to a Name Registration Request
 *          over the same adapter
 *====================================================================
 */


NQ_STATUS
ndInternalNameNegativeRelease(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p", adapter, name);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", NQ_SUCCESS);
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Process timeout
 *--------------------------------------------------------------------
 * PARAMS:  IN elapsed time in seconds
 *
 * RETURNS: next timeout interval
 *
 * NOTES:
 *====================================================================
 */

NQ_COUNT
ndInternalNameTimeout(
    NQ_INT delta
    )
{
    NQ_UINT idx;       /* index in names */
    NQ_COUNT retValue = CM_NB_VERYBIGNBTIMEOUT;   /* the result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "delta:%d", delta);

    for (idx = 0; idx < UD_ND_MAXINTERNALNAMES; idx++)
    {
        NQ_UINT i;     /* index in adapters */

        for (i = 0; i < UD_NS_MAXADAPTERS; i++)
        {
            switch (staticData->names[idx].operations[i].status)
            {
            case OPERATION_REGISTERED_H:
                /* refresh name for those adapters that registered this name over WINS */
                if (staticData->names[idx].operations[i].ttl != 0)
                {
                    staticData->names[idx].operations[i].timeout -= (NQ_UINT)delta;
                    if (staticData->names[idx].operations[i].timeout <= 0)
                    {
                        staticData->names[idx].operations[i].timeout = staticData->names[idx].operations[i].ttl;
                        retValue = staticData->names[idx].operations[i].ttl;
                        sendRefreshRequest(
                            &staticData->names[idx],
                            staticData->names[idx].operations[i].adapter
                            );
                    }
                }
                break;
            case OPERATION_INREGISTRATION_B:
                retValue = UD_ND_DAEMONTIMEOUT;
                /* a B adapter was in registration and no response received:
                   after several repeats this means successful registration */
                if (   staticData->names[idx].operations[i].ttl !=0
                    && --staticData->names[idx].operations[i].timeout <= 0
                   )
                {
                    if (--staticData->names[idx].operations[i].count <= 0)
                    {
                        /* registered */
                        staticData->names[idx].operations[i].status = OPERATION_REGISTERED_B;
						returnPositiveRegistrationResponse(
							&staticData->names[idx],
							staticData->names[idx].operations[i].adapter
							);
                    }
                    else
                    {
                        /* try more - send another registration request */
                        staticData->names[idx].operations[i].ttl = CM_NB_UNICASTREQRETRYTIMEOUT;
                        staticData->names[idx].operations[i].timeout = BCAST_TIMEOUT;
                        sendRegistrationRequest(&staticData->names[idx], staticData->names[idx].operations[i].adapter, (ndGetNumAdapters() > 1));
                    }
                }
                break;
            case OPERATION_INREGISTRATION_H:
                retValue = UD_ND_DAEMONTIMEOUT;
                /* adapter trying to register and no response received - retry or switch to B */
                if (   staticData->names[idx].operations[i].ttl !=0
                    && staticData->names[idx].operations[i].timeout-- <= 0
                   )
                {
                	/* time out for this operation */
                	/* all operations for this adapter are no more pending */
                	LOGMSG(80, "OPERATION_INREGISTRATION_H timeout, name pending: %d, adapter pending: %d, anyPositive: %d",
               			staticData->names[idx].numPendingRequests, staticData->names[idx].operations[i].numPendingRequestsPerAdapter, staticData->names[idx].isAnyPositiveResponse);
                	staticData->names[idx].numPendingRequests -= staticData->names[idx].operations[i].numPendingRequestsPerAdapter;
                	staticData->names[idx].operations[i].numPendingRequestsPerAdapter = 0;
                	if (staticData->names[idx].isAnyPositiveResponse)
                	{
                		/* some positive resposne arrived for this name. stop sending new registrations */
                		if (staticData->names[idx].numPendingRequests <= 0)
                		{
                			handlePositiveRegistration(&staticData->names[idx], staticData->names[idx].operations[i].adapter);
                		}
                	}
                	else
                	{
						if (staticData->names[idx].operations[i].count-- <= 0)
						{
							/* unicast registration failed, switch state */
							if (staticData->names[idx].numPendingRequests <= 0)
							{
								/* no more pending requests for h registration switch to boradcast*/
								staticData->names[idx].isHRegistrationFailed = TRUE;
								staticData->names[idx].operations[i].status = OPERATION_INREGISTRATION_B;
								staticData->names[idx].operations[i].count = CM_NB_UNICASTREQRETRYCOUNT;
							}
							else
							{
								/* more pending requests for h registration switch to pending boradcast*/
								staticData->names[idx].operations[i].status = OPERATION_PENDINGBCAST;
								staticData->names[idx].operations[i].count = 0;
							}
						}
						staticData->names[idx].operations[i].timeout = staticData->names[idx].operations[i].ttl;
						if (staticData->names[idx].operations[i].count > 0)
						{
							sendRegistrationRequest(&staticData->names[idx], staticData->names[idx].operations[i].adapter, (ndGetNumAdapters() > 1));
						}
                	}
                }
                break;
            case OPERATION_PENDINGBCAST:
            /* if all h regisrations failed for this name. switch to B cast */
			if (staticData->names[idx].isHRegistrationFailed)
			{
				staticData->names[idx].operations[i].status = OPERATION_INREGISTRATION_B;
				staticData->names[idx].operations[i].count = CM_NB_UNICASTREQRETRYCOUNT;
				staticData->names[idx].operations[i].timeout = staticData->names[idx].operations[i].ttl;
				sendRegistrationRequest(&staticData->names[idx], staticData->names[idx].operations[i].adapter, (ndGetNumAdapters() > 1));
			}
			break;
            case OPERATION_CLAIM:
                retValue = UD_ND_DAEMONTIMEOUT;
                /* adapter was in registration and no response received - retry or fail */
                if (   staticData->names[idx].operations[i].ttl !=0
                    && staticData->names[idx].operations[i].timeout-- <= 0
                   )
                {
                    if (staticData->names[idx].operations[i].count-- <= 0)
                    {
                        staticData->names[idx].operations[i].status = OPERATION_RELEASED;
                        returnNegativeRegistrationResponse(
                            &staticData->names[idx],
                            staticData->names[idx].operations[i].adapter,
                            CM_NB_RCODE_NAMERR
                            );
                    }
                    else
                    {
                        staticData->names[idx].operations[i].timeout = staticData->names[idx].operations[i].ttl;
                        sendRefreshRequest(&staticData->names[idx], staticData->names[idx].operations[i].adapter);
                    }
                }
                break;
            }
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", retValue);
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Process Name Registration Request from outside
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the request
 *          IN: name to check
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   If we already registered this name or it is under registration -
 *          respond with NEGATIVE NAME REGISTRATION RESPONSE
 *====================================================================
 */


NQ_STATUS                              /* NQ_SUCCESS or NQ_FAIL */
ndInternalNameCheckNameConflict(
    const NDAdapterInfo* adapter,   /* adapter structure */
    const CMNetBiosName name        /* name to check */
    )
{
    NQ_INT idx;       /* index in names */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%p", adapter, name);

    if ((idx = findName(name)) != NO_NAME && adapter->inIp != adapter->ip && staticData->names[idx].regName && !staticData->names[idx].nameInfo.isGroup && adapter->typeB)
    {
        sendNegativeWhateverResponse(&staticData->names[idx], adapter, CM_NB_OPCODE_REGISTRATION, CM_NB_RCODE_CONFLICT);
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

NQ_STATUS static 
ndInternalSendNameResponse(
		NQ_UINT idx,
		const NDAdapterInfo *  response,
		NQ_BOOL sendNegativeResponse
		)
{
	/* Send a response adapter address only */
	NQ_UINT i = 0; /* Index  in adapters */
	static CMNetBiosAddrEntry addresses[UD_NS_MAXADAPTERS]; /* NB addresses to report */
	NQ_UINT numAddr = 0; /* Number of addresses to return */
	NameEntry * name = &staticData->names[idx];
	NQ_STATUS	result = NQ_FAIL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "idx:%d response:%p", idx, response);
	while (i <UD_NS_MAXADAPTERS)
	{
		Operation * op = &name->operations[i];
		if (op-> status == OPERATION_REGISTERED_B ||op-> status == OPERATION_REGISTERED_H)
		{
			if (op-> adapter == response)
			{
				cmPutSUint16(addresses[numAddr].flags, (name->nameInfo.isGroup) ?CM_NB_NAMESTATUS_G: 0);
				if (op-> adapter-> typeB)
				{
					cmPutSUint16(addresses[numAddr].flags, cmGetSUint16(addresses[numAddr].flags) | CM_NB_NAMESTATUS_ONT_B);
				}
				else
				{
					cmPutSUint16(addresses[numAddr].flags, cmGetSUint16(addresses[numAddr].flags) | CM_NB_NAMESTATUS_ONT_M);
				}
				cmPutSUint16(addresses[numAddr].flags, syHton16(cmGetSUint16 (addresses[numAddr].flags)));
				cmPutSUint32(addresses[numAddr].ip, op->adapter->ip);
				numAddr++;
				break;
			}
		}
		i++;
	}
	if (numAddr == 0)
	{
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Name is being registered:% s", formatName(staticData->names[idx].nameInfo.name));
		if (sendNegativeResponse)
			sendNegativeWhateverResponse (&staticData->names[idx], response, CM_NB_OPCODE_QUERY, CM_NB_RCODE_NAMERR);
		goto Exit;
	}
	sendPositiveQueryResponse (&staticData->names[idx], response, addresses, numAddr);
	result = NQ_SUCCESS;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
	return result;
}

/*
 *====================================================================
 * PURPOSE: Process incoming query request to an internal name
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the request
 *          IN: name to query
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Depending on whether this name is registered (on any adapter)
 *          we send either QUERY_POSITIVE RESPONSE or QUERY_NEGATIVE
 *          RESPONSE
 *====================================================================
 */

NQ_STATUS
ndInternalProcessNameQuery(
    const NDAdapterInfo* response,
    const CMNetBiosName name,
    NQ_BOOL sendNegativeResponse
    )
{
    NQ_INT idx;                 /* index in names */
    NQ_STATUS result = NQ_FAIL;

    /* find name in the list */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p name:%p sendNegativeResponse:%s", response, name ? name : "", sendNegativeResponse ? "TRUE" : "FALSE");

    idx = findName(name);

    /* check if this name exists and should be reported */

    if (idx == NO_NAME || !staticData->names[idx].regName)
    {
		if (syStrcmp(name, "*") == 0)
		{
			NQ_UINT i = 0; /* Index in names */
			LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, ">> Query for all existing names:% s", formatName(name));
			for (i = 0; i < sizeof(staticData->names) / sizeof(staticData->names[0]); i++)
			{
				idx = staticData->names[i].idx;
				if (idx != NO_NAME)
				{
					/* Do not send negative responses */ 
					ndInternalSendNameResponse((NQ_UINT)idx, response, FALSE);
				}
			}
			result = NQ_SUCCESS;
		} 
		else
		{
			if (!response->bcastDest)
			{
				LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Query for non-existing name: %s", formatName(name));

				/* syMemcpy(noName.nameInfo.name, name, sizeof(CMNetBiosName)); */
				/* sendNegativeWhateverResponse(&noName, response, CM_NB_OPCODE_QUERY, CM_NB_RCODE_NAMERR); */
			}
		}
        goto Exit;
    }

    /* find registered IPs (per adapter) and send all IPs in the response */

    {
        NQ_UINT i;                             /* index in adapters */
        CMNetBiosAddrEntry  addresses[UD_NS_MAXADAPTERS];      /* NB addresses to report */
        NQ_UINT numAddr;                       /* number of addresses to return */

        numAddr = 0;

        for (i = 0; i < UD_NS_MAXADAPTERS; i++)
        {
            if (   staticData->names[idx].operations[i].status == OPERATION_REGISTERED_B
                || staticData->names[idx].operations[i].status == OPERATION_REGISTERED_H
				|| staticData->names[idx].operations[i].status == OPERATION_INREGISTRATION_H
				|| staticData->names[idx].operations[i].status == OPERATION_INREGISTRATION_B
               )
            {
                cmPutSUint16(addresses[numAddr].flags, (staticData->names[idx].nameInfo.isGroup) ? CM_NB_NAMESTATUS_G : 0);
                if (staticData->names[idx].operations[i].adapter->typeB)
                {
                    cmPutSUint16(addresses[numAddr].flags, cmGetSUint16(addresses[numAddr].flags) | CM_NB_NAMESTATUS_ONT_B);
                }
                else
                {
                    cmPutSUint16(addresses[numAddr].flags, cmGetSUint16(addresses[numAddr].flags) | CM_NB_NAMESTATUS_ONT_M);
                }

                cmPutSUint16(addresses[numAddr].flags, syHton16(cmGetSUint16(addresses[numAddr].flags)));
                cmPutSUint32(addresses[numAddr].ip, staticData->names[idx].operations[i].adapter->ip);
                numAddr++;
            }
        }

        if (numAddr == 0)
        {
            LOGMSG(CM_TRC_LEVEL_MESS_SOME, ">> Name is being registered: %s", formatName(name));

            if (sendNegativeResponse)
                sendNegativeWhateverResponse(&staticData->names[idx], response, CM_NB_OPCODE_QUERY, CM_NB_RCODE_NAMERR);

            goto Exit;
        }

        sendPositiveQueryResponse(&staticData->names[idx], response, addresses, numAddr);
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Process incoming Node Status request
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the request
 *          IN: response name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   We send all registered names and an empty statistics record
 *====================================================================
 */

static NQ_STATUS
processNodeStatus(
    const NDAdapterInfo* response,
    const CMNetBiosName name
    )
{
    NQ_INT msgLen;              /* length of the outgoing message */
    NQ_INT resLen;              /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    NQ_INDEX idx;               /* index in names */
    NQ_BYTE statusData[STATUS_DATA_LENGTH]; /* buffer for status data */
    NQ_BYTE* pData;                                /* pointer to the current position there */
    NQ_BYTE numNames;           /* number of reported names */
    NQ_UINT16 tranId;           /* saved tran id in NBO */
    NQ_UINT16 flags;            /* name flags */
    NQ_UINT16 temp;             /* for converting flags */
    NQ_IPADDRESS to;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p name:%p", response, name);

    /* don't respond on non registered name */
    if((name[0] != '*') && (findName(name) == NO_NAME))
    {
        result = NQ_SUCCESS;
        goto Exit;
    }
    pData = &statusData[1];
    numNames = 0;

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        NQ_BOOL reportName;    /* whether to report on name */

        if (staticData->names[idx].idx == NO_NAME)
            continue;

        flags = CM_NB_NAMESTATUS_PRM | CM_NB_NAMESTATUS_ACT;
        if (response->typeB)
        {
            flags |= CM_NB_NAMESTATUS_ONT_B;
        }
        else
        {
            flags |= CM_NB_NAMESTATUS_ONT_M;
        }
        if (staticData->names[idx].nameInfo.isGroup)
        {
            flags |= CM_NB_NAMESTATUS_G;
        }

        reportName = TRUE;

        switch (staticData->names[idx].operations[response->idx].status)
        {
        case OPERATION_NEW:
        case OPERATION_RELEASED:
        case OPERATION_INREGISTRATION_H:
        case OPERATION_INREGISTRATION_B:
            reportName = FALSE;
            break;
        case OPERATION_INRELEASE_H:
        case OPERATION_INRELEASE_B:
            flags |= CM_NB_NAMESTATUS_DRG;
            break;
        case OPERATION_ENDNODECHALLENGE:
            flags |= CM_NB_NAMESTATUS_CNF;
            break;
        default:
            break;
        }

        if (!reportName)
            continue;

        numNames++;
        syMemcpy(pData, staticData->names[idx].nameInfo.name, sizeof(CMNetBiosName));
        pData += 16;
        temp = syHton16(flags);
        syMemcpy(pData, &temp, sizeof(flags));
        pData += sizeof(flags);
    }

    /* place the number of names */

    statusData[0] = numNames;

    /* place statistics */

    syMemset(pData, 0, sizeof(CMNetBiosNodeStatistics));
    syMemcpy(pData, response->mac, sizeof(response->mac));
    pData += sizeof(CMNetBiosNodeStatistics);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)response->inMsg;
    tranId = cmGetSUint16(msgHdr->tranID);

    msgHdr = (CMNetBiosHeader*)response->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name,
        CM_NB_RTYPE_NBSTAT,
        statusData,
        (NQ_UINT)(pData - statusData)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    cmPutSUint16(msgHdr->tranID, tranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_QUERY | CM_NB_RESPONSE | CM_NB_NAMEFLAGS_AA));

    /* send the message */

    CM_IPADDR_ASSIGN4(to, response->inIp);
    resLen = sySendToSocket(
        response->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        response->inPort
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Query NBSTAT Response");
        result = NQ_SUCCESS;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Find name in the list
 *--------------------------------------------------------------------
 * PARAMS:  IN: Name to query
 *
 * RETURNS: Name index or NO_NAME
 *
 * NOTES:

 *====================================================================
 */

static NQ_INT
findName(
    const CMNetBiosName name
    )
{
    NQ_COUNT idx;       /* index in names */
    NQ_INT result = NO_NAME;

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx != NO_NAME)
        {
            if (cmNetBiosSameNames(name, staticData->names[idx].nameInfo.name))
            {
                result = (NQ_INT)idx;
                goto Exit;
            }
        }
    }

Exit:
    return result;
}

/*
 *====================================================================
 * PURPOSE: Find an empty entry in the list
 *--------------------------------------------------------------------
 * PARAMS:  IN: Name to query
 *
 * RETURNS: Name index or NO_NAME
 *
 * NOTES:
 *====================================================================
 */

static NQ_INT
findNoName(
    void
    )
{
	NQ_COUNT idx;       /* index in names */
    NQ_INT result = NO_NAME;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx == NO_NAME)
        {
            NQ_UINT i;     /* index in operations */

            for (i = 0; i < UD_NS_MAXADAPTERS; i++)
            {
                staticData->names[idx].operations[i].status = OPERATION_NEW;
            }
            staticData->names[idx].idx = (NQ_INT)idx;
            result = (NQ_INT)idx;
            goto Exit;
        }
    }

    LOGERR(CM_TRC_LEVEL_ERROR, "Overflow in the name table");

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Name Registration Request externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to register
 *          IN: adapter to register over
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
sendRegistrationRequest(
    NameEntry* name,
    const NDAdapterInfo* adapter,
	NQ_BOOL isMultiHome
    )
{
    NQ_INT msgLen;                /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    NQ_COUNT numRegistraionCurrAdapter;	/* number of registration packets to send */
    NQ_COUNT winsCounter;			/* counter */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_UINT16 flags;               /* header flags (B only) */
    NQ_IPADDRESS to;               /* called IP */
    NQ_STATUS result = NQ_FAIL;
    NQ_BOOL isBCast;				/* is this a broad cast registration */
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p", name, adapter);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverRequest(
        msgHdr,
        name->nameInfo.name,
        adapter->ip,
        adapter->typeB,
		name->nameInfo.isGroup
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */
    if (name->operations[adapter->idx].status == OPERATION_INREGISTRATION_B)
    {
        CM_IPADDR_ASSIGN4(to, adapter->bcast);
        numRegistraionCurrAdapter = 1;
        isBCast = TRUE;
        flags = CM_NB_NAMEFLAGS_B;
    }
    else
    {
    	numRegistraionCurrAdapter = cmNetBiosGetNumWinsServers();
    	isBCast = FALSE;
        flags = 0;
    }


    if (isMultiHome && !name->nameInfo.isGroup)
    {
    	/* use multihome flag only for our name registration. group registration is usually domain name. */
    	cmPutSUint16(msgHdr->packCodes, syHton16((NQ_UINT16)(CM_NB_OPCODE_MHREGISTRATION)));
    }
    else
    {
    	cmPutSUint16(msgHdr->packCodes, syHton16((NQ_UINT16)(CM_NB_OPCODE_REGISTRATION | flags)));
    }

    for (winsCounter = 0; winsCounter < numRegistraionCurrAdapter; ++winsCounter )
    /* send the message */
    {
    	if (!isBCast)
    		CM_IPADDR_ASSIGN4(to , cmNetBiosGetWins(winsCounter));

    	name->operations[adapter->idx].tranId = cmNetBiosGetNextTranId();
    	cmPutSUint16(msgHdr->tranID, syHton16(name->operations[adapter->idx].tranId));
    	if (0 == winsCounter)
    	{
    		/* when sending a few at a time, should know first and last IDs */
    		name->operations[adapter->idx].firstTranId = name->operations[adapter->idx].tranId;
    	}

		resLen = sySendToSocket(
			adapter->nsSocket,
			(NQ_BYTE*)msgHdr,
			(NQ_UINT)msgLen,
			&to,
			syHton16(CM_NB_NAMESERVICEPORT)
			);
		if (resLen <= 0)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Registration Request");
			result = NQ_SUCCESS;
			goto Exit;
		}
		++name->numPendingRequests;
		++(name->operations[adapter->idx].numPendingRequestsPerAdapter);
    }
    result = NQ_SUCCESS;
Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Name Refresh Request externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to register
 *          IN: adapter to use
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
sendRefreshRequest(
    NameEntry* name,
    const NDAdapterInfo* adapter
    )
{
    NQ_INT msgLen;                 	/* length of the outgoing message */
    NQ_INT resLen;                 	/* length of the sent data */
    CMNetBiosHeader* msgHdr;       	/* casted pointer to the outgoing message */
    NQ_UINT16 flags;               	/* header flags (B only) */
    NQ_IPADDRESS to;               	/* called IP */
    NQ_COUNT numRefreshRequest;			/* number of registration packets to send */
    NQ_STATUS result = NQ_FAIL;
	NQ_COUNT winsCounter;			/* counter */
    NQ_BOOL isBCast;				/* is this a broad cast registration */
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p", name, adapter);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverRequest(
        msgHdr,
        name->nameInfo.name,
        adapter->ip,
        adapter->typeB,
		name->nameInfo.isGroup
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine trans ID, called address type and flags */

    if (name->operations[adapter->idx].status == OPERATION_REGISTERED_B)
    {
        CM_IPADDR_ASSIGN4(to, adapter->bcast);
        numRefreshRequest = 1;
        isBCast = TRUE;
        flags = CM_NB_NAMEFLAGS_ONT_B;
    }
    else
    {
    	numRefreshRequest = cmNetBiosGetNumWinsServers();
    	isBCast = FALSE;
        flags = 0;
    }

    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_REFRESH | flags));

    for (winsCounter = 0; winsCounter < numRefreshRequest; ++winsCounter )
       /* send the message */
    {
    	if (!isBCast)
		{
			CM_IPADDR_ASSIGN4(to , cmNetBiosGetWins(winsCounter));
		}

    	name->operations[adapter->idx].tranId = cmNetBiosGetNextTranId();
    	cmPutSUint16(msgHdr->tranID, syHton16(name->operations[adapter->idx].tranId));

    	if (0 == winsCounter)
		{
			/* when sending a few at a time, should know first and last IDs */
			name->operations[adapter->idx].firstTranId = name->operations[adapter->idx].tranId;
		}
		resLen = sySendToSocket(
			adapter->nsSocket,
			(NQ_BYTE*)msgHdr,
			(NQ_UINT)msgLen,
			&to,
			syHton16(CM_NB_NAMESERVICEPORT)
			);
		if (resLen <= 0)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Registration Request");
			result = NQ_SUCCESS;
			goto Exit;
		}
	}
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Query Response externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to respond on
 *          IN: adapter to use
 *          IN: opcode (either QUERY or REGISTRATION)
 *          IN: error code
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
sendNegativeWhateverResponse(
    NameEntry* name,
    const NDAdapterInfo* adapter,
    NQ_UINT opcode,
    NQ_UINT error
    )
{
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_IPADDRESS to;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p opcode:%u error:%u", name, adapter, opcode, error);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        NULL,
        0
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    cmPutSUint16(msgHdr->anCount, syHton16(0));      /* undocumented feature - this is the way Windows responds */
    cmPutSUint16(msgHdr->tranID, adapter->inTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16((NQ_UINT16)(opcode | CM_NB_RESPONSE | error)));

    /* send the message */

    CM_IPADDR_ASSIGN4(to, adapter->inIp);
    resLen = sySendToSocket(
        adapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        adapter->inPort
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Negative Response");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Query Response externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to respond on
 *          IN: adapter to use
 *          IN: an array of ADDR ENTRY structures
 *          IN: number of those structures
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
sendPositiveQueryResponse(
    NameEntry* name,
    const NDAdapterInfo* adapter,
    const CMNetBiosAddrEntry* addresses,
    NQ_UINT numAddr
    )
{
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_IPADDRESS to;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p addresses:%p numAddr:%u", name, adapter, addresses, numAddr);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        (NQ_BYTE*)addresses,
        (NQ_UINT)(sizeof(*addresses)*numAddr)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    cmPutSUint16(msgHdr->tranID, adapter->inTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_QUERY | CM_NB_RESPONSE | CM_NB_NAMEFLAGS_AA | CM_NB_NAMEFLAGS_RD));

    /* send the message */

    CM_IPADDR_ASSIGN4(to, adapter->inIp);
    resLen = sySendToSocket(
        adapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        adapter->inPort
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Registration Request");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Name Release Request externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to release
 *          IN: adapter to use
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
sendReleaseRequest(
    NameEntry* name,
    const NDAdapterInfo* adapter
    )
{
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_UINT16 flags;               /* header flags (B only) */
    NQ_IPADDRESS to;               /* called IP */
    NQ_STATUS result = NQ_FAIL;
    NQ_COUNT numReleaseRequests;	/* number of registration packets to send */
    NQ_COUNT winsCounter;			/* counter */
    NQ_BOOL isBCast;				/* is this a broad cast registration */


    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p", name, adapter);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverRequest(
        msgHdr,
        name->nameInfo.name,
        adapter->ip,
        adapter->typeB,
		name->nameInfo.isGroup
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    if (name->operations[adapter->idx].status == OPERATION_INRELEASE_B)
    {
        CM_IPADDR_ASSIGN4(to, adapter->bcast);
        flags = CM_NB_NAMEFLAGS_B;
        numReleaseRequests = 1;
        isBCast = TRUE;
    }
    else
    {
    	numReleaseRequests = cmNetBiosGetNumWinsServers();
    	isBCast = FALSE;
    	flags = 0;
    }

    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_RELEASE | flags));

    name->operations[adapter->idx].status = OPERATION_RELEASED;


    for (winsCounter = 0; winsCounter < numReleaseRequests; ++winsCounter )
    {
        if (!isBCast)
        {
        	CM_IPADDR_ASSIGN4(to , cmNetBiosGetWins(winsCounter));
        }

        name->operations[adapter->idx].tranId = cmNetBiosGetNextTranId();
        cmPutSUint16(msgHdr->tranID, syHton16(name->operations[adapter->idx].tranId));
    	if (0 == winsCounter)
		{
			/* when sending a few at a time, should know first and last IDs */
			name->operations[adapter->idx].firstTranId = name->operations[adapter->idx].tranId;
		}

		resLen = sySendToSocket(
			adapter->nsSocket,
			(NQ_BYTE*)msgHdr,
			(NQ_UINT)msgLen,
			&to,
			syHton16(CM_NB_NAMESERVICEPORT)
			);
		if (resLen <= 0)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Release Request");
			result = NQ_SUCCESS;
			goto Exit;
		}
	}
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Name Release Request externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to query for
 *          IN: adapter to use
 *          IN: called address in NBO
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
sendQueryRequest(
    NameEntry* name,
    const NDAdapterInfo* adapter,
    NQ_UINT32 ip
    )
{
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_IPADDRESS to;
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p ip:0x%x", name, adapter, ip);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameQueryRequest(msgHdr, name->nameInfo.name);

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, syHton16(name->operations[adapter->idx].tranId));
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_QUERY));  /* unicast */

    /* send the message */

    CM_IPADDR_ASSIGN4(to, ip);
    resLen = sySendToSocket(
        adapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        syHton16(CM_NB_NAMESERVICEPORT)
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Release Request");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Positive Name Registration Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name entry to report on
 *          IN: adapter to use as the registrated address
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
returnPositiveRegistrationResponse(
    NameEntry* name,
    const NDAdapterInfo* adapter
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    CMNetBiosAddrEntry address; /* address to report on */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p", name, adapter);

    if (NULL == name->resAdapter)
    {
        result = NQ_SUCCESS;
        goto Exit;
    }

    /* increment the number of registrations only once per application request */

    if (name->increment)
    {
        name->increment = FALSE;
        name->regCount++;
    }

    /* compose the message */
    cmPutSUint16(address.flags, (adapter->typeB)? CM_NB_NAMEFLAGS_ONT_B : 0);
    cmPutSUint32(address.ip, adapter->ip);

    msgHdr = (CMNetBiosHeader*)name->resAdapter->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        (NQ_BYTE*)&address,
        sizeof(address)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, name->resTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_REGISTRATION | CM_NB_RESPONSE));

    resLen = sySendToSocket(
        name->resAdapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &localhost,
        name->resPort
        );

    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send Positive Registration Response internally");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Registration Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name entry to report on
 *          IN: adapter to use as the registered address
 *          IN: error to report
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
returnNegativeRegistrationResponse(
    const NameEntry* name,
    const NDAdapterInfo* adapter,
    NQ_UINT error
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    CMNetBiosAddrEntry address; /* address to report on */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p error:%u", name, adapter, error);
    if (NULL == name->resAdapter)
    {
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        result = NQ_SUCCESS;
        goto Exit;
    }

    /* compose the message */

    cmPutSUint16(address.flags, (adapter->typeB)? CM_NB_NAMEFLAGS_ONT_B : 0);
    cmPutSUint32(address.ip, adapter->ip);

    msgHdr = (CMNetBiosHeader*)name->resAdapter->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        (NQ_BYTE*)&address,
        sizeof(address)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */
    cmPutSUint16(msgHdr->tranID, name->resTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16((NQ_UINT16)(CM_NB_OPCODE_REGISTRATION | CM_NB_RESPONSE | error)));

    /* send the message */

    resLen = sySendToSocket(
        name->resAdapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &localhost,
        name->resPort
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send Negative registration Response internally");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Positive Name Release Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name entry to report on
 *          IN: adapter to use as the registered address
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
returnPositiveReleaseResponse(
    const NameEntry* name,
    const NDAdapterInfo* adapter
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    CMNetBiosAddrEntry address; /* address to report on */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p adapter:%p", name, adapter);

    if (NULL == name->resAdapter)
    {
        result = NQ_SUCCESS;
        goto Exit;
    }

    /* compose the message */

    cmPutSUint16(address.flags, (adapter->typeB)? CM_NB_NAMEFLAGS_ONT_B : 0);
    cmPutSUint32(address.ip, adapter->ip);

    msgHdr = (CMNetBiosHeader*)name->resAdapter->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        (NQ_BYTE*)&address,
        sizeof(address)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, name->resTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_RELEASE | CM_NB_RESPONSE));

    /* send the message */

    resLen = sySendToSocket(
        name->resAdapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &localhost,
        name->resPort
        );

    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send Positive registration Response internally");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Release Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name to report on
 *          IN: adapter to response over
 *          IN: adapter to use as the registered address
 *          IN: error to report
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
returnNegativeReleaseResponse(
    const CMNetBiosName name,
    const NDAdapterInfo* response,
    const NDAdapterInfo* adapter,
    NQ_UINT error
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    CMNetBiosAddrEntry address; /* address to report on */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p response:%p adapter:%p error:%u", name, response, adapter, error);

    /* compose the message */

    cmPutSUint16(address.flags, (adapter->typeB)? CM_NB_NAMEFLAGS_ONT_B : 0);
    cmPutSUint32(address.ip, adapter->ip);

    msgHdr = (CMNetBiosHeader*)response->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name,
        CM_NB_RTYPE_NB,
        (NQ_BYTE*)&address,
        sizeof(address)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, response->inTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16((NQ_UINT16)(CM_NB_OPCODE_RELEASE | CM_NB_RESPONSE | error)));

    /* send the message */

    resLen = sySendToSocket(
        response->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &localhost,
        response->inPort
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send Positive registration Response internally");
        result = NQ_SUCCESS;
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

NQ_IPADDRESS4 *
ndLLMNRNameLookup(NQ_CHAR * name)
{
	NameEntry	*	nameRec = NULL;
	NQ_INT			nameId;
	NQ_IPADDRESS4 * pResult = NULL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p", name);

	cmNetBiosNameFormat(name , CM_NB_POSTFIX_WORKSTATION);
	nameId = findName(name);

	if (nameId == NO_NAME)
	{
        LOGERR(CM_TRC_LEVEL_ERROR, "NO NAME");
		goto Exit;
	}
	nameRec = &staticData->names[nameId];
	if (nameRec != NULL)
	{
		pResult = (NQ_IPADDRESS4 *)&nameRec->resAdapter->ip;
	}

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
	return pResult;
}

/* When we register a name, we register on all adapters local host has.
 * Many times actual registration is sent on one adapter (according to WINS address)
 * in this cases a response is received from one adapter but its target is another adapter. */
NQ_STATUS findNameAndAdapterForResponse(
		const CMNetBiosName name,
		NQ_INT *idx,
		const NDAdapterInfo* adapter,
		const NDAdapterInfo** correctAdapter
		)
{
	 NQ_UINT16 recievedTranID;		/* transaction ID in recieved message*/
	 NQ_STATUS result = NQ_FAIL;
	 NQ_COUNT i;

	/* find name in the list */
	*idx = findName(name);

	if (*idx == NO_NAME)
	{
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Response for non-existing name: %s", formatName(name));
		goto Exit;
	}

	recievedTranID = syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID));

	/* iterate all adapters for this name, find which is relevant one according to Transaction ID */

	for (i = 0; i < UD_NS_MAXADAPTERS; i++)
	{
		if(recievedTranID <= staticData->names[*idx].operations[i].tranId &&
			recievedTranID >= staticData->names[*idx].operations[i].firstTranId)
		{
			*correctAdapter = staticData->names[*idx].operations[i].adapter;
			break;
		}
	}

	if (NULL == *correctAdapter)
	{
		/* this transaction ID wasn't sent on any adapter */
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL,
			"Pos Reg Response with unexpected Tran ID: %d",
			recievedTranID
			);
		goto Exit;
	}

	result = NQ_SUCCESS;

Exit:
	return result;
}
#endif /* UD_ND_INCLUDENBDAEMON */

