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
#include "ndframes.h"
#include "nsapi.h"

#ifdef UD_ND_INCLUDENBDAEMON

/* This source implents routines responsible for operations with internal names.
   Internal names are those registered by the host applications. */

typedef struct                  /* Name entry per adapter - used as a status for
                                   name registration/release process */
{
    const NDAdapterInfo* adapter;      /* pointer to the adapter structure */
    NQ_INT status;                     /* name registration/release status (see below) */
    NQ_UINT count;                     /* repeat counter */
    NQ_UINT timeout;                   /* time when the next operation on this entry times out -
                                          this value is measured in timeout counts as:
                                       <time> / <daemon timeout> and is decreased */
    NQ_UINT ttl;                       /* the intial value for the previous field */
    NQ_UINT16 tranId;                  /* transaction ID for comparing with a response in NBO */
}
Operation;

/* values for the Status field */

#define OPERATION_NEW               0   /* nothing done yet */
#define OPERATION_REGISTERED_B      1   /* name registered over this adapter */
#define OPERATION_REGISTERED_H      2   /* name registered over this adapter with WINS */
#define OPERATION_RELEASED          3   /* name released over this adapter */
#define OPERATION_INREGISTRATION_H  4   /* ND is sending Name Registration Requests to WINS */
#define OPERATION_INREGISTRATION_B  5   /* ND is sending Name Registration Request broadcasts */
#define OPERATION_INRELEASE_H       6   /* ND is sending Name Release Requests to WINS */
#define OPERATION_INRELEASE_B       7   /* ND is sending Name Release Request broadcasts */
#define OPERATION_ENDNODECHALLENGE  8   /* ND is sending Name Query Requests to a
                                           presumed owner */
#define OPERATION_CLAIM             9   /* ND is sending Name Refresh Requests to claim a name */

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
    NQ_UINT16 bindPort;                     /* the port this name is bind to */
    NQ_UINT16 resPort;                      /* requestor port (internal) */
    NQ_UINT16 resTranId;                    /* requestor tranId */
    const NDAdapterInfo* resAdapter;        /* requestor adapter (dummy) */
    Operation operations[UD_NS_MAXADAPTERS];/* operations per adapter */
    NQ_COUNT regCount;                      /* registration count */
    NQ_BOOL increment;                      /* when TRUE regCount increment allowed */
    NQ_BOOL regName;                        /* whether to register this name on the network */
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
    apprlication */

static NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
sendRegistrationRequest(
    NameEntry* name,                /* name to register */
    const NDAdapterInfo* adapter    /* adapter to use */
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

/* special values, indicating no value */

#define NO_NAME -1  /* index of an empty name entry */
#define NO_TID 0    /* "no transaction" ID */

/* request operation timeouts measured in daemon cycles */

#define UNICAST_TIMEOUT \
        (CM_NB_UNICASTREQRETRYTIMEOUT + UD_ND_DAEMONTIMEOUT - 1) / UD_ND_DAEMONTIMEOUT
#define BCAST_TIMEOUT   1       /* this is as least as possible */

#ifdef UD_NQ_INCLUDETRACE
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
#endif /*UD_NQ_INCLUDETRACE*/

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

    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate External Names data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        NQ_UINT i;         /* index in operations */

        staticData->names[idx].idx = NO_NAME;
        for (i = 0; i < UD_NS_MAXADAPTERS; i++)
        {
            staticData->names[idx].operations[i].tranId = NO_TID;
            staticData->names[idx].bindPort = 0;
            staticData->names[idx].increment = FALSE;
        }
    }

    TRCE();
    return NQ_SUCCESS;
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
 * PURPOSE: Find a port bound to an internal name
 *--------------------------------------------------------------------
 * PARAMS:  IN: name to look for
 *
 * RETURNS: port number (in NBO) or -1 when name was not found
 *
 * NOTES:   A name may either exist or not
 *====================================================================
 */

NQ_INT16
ndInternalNameGetPort(
    const CMNetBiosName name
    )
{
    NQ_INT idx;           /* index in names */

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRC1P("Name not found: %s", formatName(name));

        TRCE();
        return ND_NOINTERNALNAME;
    }

    TRCE();
    return (NQ_INT16)staticData->names[idx].bindPort;
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

    TRCB();

    /* find name in the list */
    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRC1P("Name not found: %s", formatName(name));

        TRCE();
        return NQ_FAIL;
    }

    staticData->names[idx].bindPort = port;

    TRCE();
    return NQ_SUCCESS;
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
    NQ_INDEX nameIndex
    )
{
    /* get name entry by index */
    NameEntry *name = &staticData->names[nameIndex];
    Operation *operation = &name->operations[adapter->idx];

    TRCB();
    TRC2P("Registering name %s on adapter %d", formatName(name->nameInfo.name), adapter->idx);

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

		TRCE();
		return NQ_SUCCESS;
    }
    if (!name->regName)
    {
        /* do not register on the network: mark this name as virtually registered so far */
        operation->status = OPERATION_REGISTERED_B;
        returnPositiveRegistrationResponse(name, adapter);

        TRCE();
        return NQ_SUCCESS;
    }

    switch (operation->status)
    {
    case OPERATION_NEW:
    case OPERATION_RELEASED:
        break;          /* valid status - send request */
    case OPERATION_REGISTERED_B:
    case OPERATION_REGISTERED_H:
        returnPositiveRegistrationResponse(name, adapter);

        TRCE();
        return NQ_SUCCESS;
    case OPERATION_INRELEASE_H:
    case OPERATION_INRELEASE_B:
        TRC1P(">> An attempt to register a name (%s) that is being released", formatName(name->nameInfo.name));

        returnNegativeRegistrationResponse(name, adapter, CM_NB_RCODE_NAMERR);

        TRCE();
        return NQ_SUCCESS;
    default:
        TRCE();
        return NQ_SUCCESS; /* do nothing - operation already in progress */
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
    operation->tranId = syHton16(cmNetBiosGetNextTranId());

    sendRegistrationRequest(name, adapter);

    TRCE();
    return NQ_SUCCESS;
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
 *          This function should be called subsequently (and not interruptably)
 *          for all adapters. Thus, these calls should reorganize the list
 *          operations for each of the names.
 *====================================================================
 */

NQ_STATUS
ndInternalNameRegisterAllNames(
    const NDAdapterInfo* response,
    const NDAdapterInfo* adapter
    )
{
    NQ_INDEX idx;       /* index in the names */

    TRCB();

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx != NO_NAME && adapter->status != ND_ADAPTER_NONE)
        {
            ndInternalNameRegister(response, adapter, idx);
        }
    }

    TRCE();
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
    NQ_UINT regAdapterCount = 0; /* Counter of adapters if its 0 (no adapters) nqnd will send a negative response */
    NDAdapterInfo fakeAdpt; /* fake adapter for the negative registration response*/


    TRCB();

    if (n == NO_NAME)
    {
        /* create name */
        n = findNoName();

        if (n == NO_NAME)
        {
            TRCE();
            return NQ_FAIL;
        }

        staticData->names[n].regCount = 0;
        syMemcpy(&staticData->names[n].nameInfo, nameInfo, sizeof(CMNetBiosNameInfo));
    }

    /* allow increasing registration count */
    staticData->names[n].increment = TRUE;

    while ((adapter = ndAdapterGetNext()) != NULL)
    {
        ndInternalNameRegister(response, adapter, (NQ_INDEX)n);
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

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Releasing all internal names over all adapters
 *--------------------------------------------------------------------
 * PARAMS:  IN whether to free entry
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Only for those adapters that this name is regsitered over them
 *====================================================================
 */

NQ_STATUS
ndInternalNameReleaseAllNames(
    const NQ_BOOL doFreeEntry
    )
{
    NQ_UINT idx;   /* index in names */

    TRCB();

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx != NO_NAME)
        {
            ndInternalNameReleaseAllAdapters(NULL, staticData->names[idx].nameInfo.name, doFreeEntry);
        }
    }

    TRCE();
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

    TRCB();
    
    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRC1P(">> An attempt to release a non-existing name: %s", formatName(name));

        if (response != NULL)
            returnNegativeReleaseResponse(name, response, response, CM_NB_RCODE_NAMERR);

        TRCE();
        return NQ_SUCCESS;
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
        TRCE();

        return NQ_SUCCESS;
    }
    staticData->names[idx].regCount = 0;

    while ((adapter = ndAdapterGetNext()) != NULL)
    {
        NQ_INT opStatus;  /* operation status */

        relAdapterCount++;
        /* validate operation status */

        opStatus = staticData->names[idx].operations[adapter->idx].status;

        switch (opStatus)
        {
        case OPERATION_NEW:
            TRC1P(">> An attempt to release a name (%s) that is not registered yet", formatName(name));

            if (response != NULL)
                returnNegativeReleaseResponse(name, response, adapter, CM_NB_RCODE_NAMERR);

            TRCE();
            return NQ_SUCCESS;
        case OPERATION_RELEASED:
            if (response != NULL)
                returnPositiveReleaseResponse(&staticData->names[idx], adapter);

            TRCE();         /* valid status - do nothing */
            return NQ_SUCCESS;
        case OPERATION_REGISTERED_B:
        case OPERATION_INREGISTRATION_B:
            opStatus = OPERATION_INRELEASE_B;
            break;          /* valid status */
        case OPERATION_REGISTERED_H:
            opStatus = OPERATION_INRELEASE_H;
            break;          /* valid status */
        default:
            TRCE();
            return NQ_SUCCESS; /* do nothing - operation already in progress */
        }

        staticData->names[idx].operations[adapter->idx].status = opStatus;

        if (staticData->names[idx].regName)
        {
            staticData->names[idx].operations[adapter->idx].tranId = syHton16(cmNetBiosGetNextTranId());
            sendReleaseRequest(&staticData->names[idx], adapter);
        }
        if (response != NULL)
            returnPositiveReleaseResponse(&staticData->names[idx], adapter);
            
        staticData->names[idx].operations[adapter->idx].status = OPERATION_NEW;  
    }

    if (relAdapterCount == 0 && response != NULL)
    	returnNegativeReleaseResponse(name, response, response, CM_NB_RCODE_NAMERR);

    /* free entry in names table for released name*/
    if (doFreeEntry)
        staticData->names[idx].idx = NO_NAME;

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

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

    TRCE();
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRC1P(">> Positive response for non-existing name: %s", formatName(name));

        TRCE();
        return NQ_SUCCESS;
    }

    /* compare TranID with the expected TranID */

    if (!(staticData->names[idx].operations[adapter->idx].tranId == cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)))
    {
        TRC2P(
            ">> Pos Reg Response with unexpected Tran ID: %d, while expected: %d",
            syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)),
            syNtoh16(staticData->names[idx].operations[adapter->idx].tranId)
            );

        TRCE();
        return NQ_SUCCESS;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].operations[adapter->idx].status;

    switch (opStatus)
    {
    case OPERATION_INREGISTRATION_H:
    case OPERATION_CLAIM:
        break;          /* valid status */
    default:
        TRC2P(">> Unexpected Pos Reg Response for name: %s, state: %d", formatName(name), opStatus);

        TRCE();
        return NQ_SUCCESS;
    }

    /* distinguish between Positive Registration Response and End-Node Chalenge Response */

    if (syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->packCodes)) & CM_NB_NAMEFLAGS_RA)
    {
        /* success */

        staticData->names[idx].operations[adapter->idx].status = OPERATION_REGISTERED_H;

        /* calculate TTL */

        {
            const CMNetBiosResourceRecord* resourceRecord;  /* casting to the rest of the packet */
            NQ_UINT32 ttl;                                     /* ttl value */

            resourceRecord = (CMNetBiosResourceRecord*)addData;
            ttl = syNtoh32(cmGetSUint32(resourceRecord->ttl));
            staticData->names[idx].operations[adapter->idx].ttl = (ttl - 1)/UD_ND_DAEMONTIMEOUT;
            staticData->names[idx].operations[adapter->idx].timeout = staticData->names[idx].operations[adapter->idx].ttl;
        }

        staticData->names[idx].operations[adapter->idx].tranId = NO_TID;
        returnPositiveRegistrationResponse(&staticData->names[idx], adapter);
    }
    else
    {
        const CMNetBiosAddrEntry* addrEntry;         /* to discover the claiming IP */

        /* another node claims to own this name -  start end-node challenge */

        addrEntry = (const CMNetBiosAddrEntry*)(addData + sizeof(CMNetBiosResourceRecord));
        staticData->names[idx].operations[adapter->idx].status = OPERATION_ENDNODECHALLENGE;
        staticData->names[idx].operations[adapter->idx].count = UD_ND_REGISTRATIONCOUNT;
        sendQueryRequest(&staticData->names[idx], adapter, cmGetSUint32(addrEntry->ip));
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRCE();
        return NQ_SUCCESS;
    }

    /* compare TranID with the expected TranID */

    if (!(staticData->names[idx].operations[adapter->idx].tranId == cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)))
    {
        TRC2P(
            ">> WACK with unexpected Tran ID: %d, expected - %d",
            syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)),
            syNtoh16(staticData->names[idx].operations[adapter->idx].tranId)
            );

        TRCE();
        return NQ_SUCCESS;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].operations[adapter->idx].status;

    switch (opStatus)
    {
    case OPERATION_INREGISTRATION_H:
    case OPERATION_CLAIM:
        break;          /* valid status */
    default:
        TRC2P(">> Unexpected WACK for name: %s, state: %d", formatName(name), opStatus);

        TRCE();
        return NQ_SUCCESS;
    }

    {
        const CMNetBiosResourceRecord* resourceRecord;  /* casting to the rest of the packet */
        NQ_UINT32 ttl;                                     /* ttl value */

        resourceRecord = (CMNetBiosResourceRecord*)addData;
        ttl = syNtoh32(cmGetSUint32(resourceRecord->ttl));
        staticData->names[idx].operations[adapter->idx].ttl = (ttl - 1)/UD_ND_DAEMONTIMEOUT;
        staticData->names[idx].operations[adapter->idx].timeout = staticData->names[idx].operations[adapter->idx].ttl;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRC1P(">> Registration response for non-existing name: %s", formatName(name));

        TRCE();
        return NQ_SUCCESS;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].operations[adapter->idx].status;
    switch (opStatus)
    {
    case OPERATION_INREGISTRATION_H:
    case OPERATION_INREGISTRATION_B:
        break;          /* valid status */
    default:
        TRC2P(">> Unexpected Neg Reg Response for name: %s, state: %d", formatName(name), opStatus);

        TRCE();         /* valid status - do nothing */
        return NQ_SUCCESS;
    }
    returnNegativeRegistrationResponse(&staticData->names[idx], adapter, CM_NB_RCODE_NAMERR);

    /* if name registration failed mark name entry as fake registered */
    staticData->names[idx].regName = FALSE;
    staticData->names[idx].operations[adapter->idx].status = OPERATION_INREGISTRATION_B;

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Process Positive Query Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the resgistered name
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)     /* this may be also a response for expternal name query */
    {
        TRCE();
        return NQ_SUCCESS;
    }

    /* compare TranID with the expected TranID */

    if (!(staticData->names[idx].operations[adapter->idx].tranId == cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)))
    {
        TRC2P(
            ">> Pos Reg Response with unexpected Tran ID: %d, expected - %d",
            syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)),
            syNtoh16(staticData->names[idx].operations[adapter->idx].tranId)
            );

        TRCE();
        return NQ_SUCCESS;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].operations[adapter->idx].status;

    switch (opStatus)
    {
    case OPERATION_ENDNODECHALLENGE:
        break;          /* valid status */
    default:
        TRC2P(">> Unexpected Pos Query Response for name: %s, state: %d", formatName(name), opStatus);

        TRCE();         /* valid status - do nothing */
        return NQ_SUCCESS;
    }

    staticData->names[idx].operations[adapter->idx].status = OPERATION_RELEASED;
    returnNegativeRegistrationResponse(&staticData->names[idx], adapter, CM_NB_RCODE_NAMERR);

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NO_NAME)
    {
        TRCE();
        return NQ_SUCCESS;
    }

    /* compare TranID with the expected TranID */

    if (!(staticData->names[idx].operations[adapter->idx].tranId == cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)))
    {
        TRC2P(
            ">> Neg Query Response with unexpected Tran ID: %d, expected - %d",
            syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)),
            syNtoh16(staticData->names[idx].operations[adapter->idx].tranId)
            );

        TRCE();
        return NQ_SUCCESS;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].operations[adapter->idx].status;

    switch (opStatus)
    {
    case OPERATION_ENDNODECHALLENGE:
        break;          /* valid status */
    default:
        TRC2P(">> Unexpected Neg Reg Response for name: %s, state: %d", formatName(name), opStatus);

        TRCE();         /* valid status - do nothing */
        return NQ_SUCCESS;
    }

    staticData->names[idx].operations[adapter->idx].status = OPERATION_CLAIM;
    staticData->names[idx].operations[adapter->idx].count = UD_ND_REGISTRATIONCOUNT;
    sendRefreshRequest(&staticData->names[idx], adapter);

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Process Positive Release Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the resgistered name
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
    TRCB();

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Process Negative Release Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the response
 *          IN: the resgistered name
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
    TRCB();

    TRCE();
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

    TRCB();

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
                   after several repeats this means successfull registration */
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
                        staticData->names[idx].operations[i].tranId = syHton16(cmNetBiosGetNextTranId());
                        sendRegistrationRequest(&staticData->names[idx], staticData->names[idx].operations[i].adapter);
                    }
                }
                break;
            case OPERATION_INREGISTRATION_H:
                retValue = UD_ND_DAEMONTIMEOUT;
                /* adapter was in registration and no response received - retry or switch to B */
                if (   staticData->names[idx].operations[i].ttl !=0
                    && staticData->names[idx].operations[i].timeout-- <= 0
                   )
                {
                    if (staticData->names[idx].operations[i].count-- <= 0)
                    {
                        staticData->names[idx].operations[i].status = OPERATION_INREGISTRATION_B;
                        staticData->names[idx].operations[i].count = CM_NB_UNICASTREQRETRYCOUNT;
                    }
                    staticData->names[idx].operations[i].timeout = staticData->names[idx].operations[i].ttl;
                    sendRegistrationRequest(&staticData->names[idx], staticData->names[idx].operations[i].adapter);
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

    TRCE();
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Process Name Registration Request from outside
 *--------------------------------------------------------------------
 * PARAMS:  IN: adapter - the source of the request
 *          IN: name to checke
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

    TRCB();

    if ((idx = findName(name)) != NO_NAME && adapter->inIp != adapter->ip && staticData->names[idx].regName && !staticData->names[idx].nameInfo.isGroup && adapter->typeB)
    {
        sendNegativeWhateverResponse(&staticData->names[idx], adapter, CM_NB_OPCODE_REGISTRATION, CM_NB_RCODE_CONFLICT);

        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
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
    /*NQ_STATIC NameEntry noName;*/ /* to report no name */

    /* find name in the list */

    TRCB();

    idx = findName(name);

    /* check if this name exists and should be reported */

    if (idx == NO_NAME  || !staticData->names[idx].regName)
    {
        if (!response->bcastDest)
        {
            TRC1P(">> Query for non-existing name: %s", formatName(name));

            /* syMemcpy(noName.nameInfo.name, name, sizeof(CMNetBiosName)); */
            /* sendNegativeWhateverResponse(&noName, response, CM_NB_OPCODE_QUERY, CM_NB_RCODE_NAMERR); */
        }

        TRCE();
        return NQ_FAIL;
    }

    /* find registered IPs (per adapter) and send all IPs in the response */

    {
        NQ_UINT i;                             /* index in adapters */
        NQ_STATIC CMNetBiosAddrEntry
            addresses[UD_NS_MAXADAPTERS];      /* NB addresses to report */
        NQ_UINT numAddr;                       /* number of addresses to return */

        numAddr = 0;

        for (i = 0; i < UD_NS_MAXADAPTERS; i++)
        {
            if (   staticData->names[idx].operations[i].status == OPERATION_REGISTERED_B
                || staticData->names[idx].operations[i].status == OPERATION_REGISTERED_H
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
            TRC1P(">> Name is being registered: %s", formatName(name));

            if (sendNegativeResponse)
                sendNegativeWhateverResponse(&staticData->names[idx], response, CM_NB_OPCODE_QUERY, CM_NB_RCODE_NAMERR);

            TRCE();
            return NQ_FAIL;
        }

        sendPositiveQueryResponse(&staticData->names[idx], response, addresses, numAddr);
    }

    TRCE();
    return NQ_SUCCESS;
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
    NQ_STATIC NQ_BYTE statusData[STATUS_DATA_LENGTH]; /* buffer for status data */
    NQ_BYTE* pData;                                /* pointer to the current position there */
    NQ_BYTE numNames;           /* number of reported names */
    NQ_UINT16 tranId;           /* saved tran id in NBO */
    NQ_UINT16 flags;            /* name flags */
    NQ_UINT16 temp;             /* for converting flags */
    NQ_IPADDRESS to;

    TRCB();

    /* don't respond on nonregistered name */
    if((name[0] != '*') && (findName(name) == NO_NAME))
        return NQ_SUCCESS;

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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send the Name Query NBSTAT Response");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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
    NQ_INT idx;       /* index in names */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx != NO_NAME)
        {
            if (cmNetBiosSameNames(name, staticData->names[idx].nameInfo.name))
            {
                return idx;
            }
        }
    }

    return NO_NAME;
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
    NQ_INT idx;       /* index in names */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].idx == NO_NAME)
        {
            NQ_UINT i;     /* index in operations */

            for (i = 0; i < UD_NS_MAXADAPTERS; i++)
            {
                staticData->names[idx].operations[i].status = OPERATION_NEW;
            }
            staticData->names[idx].idx = idx;
            return idx;
        }
    }

    TRCERR("Overflow in the name table");

    return NO_NAME;
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
    const NDAdapterInfo* adapter
    )
{
    NQ_INT msgLen;                /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_UINT16 flags;               /* header flags (B only) */
    NQ_IPADDRESS to;               /* called IP */

    TRCB();

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverRequest(
        msgHdr,
        name->nameInfo.name,
        adapter->ip,
        adapter->typeB
        );

    if (msgLen <= 0)
    {
        TRCE();
        return NQ_FAIL;
    }

    /* determine tran ID, called address type and flags */

    if (name->operations[adapter->idx].status == OPERATION_INREGISTRATION_B)
    {
        CM_IPADDR_ASSIGN4(to, adapter->bcast);
        flags = CM_NB_NAMEFLAGS_B;
    }
    else
    {
        CM_IPADDR_ASSIGN4(to, adapter->wins);
        flags = 0;
    }
    cmPutSUint16(msgHdr->tranID, name->operations[adapter->idx].tranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_REGISTRATION | (NQ_UINT16)flags));

    /* send the message */

    resLen = sySendToSocket(
        adapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        syHton16(CM_NB_NAMESERVICEPORT)
        );
    if (resLen <= 0)
    {
        TRCERR("Failed to send the Name Registration Request");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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
    NQ_INT msgLen;                 /* length of the outgoing message */
    NQ_INT resLen;                 /* length of the sent data */
    CMNetBiosHeader* msgHdr;       /* casted pointer to the outgoing message */
    NQ_UINT16 flags;               /* header flags (B only) */
    NQ_IPADDRESS to;               /* called IP */

    TRCB();

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverRequest(
        msgHdr,
        name->nameInfo.name,
        adapter->ip,
        adapter->typeB
        );

    if (msgLen <= 0)
    {
        TRCE();
        return NQ_FAIL;
    }

    /* determine trans ID, called address type and flags */

    if (name->operations[adapter->idx].status == OPERATION_REGISTERED_B)
    {
        CM_IPADDR_ASSIGN4(to, adapter->bcast);
        flags = CM_NB_NAMEFLAGS_ONT_B;
    }
    else
    {
        CM_IPADDR_ASSIGN4(to, adapter->wins);
        flags = 0;
    }
    cmPutSUint16(msgHdr->tranID, name->operations[adapter->idx].tranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_REFRESH | flags));

    /* send the message */

    resLen = sySendToSocket(
        adapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        syHton16(CM_NB_NAMESERVICEPORT)
        );
    if (resLen <= 0)
    {
        TRCERR("Failed to send the Name Registration Request");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send the Negative Response");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send the Name Registration Request");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameWhateverRequest(
        msgHdr,
        name->nameInfo.name,
        adapter->ip,
        adapter->typeB
        );

    if (msgLen <= 0)
    {
        TRCE();
        return NQ_FAIL;
    }

    /* determine tran ID, called address type and flags */

    if (name->operations[adapter->idx].status == OPERATION_INRELEASE_B)
    {
        CM_IPADDR_ASSIGN4(to, adapter->bcast);
        flags = CM_NB_NAMEFLAGS_B;
    }
    else
    {
        CM_IPADDR_ASSIGN4(to, adapter->wins);
        flags = 0;
    }
    cmPutSUint16(msgHdr->tranID, name->operations[adapter->idx].tranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_RELEASE | flags));

    name->operations[adapter->idx].status = OPERATION_RELEASED;

    /* send the message */

    resLen = sySendToSocket(
        adapter->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &to,
        syHton16(CM_NB_NAMESERVICEPORT)
        );
    if (resLen <= 0)
    {
        TRCERR("Failed to send the Name Release Request");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)adapter->outMsg;
    msgLen = ndGenerateNameQueryRequest(msgHdr, name->nameInfo.name);

    if (msgLen <= 0)
    {
        TRCE();
        return NQ_FAIL;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, name->operations[adapter->idx].tranId);
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
        TRCERR("Failed to send the Name Release Request");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

    if (NULL == name->resAdapter)
    {
        TRCE();
        return NQ_SUCCESS;
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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send Positive Registration Response internally");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Registration Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name entry to report on
 *          IN: adapter to use as the registrated address
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

    TRCB();
    if (NULL == name->resAdapter)
    {
        TRCE();
        return NQ_SUCCESS;
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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send Negative registration Response internally");
        TRCE();
        return NQ_SUCCESS;
    }
    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Send Positive Name Release Response internally
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

    TRCB();

    if (NULL == name->resAdapter)
    {
        TRCE();
        return NQ_SUCCESS;
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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send Positive registration Response internally");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Release Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name to report on
 *          IN: adapter to response over
 *          IN: adapter to use as the registrated address
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

    TRCB();

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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send Positive registration Response internally");
        TRCE();
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
}

#endif /* UD_ND_INCLUDENBDAEMON */

