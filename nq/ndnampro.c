/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Processing incoming messages and timeouts for
 *                 Naming Service
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndnampro.h"
#include "ndinname.h"
#include "ndexname.h"

#ifdef UD_ND_INCLUDENBDAEMON

/*
    Static functions & data
    -----------------------
 */

typedef struct
{
    NQ_CHAR scopeId[255];       /* buffer for parsed scope ID */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* determine packet type for incoming message */

static NQ_UINT16                /* packet type code */
getPacketType(
    const CMNetBiosHeader* pHdr /* incoming message */
    );

/* Operation codes

   codes are composed from:
    1) opcode
    2) response flag
    3) RCODE (error) field

   any RCODE other then zero is considered as error

   we compose one value from 1), 2) and 1 in BIT 0 when RCODE is not zero
 */

#define ANY_ERROR           1

#define QUERY_REQUEST           CM_NB_OPCODE_QUERY
#define POSITIVE_QUERY          CM_NB_OPCODE_QUERY | CM_NB_RESPONSE
#define NEGATIVE_QUERY          CM_NB_OPCODE_QUERY | CM_NB_RESPONSE | ANY_ERROR
#define REGISTRATION_REQUEST    CM_NB_OPCODE_REGISTRATION
#define POSITIVE_REGISTRATION   CM_NB_OPCODE_REGISTRATION | CM_NB_RESPONSE
#define NEGATIVE_REGISTRATION   CM_NB_OPCODE_REGISTRATION | CM_NB_RESPONSE | ANY_ERROR
#define RELEASE_REQUEST         CM_NB_OPCODE_RELEASE
#define POSITIVE_RELEASE        CM_NB_OPCODE_RELEASE | CM_NB_RESPONSE
#define NEGATIVE_RELEASE        CM_NB_OPCODE_RELEASE | CM_NB_RESPONSE | ANY_ERROR
#define REFRESH_REQUEST         CM_NB_OPCODE_REFRESH
#define REFRESHHALT_REQUEST     CM_NB_OPCODE_REFRESHALT
#define MULTIHOME_REQUEST       CM_NB_OPCODE_MHREGISTRATION
#define WACK                    CM_NB_OPCODE_WACK | CM_NB_RESPONSE

/*
 *====================================================================
 * PURPOSE: initalize internal data
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
ndNameInit(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate Naming Service data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    if (NQ_FAIL == ndInternalNameInit() || NQ_FAIL == ndExternalNameInit())
    {
        return NQ_FAIL;
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
ndNameStop(
    void
    )
{
    TRCB();

    ndInternalNameStop();
    ndExternalNameStop();

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
 * PURPOSE: Processing incoming message for Name Service
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT message origin - adapter structure
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL. NQ_FAIL is returned on internal error only.
 *          illegal incoming packet is reported as NQ_SUCCESS
 *
 * NOTES:   1. parse message to determine the packet type
 *          2. find existing name request or create a new one
 *          3. check if this packet type is appropriate for the request state
 *          4. call packet processing
 *          5. change state
 *====================================================================
 */

NQ_STATUS
ndNameProcessExternalMessage(
    NDAdapterInfo* adapter
    )
{
    NQ_UINT16 code;                 /* packet code including the response flag */
    CMNetBiosHeader* pHdr;          /* pointer to the header */
    CMNetBiosName name;             /* called name after parsing */
    NQ_BYTE* addData;               /* pointer to the date after the parsed name */
    NQ_STATUS status;               /* return status */

    TRCB();

    pHdr = (CMNetBiosHeader*)adapter->inMsg;
    adapter->inTranId = cmGetSUint16(pHdr->tranID);
    addData = cmNetBiosParseName(
                    adapter->inMsg,
                    pHdr + 1,
                    name,
                    staticData->scopeId,
                    sizeof(staticData->scopeId)
                    );

    if (addData == NULL)
    {
        TRCE();
        return NQ_FAIL;
    }

    code = getPacketType((CMNetBiosHeader*)adapter->inMsg);

    /* call packet processing */

    switch (code)
    {
    case REGISTRATION_REQUEST:
        status = ndInternalNameCheckNameConflict(adapter, name);
        break;
    case QUERY_REQUEST:
        status = ndInternalNameWhateverQuery(adapter, name, addData);
        break;
    case POSITIVE_REGISTRATION:
        status = ndInternalNamePositiveRegistration(adapter, name, addData);
        break;
    case NEGATIVE_REGISTRATION:
        status = ndInternalNameNegativeRegistration(adapter, name);
        break;
    case POSITIVE_RELEASE:
        status = ndInternalNamePositiveRelease(adapter, name);
        break;
    case NEGATIVE_RELEASE:
        status = ndInternalNameNegativeRelease(adapter, name);
        break;
    case POSITIVE_QUERY:
        status = ndInternalNamePositiveQuery(adapter, name, addData);
        status = ndExternalNamePositiveQuery(adapter, name, addData);
        break;
    case NEGATIVE_QUERY:
        status = ndInternalNameNegativeQuery(adapter, name);
        status = ndExternalNameNegativeQuery(adapter, name);
        break;
    case WACK:
        status = ndInternalNameWack(adapter, name, addData);
        status = ndExternalNameWack(adapter, name, addData);
        break;
    default:
        TRCERR("Illegal code");
        TRC1P("  code: %04x", code);
        return NQ_SUCCESS;
    }

    TRCE();
    return status;
}

/*
 *====================================================================
 * PURPOSE: Processing internal request for Name Service
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT message origin - adapter structure
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   the adapter is a "dummy" adapter
 *          1. parse message to determine the packet type
 *          2. find existing name request or create a new one
 *          3. check if this packet type is appropriate for the request state
 *          4. call packet processing
 *          5. change state
 *====================================================================
 */

NQ_STATUS
ndNameProcessInternalMessage(
    NDAdapterInfo* adapter
    )
{
    NQ_UINT16 code;                 /* packet code including the response flag */
    CMNetBiosHeader* pHdr;          /* pointer to the header */
    CMNetBiosNameInfo nameInfo;     /* called name after parsing */
    NQ_BYTE* addData;               /* pointer to the date after the parsed name */
    CMNetBiosAddrEntry* addrEntry;  /* pointer to the date after the parsed name */
    NQ_UINT16 flags;                /* name flags */

    TRCB();

    pHdr = (CMNetBiosHeader*)adapter->inMsg;
    adapter->inTranId = cmGetSUint16(pHdr->tranID);
    addData = cmNetBiosParseName(
                    adapter->inMsg,
                    pHdr + 1,
                    nameInfo.name,
                    staticData->scopeId,
                    sizeof(staticData->scopeId)
                    );

    if (addData == NULL)
    {
        TRCERR("Illegal message");
        TRCE();
        return NQ_FAIL;
    }

    addData += sizeof(CMNetBiosQuestion);

    /* dispatch the operation */

    code = getPacketType((CMNetBiosHeader*)adapter->inMsg);
    switch (code)
    {
    case QUERY_REQUEST:
        /* first check the internal name table (do not send any negative response if the name not found */
        if (ndInternalProcessNameQuery(adapter, nameInfo.name, FALSE) != NQ_SUCCESS)
            ndExternalNameQuery(adapter, nameInfo.name);
        break;
    case REGISTRATION_REQUEST:
        /* continue parsing the message */

        addData = cmNetBiosSkipName(
                        adapter->inMsg,
                        addData
                        );

        addrEntry = (CMNetBiosAddrEntry*)(addData + sizeof(CMNetBiosResourceRecord));
        flags = syNtoh16(cmGetSUint16(addrEntry->flags));
        nameInfo.isGroup = (flags & CM_NB_NAMEFLAGS_G) != 0;

        ndInternalNameRegisterAllAdapters(adapter, &nameInfo);
        break;
    case RELEASE_REQUEST:
        ndInternalNameReleaseAllAdapters(adapter, nameInfo.name, TRUE);
        break;
    default:
        TRCERR("Illegal code");
        TRC1P("code: %04x", code);
        return NQ_SUCCESS;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Timeout processing
 *--------------------------------------------------------------------
 * PARAMS:  IN elapsed time in seconds
 *
 * RETURNS: next timeout interval
 *
 * NOTES:   Scan name requests to determine an expired entry
 *          this may happen for internal name registration or
 *          internal name query only. Call processing and compose an error
 *          response.
 *====================================================================
 */

NQ_COUNT
ndNameProcessTimeout(
    NQ_INT delta
    )
{
    NQ_COUNT internal = ndInternalNameTimeout(delta);
    NQ_COUNT external = ndExternalNameTimeout(delta);

    return internal < external? internal : external;
}

/*
 *====================================================================
 * PURPOSE: Determine incoming packet type
 *--------------------------------------------------------------------
 * PARAMS:  IN packet pointer
 *
 * RETURNS: packet type code
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT16
getPacketType(
    const CMNetBiosHeader* pHdr
    )
{
    NQ_UINT16 codes;       /* the codes word from the packet */
    codes = syNtoh16(cmGetSUint16(pHdr->packCodes));
    return (NQ_UINT16)((codes & (CM_NB_OPCODE | CM_NB_RESPONSE)) | ((codes & CM_NB_RCODE)? ANY_ERROR:0));
}

#endif /* UD_ND_INCLUDENBDAEMON */

