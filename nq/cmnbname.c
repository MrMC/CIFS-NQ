/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : NetBIOS name routines
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 25-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmnbname.h"

/*
  This file implements NetBIOS functions for processing and representing NetBIOS names

  NetBIOS name and NetBIOS name encoding is implemented according to RFC-1001 and
  RFC-1002.
 */

/*
    Static data and functions
    -------------------------
 */

typedef struct
{
    NQ_CHAR scopeID[UD_NS_SCOPEIDLEN];
    NQ_UINT scopeLength;
    CMNetBiosNameInfo hostNameInfo;
    CMNetBiosName hostNameZeroed;
    CMNetBiosName hostNameSpaced;
    CMNetBiosNameInfo domainInfo;
    CMNetBiosNameInfo domainInfoAuth; /* valid NetBIOS domain name received from DC */
    NQ_BOOL hasFullDomainName;
    NQ_CHAR fullDomainName[CM_NQ_HOSTNAMESIZE + 1];
    NQ_CHAR fullHostName[CM_NQ_HOSTNAMESIZE + 1];
    NQ_WCHAR tempScope[CM_BUFFERLENGTH(NQ_WCHAR, UD_NS_SCOPEIDLEN)];
    NQ_WCHAR tempHost[CM_DATALENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE)];
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* giving an offset to a name label find this label */

static
NQ_BYTE*                   /* returns a pointer to the 1st byte (size) of an actual label */
resolveLabel(
    const void* msg,       /* pointer to the beginning of the message */
    NQ_BYTE** origin       /* address of a pointer the original label, that may be a pointer
                           this pointer will be shifted to the next label */
    );

/* asks system for the host name, converts it to upper case and pads with a special
   symbol */

static void
getHostName(
    NQ_CHAR *nameBuffer,   /* buffer for name */
    NQ_UINT length,        /* name length */
    NQ_CHAR pad            /* symbol to pad after the name end */
    );

/*
 *====================================================================
 * PURPOSE: Initialize name resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS:  NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Prepares commonly used names and constants
 *====================================================================
 */

NQ_STATUS
cmNetBiosNameInit(
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
        result = NQ_FAIL;
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    syMemset(staticData->hostNameInfo.name, 0, sizeof(staticData->hostNameInfo.name));
    syMemset(staticData->hostNameZeroed, 0, sizeof(staticData->hostNameZeroed));
    syMemset(staticData->hostNameSpaced, 0, sizeof(staticData->hostNameSpaced)); 
    syMemset(staticData->domainInfo.name, 0, sizeof(staticData->domainInfo.name)); 
    syMemset(staticData->domainInfoAuth.name, 0, sizeof(staticData->domainInfoAuth.name));
    syMemset(staticData->fullHostName, 0, sizeof(staticData->fullHostName)); 
    syMemset(staticData->fullDomainName, 0, sizeof(staticData->fullDomainName));
    /* scope ID is defined in UD */

    syStrncpy(staticData->scopeID, CM_NB_DEFAULT_SCOPEID, UD_NS_SCOPEIDLEN);

    udGetScopeID(staticData->tempScope);

    if (0 != cmWStrlen(staticData->tempScope))
    {
        cmUnicodeToAnsi(staticData->scopeID, staticData->tempScope);
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " Init scope id: %s", staticData->scopeID);

    staticData->scopeLength = (NQ_UINT)syStrlen(staticData->scopeID);
    getHostName(staticData->hostNameInfo.name, CM_NB_NAMELEN - 1, ' ');
    staticData->hostNameInfo.isGroup = FALSE;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " NetBIOS host name: %s", staticData->hostNameInfo.name);
    getHostName((NQ_CHAR*)staticData->hostNameZeroed, CM_NB_NAMELEN - 1, '\0');
    getHostName((NQ_CHAR*)staticData->hostNameSpaced, CM_NB_NAMELEN - 1, ' ');
	if (staticData->hostNameSpaced[0] == '\0')
		syMemset(staticData->hostNameSpaced, ' ', sizeof(staticData->hostNameSpaced));
    {
        NQ_WCHAR *s;
        NQ_UINT i;

        udGetDomain(staticData->tempHost, &staticData->domainInfo.isGroup);
        s = cmWStrchr(staticData->tempHost, cmWChar('.'));
        if (s)
            cmUnicodeToAnsiN(
                staticData->domainInfo.name,
                staticData->tempHost,
                (NQ_UINT)(s - staticData->tempHost) * 2
                );
        else
            cmUnicodeToAnsi(staticData->domainInfo.name, staticData->tempHost);

        i = (NQ_UINT)syStrlen(staticData->domainInfo.name);

        /* default value for domain name is WORKGROUP */
        if (i == 0)
        {
            syStrcpy(staticData->domainInfo.name, "WORKGROUP");
            staticData->domainInfo.isGroup = TRUE;
            i = (NQ_UINT)syStrlen(staticData->domainInfo.name);
        }

        while (i < sizeof(staticData->domainInfo.name))
            staticData->domainInfo.name[i++] = 0;

        syMemcpy(&staticData->domainInfoAuth, &staticData->domainInfo, sizeof(staticData->domainInfoAuth));
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " NetBIOS domain name: %s", staticData->domainInfo.name);
    }

    {
        NQ_BOOL isGroup;
        udGetDomain(staticData->tempHost, &isGroup);
        if (!isGroup && cmWStrchr(staticData->tempHost, cmWChar('.')))
        {
            cmUnicodeToAnsi(staticData->fullDomainName, staticData->tempHost);
            staticData->hasFullDomainName = TRUE;
        }
        else
        {
            staticData->hasFullDomainName = FALSE;
        }
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " FQDN domain name: %s", staticData->hasFullDomainName ? staticData->fullDomainName : "<none>");
    }
    {
        getHostName((NQ_CHAR*)staticData->fullHostName, CM_NB_NAMELEN - 1, '\0');
        if (staticData->hasFullDomainName)
        {
            syStrcat(staticData->fullHostName, ".");
            syStrcat(staticData->fullHostName, staticData->fullDomainName);
        }
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " FQDN host name: %s", staticData->fullHostName);
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release name resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   
 *====================================================================
 */

void
cmNetBiosNameExit(
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
 * PURPOSE: create a NetBIOS name from an ASCII name
 *--------------------------------------------------------------------
 * PARAMS:  OUT name to create
 *          IN text name
 *          IN name suffix
 *
 * RETURNS: NONE
 *
 * NOTES:   Pad with spaces
 *====================================================================
 */

void
cmNetBiosNameCreate(
    CMNetBiosName nbName,
    const NQ_CHAR* textName,
    NQ_BYTE postfix
    )
{
    NQ_CHAR *dot;
    NQ_UINT len;

    if ((dot = (NQ_CHAR *)syStrchr(textName, '.')) != NULL && (dot - textName) < CM_NB_NAMELEN)
        len = (NQ_UINT)(dot - textName);
    else
        len = (CM_NB_NAMELEN - 1);

    syStrncpy(nbName, textName, len);
    nbName[len] = 0;
    cmNetBiosNameFormat(nbName, postfix);
}

/*
 *====================================================================
 * PURPOSE: remove trailing spaces after the name
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT name to process
 *
 * RETURNS: NONE
 *
 * NOTES:   Pad with spaces
 *====================================================================
 */

void
cmNetBiosNameClean(
    CMNetBiosName nbName
    )
{
    NQ_UINT i;

    nbName[CM_NB_NAMELEN] = 0;
    for (i = (NQ_UINT)syStrlen(nbName); nbName[--i] == ' ';) ;
    nbName[++i] = (NQ_CHAR)0;
}

/*
 *====================================================================
 * PURPOSE: format a name as a NetBIOS name
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT name to format
 *          IN name postfix
 *
 * RETURNS: NONE
 *
 * NOTES:   Pad with spaces
 *====================================================================
 */

void
cmNetBiosNameFormat(
    CMNetBiosName name,
    NQ_BYTE postfix
    )
{
    NQ_UINT i;

	if (syStrlen(name) != 0)
	{
		name[CM_NB_NAMELEN - 1] = (NQ_CHAR)0;   /* terminator for printouts */
/*		for (i = 0; i<syStrlen(name); i++)
			name[i] = syToupper(name[i]);*/
		cmAStrupr(name);
		for (i = (NQ_UINT)syStrlen(name); i < sizeof(CMNetBiosName); i++)
			name[i] = ' ';
		name[CM_NB_NAMELEN] = (NQ_CHAR)0;       /* terminator for printouts */
		name[CM_NB_POSTFIXPOSITION] = (NQ_CHAR)postfix;  /* NB postfix */
	}
}

/*
 *====================================================================
 * PURPOSE: Get the NetBIOS scope
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: pointer to the scope string
 *====================================================================
 */

const NQ_CHAR*
cmNetBiosGetScope(
    void
    )
{
    return staticData->scopeID;
}

/*
 *====================================================================
 * PURPOSE: Get the NetBIOS scope
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: scope length
 *====================================================================
 */

NQ_UINT
cmNetBiosGetScopeLength(
    void
    )
{
    return staticData->scopeLength;
}


/*
 *====================================================================
 * PURPOSE: Returns node type ready to use in NB_NAME - shifted to an
 *          appropriate bit position
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: node type in an appropriate position
 *====================================================================
 */

NQ_UINT16
cmNetBiosGetNodeType(
    void
    )
{
    return (udGetWins()==0)? (NQ_UINT16)CM_NB_NAMEFLAGS_ONT_B : (NQ_UINT16)CM_NB_NAMEFLAGS_ONT_M;
}

/*
 *====================================================================
 * PURPOSE: encode a NetBIOS name according the domain name rules
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the name to encode
 *          OUT buffer for the encoded name
 *
 * RETURNS: number of bytes in the encode name + scope
 *
 * NOTES:   This function encodes a NetBIOS name according to RFC1001,
 *          RFC1002. The name is encoded with the system scope
 *====================================================================
 */

NQ_COUNT
cmNetBiosEncodeName(
    const CMNetBiosName name,
    NQ_BYTE* encodedName
    )
{
    NQ_BYTE* curPtr;        /* pointer to the current place in the encoded name */
    NQ_UINT  i;             /* just a counter */
    const NQ_CHAR* scopePtr;   /* pointer to the next name in the scope id */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p encodedName:%p", name, encodedName);

    curPtr = (NQ_BYTE*)encodedName;

    /* encode a NetBios name according to rfc-1001 */

    *curPtr++ = CM_NB_ENCODEDNAMELEN;

    for(i=0; i<CM_NB_NAMELEN; i++)
    {
        *curPtr++ = (NQ_BYTE)((((NQ_BYTE)name[i]) >> 4) + (NQ_BYTE)'A'); /* high half-octet */
        *curPtr++ = (NQ_BYTE)((((NQ_BYTE)name[i]) & 0xf) + (NQ_BYTE)'A');  /* low half-octet */
    }

    /* encode each label of the scope id */

    scopePtr = staticData->scopeID;

    while (TRUE)
    {
        NQ_CHAR* dotPtr;   /* pointer to the next dot symbol if any */
        NQ_UINT labelLen;  /* current label length */

        dotPtr = (NQ_CHAR *)syStrchr(scopePtr, '.');

        if (dotPtr == NULL)
        {
            labelLen = (NQ_UINT)syStrlen(scopePtr);
        }
        else
        {
            labelLen = (NQ_UINT)(dotPtr - scopePtr);
        }

        *curPtr++ = (NQ_BYTE)labelLen;

        syMemcpy(curPtr, scopePtr, labelLen);
        curPtr += labelLen;

        if (dotPtr == NULL)
            break;

        scopePtr = dotPtr + 1;
    }

    if (*(curPtr - 1)!=0)
        *curPtr++ = 0;        /* place a zero label as a terminator */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", ((NQ_BYTE*)curPtr - (NQ_BYTE*)encodedName));

    return (NQ_COUNT)((NQ_BYTE*)curPtr - (NQ_BYTE*)encodedName);
}

/*
 *====================================================================
 * PURPOSE: encode a NetBIOS name as pointer to the label of a previously
 *          encoded name
 *--------------------------------------------------------------------
 * PARAMS:  IN the beginning of the message
 *          OUT buffer for the encoded pointer
 *          IN pointer to the name to reference by the pointer
 *
 * RETURNS: number of bytes in the encoded pointer
 *
 * NOTES:   we encode a pointer as an offset from the message start (as in
 *          RFC1001, RFC1002)
 *          we assume that the origin label preceeds to a pointer to it
 *====================================================================
 */

NQ_COUNT
cmNetBiosEncodeNamePointer(
    void* msg,
    void* encodedName,
    const void* oldName
    )
{

    /* a pointer to a label is a 16-bit value with bits 15,16 set */

    CMNetBiosNameOffset* offsetPtr; /* pointer to a referencing offset */
    NQ_BYTE* curPtr;   /* pointer to the current place */
    NQ_BYTE* labelPtr; /* pointer to the refrenced label, may be a resolved label pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msg:%p encodedName:%p oldName:%p", msg, encodedName, oldName);

    offsetPtr = (CMNetBiosNameOffset*)encodedName;
    curPtr = (NQ_BYTE*)oldName;
    labelPtr = resolveLabel(msg, &curPtr);
    cmPutSUint16(offsetPtr->offset, syHton16((NQ_UINT16)((NQ_BYTE*)labelPtr - (NQ_BYTE*)msg) | (CM_NB_NAMEOFFSET<<8)));
    labelPtr = (NQ_BYTE*)(offsetPtr + 1);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", (labelPtr - (NQ_BYTE*)encodedName));

    return (NQ_COUNT)(labelPtr - (NQ_BYTE*)encodedName);
}

/*
 *====================================================================
 * PURPOSE: Skip a NetBIOS name + scope in a message
 *--------------------------------------------------------------------
 * PARAMS:  IN the beginning of the message
 *          IN pointer to the encoded name + scope
 *
 * RETURNS: a pointer to the 1st byte after the name (+ scope) or NULL
 *          if the parsing failed
 *
 * NOTES:   This function does calculates the encoded name length
 *          It parses real labels as well as label pointers
 *====================================================================
 */

NQ_BYTE*
cmNetBiosSkipName(
    const void* msg,
    const void* encodedName
    )
{
    NQ_UINT length;    /* length of name fragments */
    NQ_BYTE* curPtr;   /* pointer to the current place in the encoded name */
    NQ_BYTE* labelPtr; /* pointer to the current label, may be a resolved label pointer */
    NQ_BYTE* pResult = NULL; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msg:%p encodedName:%p", msg, encodedName);

    curPtr = (NQ_BYTE*)encodedName;

    /* resolve a possible pointer to a label */

    labelPtr = resolveLabel(msg, &curPtr);

    length = (NQ_UINT)*labelPtr++;

    if (length  != CM_NB_ENCODEDNAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "NetBIOS name is not 32 bytes long");
        goto Exit;
    }

    if (curPtr == ((NQ_BYTE*)encodedName + sizeof(CMNetBiosNameOffset)))   /* label encountered */
    {
        pResult = curPtr;
        goto Exit;
    }

    /* parse the labels of the scope ID */

    while (*curPtr != 0)
    {
        resolveLabel(msg, &curPtr); /* skip a label */
    }

    pResult = curPtr + 1;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

/*
 *====================================================================
 * PURPOSE: Decode a NetBIOS name + scope in a message
 *--------------------------------------------------------------------
 * PARAMS:  IN the beginning of the message
 *          IN pointer to the encoded name + scope
 *          OUT buffer for decoded NetBIOS name
 *          OUT buffer for the scope string
 *          IN this buffer size
 *
 * RETURNS: a pointer to the 1st byte after the name (+ scope) or NULL
 *          if the parsing failed
 *
 * NOTES:   This function decodes the name and the scope ID into user buffers
 *          It parses real labels as well as label pointers
 *====================================================================
 */

NQ_BYTE*
cmNetBiosParseName(
    const void* msg,
    const void* encodedName,
    CMNetBiosName decodedName,
    NQ_CHAR *scope,
    NQ_UINT scopeSize
    )
{
    NQ_UINT length;    /* length of name fragments */
    NQ_BYTE* curPtr;   /* pointer to the current place in the encoded name */
    NQ_BYTE* labelPtr; /* pointer to the current label, may be a resolved label pointer */
    NQ_UINT i;         /* just an index */
    NQ_BYTE* pResult = NULL; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msg:%p encodedName:%p decodedName:%p scope:%p scopeSize:%u", msg, encodedName, decodedName, scope, scopeSize);

    curPtr = (NQ_BYTE*)encodedName;

    /* resolve a possible pointer to a label */

    labelPtr = resolveLabel(msg, &curPtr);

    length = (NQ_UINT)*labelPtr++;

    if (length  != CM_NB_ENCODEDNAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "NetBIOS name is not 32 bytes long");
        goto Exit;
    }

    /* decode the NetBIOS name skipping two bytes at once */

    for(i=0; i<CM_NB_NAMELEN; i++)
    {
        NQ_BYTE nextByte;  /* for composing a char from two bytes of the encoded name */

        nextByte = 	(NQ_BYTE)((*labelPtr++ - (NQ_BYTE)'A') << 4);  	/* the high half-octet */
        nextByte |= (NQ_BYTE)(*labelPtr++ - (NQ_BYTE)'A');      	/* the low half-octet */

        decodedName[i] = (NQ_CHAR)nextByte;
    }

    /* parse the labels of the scope ID */

    if (*curPtr != 0)
    {
        while (*curPtr != 0)
        {
            labelPtr = resolveLabel(msg, &curPtr);

            length = (NQ_UINT)*labelPtr++;

            if (scopeSize > length)
            {
                syMemcpy((void*)scope, labelPtr, length);
                scope += length;
                scopeSize -= length;
                *scope++ = '.';     /* place a label delimiter */
            }
        }
        *--scope = (NQ_CHAR)0; /* place end of string instead of the last dot */
    }
    else
        *scope = (NQ_CHAR)0;

    pResult = curPtr + 1;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

/*
 *====================================================================
 * PURPOSE: Get host name
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Host name padded by zeros
 *
 * NOTES:
 *====================================================================
 */

const NQ_CHAR*
cmNetBiosGetHostNameZeroed(
    void
    )
{
    return (NQ_CHAR*)staticData->hostNameZeroed;
}

/*
 *====================================================================
 * PURPOSE: Get host name
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Host name padded by spaces
 *
 * NOTES:
 *====================================================================
 */

const NQ_CHAR*
cmNetBiosGetHostNameSpaced(
    void
    )
{
    return (NQ_CHAR*)staticData->hostNameSpaced;
}

/*
 *====================================================================
 * PURPOSE: Get host name information
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Host name padded by spaces
 *
 * NOTES:
 *====================================================================
 */

const CMNetBiosNameInfo*
cmNetBiosGetHostNameInfo(
    void
    )
{
    return &staticData->hostNameInfo;
}

/*
 *====================================================================
 * PURPOSE: Get NetBIOS domain name for broadcast
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Domain name zero-padded with group flag set
 *
 * NOTES:
 *====================================================================
 */

const CMNetBiosNameInfo*
cmNetBiosGetDomain(
    void
    )
{
    return &staticData->domainInfo;
}


/*
 *====================================================================
 * PURPOSE: Set NetBIOS domain name for authentication
 *--------------------------------------------------------------------
 * PARAMS:  name
 *
 * RETURNS:
 *
 * NOTES:
 *====================================================================
 */

void
cmNetBiosSetDomainAuth(
	NQ_WCHAR *name
	)
{
	syMemset(staticData->domainInfoAuth.name, 0, sizeof(staticData->domainInfoAuth.name));
	cmUnicodeToAnsi(staticData->domainInfoAuth.name, name);
}

/*
 *====================================================================
 * PURPOSE: Get NetBIOS domain name for authentication
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Domain name zero-padded
 *
 * NOTES:
 *====================================================================
 */

const CMNetBiosNameInfo*
cmNetBiosGetDomainAuth(
    void
    )
{
    return &staticData->domainInfoAuth;
}

/*
 *====================================================================
 * PURPOSE: Get full-qualified domain name
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Full qualified domain name if it is presented or NULL
 *
 * NOTES:
 *====================================================================
 */

const NQ_CHAR*
cmGetFullDomainName(
    void
    )
{
    return staticData->hasFullDomainName? staticData->fullDomainName : NULL;
}

/*
 *====================================================================
 * PURPOSE: Get full-qualified host name
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Full qualified host name
 *
 * NOTES:
 *====================================================================
 */

const NQ_CHAR*
cmGetFullHostName(
    void
    )
{
    return staticData->fullHostName;
}

/*
 *====================================================================
 * PURPOSE: get host name
 *--------------------------------------------------------------------
 * PARAMS:  OUT: buffer for the name
 *          IN: buffer length
 *          IN: pad character
 *
 * RETURNS: NONE
 *
 * NOTES:   asks system for host name, converts it to upper case
 *          and pads it with a special symbol
 *====================================================================
 */

static void
getHostName(
    NQ_CHAR *nameBuffer,
    NQ_UINT length,
    NQ_CHAR pad
    )
{
    NQ_UINT i;         /* just a counter */
    NQ_BOOL zeroName;

    syGetHostName(nameBuffer, length);    

    zeroName = syStrlen(nameBuffer) == 0 ? TRUE : FALSE;
    for (i = 0; i < length && nameBuffer[i] != '\0'; i++)
    {
        if (nameBuffer[i] == '.')
        {
            nameBuffer[i] = '\0';
            break;
        }
        nameBuffer[i] = syToupper(nameBuffer[i]);
    }

    for (; i <= length; i++)
    {
    	if (zeroName)
    	{
    		nameBuffer[i] = '\0';
    		continue;
    	}

        nameBuffer[i] = pad;
    }
}

/*
 *====================================================================
 * PURPOSE: Find a pointer to the name label in a case it is a
 *          pointer
 *--------------------------------------------------------------------
 * PARAMS:  IN the beginning of the message
 *          IN/OUT address of a pointer to the original label, that may
 *          be a pointer. This pointer will be set to the next label
 *
 * RETURNS: a pointer to a resolved label (either original or referenced
 *          by a pointer
 *
 * NOTES:   On a real label this function returns the original pointer
 *          On a label pointer it returns a pointer to the preceeding label
 *          It increments the double pointer to the origin so that it will
 *          point to the next label in the name
 *====================================================================
 */

static
NQ_BYTE*
resolveLabel(
    const void* msg,
    NQ_BYTE** origin
    )
{
    NQ_BYTE length;        /* length of name fragments */
    NQ_BYTE* savedOrigin;  /* may be a return value in some cases */
    NQ_BYTE* pResult = NULL; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "msg:%p origin:%p", msg, origin);

    savedOrigin = *origin;

    /* read the NetBIOS name length */

    length = **origin;

    /* distinguish between name and offset (rfc1002) */

    if ((length & CM_NB_NAMEOFFSET) == CM_NB_NAMEOFFSET)
    {
        /* we are dealing with an offset - fix the pointer and continue */

        CMNetBiosNameOffset* offsetPtr;   /* an offset record */
        NQ_UINT16 offset;                    /* offset to a name */

        offsetPtr = (CMNetBiosNameOffset*)(*origin);
        offset = syNtoh16(cmGetSUint16(offsetPtr->offset));
  
        /* the offset value is 14 bit. If it is negative we need to spread the 14th bit
           out to the 15th and the 16bit */

        if ((offset & (1<<13))!=0)
        {
            offset |= (CM_NB_NAMEOFFSET<<8);
        }
        else
        {
            offset &= (NQ_UINT16)(~(CM_NB_NAMEOFFSET<<8));
        }

        *origin += sizeof(CMNetBiosNameOffset);

        LOGMSG(CM_TRC_LEVEL_MESS_SOME, "an offset found");
        pResult = (NQ_BYTE*)msg + offset;        /* a referenced label */
        goto Exit;
    }
    else
    {
        *origin += length + 1; /* skip to the next label, this will work also on a zero
                                  label */
        LOGMSG(CM_TRC_LEVEL_MESS_SOME, "a label found");
        pResult = savedOrigin;
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

