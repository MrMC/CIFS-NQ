/*********************************************************************
 *
 *           Copyright (c) 2006 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : WINREG pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2006
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cswrgrpc.h"

#ifdef UD_NQ_INCLUDECIFSSERVER
#ifdef UD_CS_INCLUDERPC_WINREG

#define MAXOPENKEYS   10
#define MAXKEYNAMELEN 64

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define WINREG_ERROR_FILENOTFOUND 2
#define WINREG_ERROR_ACCESSDENIED 5
#define WINREG_ERROR_NOMOREITEMS  0x00000103

#define HKLM "HKLM"

#if 0
typedef enum {
    KT_NONE,
    KT_HKCR,
    KT_HKCU,
    KT_HKLM,
    KT_HKPD,
    KT_HKU,
    KT_HKCC,
    KT_HKDD,
    KT_HKPT,
    KT_HKPN
}
KeyType;
#endif

/* value types */

typedef enum {
    VT_SZ                  = 1,
    VT_EXPAND_SZ           = 2, /* Unicode null terminated string (with environment variable references) */
    VT_BINARY              = 3, /* Free form binary */
    VT_DWORD               = 4, /* 32-bit number */
#if 0
    VT_DWORD_LITTLE_ENDIAN = 4, /* 32-bit number (same as REG_DWORD) */
    VT_DWORD_BIG_ENDIAN    = 5, /* 32-bit number */
    VT_LINK                = 6, /* Symbolic Link (unicode) */
#endif
    VT_MULTI_SZ            = 7  /* Multiple Unicode strings */
}
ValueType;

/* registry key */

struct Key {
    struct Key    *parent;
    const NQ_CHAR *name;
};

/* name/value pair */

typedef struct {
    struct Key    *key;
    ValueType      type;
    const NQ_CHAR *name;
    const NQ_BYTE *value;
    NQ_UINT        size;
}
Pair;

/* keys hierarchy */

static struct Key _keys[] = {
    /* 00 */ {NULL,       HKLM},             /* HKLM root */
    /* 01 */ {&_keys[0],  "Software"},
    /* 02 */ {&_keys[1],  "Microsoft"},
    /* 03 */ {&_keys[2],  "Windows NT"},
    /* 04 */ {&_keys[3],  "CurrentVersion"}, /* HKLM\Software\Microsoft\Windows NT\CurrentVersion */
    /* 05 */ {&_keys[0],  "System"},
    /* 06 */ {&_keys[5],  "CurrentControlSet"},
    /* 07 */ {&_keys[6],  "Services"},
    /* 08 */ {&_keys[7],  "EventLog"},       /* HKLM\System\CurrentControlSet\Services\EventLog */
    /* 09 */ {&_keys[8],  "Application"},    /* HKLM\System\CurrentControlSet\Services\EventLog\Application */
    /* 10 */ {&_keys[8],  "Security"},       /* HKLM\System\CurrentControlSet\Services\EventLog\Securrity */
    /* 11 */ {&_keys[8],  "System"},         /* HKLM\System\CurrentControlSet\Services\EventLog\System */
    /* 12 */ {&_keys[6],  "Control"},
    /* 13 */ {&_keys[12], "ProductOptions"}, /* HKLM\System\CurrentControlSet\Control\ProductOptions */
    /* 14 */ {&_keys[7],  "Tcpip"},
    /* 15 */ {&_keys[14],  "Parameters"},    /* HKLM\System\CurrentControlSet\Services\Tcpip\Parameters */
};

/* values */

#define P_CURRENTVERSION "5.1"
#define P_SYSTEMROOT     "C:\\Windows"
#define P_FILE           "%SystemRoot%\\system32\\config\\AppEvent.Evt"
#define P_PRODUCTTYPE    "NQE"

static NQ_COUNT
localGetHostName(
    const NQ_BYTE** pData
    );

static NQ_COUNT
localGetDomainName(
    const NQ_BYTE** pData
    );

typedef NQ_COUNT (*ValueFunction)(const NQ_BYTE** pData);

static Pair _pairs[] = {
    {&_keys[4],  VT_SZ, "CurrentVersion", (const NQ_BYTE *)P_CURRENTVERSION, sizeof(P_CURRENTVERSION)},
    {&_keys[4],  VT_SZ, "SystemRoot",     (const NQ_BYTE *)P_SYSTEMROOT,     sizeof(P_SYSTEMROOT)},
    {&_keys[9],  VT_SZ, "File",           (const NQ_BYTE *)P_FILE,           sizeof(P_FILE)},
    {&_keys[13], VT_SZ, "ProductType",    (const NQ_BYTE *)P_PRODUCTTYPE,    sizeof(P_PRODUCTTYPE)},
    {&_keys[15], VT_SZ, "Hostname",       (const NQ_BYTE *)localGetHostName,    0},
    {&_keys[15], VT_SZ, "Domain",         (const NQ_BYTE *)localGetDomainName,  0},
};

/*====================================================================
 * PURPOSE: value function (host name)
 *--------------------------------------------------------------------
 * PARAMS:  double pointer to the value
 *
 * RETURNS: value size
 *
 * NOTES:
 *====================================================================
 */

static NQ_COUNT
localGetHostName(
    const NQ_BYTE** pData
    )
{
    *pData = (const NQ_BYTE*)cmNetBiosGetHostNameZeroed();
    return (NQ_COUNT)(syStrlen((NQ_CHAR*)*pData) + 1);
}

/*====================================================================
 * PURPOSE: value function (domain name)
 *--------------------------------------------------------------------
 * PARAMS:  double pointer to the value
 *
 * RETURNS: value size
 *
 * NOTES:
 *====================================================================
 */

static NQ_COUNT
localGetDomainName(
    const NQ_BYTE** pData
    )
{
    *pData = (const NQ_BYTE*)cmNetBiosGetDomain();
    return (NQ_COUNT)(syStrlen((NQ_CHAR*)*pData) + 1);
}

/*====================================================================
 * PURPOSE: Search key table to find a key by its name and parent
 *--------------------------------------------------------------------
 * PARAMS:  IN  parent key
 *          IN  key name
 *          IN  key name length
 *
 * RETURNS: pointer to the key if found, NULL otherwise
 *
 * NOTES:
 *====================================================================
 */

static struct Key *findKey2(struct Key *parent, const NQ_CHAR *name, NQ_UINT length)
{
    NQ_COUNT i;

    for (i = 0; i < ARRAY_SIZE(_keys); i++)
    {
        struct Key *k = &_keys[i];

        /* check populated entries only */
        if (k->parent == parent && cmAStrincmp(k->name, name, length) == 0)
            return k;
    }

    TRC2P("    key [%s] not found, parent [%s]", name, parent->name);

    return NULL;
}

/*====================================================================
 * PURPOSE: Find a key by its name and parent
 *--------------------------------------------------------------------
 * PARAMS:  IN  parent key
 *          IN  key name (absolute or relative)
 *
 * RETURNS: pointer to the key if found, NULL otherwise
 *
 * NOTES:   Traverses the name and uses findKey2()
 *====================================================================
 */

static struct Key *findKey(struct Key *parent, const NQ_CHAR *name)
{
    const NQ_CHAR *p = syStrchr(name, '\\');

    if (p == NULL)
        return findKey2(parent, name, (NQ_UINT)syStrlen(name));

    parent = findKey2(parent, name, (NQ_UINT)(p - name));

    if (parent == NULL)
        return NULL;

    return findKey(parent, p + 1);
}

/*====================================================================
 * PURPOSE: Get key under given key at given index
 *--------------------------------------------------------------------
 * PARAMS:  IN  parent key
 *          IN  index
 *
 * RETURNS: pointer to the key if found, NULL otherwise
 *
 * NOTES:
 *====================================================================
 */

static struct Key *getKey(struct Key *key, NQ_UINT index)
{
    NQ_COUNT i;

    for (i = 0; i < ARRAY_SIZE(_keys); i++)
    {
        struct Key *k = &_keys[i];

        if (k->parent == key)
            if (index-- == 0)
            {
                TRC1P("    found [%s]", k->name);
                return k;
            }
    }

    TRC("    no keys found");
    return NULL;
}

/*====================================================================
 * PURPOSE: Find name/value pair under given key
 *--------------------------------------------------------------------
 * PARAMS:  IN  parent key
 *          IN  value name
 *
 * RETURNS: pointer to the pair if found, NULL otherwise
 *
 * NOTES:
 *====================================================================
 */

static Pair *findPair(struct Key *key, const NQ_CHAR *name)
{
    NQ_COUNT i;

    for (i = 0; i < ARRAY_SIZE(_pairs); i++)
    {
        Pair *p = &_pairs[i];

        if (p->key == key && syStrcmp(p->name, name) == 0)
        {
            static Pair dummy;

            if (0 != p->size)
                return p;

            dummy.type = p->type;
            dummy.size = ((ValueFunction)p->value)(&dummy.value);

            return &dummy;
        }
    }

    TRC1P("    value of [%s] not found", name);

    return NULL;
}

#if 0
/*====================================================================
 * PURPOSE: Get name/value pair under given key at given index
 *--------------------------------------------------------------------
 * PARAMS:  IN  parent key
 *          IN  index
 *
 * RETURNS: pointer to the pair if found, NULL otherwise
 *
 * NOTES:
 *====================================================================
 */

static Pair *getPair(struct Key *key, NQ_UINT index)
{
    NQ_INT i;

    for (i = 0; i < ARRAY_SIZE(_pairs); i++)
    {
        Pair *p = &_pairs[i];

        if (p->key == key)
            if (index-- == 0)
                return p;
    }

    return NULL;
}
#endif

/* function prototypes */

/*
static NQ_UINT32 wrgOpenHKCR(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgOpenHKCU(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/
static NQ_UINT32 wrgOpenHKLM(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/*
static NQ_UINT32 wrgOpenHKPD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgOpenHKU(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/
static NQ_UINT32 wrgCloseKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/*
static NQ_UINT32 wrgCreateKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgDeleteKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgDeleteValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/
static NQ_UINT32 wrgEnumKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/*
static NQ_UINT32 wrgEnumValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgFlushKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgGetKeySecurity(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgLoadKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgNotifyChangeKeyValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/
static NQ_UINT32 wrgOpenKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/*
static NQ_UINT32 wrgQueryInfoKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/
static NQ_UINT32 wrgQueryValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/*
static NQ_UINT32 wrgReplaceKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgRestoreKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgSaveKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgSetKeySecurity(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgSetValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgUnLoadKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgInitiateSystemShutdown(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgAbortSystemShutdown(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/
static NQ_UINT32 wrgGetVersion(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
/*
static NQ_UINT32 wrgOpenHKCC(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgOpenHKDD(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgQueryMultipleValues(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgInitiateSystemShutdownEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgSaveKeyEx(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgOpenHKPT(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgOpenHKCR(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgOpenHKPN(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
static NQ_UINT32 wrgQueryMultipleValues2(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out);
*/

/* function table */

static const CSRpcFunctionDescriptor functions[] =
{
    { NULL /* wrgOpenHKCR */                                        /* 0x00 */ },
    { NULL /* wrgOpenHKCU */                                        /* 0x01 */ },
    { wrgOpenHKLM                                                   /* 0x02 */ },
    { NULL /* wrgOpenHKPD */                                        /* 0x03 */ },
    { NULL /* wrgOpenHKU */                                         /* 0x04 */ },
    { wrgCloseKey                                                   /* 0x05 */ },
    { NULL /* wrgCreateKey */                                       /* 0x06 */ },
    { NULL /* wrgDeleteKey */                                       /* 0x07 */ },
    { NULL /* wrgDeleteValue */                                     /* 0x08 */ },
    { wrgEnumKey                                                    /* 0x09 */ },
    { NULL /* wrgEnumValue */                                       /* 0x0a */ },
    { NULL /* wrgFlushKey */                                        /* 0x0b */ },
    { NULL /* wrgGetKeySecurity */                                  /* 0x0c */ },
    { NULL /* wrgLoadKey */                                         /* 0x0d */ },
    { NULL /* wrgNotifyChangeKeyValue */                            /* 0x0e */ },
    { wrgOpenKey                                                    /* 0x0f */ },
    { NULL /* wrgQueryInfoKey */                                    /* 0x10 */ },
    { wrgQueryValue                                                /* 0x11 */ },
    { NULL /* wrgReplaceKey */                                      /* 0x12 */ },
    { NULL /* wrgRestoreKey */                                      /* 0x13 */ },
    { NULL /* wrgSaveKey */                                         /* 0x14 */ },
    { NULL /* wrgSetKeySecurity */                                  /* 0x15 */ },
    { NULL /* wrgSetValue */                                        /* 0x16 */ },
    { NULL /* wrgUnLoadKey */                                       /* 0x17 */ },
    { NULL /* wrgInitiateSystemShutdown */                          /* 0x18 */ },
    { NULL /* wrgAbortSystemShutdown */                             /* 0x19 */ },
    { wrgGetVersion                                                /* 0x1a */ },
    { NULL /* wrgOpenHKCC */                                        /* 0x1b */ },
    { NULL /* wrgOpenHKDD */                                        /* 0x1c */ },
    { NULL /* wrgQueryMultipleValues */                             /* 0x1d */ },
    { NULL /* wrgInitiateSystemShutdownEx */                        /* 0x1e */ },
    { NULL /* wrgSaveKeyEx */                                       /* 0x1f */ },
    { NULL /* wrgOpenHKPT */                                        /* 0x20 */ },
    { NULL /* wrgOpenHKPN */                                        /* 0x21 */ },
    { NULL /* wrgQueryMultipleValues2 */                            /* 0x22 */ },
};

/* initialialization and cleanup */

static NQ_STATUS initData(void);
static void stopData(void);

/* pipe descriptor record */

static const CSRpcPipeDescriptor pipedesc =
{
    initData,
    stopData,
    NULL,
    "winreg",
    {cmPack32(0x338cd001),cmPack16(0x2244),cmPack16(0x31f1),{0xaa,0xaa},{0x90,0x00,0x38,0x00,0x10,0x03}},
    cmRpcVersion(1, 0),
    (sizeof(functions) / sizeof(functions[0])),
    functions,
    NULL
};

/* open handles table */

typedef struct
{
    NQ_BOOL     isFree;
    NQ_UINT16   id;
    struct Key *key;
    NQ_UINT16   system;
    NQ_UINT32   access;
}
Handle;

/* local data */

typedef struct
{
    Handle handles[MAXOPENKEYS];
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/*====================================================================
 * PURPOSE: Get pipe descriptor
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pipe descriptor for this pipe
 *
 * NOTES:
 *====================================================================
 */

const CSRpcPipeDescriptor*
csRpcWinReg(
    void
    )
{
    return &pipedesc;
}

/*====================================================================
 * PURPOSE: Initialize local data
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS on success, NQ_FAIL on error
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
initData(
    void
    )
{
    NQ_COUNT i;

     TRCB();

#ifdef SY_FORCEALLOCATION
    staticData = (StaticData*)syMalloc(sizeof(*staticData));

    if (staticData == NULL)
    {
        TRCERR("Unable to allocate memoty region for static data");
        TRCE();

        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    /* initialize handle table */
    for (i = 0; i < ARRAY_SIZE(staticData->handles); i++)
        staticData->handles[i].isFree = TRUE;

    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: Clean up local data
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
stopData(
    void
    )
{
    /* TRCB(); */

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);

    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    TRCE();
}

/*====================================================================
 * PURPOSE: Allocate internal policy handle record
 *--------------------------------------------------------------------
 * PARAMS:  none
 *
 * RETURNS: pointer to handle in the table or NULL if no record was allocated
 *
 * NOTES:
 *====================================================================
 */

static Handle *allocateHandle(void)
{
    NQ_UINT16 i;

    for (i = 0; i < ARRAY_SIZE(staticData->handles); i++)
    {
        Handle *h = &staticData->handles[i];

        if (h->isFree)
        {
            TRC1P("allocateHandle: handle allocated at slot %d", i);

            h->id = (NQ_UINT16)(i + 1);
            h->isFree = FALSE;

            return h;
        }
    }

    TRCERR("allocateHandle: could not allocate new handle");

    return NULL;
}

/*====================================================================
 * PURPOSE: Release previously allocated handle
 *--------------------------------------------------------------------
 * PARAMS:  IN  handle to release
 *
 * RETURNS: none
 *
 * NOTES:
 *====================================================================
 */

static void releaseHandle(Handle *h)
{
    h->isFree = TRUE;
}

/*====================================================================
 * PURPOSE: Get internal handle from the table by policy handle
 *--------------------------------------------------------------------
 * PARAMS:  IN  incoming packet descriptor
 *
 * RETURNS: pointer to handle in the table or NULL if not found
 *
 * NOTES:
 *====================================================================
 */

static Handle *getHandle(CMRpcPacketDescriptor* in)
{
    NQ_UINT16 ix;

    /* skip first 18 bytes of policy handle */
    cmRpcParseSkip(in, 18);
    cmRpcParseUint16(in, &ix);

    ix--;

    if (ix < ARRAY_SIZE(staticData->handles))
    {
        Handle *h = &staticData->handles[ix];

        if (!h->isFree)
        {
            TRC1P("getHandle: handle found at slot %d", ix);

            return h;
        }
    }

    TRCERR("getHandle: handle not found");

    return NULL;
}

/*====================================================================
 * PURPOSE: Put policy handle into a response packet
 *--------------------------------------------------------------------
 * PARAMS:  IN  response packet descriptor
 *          IN  internal handle record
 *
 * RETURNS: none
 *
 * NOTES:
 *====================================================================
 */

static void putHandle(CMRpcPacketDescriptor* out, Handle *h)
{
    /* 20 bytes of policy handle */
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint32(out, 0);
    cmRpcPackUint16(out, 0);
    cmRpcPackUint16(out, (NQ_UINT16)(h != NULL ? h->id : 0));
}

static void parseUnicodeString(CMRpcPacketDescriptor *in, CMRpcUnicodeString *s)
{
    NQ_UINT16 size;     /* name size */
    static const NQ_WCHAR  noName[] = {0};

    cmRpcParseSkip(in, 2);       /* name length */
    cmRpcParseUint16(in, &size);
    cmRpcParseSkip(in, 4);       /* ref ID */
    if (0 != size)
        cmRpcParseUnicode(in, s, CM_RP_SIZE32 | CM_RP_FRAGMENT32);
    else
    {
        s->size = 0;
        s->length = 0;
        s->offset = 0;
        s->text = (NQ_WCHAR *)&noName;
    }
}

/*====================================================================
 * PURPOSE: Open HKLM
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: 0 on success, error code on failure
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 wrgOpenHKLM(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out)
{
    NQ_UINT32 access;
    NQ_UINT16 system;

    TRCB();

    /* read data */
      /* ref ID */
    cmRpcParseSkip(in, 4);
      /* system name */
    cmRpcParseUint16(in, &system);
    cmRpcAllign(in, 4);
      /* access mask */
    cmRpcParseUint32(in, &access);

    TRC2P("System name: %u, access mask: %08lX", system, access);

#if 0
    if (TRUE /* accessAllowed(in, access) */)
#endif
    {
        Handle *h = allocateHandle();

        /* write policy handle (can be NULL) */
        putHandle(out, h);

        if (h != NULL)
        {
            h->key = findKey(NULL, HKLM);
            h->system = system;
            h->access = access;

            TRCE();
            return 0;
        }

        TRCE();
        return CM_RP_INSUFFICIENTRESOURCE;
    }

#if 0
    putHandle(out, NULL);

    TRCE();
    return WINREG_ERROR_ACCESSDENIED;
#endif
}

/*====================================================================
 * PURPOSE: Close key
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: 0 on success, error code on failure
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 wrgCloseKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out)
{
    Handle *h = getHandle(in);
    int i;      /* just a counter */

    TRCB();

    for (i = 0; i < 5; i++)
        cmRpcPackUint32(out, 0);

    if (h != NULL)
    {
        TRC1P("Close key: %s", h->key->name);

        releaseHandle(h);
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Enumerate key
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: 0 on success, error code on failure
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 wrgEnumKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out)
{
    NQ_UINT32 refID = 1;
    NQ_UINT32 index;
    NQ_UINT16 size;
    struct Key *k;
    Handle *h = getHandle(in);

    TRCB();

    if (NULL == h)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "handle is not available");
        TRCE();
    	return 0;
    }

    cmRpcParseUint32(in, &index);
    cmRpcParseSkip(in, 2);
    cmRpcParseUint16(in, &size);

    TRC2P("Enumerate keys under [%s] at index %d", h->key->name, (NQ_UINT16)index);

    k = getKey(h->key, (NQ_UINT)index);

    if (k != NULL)
    {
        NQ_UINT16 length = (NQ_UINT16)((syStrlen(k->name) + 1) * 2);

        /* name: length and size */
        cmRpcPackUint16(out, length);
        cmRpcPackUint16(out, size);
        /* pointer to name: ref ID, max count, offset, actual count, UNICODE string */
        cmRpcPackUint32(out, refID++);
        cmRpcPackAsciiAsUnicode(out, k->name, CM_RP_NULLTERM | CM_RP_SIZE32 | CM_RP_FRAGMENT32);
        /* pointer to key class: ref ID, length, size, pointer to name (NULL) */
        cmRpcPackUint32(out, refID++);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint32(out, 0);
        /* pointer to last changed time */
        cmRpcPackUint32(out, refID++);
        cmRpcPackTimeAsUTC(out, syGetTimeInMsec());

        TRCE();
        return 0;
    }
    else
    {
    	NQ_TIME zero = {0, 0};

        /* name: length and size */
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, size);
        /* pointer to name: ref ID, max count, offset, actual count, UNICODE string */
        cmRpcPackUint32(out, refID++);
        cmRpcPackUint32(out, 0);
        cmRpcPackUint32(out, 0);
        cmRpcPackUint32(out, 0);
        /* pointer to key class: ref ID, length, size, pointer to name (NULL) */
        cmRpcPackUint32(out, refID++);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint16(out, 0);
        cmRpcPackUint32(out, 0);
        /* pointer to last changed time */
        cmRpcPackUint32(out, refID++);
        cmRpcPackTimeAsUTC(out, zero);

        TRCE();
        return WINREG_ERROR_NOMOREITEMS;
    }
}

/*====================================================================
 * PURPOSE: Open registry key
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: 0 on success, error code on failure
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 wrgOpenKey(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out)
{
    CMRpcUnicodeString name;
    NQ_UINT32 access;
    NQ_UINT32 result = WINREG_ERROR_ACCESSDENIED;
    /* read policy handle */
    Handle *parent = getHandle(in);

    TRCB();

    if (parent != NULL)
    {
        NQ_CHAR buf[MAXKEYNAMELEN+1];

        /* key name */
        parseUnicodeString(in, &name);
        /* unknown */
        cmRpcParseSkip(in, 4);
        /* access mask */
        cmRpcParseUint32(in, &access);

        cmUnicodeToAnsi(buf, name.text);
        TRC2P("Open key: %s, access mask: 0x%08lX", buf, access);

        if (TRUE /* isAccessAllowed(in, access) */)
        {
            struct Key *k = findKey(parent->key, buf);

            if (k != NULL)
            {
                Handle *h = allocateHandle();

                putHandle(out, h);

                if (h != NULL)
                {
                    h->key = k;
                    h->access = access;

                    TRCE();
                    return 0;
                }
                else
                    result = CM_RP_INSUFFICIENTRESOURCE;
            }
            else
                result = WINREG_ERROR_FILENOTFOUND;
        }
    }

    putHandle(out, NULL);

    TRCE();
    return result;
}

/*====================================================================
 * PURPOSE: Query key value
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: 0 on success, error code on failure
 *
 * NOTES:   If the size supplied in the packet is 0 then the actual size of data is requested. In this case no
 *           data is sent back, only its type and size. Length is also should be 0 but not NULL!
 *====================================================================
 */

static NQ_UINT32 wrgQueryValue(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out)
{
    NQ_UINT32 ref = 0;
    Handle *h = getHandle(in);

    TRCB();

    if (h != NULL && h->key != NULL)
    {
        NQ_UINT32 size, length, type;
        CMRpcUnicodeString uname;
        NQ_CHAR aname[MAXKEYNAMELEN];
        Pair *p;

        /* value name in UNICODE */
        parseUnicodeString(in, &uname);
        /* pointer to type (ref ID, type) */
        cmRpcParseSkip(in, 4);
        cmRpcParseUint32(in, &type);
        /* pointer to data (ref ID, max count, offset, actual count) */
        cmRpcParseSkip(in, 4 * 4);
        /* pointer to size (ref ID, size) */
        cmRpcParseSkip(in, 4);
        cmRpcParseUint32(in, &size);
        /* pointer to length (ref ID, length) */
        cmRpcParseSkip(in, 4);
        cmRpcParseUint32(in, &length);

        cmUnicodeToAnsiN(aname, uname.text, MAXKEYNAMELEN);
        TRC3P("Query value: %s, data size: %ld, length: %ld", aname, size, length);
        TRC1P("    requested type: %ld", type);

        p = findPair(h->key, aname);

        if (p != NULL /* && p->size <= size */)
        {
            /* string are UNICODE */
            NQ_UINT32 sz = (NQ_UINT32)((p->type == VT_SZ) ? p->size * sizeof(NQ_WCHAR) : p->size);

            /* pointer to type (ref ID, type) */
            cmRpcPackUint32(out, ++ref);
            cmRpcPackUint32(out, (NQ_UINT32)p->type);

            /* pointer to data (ref ID, max count, offset, actual count) */
            if (size > 0)
            {
                cmRpcPackUint32(out, ++ref);
                cmRpcPackUint32(out, sz);
                cmRpcPackUint32(out, 0);
                cmRpcPackUint32(out, sz);

                /* data (for strings convert to UNICODE */
                if (p->type == VT_SZ)
                {
                    TRC1P("    data type: REG_SZ, value: %s", (const NQ_CHAR *)p->value);

                    cmAnsiToUnicode((NQ_WCHAR *)out->current, (const NQ_CHAR *)p->value);
                    cmRpcPackSkip(out, sz);
                }
                else
                {
                    cmRpcPackBytes(out, p->value, sz);
                }
            }
            else
                cmRpcPackUint32(out, 0);

            /* pointer to size (ref ID, size) */
            cmRpcAllign(out, 4);
            cmRpcPackUint32(out, ++ref);
            cmRpcPackUint32(out, sz);

            /* pointer to length (ref ID, length) */
            cmRpcPackUint32(out, ++ref);
            cmRpcPackUint32(out, (size > 0 ? sz : 0));

            TRCE();
            return 0;
        }
    }

    /* in case of error output NULL pointers */

    /* pointer to type (ref ID, type) */
    cmRpcPackUint32(out, 0);
    /* pointer to data (ref ID, max count, offset, actual count) */
    cmRpcPackUint32(out, 0);
    /* pointer to size (ref ID, size) */
    cmRpcAllign(out, 4);
    cmRpcPackUint32(out, 0);
    /* pointer to length (ref ID, length) */
    cmRpcPackUint32(out, 0);

    TRCE();
    return WINREG_ERROR_FILENOTFOUND;
}

/*====================================================================
 * PURPOSE: Get version
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: 0 on success, error code on failure
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32 wrgGetVersion(CMRpcPacketDescriptor* in, CMRpcPacketDescriptor* out)
{
    Handle *h = getHandle(in);

    TRCB();

    if (h != NULL)
    {
        cmRpcPackUint32(out, 1);

        return 0;
    }

    return WINREG_ERROR_ACCESSDENIED;
}

#endif
#endif

