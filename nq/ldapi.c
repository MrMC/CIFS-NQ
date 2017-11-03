/*********************************************************************
 *
 *           Copyright (c) 2009 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : LDAP Client abstract API
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Jul-2005
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ldapi.h"

#ifdef UD_CC_INCLUDELDAP
#include "syldap.h"

/*
 * Start LDAP client
 *
 */
NQ_STATUS                               /* error code */
ldStart( )
{
    return syLdStart();
}


/*
 * Stop LDAP client
 *
 */
void
ldStop(
        )
{
    syLdStop();
}

/*
 * Connect to LDAP Server
 * - open + bind
 * - the server is initially the DC
 * - rebinding (on a referral is proceed internally with the same credentials
 * - GSS is used with available security mechanisms
 * - this call creates dynamic context, to release call ldCloseConnection
 */
NQ_STATUS                           /* error code */
ldConnectA(
        const NQ_CHAR * domain,     /* domain name */
        const NQ_CHAR * user,       /* user account name */
        const NQ_CHAR * password,   /* account password */
        LDConnectionHandle * handle /* resulted handle */
        )
{
    NQ_STATIC NQ_WCHAR domainW[CM_BUFFERLENGTH(NQ_WCHAR, CM_NQ_HOSTNAMESIZE)];
    NQ_STATIC NQ_WCHAR userW[CM_BUFFERLENGTH(NQ_WCHAR, CM_USERNAMELENGTH)];
    NQ_STATIC NQ_WCHAR passwordW[CM_BUFFERLENGTH(NQ_WCHAR, 65)];

    if (domain)     cmAnsiToUnicode(domainW, domain);
    if (user)       cmAnsiToUnicode(userW, user);
    if (password)   cmAnsiToUnicode(passwordW, password);

    return ldConnectW(domainW, userW, passwordW, handle);
}

/*
 * Connect to LDAP Server
 * - open + bind
 * - the server is initially the DC
 * - rebinding (on a referral is proceed internally with the same credentials
 * - GSS is used with available security mechanisms
 * - this call creates dynamic context, to release call ldCloseConnection
 */
NQ_STATUS                            /* error code */
ldConnectW(
        const NQ_WCHAR * domain,     /* domain name */
        const NQ_WCHAR * user,       /* user account name */
        const NQ_WCHAR * password,   /* account password */
        LDConnectionHandle * handle  /* resulted handle */
        )
{
     return syLdConnect(domain, user, password, handle);
}

/*
 * Disconnect from LDAP Server
 */
NQ_STATUS                           /* error code */
ldCloseConnection(
        LDConnectionHandle handle   /* LDAP handle */
        )
{
    return syLdCloseConnection(handle);
}

/* LDAP_msgfree() regardless of return value !!!*/
NQ_STATUS                           /* error code */
ldSearch(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * base,       /* root item to start search from */
        NQ_INT scope,               /* one of the SY_LDAPSCOPE constants above */
        const NQ_CHAR * filter,     /* search filter, may be NULL */
        const NQ_CHAR * attribs[],  /* pointer to an array of attribute names, NULL-terminated.
                                       NULL means all attributes. */
        LDResultHandle * result     /* buffer for resulted message handle */
        )
{
    return syLdSearch(handle, base, scope, filter, attribs, result);
}


/*
 * Close a search result and free memory
 */
NQ_STATUS                           /* error code */
ldReleaseResult(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */
        )
{
    return syLdReleaseResult(handle, result);
}

/*
 * Get number of entries
 */
NQ_INT                              /* number of entries or -1 on error */
ldGetNumEntries(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */
        )
{
    return syLdGetNumEntries(handle, result);
}

/*
 * Get entry by its position in result
 * This call tries to enumerate entries using result context
 */
LDEntryHandle                       /* entry handle or NULL on wrong index */
ldGetEntry(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result,      /* message handle */
        NQ_INT index                /* entry index */
        )
{
    return syLdGetEntry(handle, result, index);
}


/*
 * Get DN of the entry's object
 */
void
ldEntryName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_CHAR *dn,                /* buffer for DN name */
        NQ_UINT lenDn               /* length of DN buffer */
        )
{
    syLdEntryName(handle, entry, dn, lenDn);
}

/*
 * Get number of attributes  (no corresponding direct openLDAP API)
 */
NQ_COUNT                            /* number of attributes */
ldGetNumAttribs(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry         /* entry handle */
        )
{
    return syLdGetNumAttribs(handle, entry);
}


/*
 * Get attribute index in result by its name
 */
NQ_INT                              /* index or LDAP_ERROR */
ldGetAttrIndexByName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        const NQ_CHAR * attr        /* attribute name */
        )

{
    return syLdGetAttrIndexByName(handle, entry, attr);
}

/*
 * Get attribute name in result by its index (caller must free memory: ldFreeAttrName())
 */
const NQ_CHAR *                     /* name or NULL */
ldGetAttrNameByIndex(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        )
{
    return syLdGetAttrNameByIndex(handle, entry, index);
}

/*
 * Free attribute name in result   (after ldGetAttrNameByIndex())
 */
void
ldFreeAttrName(
        const NQ_CHAR * name
        )
{
    syLdFreeAttrName(name);
}

/*
 * Get number of attribute values
 */
NQ_COUNT                            /* number of attribute values or LDAP_ERROR on wrong index */
ldGetNumValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        )
{
    return syLdGetNumValues(handle, entry, index);
}

/*
 * Get attribute values pointer (caller must free memory with ldFreeAttrValues)
 */
const LDValue **                    /* values pointer or NULL */
ldGetAttrValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        )
{
    return syLdGetAttrValues(handle, entry, index);
}

/*
 * Free attribute values pointer (returned by ldGetAttrValues)
 */
void
ldFreeAttrValues(
        const LDValue **values      /* values array */
        )
{
    syLdFreeAttrValues(values);
}

/*
 * Delete an object
 */
NQ_STATUS                           /* 0 on success, error code on failure */
ldDelete(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name        /* object DN */
        )
{
    return syLdDelete(handle, name);
}

/*
 * Delete an attribute
 */
NQ_STATUS                           /* error code */
ldDeleteAttrib(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name,       /* object DN */
        const NQ_CHAR * attr        /* attribute name */
        )
{
    return syLdDeleteAttrib(handle, name, attr);
}

/*
 * Start an add transaction, ldAddAttributeString()/ldAddAttributeBinary() must follow
 */
LDTransactionHandle                 /* transaction handle or NULL */
ldAdd(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name,       /* object DN or just name if parent exists */
        const NQ_CHAR * objectClass /* object class name */
        )
{
    return syLdAdd(handle, parent, name, objectClass);
}


/*
 * Start a modify transaction
 */
LDTransactionHandle                 /* transaction handle or NULL */
ldModify(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name        /* object DN or just name if parent exists */
        )
{
    return syLdModify(handle, parent, name);
}

/*
 * Add/modify attribute value (string)
 */
NQ_STATUS                           /* error code */
ldAddAttributeString(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_CHAR * value       /* ASCII or UTF-8 null-terminated */
        )
{
    return syLdAddAttributeString(tran, attr, value);
}

/*
 * Add/modify attribute value (binary)
 */
NQ_STATUS                           /* error code */
ldAddAttributeBinary(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_BYTE * value,      /* value */
        NQ_COUNT len                /* value length */
        )
{
    return syLdAddAttributeBinary(tran, attr, value, len);
}

/*
 * Delete attribute
 * - available only for Modify transaction
 */
NQ_STATUS                           /* error code */
ldDeleteAttribute(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr        /* attribute name */
        )
{
    return syLdDeleteAttribute(tran, attr);
}

/*
 * Perform transaction
 * - also clears the memory
 */
NQ_STATUS                           /* error code */
ldExecute(
        LDTransactionHandle tran,   /* transaction handle */
        NQ_BOOL releaseHandle       /* whether to release a transaction handle */
        )
{
    return syLdExecute(tran, releaseHandle);
}

/* Get cover page info (full name, address and fax number) for particular user */
/* Caller should allocate buffers and pass their lengths.
   In case of insufficient buffer length error code LDAP_MOREDATA is returned and required length
   put by corresponding pointer for subsequent call with reallocated buffers */
NQ_STATUS                           /* error code */
ldGetUserCoverPageInfoA(
        LDConnectionHandle handle, /* LDAP connection handle */
        const NQ_CHAR *accountName,/* account name */
        const NQ_CHAR *domainName, /* domain name */
        NQ_UINT *personalNameLen,  /* pointer to personal name length */
        NQ_CHAR *personalName,     /* personal name */
        NQ_UINT *surnameLen,       /* pointer to personal surname length */
        NQ_CHAR *surname,          /* pointer to surname */
        NQ_UINT *addressLen,       /* pointer to address length */
        NQ_CHAR *address,          /* pointer to address */
        NQ_UINT *faxNumberLen,     /* pointer to fax number length */
        NQ_CHAR *faxNumber         /* pointer to fax number */
        )
{
    NQ_STATUS status = LDAP_ERROR;
    NQ_WCHAR *accountNameW, *domainNameW, *personalNameW, *surnameW, *addressW, *faxNumberW;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    accountNameW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((syStrlen(accountName) + 1) * sizeof(NQ_WCHAR)));
    domainNameW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((syStrlen(domainName) + 1) * sizeof(NQ_WCHAR)));
    personalNameW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((*personalNameLen + 1) * sizeof(NQ_WCHAR)));
    surnameW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((*surnameLen+ 1) * sizeof(NQ_WCHAR)));
    addressW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)((*addressLen + 1) * sizeof(NQ_WCHAR)));
    faxNumberW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)(*faxNumberLen + 1) * (NQ_UINT)sizeof(NQ_WCHAR)));

    if (accountNameW && domainNameW && personalNameW && surnameW && addressW && faxNumberW)
    {
        cmAnsiToUnicode(accountNameW, accountName);
        cmAnsiToUnicode(domainNameW, domainName);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }

    status = ldGetUserCoverPageInfoW(handle,
                                    accountNameW,
                                    domainNameW,
                                    personalNameLen,
                                    personalNameW,
                                    surnameLen,
                                    surnameW,
                                    addressLen,
                                    addressW,
                                    faxNumberLen,
                                    faxNumberW);
    if (NQ_SUCCESS == status)
    {
        cmUnicodeToAnsi(personalName, personalNameW);
        cmUnicodeToAnsi(surname, surnameW);
        cmUnicodeToAnsi(address, addressW);
        cmUnicodeToAnsi(faxNumber, faxNumberW);
    }

Exit:
    cmMemoryFree(accountNameW);
    cmMemoryFree(domainNameW);
    cmMemoryFree(personalNameW);
    cmMemoryFree(surnameW);
    cmMemoryFree(addressW);
    cmMemoryFree(faxNumberW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    
    return status;
}

/* Get cover page info (full name, address and fax number) for particular user */
/* Caller should allocate buffers and pass their lengths.
   In case of insufficient buffer length error code LDAP_MOREDATA is returned and required length
   put by corresponding pointer for subsequent call with reallocated buffers */
NQ_STATUS                           /* error code */
ldGetUserCoverPageInfoW(
        LDConnectionHandle handle, /* LDAP handle */
        const NQ_WCHAR *accountName,/* account name */
        const NQ_WCHAR *domainName,/* domain name */
        NQ_UINT *personalNameLen,  /* pointer to personal name length */
        NQ_WCHAR *personalName,    /* personal name */
        NQ_UINT *surnameLen,       /* pointer to personal surname length */
        NQ_WCHAR *surname,         /* pointer to surname */
        NQ_UINT *addressLen,       /* pointer to address length */
        NQ_WCHAR *address,         /* pointer to address */
        NQ_UINT *faxNumberLen,     /* pointer to fax number length */
        NQ_WCHAR *faxNumber        /* pointer to fax number */
        )
{
    LDResultHandle  result;
    const NQ_CHAR *attribs[] = {"name", "sn", "postalAddress", "facsimileTelephoneNumber", NULL};
    LDEntryHandle entry;
    NQ_INT index;
    const LDValue **values;
    NQ_WCHAR *baseNameW = NULL;
    NQ_CHAR *baseNameA = NULL;
    NQ_COUNT length;
	NQ_WCHAR emptyNameW[] = {cmWChar('\0')};
    NQ_WCHAR *p1, *p2;
    NQ_STATUS status = LDAP_SUCCESS;
	NQ_STATIC const NQ_WCHAR cnString[] = {cmWChar('C'), cmWChar('N'), cmWChar('='), cmWChar('\0')};

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p accountName:%s domainName:%s", handle, cmWDump(accountName), cmWDump(domainName)); 

    /* create account name of type 'CN=<user>, CN=Users, DC=<domain>, DC=<com>' */
    length = syWStrlen(accountName) + syWStrlen(domainName) + 24;
    baseNameW = (NQ_WCHAR *)cmMemoryAllocate(length * (NQ_UINT)sizeof(NQ_WCHAR));
    if (!baseNameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        status = LDAP_ERROR;
        goto Exit;
    }

    if (cmWStricmp(cnString, accountName) != 0)
    {
        cmAnsiToUnicode(baseNameW, "CN=");
        cmWStrcat(baseNameW, accountName);
        cmAnsiToUnicode(baseNameW + cmWStrlen(baseNameW), ", CN=Users");
        p1 = (NQ_WCHAR *)domainName;
        p2 = cmWStrchr(p1, cmWChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmWChar('\0');
            cmAnsiToUnicode(baseNameW + cmWStrlen(baseNameW), ", DC=");
            cmWStrcat(baseNameW, p1);
            p1 = p2 + 1;
            p2 = cmWStrchr(p1, cmWChar('.'));
        }
        cmAnsiToUnicode(baseNameW + cmWStrlen(baseNameW), ", DC=");
        cmWStrcat(baseNameW, p1);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "baseName %s", cmWDump(baseNameW));

    /* convert to UTF8 string */
    if ((baseNameA = (NQ_CHAR *)cmMemoryAllocate(length * 4)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to allocate memory");
        status = LDAP_ERROR;
        goto Exit;
    }
    cmUnicodeToUTF8N(baseNameA, baseNameW, length * 4);

    /* find a user entry */
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "handle 0x%x, baseName %s", handle, baseNameA);
    if (ldSearch(handle, baseNameA, LDAP_SCOPESUBTREE, "(ObjectClass=user)", attribs, &result) != 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get user %s", baseNameA);
        status = LDAP_ERROR;
        goto Exit;
    }

    /* iterate through search result */
    if ((entry = ldGetEntry(handle, result, 0)) != NULL)
    {
        NQ_COUNT num = ldGetNumAttribs(handle, entry);

        if (num == 0)
        {
            ldReleaseResult(handle, result);
            LOGERR(CM_TRC_LEVEL_ERROR, "failed to get attributes %s", baseNameA);
            status = LDAP_ERROR;
            goto Exit;
        }

        /* get personal name */
        if ((index = ldGetAttrIndexByName(handle, entry, "name")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *personalNameLen)
            {
                *personalNameLen = (NQ_UINT)values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToUnicodeN(personalName, (const NQ_CHAR *)values[0]->data, (NQ_UINT)values[0]->len * (NQ_UINT)sizeof(NQ_WCHAR));
            }
            ldFreeAttrValues(values);
        }
        else
        {
            cmWStrcpy(personalName, emptyNameW);
        }

        /* get surname */
        if ((index = ldGetAttrIndexByName(handle, entry, "sn")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *surnameLen)
            {
                *surnameLen = (NQ_UINT)values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToUnicodeN(surname, (const NQ_CHAR *)values[0]->data, (NQ_UINT)values[0]->len * (NQ_UINT)sizeof(NQ_WCHAR));
            }
            ldFreeAttrValues(values);
        }
        else
        {
             cmWStrcpy(surname, emptyNameW);
        }

        /* get address */
        if ((index = ldGetAttrIndexByName(handle, entry, "postalAddress")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *addressLen)
            {
                *addressLen = (NQ_UINT)values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToUnicodeN(address, (const NQ_CHAR *)values[0]->data, (NQ_UINT)values[0]->len * (NQ_UINT)sizeof(NQ_WCHAR));
            }
            ldFreeAttrValues(values);
        }
        else
        {
            cmWStrcpy(address, emptyNameW);
        }

        /* get fax number */
        if ((index = ldGetAttrIndexByName(handle, entry, "facsimileTelephoneNumber")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *faxNumberLen)
            {
                *faxNumberLen = (NQ_UINT)values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToUnicodeN(faxNumber, (const NQ_CHAR *)values[0]->data, (NQ_UINT)values[0]->len * (NQ_UINT)sizeof(NQ_WCHAR));
            }
            ldFreeAttrValues(values);
        }
        else
        {
            cmWStrcpy(faxNumber, emptyNameW);
        }
    }

    /* release search result */
    ldReleaseResult(handle, result);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
	return status;
}


NQ_STATUS                               /* error code */
ldPublishPrinterW(
        LDConnectionHandle handle,      /* LDAP connection handle */
        const NQ_WCHAR * parent,        /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_WCHAR * domainName,    /* domain name (may be NULL if parent not NULL)*/
        const NQ_WCHAR * printerName    /* printer name */
        )
{
    LDTransactionHandle trns;       /* transaction descriptor */
    NQ_CHAR *uNCName = NULL, *parentA = NULL, *printerNameA = NULL;
    NQ_STATUS status = LDAP_ERROR;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p parent:%s domainName:%s printerName:%s", handle, cmWDump(parent), cmWDump(domainName), cmWDump(printerName)); 

    if (!handle || !printerName || (!parent && !domainName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        goto Exit;
    }

    /* construct printer name of form 'CN=' */
    if ((printerNameA = (NQ_CHAR *)cmMemoryAllocate((cmWStrlen(printerName) + 4) * sizeof(NQ_CHAR))) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    syStrcpy(printerNameA, "CN=");
    cmUnicodeToAnsi(printerNameA + syStrlen(printerNameA), printerName);

    /* construct printer uNCName */
    if ((uNCName = (NQ_CHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen((NQ_CHAR *)cmGetFullHostName()) + (NQ_UINT)cmWStrlen(printerName) + 4) * sizeof(NQ_CHAR))) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    syStrcpy(uNCName, "\\\\");
    syStrcat(uNCName, cmGetFullHostName());
    syStrcat(uNCName, "\\");
    syStrcat(uNCName, printerNameA + 3);

    /* construct parent */

    if (parent)
    {
        if ((parentA = (NQ_CHAR *)cmMemoryAllocate((cmWStrlen(parent) + 1) * sizeof(NQ_CHAR))) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        cmUnicodeToAnsi(parentA, parent);
    }
    else /* construct domain name */
    {
        NQ_WCHAR *p1, *p2;

        if ((parentA = (NQ_CHAR *)cmMemoryAllocate(((NQ_UINT)cmWStrlen(domainName) + 25) * (NQ_UINT)sizeof(NQ_CHAR) * 2)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        syStrcpy(parentA, "CN=Computers, ");
        p1 = (NQ_WCHAR *)domainName;
        p2 = cmWStrchr(p1, cmWChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmWChar('\0');
            syStrcat(parentA, "DC=");
            cmUnicodeToAnsi(parentA + syStrlen(parentA), p1);
            p1 = p2 + 1;
            p2 = cmWStrchr(p1, cmWChar('.'));
        }
        syStrcat(parentA, ", DC=");
        cmUnicodeToAnsi(parentA + syStrlen(parentA), p1);
    }

    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "printer: %s, parent: %s", printerNameA, parentA ? parentA : "");

    /* start Add transaction */
    trns = ldAdd(handle, parentA, printerNameA, "printQueue");

    /* add mandatory attributes for creating a printer entry in LDAP */
    ldAddAttributeString(trns, "printerName", printerNameA + 3);
    ldAddAttributeString(trns, "versionNumber", "4");
    ldAddAttributeString(trns, "serverName", cmGetFullHostName());
    ldAddAttributeString(trns, "shortServerName", cmNetBiosGetHostNameZeroed());
    ldAddAttributeString(trns, "uNCName", uNCName);
    ldAddAttributeString(trns, "printShareName", printerNameA + 3);

    /* execute transaction */
    status = ldExecute(trns, TRUE);

Exit:
    cmMemoryFree(parentA);
    cmMemoryFree(uNCName);
    cmMemoryFree(printerNameA);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}


/* Publish printer transaction */
NQ_STATUS                           /* error code */
ldPublishPrinterA(
        LDConnectionHandle handle,  /* LDAP connection handle */
        const NQ_CHAR * parent,     /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_CHAR * domainName, /* domain name (may be NULL if parent not NULL)*/
        const NQ_CHAR * printerName /* printer name */
        )
{
    NQ_STATUS status = LDAP_ERROR;
    NQ_WCHAR *parentW = NULL, *printerNameW = NULL, *domainNameW = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (!handle || !printerName || (!parent && !domainName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        goto Exit;
    }

    if (parent)
    {
        if ((parentW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(parent) + 1) * (NQ_UINT)sizeof(NQ_WCHAR) * 2)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        cmAnsiToUnicode(parentW, parent);
    }

    if (domainName)
    {
        if ((domainNameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(domainName) + 1) * (NQ_UINT)sizeof(NQ_WCHAR) * 2)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        cmAnsiToUnicode(domainNameW, domainName);
    }

    if ((printerNameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(printerName) + 1) * (NQ_UINT)    sizeof(NQ_WCHAR) * 2)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    cmAnsiToUnicode(printerNameW, printerName);

    status = ldPublishPrinterW(handle, parentW, domainNameW, printerNameW);
    
Exit:
    status = ldPublishPrinterW(handle, parentW, domainNameW, printerNameW);
    if (parentW)        cmMemoryFree(parentW);
    if (domainNameW)    cmMemoryFree(domainNameW);
    cmMemoryFree(printerNameW);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d",status);
    return status;
}


/* Add printer property with string value (ASCII) */
NQ_STATUS
ldAddPrinterPropertyStringA(
        LDConnectionHandle handle,  /* LDAP connection handle */
        const NQ_CHAR *printerName, /* printer name */
        const NQ_CHAR *domainName,  /* domain name (may be NULL if printerName has LDAP syntax */
        const NQ_CHAR *name,        /* property/attribute name */
        const NQ_CHAR *value        /* property/attribute value */
        )
{
    NQ_STATUS status = LDAP_ERROR;
    NQ_WCHAR *printerNameW = NULL, *domainNameW = NULL, *nameW = NULL, *valueW = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        goto Exit;
    }

    printerNameW = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(syStrlen(printerName) + 1) * (NQ_UINT)sizeof(NQ_WCHAR));
    if (domainName)
        domainNameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(domainName) + 1) * (NQ_UINT)sizeof(NQ_WCHAR));
    nameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(name) + 1) * (NQ_UINT)sizeof(NQ_WCHAR));
    valueW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(value) + 1) * (NQ_UINT)sizeof(NQ_WCHAR));

    if (!printerNameW || !nameW || !valueW || (domainName && !domainNameW))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    else
    {
        cmAnsiToUnicode(printerNameW, printerName);
        if (domainName)
            cmAnsiToUnicode(domainNameW, domainName);
        cmAnsiToUnicode(nameW, name);
        cmAnsiToUnicode(valueW, value);
    }

    status = ldAddPrinterPropertyStringW(handle, printerNameW, domainNameW, nameW, valueW);

Exit:
    cmMemoryFree(printerNameW);
    cmMemoryFree(domainNameW);
    cmMemoryFree(nameW);
    cmMemoryFree(valueW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

/* Add printer property with string value (Unicode) */
NQ_STATUS
ldAddPrinterPropertyStringW(
        LDConnectionHandle handle,   /* LDAP connection handle */
        const NQ_WCHAR *printerName, /* printer name */
        const NQ_WCHAR *domainName,  /* domain name (may be NULL if printerName has LDAP syntax */
        const NQ_WCHAR *name,        /* property/attribute name */
        const NQ_WCHAR *value        /* property/attribute value */
        )
{
    NQ_STATUS status = LDAP_ERROR;
    NQ_CHAR *base = NULL, *nameA = NULL, *valueA = NULL;
	LDTransactionHandle *trns;
	LDResultHandle result;
	const NQ_WCHAR cn[] = {cmWChar('C'), cmWChar('N'), cmWChar('='), cmWChar('\0')};

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "handle:%p printerName:%s domainName:%s name:%s value:%s", handle, cmWDump(printerName), cmWDump(domainName), cmWDump(name), value);

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        goto Exit;
    }
    /* at this point TCHAR function and WChar functions were jointed together */

    /* construct base name for search operation */
    if (cmWStrincmp(cn, printerName, cmWStrlen(cn)) == 0)
    {
        if ((base = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(printerName) * 4 + 1)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        cmUnicodeToUTF8N(base, printerName, cmWStrlen(printerName));
    }
    else
    {
        NQ_WCHAR *p1, *p2;
        if ((base = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(printerName) * 4 + cmWStrlen(domainName) * 4 + 6)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        syStrcpy(base, "CN=");
        cmUnicodeToUTF8N(base + syStrlen(base), printerName, (NQ_UINT)cmWStrlen(printerName) * 4 + (NQ_UINT)cmWStrlen(domainName) * 4 + 6 - (NQ_COUNT)syStrlen(base));
        syStrcat(base, ",CN=Computers, ");

        /* construct domain name */

        p1 = (NQ_WCHAR *)domainName;
        p2 = cmWStrchr(p1, cmWChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmWChar('\0');
            syStrcat(base, "DC=");
            cmUnicodeToAnsi(base + syStrlen(base), p1);
            p1 = p2 + 1;
            p2 = cmWStrchr(p1, cmWChar('.'));
        }
        syStrcat(base, ", DC=");
        cmUnicodeToAnsi(base + syStrlen(base), p1);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "base: %s", base);
    }

    /* find printer*/
    if (ldSearch(handle, base, LDAP_SCOPESUBTREE, "(objectCategory=PrintQueue)", NULL, &result) != 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to find printer");
        goto Exit;
    }
    ldReleaseResult(handle, result);

    /* convert attribute name */
    if ((nameA = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(name) * 4)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    cmUnicodeToUTF8N(nameA, name, cmWStrlen(name));

    /* convert attribute value */
    if ((valueA = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(value) * 4)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    cmUnicodeToUTF8N(valueA, value, cmWStrlen(value));

    /* start Modify transaction */
    trns = ldModify(handle, NULL, base);

    /* add attribute */
    ldAddAttributeString(trns, nameA, valueA);

    /* execute transaction */
    status = ldExecute(trns, TRUE);

Exit:
    /* free pointers */
    cmMemoryFree(base);
    cmMemoryFree(nameA);
    cmMemoryFree(valueA);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status); 
    return status;
}


/* Add printer property with binary value */
NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryA(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_CHAR *printerName, /* printer name */
        const NQ_CHAR *domainName,  /* domain name (may be NULL if printerName has LDAP syntax */
        const NQ_CHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,       /* property/attribute value */
        NQ_UINT length              /* property/attribute value length */
        )
{
    NQ_STATUS status = LDAP_ERROR;
    NQ_WCHAR *printerNameW = NULL, *domainNameW = NULL, *nameW = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        goto Exit;
    }

    printerNameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(printerName) + 1) * (NQ_UINT)sizeof(NQ_WCHAR));
    if (domainName)
        domainNameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_UINT)syStrlen(domainName) + 1) * (NQ_UINT)sizeof(NQ_WCHAR));
    nameW = (NQ_WCHAR *)cmMemoryAllocate(((NQ_COUNT)syStrlen(name) + 1) * (NQ_COUNT)sizeof(NQ_WCHAR));

    if (!printerNameW || !nameW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    else
    {
        cmAnsiToUnicode(printerNameW, printerName);
        if (domainName)
            cmAnsiToUnicode(domainNameW, domainName);
        cmAnsiToUnicode(nameW, name);
    }

    status = ldAddPrinterPropertyBinaryW(handle, printerNameW, domainNameW, nameW, value, length);

Exit:
    cmMemoryFree(printerNameW);
    if (domainNameW) cmMemoryFree(domainNameW);
    cmMemoryFree(nameW);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}

/* Add printer property with binary value */
NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryW(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_WCHAR *printerName, /* printer name */
        const NQ_WCHAR *domainName,  /* domain name (may be NULL if printerName has LDAP syntax */
        const NQ_WCHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,        /* property/attribute value */
        NQ_UINT length               /* property/attribute value length */
        )
{
    NQ_STATUS status = LDAP_ERROR;
    NQ_CHAR *base = NULL, *nameA = NULL;
	LDTransactionHandle *trns;
	LDResultHandle result;
	const NQ_WCHAR cn[] = {cmWChar('C'), cmWChar('N'), cmWChar('='), cmWChar('\0')};
	NQ_WCHAR *p1, *p2;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        goto Exit;
    }

    /* construct base name for search operation */
    if (cmWStrincmp(cn, printerName, cmWStrlen(cn)) == 0)
    {
        if ((base = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(printerName) * 4 + 1)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        cmUnicodeToUTF8N(base, printerName, cmWStrlen(printerName));
    }
    else
    {
        if ((base = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(printerName) * 4 + cmWStrlen(domainName) * 4 + 6)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            goto Exit;
        }
        syStrcpy(base, "CN=");
        cmUnicodeToUTF8N(base + syStrlen(base), printerName, cmWStrlen(printerName));
        syStrcat(base, ",CN=Computers, ");

        /* construct domain name */
        p1 = (NQ_WCHAR *)domainName;
        p2 = cmWStrchr(p1, cmWChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmWChar('\0');
            syStrcat(base, "DC=");
            cmUnicodeToAnsi(base + syStrlen(base), p1);
            p1 = p2 + 1;
            p2 = cmWStrchr(p1, cmWChar('.'));
        }
        syStrcat(base, ", DC=");
        cmUnicodeToAnsi(base + syStrlen(base), p1);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "base: %s", base);
    }

    /* find printer*/
    if (ldSearch(handle, base, LDAP_SCOPESUBTREE, "(objectCategory=PrintQueue)", NULL, &result) != 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to find printer");
        goto Exit;
    }
    ldReleaseResult(handle, result);

    /* convert attribute name */
    if ((nameA = (NQ_CHAR *)cmMemoryAllocate(cmWStrlen(name) * 4)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        goto Exit;
    }
    cmUnicodeToUTF8N(nameA, name, cmWStrlen(name));

    /* start Modify transaction */
    trns = ldModify(handle, NULL, base);

    /* add attribute */
    ldAddAttributeBinary(trns, nameA, value, length);

    /* execute transaction */
    status = ldExecute(trns, TRUE);

Exit:
	/* free pointers */
	cmMemoryFree(base);
    cmMemoryFree(nameA);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", status);
    return status;
}
#endif /* UD_CC_INCLUDELDAP */
