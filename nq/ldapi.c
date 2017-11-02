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

#include "cmapi.h"

#ifdef UD_CC_INCLUDELDAP

static
NQ_STATUS                               /* error code */
ldConnectT(
        const NQ_TCHAR * domain,        /* domain name */
        const NQ_TCHAR * user,          /* user account name */
        const NQ_TCHAR * password,      /* account password */ 
        LDConnectionHandle * handle     /* resulted handle */ 
        );

static
NQ_STATUS                               /* error code */
ldGetUserCoverPageInfoT(
        LDConnectionHandle handle,      /* LDAP handle */
        const NQ_TCHAR *accountNameT,   /* account name */
        const NQ_TCHAR *domainNameT,    /* domain name */
        NQ_UINT *personalNameLen,       /* pointer to personal name length */
        NQ_TCHAR *personalName,         /* personal name */
        NQ_UINT *surnameLen,            /* pointer to personal surname length */
        NQ_TCHAR *surname,              /* pointer to surname */
        NQ_UINT *addressLen,            /* pointer to address length */
        NQ_TCHAR *address,              /* pointer to address */
        NQ_UINT *faxNumberLen,          /* pointer to fax number length */
        NQ_TCHAR *faxNumber             /* pointer to fax number */
        );

static
NQ_STATUS                               /* error code */ 
ldPublishPrinterT(
        LDConnectionHandle handle,      /* LDAP connection handle */
        const NQ_TCHAR * parent,        /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_TCHAR * domainName,    /* domain name (may be NULL if parent not NULL)*/
        const NQ_TCHAR * printerName    /* printer name */
        );

static
NQ_STATUS                            
ldAddPrinterPropertyStringT(
        LDConnectionHandle handle,   /* LDAP connection handle */
        const NQ_TCHAR *printerName, /* printer name (may be ldap dn name (CN=..., DC=...) */
        const NQ_TCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_TCHAR *name,        /* property/attribute name */
        const NQ_TCHAR *value        /* property/attribute value */
        );

NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryT(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_TCHAR *printerName, /* printer name */
        const NQ_TCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_TCHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,        /* property/attribute value */
        NQ_UINT length               /* property/attribute value length */
        );

/* 
 * Start LDAP client
 * 
 */
NQ_STATUS                               /* error code */
ldStart(
        )
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
 * - rebinding (on a referral is proceed internaly with the same credentials
 * - GSS is used with avaiable security mechanisms
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
    NQ_STATIC NQ_TCHAR domainT[CM_BUFFERLENGTH(NQ_TCHAR, CM_NQ_HOSTNAMESIZE)];  
    NQ_STATIC NQ_TCHAR userT[CM_BUFFERLENGTH(NQ_TCHAR, CM_USERNAMELENGTH)];
    NQ_STATIC NQ_TCHAR passwordT[CM_BUFFERLENGTH(NQ_TCHAR, 65)];

    if (domain)     cmAnsiToTchar(domainT, domain);
    if (user)       cmAnsiToTchar(userT, user);
    if (password)   cmAnsiToTchar(passwordT, password);

    return ldConnectT(domainT, userT, passwordT, handle);
}

/*
 * Connect to LDAP Server
 * - open + bind
 * - the server is initially the DC
 * - rebinding (on a referral is proceed internaly with the same credentials
 * - GSS is used with avaiable security mechanisms
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
    NQ_STATIC NQ_TCHAR domainT[CM_BUFFERLENGTH(NQ_TCHAR, CM_NQ_HOSTNAMESIZE)];  
    NQ_STATIC NQ_TCHAR userT[CM_BUFFERLENGTH(NQ_TCHAR, CM_USERNAMELENGTH)];
    NQ_STATIC NQ_TCHAR passwordT[CM_BUFFERLENGTH(NQ_TCHAR, 65)];

    if (domain)     cmUnicodeToTchar(domainT, domain);
    if (user)       cmUnicodeToTchar(userT, user);
    if (password)   cmUnicodeToTchar(passwordT, password);

    return ldConnectT(domainT, userT, passwordT, handle);
}

/*
 * Connect to LDAP Server
 * - open + bind
 * - the server is initially the DC
 * - rebinding (on a referral is proceed internaly with the same credentials
 * - GSS is used with avaiable security mechanisms
 * - this call creates dynamic context, to release call ldCloseConnection
 */
static
NQ_STATUS                            /* error code */
ldConnectT(
        const NQ_TCHAR * domain,     /* domain name */
        const NQ_TCHAR * user,       /* user account name */
        const NQ_TCHAR * password,   /* account password */ 
        LDConnectionHandle * handle  /* resulted handle */ 
        )
{
     LOGFB(CM_TRC_LEVEL_FUNC_TOOL);   
     LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
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

/* ldap_msgfree() regardless of return value !!!*/
NQ_STATUS                           /* error code */
ldSearch(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * base,       /* root item to start search from */
        NQ_INT scope,               /* one of the SY_LDAPSCOPE contants above */
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
 * Get number of attributes  (no corresponding direct openldap api) 
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
    NQ_STATUS status;
    NQ_TCHAR *accountNameT, *domainNameT, *personalNameT, *surnameT, *addressT, *faxNumberT;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    accountNameT = (NQ_TCHAR *)syCalloc(syStrlen(accountName) + 1, sizeof(NQ_TCHAR));
    domainNameT = (NQ_TCHAR *)syCalloc(syStrlen(domainName) + 1, sizeof(NQ_TCHAR));
    personalNameT = (NQ_TCHAR *)syCalloc(*personalNameLen + 1, sizeof(NQ_TCHAR));
    surnameT = (NQ_TCHAR *)syCalloc(*surnameLen+ 1, sizeof(NQ_TCHAR));
    addressT = (NQ_TCHAR *)syCalloc(*addressLen + 1, sizeof(NQ_TCHAR));
    faxNumberT = (NQ_TCHAR *)syCalloc(*faxNumberLen + 1, sizeof(NQ_TCHAR));

    if (accountNameT && domainNameT && personalNameT && surnameT && addressT && faxNumberT)
    {    
        cmAnsiToTchar(accountNameT, accountName);
        cmAnsiToTchar(domainNameT, domainName);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    
    status = ldGetUserCoverPageInfoT(handle, 
                                    accountNameT, 
                                    domainNameT, 
                                    personalNameLen, 
                                    personalNameT, 
                                    surnameLen,
                                    surnameT,
                                    addressLen, 
                                    addressT, 
                                    faxNumberLen, 
                                    faxNumberT);
    if (status == NQ_SUCCESS)
    {
    cmTcharToAnsi(personalName, personalNameT);
    cmTcharToAnsi(surname, surnameT);
    cmTcharToAnsi(address, addressT);
    cmTcharToAnsi(faxNumber, faxNumberT);
    }

    syFree(accountNameT);
    syFree(domainNameT);
    syFree(personalNameT);
    syFree(surnameT);
    syFree(addressT);
    syFree(faxNumberT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
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
    NQ_STATUS status;
    NQ_TCHAR *accountNameT, *domainNameT, *personalNameT, *surnameT, *addressT, *faxNumberT;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    accountNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(accountName) + 1, sizeof(NQ_TCHAR) * 2);
    domainNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(domainName) + 1, sizeof(NQ_TCHAR) * 2);
    personalNameT = (NQ_TCHAR *)syCalloc(*personalNameLen + 1, sizeof(NQ_TCHAR));
    surnameT = (NQ_TCHAR *)syCalloc(*surnameLen+ 1, sizeof(NQ_TCHAR));
    addressT = (NQ_TCHAR *)syCalloc(*addressLen + 1, sizeof(NQ_TCHAR));
    faxNumberT = (NQ_TCHAR *)syCalloc(*faxNumberLen + 1, sizeof(NQ_TCHAR));

    if (accountNameT && domainNameT && personalNameT && surnameT && addressT && faxNumberT)
    {    
        cmUnicodeToTchar(accountNameT, accountName);
        cmUnicodeToTchar(domainNameT, domainName);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    status = ldGetUserCoverPageInfoT(handle, 
                                    accountNameT, 
                                    domainNameT, 
                                    personalNameLen, 
                                    personalNameT, 
                                    surnameLen,
                                    surnameT,
                                    addressLen, 
                                    addressT, 
                                    faxNumberLen, 
                                    faxNumberT);

    cmTcharToUnicode(personalName, personalNameT);
    cmTcharToUnicode(surname, surnameT);
    cmTcharToUnicode(address, addressT);
    cmTcharToUnicode(faxNumber, faxNumberT);

    syFree(accountNameT);
    syFree(domainNameT);
    syFree(personalNameT);
    syFree(surnameT);
    syFree(addressT);
    syFree(faxNumberT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}


/* Get cover page info (full name, address and fax number) for particular user */
/* Caller should allocate buffers and pass their lengths.
   In case of insufficient buffer length error code LDAP_MOREDATA is returned and required length 
   put by corresponding pointer for subsequent call with reallocated buffers 
   Account name parameter may be LDAP base query or username */
static
NQ_STATUS                           /* error code */
ldGetUserCoverPageInfoT(
        LDConnectionHandle handle, /* LDAP handle */
        const NQ_TCHAR *accountNameT,/* account name */
        const NQ_TCHAR *domainNameT,/* domain name */
        NQ_UINT *personalNameLen,  /* pointer to personal name length */
        NQ_TCHAR *personalName,     /* personal name */
        NQ_UINT *surnameLen,       /* pointer to personal surname length */
        NQ_TCHAR *surname,          /* pointer to surname */
        NQ_UINT *addressLen,       /* pointer to address length */
        NQ_TCHAR *address,          /* pointer to address */
        NQ_UINT *faxNumberLen,     /* pointer to fax number length */
        NQ_TCHAR *faxNumber         /* pointer to fax number */
        )
{
    LDResultHandle  result;
    /*const char *noattribs[] = {LDAP_NO_ATTRS, NULL};*/
    const NQ_CHAR *attribs[] = {"name", "sn", "postalAddress", "facsimileTelephoneNumber", NULL};
    LDEntryHandle entry;
    NQ_INT index;
    const LDValue **values;
    NQ_CHAR *baseName; 
    NQ_TCHAR *baseNameT; 
    NQ_COUNT length;
    NQ_TCHAR emptyNameT[] = {cmTChar('\0')};
    NQ_TCHAR *p1, *p2;
    NQ_STATUS status = LDAP_SUCCESS;
    NQ_STATIC NQ_TCHAR cnString[] = {cmTChar('C'), cmTChar('N'), cmTChar('='), cmTChar('\0')};

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    /* create account name of type 'CN=<user>, CN=Users, DC=<domain>, DC=<com>' */
    length = cmTStrlen(accountNameT) + cmTStrlen(domainNameT) + 24;
    baseNameT = (NQ_TCHAR *)syCalloc(length, sizeof(NQ_TCHAR));
    if (!baseNameT)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    if (cmTStricmp(cnString, accountNameT) != 0)
    {
        cmAnsiToTchar(baseNameT, "CN=");
        cmTStrcat(baseNameT, accountNameT);
        cmAnsiToTchar(baseNameT + cmTStrlen(baseNameT), ", CN=Users");  
        p1 = (NQ_TCHAR *)domainNameT;
        p2 = cmTStrchr(p1, cmTChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmTChar('\0');
            cmAnsiToTchar(baseNameT + cmTStrlen(baseNameT), ", DC=");
            cmTStrcat(baseNameT, p1);
            p1 = p2 + 1;
            p2 = cmTStrchr(p1, cmTChar('.'));
        }
        cmAnsiToTchar(baseNameT + cmTStrlen(baseNameT), ", DC=");
        cmTStrcat(baseNameT, p1);
    }
    TRC("baseName %s", cmTDump(baseNameT));

    /* convert to UTF8 string */
    if ((baseName = (NQ_CHAR *)syCalloc(length, 4)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    cmTcharToUTF8N(baseName, baseNameT, length * 4);  
    syFree(baseNameT);
    
    /* find a user entry */
    TRC("handle 0x%x, baseName %s", handle, baseName);
    if (ldSearch(handle, baseName, LDAP_SCOPESUBTREE, "(ObjectClass=user)", attribs, &result) != 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "failed to get user %s", baseName);
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    syFree(baseName);
    
    /* iterate through search result */
    if ((entry = ldGetEntry(handle, result, 0)) != NULL)
    {
        NQ_COUNT num = ldGetNumAttribs(handle, entry);

        if (num == 0)
        {
            ldReleaseResult(handle, result);
            LOGERR(CM_TRC_LEVEL_ERROR, "failed to get attributes %s", baseName);
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        
        /* get personal name */
        if ((index = ldGetAttrIndexByName(handle, entry, "name")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *personalNameLen)
            {
                *personalNameLen = values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {               
                cmUTF8ToTcharN(personalName, (const NQ_CHAR *)values[0]->data, values[0]->len * sizeof(NQ_TCHAR));   
            }
            ldFreeAttrValues(values);            
        }
        else
        {
            cmTStrcpy(personalName, emptyNameT);
        }

        /* get surname */
        if ((index = ldGetAttrIndexByName(handle, entry, "sn")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *surnameLen)
            {
                *surnameLen = values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToTcharN(surname, (const NQ_CHAR *)values[0]->data, values[0]->len * sizeof(NQ_TCHAR));   
            }
            ldFreeAttrValues(values);            
        }
        else
        {
             cmTStrcpy(surname, emptyNameT);
        }

        /* get address */
        if ((index = ldGetAttrIndexByName(handle, entry, "postalAddress")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *addressLen)
            {
                *addressLen = values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToTcharN(address, (const NQ_CHAR *)values[0]->data, values[0]->len * sizeof(NQ_TCHAR));   
            }
            ldFreeAttrValues(values);                        
        } 
        else
        {
            cmTStrcpy(address, emptyNameT);
        }

        /* get fax number */
        if ((index = ldGetAttrIndexByName(handle, entry, "facsimileTelephoneNumber")) != -1)
        {
            values = ldGetAttrValues(handle, entry, index);
            if (values[0]->len > *faxNumberLen)
            {
                *faxNumberLen = values[0]->len;
                status = LDAP_MOREDATA;
            }
            else
            {
                cmUTF8ToTcharN(faxNumber, (const NQ_CHAR *)values[0]->data, values[0]->len * sizeof(NQ_TCHAR));   
            }
            ldFreeAttrValues(values);                          
        }
        else
        {
            cmTStrcpy(faxNumber, emptyNameT);
        }
    }    
    
    /* release search result */
    ldReleaseResult(handle, result);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;

}



static
NQ_STATUS                               /* error code */ 
ldPublishPrinterT(
        LDConnectionHandle handle,      /* LDAP connection handle */
        const NQ_TCHAR * parent,        /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_TCHAR * domainName,    /* domain name (may be NULL if parent not NULL)*/
        const NQ_TCHAR * printerName    /* printer name */
        )
{
    LDTransactionHandle trns;       /* transaction descriptor */
    NQ_CHAR *uNCName = NULL, *parentA = NULL, *printerNameA = NULL;
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    /* construct printer name of form 'CN=' */
    if ((printerNameA = (NQ_CHAR *)syCalloc(cmTStrlen(printerName) + 4, sizeof(NQ_CHAR))) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    syStrcpy(printerNameA, "CN=");
    cmTcharToAnsi(printerNameA + syStrlen(printerNameA), printerName);

    /* construct printer uNCName */
    if ((uNCName = (NQ_CHAR *)syCalloc(syStrlen((NQ_CHAR *)cmGetFullHostName()) + cmTStrlen(printerName) + 4, sizeof(NQ_CHAR))) == NULL)
    {
        syFree(printerNameA);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    syStrcpy(uNCName, "\\\\");
    syStrcat(uNCName, cmGetFullHostName());
    syStrcat(uNCName, "\\");
    syStrcat(uNCName, printerNameA + 3);
   
    /* construct parent */

    if (parent)
    {
        if ((parentA = (NQ_CHAR *)syCalloc(cmTStrlen(parent) + 1, sizeof(NQ_CHAR))) == NULL)
        {
            syFree(printerNameA);
            syFree(uNCName);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmTcharToAnsi(parentA, parent);
    }
    else /* construct domain name */
    {
        NQ_TCHAR *p1, *p2;

        if ((parentA = (NQ_CHAR *)syCalloc(cmTStrlen(domainName) + 25, sizeof(NQ_CHAR) * 2)) == NULL)
        {
            syFree(printerNameA);
            syFree(uNCName);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        syStrcpy(parentA, "CN=Computers, ");
        p1 = (NQ_TCHAR *)domainName;
        p2 = cmTStrchr(p1, cmTChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmTChar('\0');
            syStrcat(parentA, "DC=");
            cmTcharToAnsi(parentA + syStrlen(parentA), p1);
            p1 = p2 + 1;
            p2 = cmTStrchr(p1, cmTChar('.'));
        }
        syStrcat(parentA, ", DC=");
        cmTcharToAnsi(parentA + syStrlen(parentA), p1);
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

    /* free pointers */
    syFree(uNCName);
    syFree(printerNameA);
    if (parentA) syFree(parentA);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;    
}

/* Publish printer transaction */
NQ_STATUS                           /* error code */ 
ldPublishPrinterW(
        LDConnectionHandle handle,   /* LDAP connection handle */
        const NQ_WCHAR * parent,     /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_WCHAR * domainName, /* domain name (may be NULL if parent not NULL)*/
        const NQ_WCHAR * printerName /* printer name */
        )
{
    NQ_STATUS status;
    NQ_TCHAR *parentT = NULL, *printerNameT, *domainNameT = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (!handle || !printerName || (!parent && !domainName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    if (parent)
    {
        if ((parentT = (NQ_TCHAR *)syCalloc(cmWStrlen(parent) + 1, sizeof(NQ_TCHAR) * 2)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmUnicodeToTchar(parentT, parent);
    }

    if (domainName)
    {
        if ((domainNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(domainName) + 1, sizeof(NQ_TCHAR) * 2)) == NULL)
        {
            if (parentT)        syFree(parentT);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmUnicodeToTchar(domainNameT, domainName);
    }

    if ((printerNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(printerName) + 1, sizeof(NQ_TCHAR) * 2)) == NULL)
    {
        if (parentT)        syFree(parentT);
        if (domainNameT)    syFree(domainNameT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    cmUnicodeToTchar(printerNameT, printerName);

    status = ldPublishPrinterT(handle, parentT, domainNameT, printerNameT);
    
    if (parentT)        syFree(parentT);
    if (domainNameT)    syFree(domainNameT);
    syFree(printerNameT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
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
    NQ_STATUS status;
    NQ_TCHAR *parentT = NULL, *printerNameT, *domainNameT = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (!handle || !printerName || (!parent && !domainName))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    if (parent)
    {
        if ((parentT = (NQ_TCHAR *)syCalloc(syStrlen(parent) + 1, sizeof(NQ_TCHAR) * 2)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmAnsiToTchar(parentT, parent);
    }

    if (domainName)
    {
        if ((domainNameT = (NQ_TCHAR *)syCalloc(syStrlen(domainName) + 1, sizeof(NQ_TCHAR) * 2)) == NULL)
        {
            if (parentT)        syFree(parentT);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmAnsiToTchar(domainNameT, domainName);
    }

    if ((printerNameT = (NQ_TCHAR *)syCalloc(syStrlen(printerName) + 1, sizeof(NQ_TCHAR) * 2)) == NULL)
    {
        if (parentT)        syFree(parentT);
        if (domainNameT)    syFree(domainNameT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    cmAnsiToTchar(printerNameT, printerName);

    status = ldPublishPrinterT(handle, parentT, domainNameT, printerNameT);
    
    if (parentT)        syFree(parentT);
    if (domainNameT)    syFree(domainNameT);
    syFree(printerNameT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}        


/* Add printer property with string value (ASCII) */
NQ_STATUS                            
ldAddPrinterPropertyStringA(
        LDConnectionHandle handle,  /* LDAP connection handle */
        const NQ_CHAR *printerName, /* printer name */
        const NQ_CHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_CHAR *name,        /* property/attribute name */
        const NQ_CHAR *value        /* property/attribute value */
        )
{
    NQ_STATUS status;
    NQ_TCHAR *printerNameT = NULL, *domainNameT = NULL, *nameT = NULL, *valueT = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    printerNameT = (NQ_TCHAR *)syCalloc(syStrlen(printerName) + 1, sizeof(NQ_TCHAR));
    if (domainName)
        domainNameT = (NQ_TCHAR *)syCalloc(syStrlen(domainName) + 1, sizeof(NQ_TCHAR));
    nameT = (NQ_TCHAR *)syCalloc(syStrlen(name) + 1, sizeof(NQ_TCHAR));
    valueT = (NQ_TCHAR *)syCalloc(syStrlen(value) + 1, sizeof(NQ_TCHAR));

    if (!printerNameT || !nameT || !valueT || (domainName && !domainNameT))
    {
        if (printerNameT)    syFree(printerNameT);
        if (domainNameT)     syFree(domainNameT);
        if (nameT)           syFree(nameT);
        if (valueT)          syFree(valueT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    else
    {
        cmAnsiToTchar(printerNameT, printerName);    
        if (domainName)
            cmAnsiToTchar(domainNameT, domainName);    
        cmAnsiToTchar(nameT, name);
        cmAnsiToTchar(valueT, value);
    }

    status = ldAddPrinterPropertyStringT(handle, printerNameT, domainNameT, nameT, valueT);
    
    syFree(printerNameT);
    if (domainNameT)    syFree(domainNameT);
    syFree(nameT);
    syFree(valueT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}

/* Add printer property with string value (Unicode) */
NQ_STATUS                            
ldAddPrinterPropertyStringW(
        LDConnectionHandle handle,   /* LDAP connection handle */
        const NQ_WCHAR *printerName, /* printer name */
        const NQ_WCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_WCHAR *name,        /* property/attribute name */
        const NQ_WCHAR *value        /* property/attribute value */
        )
{
    NQ_STATUS status;
    NQ_TCHAR *printerNameT = NULL, *domainNameT = NULL, *nameT = NULL, *valueT = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    printerNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(printerName) + 1, sizeof(NQ_TCHAR) * 2);
    if (domainName)
        domainNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(domainName) + 1, sizeof(NQ_TCHAR) * 2);
    nameT = (NQ_TCHAR *)syCalloc(cmWStrlen(name) + 1, sizeof(NQ_TCHAR) * 2);
    valueT = (NQ_TCHAR *)syCalloc(cmWStrlen(value) + 1, sizeof(NQ_TCHAR) * 2);

    if (!printerNameT || !nameT || !valueT || (domainName && !domainNameT))
    {
        if (printerNameT)    syFree(printerNameT);
        if (domainNameT)     syFree(domainNameT);
        if (nameT)           syFree(nameT);
        if (valueT)          syFree(valueT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    else
    {
        cmUnicodeToTchar(printerNameT, printerName);        
        cmUnicodeToTchar(nameT, name);
        cmUnicodeToTchar(valueT, value);
    }

    status = ldAddPrinterPropertyStringT(handle, printerNameT, domainNameT, nameT, valueT);
    
    syFree(printerNameT);
    if (domainNameT)    syFree(domainNameT);
    syFree(nameT);
    syFree(valueT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}

/* Add printer property with string value */
static
NQ_STATUS                            
ldAddPrinterPropertyStringT(
        LDConnectionHandle handle,   /* LDAP connection handle */
        const NQ_TCHAR *printerName, /* printer name (may be ldap dn name (CN=..., DC=...) */
        const NQ_TCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_TCHAR *name,        /* property/attribute name */
        const NQ_TCHAR *value        /* property/attribute value */
        )
{
    NQ_CHAR *base = NULL, *nameA, *valueA;
    LDTransactionHandle *trns; 
    LDResultHandle result;
    NQ_STATUS status;
    const NQ_TCHAR cn[] = {cmTChar('C'), cmTChar('N'), cmTChar('='), cmTChar('\0')};

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    /* construct base name for search operation */
    if (cmTStrincmp(cn, printerName, cmTStrlen(cn)) == 0)
    {
        if ((base = (NQ_CHAR *)syCalloc(1, cmTStrlen(printerName) * 4 + 1)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmTcharToUTF8N(base, printerName, cmTStrlen(printerName));
    }
    else
    {
        NQ_TCHAR *p1, *p2;
        if ((base = (NQ_CHAR *)syCalloc(1, cmTStrlen(printerName) * 4 + cmTStrlen(domainName) * 4 + 6)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        syStrcpy(base, "CN=");
        cmTcharToUTF8N(base + syStrlen(base), printerName, cmTStrlen(printerName) * 4 + cmTStrlen(domainName) * 4 + 6 - syStrlen(base));
        syStrcat(base, ",CN=Computers, ");

        /* construct domain name */

        p1 = (NQ_TCHAR *)domainName;
        p2 = cmTStrchr(p1, cmTChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmTChar('\0');
            syStrcat(base, "DC=");
            cmTcharToAnsi(base + syStrlen(base), p1);
            p1 = p2 + 1;
            p2 = cmTStrchr(p1, cmTChar('.'));
        }
        syStrcat(base, ", DC=");
        cmTcharToAnsi(base + syStrlen(base), p1);
        TRC("base: %s", base);
    }

    /* find printer*/
    if (ldSearch(handle, base, LDAP_SCOPESUBTREE, "(objectCategory=PrintQueue)", NULL, &result) != 0)
    {
        syFree(base);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to find printer");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    ldReleaseResult(handle, result);

    /* convert attribute name */
    if ((nameA = (NQ_CHAR *)syCalloc(1, cmTStrlen(name) * 4)) == NULL)
    {
        syFree(base);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    cmTcharToUTF8N(nameA, name, cmTStrlen(name));
    
    /* convert attribute value */
    if ((valueA = (NQ_CHAR *)syCalloc(1, cmTStrlen(value) * 4)) == NULL)
    {
        syFree(base);
        syFree(nameA);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    cmTcharToUTF8N(valueA, value, cmTStrlen(value));

    /* start Modify transaction */
    trns = ldModify(handle, NULL, base);

    /* add attribute */
    ldAddAttributeString(trns, nameA, valueA);

    /* execute transaction */
    status = ldExecute(trns, TRUE);

    /* free pointers */
    syFree(base);
    syFree(nameA);
    syFree(valueA);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}


/* Add printer property with binary value */
NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryA(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_CHAR *printerName, /* printer name */
        const NQ_CHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_CHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,       /* property/attribute value */
        NQ_UINT length              /* property/attribute value length */
        )
{
    NQ_STATUS status;
    NQ_TCHAR *printerNameT = NULL, *domainNameT = NULL, *nameT = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    printerNameT = (NQ_TCHAR *)syCalloc(syStrlen(printerName) + 1, sizeof(NQ_TCHAR));
    if (domainName)
        domainNameT = (NQ_TCHAR *)syCalloc(syStrlen(domainName) + 1, sizeof(NQ_TCHAR));
    nameT = (NQ_TCHAR *)syCalloc(syStrlen(name) + 1, sizeof(NQ_TCHAR));

    if (!printerNameT || !nameT)
    {
        if (printerNameT)    syFree(printerNameT);
        if (domainNameT)     syFree(domainNameT);
        if (nameT)           syFree(nameT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    else
    {
        cmAnsiToTchar(printerNameT, printerName);    
        if (domainName)
            cmAnsiToTchar(domainNameT, domainName);    
        cmAnsiToTchar(nameT, name);
    }

    status = ldAddPrinterPropertyBinaryT(handle, printerNameT, domainNameT, nameT, value, length);
    
    syFree(printerNameT);
    if (domainNameT)    syFree(domainNameT);
    syFree(nameT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}

/* Add printer property with binary value */
NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryW(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_WCHAR *printerName, /* printer name */
        const NQ_WCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_WCHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,        /* property/attribute value */
        NQ_UINT length               /* property/attribute value length */
        )
{
    NQ_STATUS status;
    NQ_TCHAR *printerNameT = NULL, *domainNameT = NULL, *nameT = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (!printerName || !name || !value)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid input");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    printerNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(printerName) + 1, sizeof(NQ_TCHAR) * 2);
    if (domainName)
        domainNameT = (NQ_TCHAR *)syCalloc(cmWStrlen(domainName) + 1, sizeof(NQ_TCHAR) * 2);
    nameT = (NQ_TCHAR *)syCalloc(cmWStrlen(name) + 1, sizeof(NQ_TCHAR) * 2);

    if (!printerNameT || !nameT)
    {
        if (printerNameT)    syFree(printerNameT);
        if (domainNameT)     syFree(domainNameT);
        if (nameT)           syFree(nameT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    else
    {
        cmUnicodeToTchar(printerNameT, printerName);    
        if (domainName)
            cmUnicodeToTchar(domainNameT, domainName);    
        cmUnicodeToTchar(nameT, name);
    }

    status = ldAddPrinterPropertyBinaryT(handle, printerNameT, domainNameT, nameT, value, length);
    
    syFree(printerNameT);
    if (domainNameT)    syFree(domainNameT);
    syFree(nameT);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}



NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryT(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_TCHAR *printerName, /* printer name */
        const NQ_TCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_TCHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,        /* property/attribute value */
        NQ_UINT length               /* property/attribute value length */
        )
{
    NQ_CHAR *base = NULL, *nameA;
    LDTransactionHandle *trns; 
    LDResultHandle result;
    NQ_STATUS status;
    const NQ_TCHAR cn[] = {cmTChar('C'), cmTChar('N'), cmTChar('='), cmTChar('\0')};
    NQ_TCHAR *p1, *p2;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    /* construct base name for search operation */
    if (cmTStrincmp(cn, printerName, cmTStrlen(cn)) == 0)
    {
        if ((base = (NQ_CHAR *)syCalloc(1, cmTStrlen(printerName) * 4 + 1)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        cmTcharToUTF8N(base, printerName, cmTStrlen(printerName));
    }
    else
    {
        if ((base = (NQ_CHAR *)syCalloc(1, cmTStrlen(printerName) * 4 + cmTStrlen(domainName) * 4 + 6)) == NULL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_ERROR;
        }
        syStrcpy(base, "CN=");
        cmTcharToUTF8N(base + syStrlen(base), printerName, cmTStrlen(printerName));
        syStrcat(base, ",CN=Computers, ");

        /* construct domain name */
        p1 = (NQ_TCHAR *)domainName;
        p2 = cmTStrchr(p1, cmTChar('.'));
        while (p2 != NULL)
        {
            *p2 = cmTChar('\0');
            syStrcat(base, "DC=");
            cmTcharToAnsi(base + syStrlen(base), p1);
            p1 = p2 + 1;
            p2 = cmTStrchr(p1, cmTChar('.'));
        }
        syStrcat(base, ", DC=");
        cmTcharToAnsi(base + syStrlen(base), p1);
        TRC("base: %s", base);
    }

    /* find printer*/
    if (ldSearch(handle, base, LDAP_SCOPESUBTREE, "(objectCategory=PrintQueue)", NULL, &result) != 0)
    {
        syFree(base);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to find printer");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    ldReleaseResult(handle, result);

    /* convert attribute name */
    if ((nameA = (NQ_CHAR *)syCalloc(1, cmTStrlen(name) * 4)) == NULL)
    {
        syFree(base);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }
    cmTcharToUTF8N(nameA, name, cmTStrlen(name));   

    /* start Modify transaction */
    trns = ldModify(handle, NULL, base);

    /* add attribute */
    ldAddAttributeBinary(trns, nameA, value, length);

    /* execute transaction */
    status = ldExecute(trns, TRUE);

    /* free pointers */
    syFree(base);
    syFree(nameA);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}


#endif /* UD_CC_INCLUDELDAP */
