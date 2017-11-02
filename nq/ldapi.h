/*********************************************************************
 *
 *           Copyright (c) 2009 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : LD LDAP Client abstract API
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 3-Jul-2005
 * CREATED BY    : Igor Lerner
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _LDAPI_H_
#define _LDAPI_H_

#include "cmapi.h"

#ifdef UD_CC_INCLUDELDAP

/*
 * Types and definitions
 * ---------------------
 */

typedef void * LDConnectionHandle;  /* abstract LDAP connection handle */
typedef void * LDResultHandle;      /* abstract LDAP message (search result) handle */
typedef void * LDEntryHandle;       /* abstract LDAP entry handle */
typedef void * LDTransactionHandle;/* abstract LDAP transaction handle */

#define LDAP_INVALIDHANDLE NULL     /* invalid handle of the above */
#define LDAP_ERROR         -1       /* illegal integer value */
#define LDAP_SUCCESS        0
#define LDAP_MOREDATA       2

typedef struct
{
    NQ_INT len;
    NQ_BYTE *data;
} 
LDValue;    

/* Search scope */
#define LDAP_SCOPEBASE        0   /* search the base object only */
#define LDAP_SCOPESINGLELEVEL 1   /* search immediate children only */
#define LDAP_SCOPESUBTREE     2   /* search whole subtree */

/*
 * API functions
 * --------------
 */

/* 
 * Start LDAP client
 * 
 */
NQ_STATUS                           /* error code */
ldStart(
        );

/* 
 * Stop LDAP client
 * 
 */
void
ldStop(
       );

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
        );

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
        );

#ifdef UD_CM_UNICODEAPPLICATION
    #define ldConnect ldConnectW
#else
    #define ldConnect ldConnectA
#endif

/*
 * Disconnect from LDAP Server
 * - unbind + close
 */
NQ_STATUS                           /* error code */
ldCloseConnection(
        LDConnectionHandle  handle /* LDAP handle */
        );

/*
 * Search the LDAP database
 * - this call creates a dynamic context, to release call 
 *   ldReleaseResult
 */
NQ_STATUS                           /* error code */
ldSearch(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * base,       /* root item to start search from */
        NQ_INT scope,               /* one of the SY_LDAPSCOPE contants above */
        const NQ_CHAR * filter,     /* search filter, may be NULL */
        const NQ_CHAR * attribs[],  /* pointer to an array of attribute names, NULL-terminated 
                                       NULL means all attrinutes */
        LDResultHandle * result     /* buffer for resulted message handle */
        );

/*
 * Close a search result and free memory
 */
NQ_STATUS                           /* error code */
ldReleaseResult(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */ 
        );

/*
 * Get number of entries
 */
NQ_INT                              /* number of entries */
ldGetNumEntries(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */ 
        );

/*
 * Get entry by its position in result
 * This call tries to enumerate entries using result context
 */
LDEntryHandle                       /* entry handle or NULL on wrong index */
ldGetEntry(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result,      /* message handle */
        NQ_INT index                /* entry index */
        );

/*
 * Get DN of the entry's object 
 */
void                     
ldEntryName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_CHAR *dn,                /* buffer for DN name */ 
        NQ_UINT lenDn               /* length of DN buffer */                      
        );        

/*
 * Get number of attributes
 */
NQ_COUNT                            /* number of attributes */
ldGetNumAttribs(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry         /* entry handle */         
        );

/*
 * Get attribute index in result by its name
 */
NQ_INT                              /* index or LDAP_ERROR */
ldGetAttrIndexByName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        const NQ_CHAR * attr        /* attribute name */
        );

/*
 * Get attribute name in result by its index  (caller must call ldFreeAttrName () to free memory)
 */
const NQ_CHAR *                     /* name or NULL */
ldGetAttrNameByIndex(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        );

/*
 * Free attribute name in result   (after ldGetAttrNameByIndex())
 */
void                     
ldFreeAttrName(
        const NQ_CHAR * name        /* entry handle */
        );

/*
 * Get number of attribute values
 */
NQ_COUNT                            /* number of attribute values or LDAP_ERROR on wrong index */
ldGetNumValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        );

/*
 * Get attribute values pointer (caller must call ldFreeAttrValues() to free memory) 
 */
const LDValue **                    /* values pointer or NULL */
ldGetAttrValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        );

/*
 * Free attribute values pointer (returned by ldGetAttrValues()) 
 */
void                   
ldFreeAttrValues(
        const LDValue **values      /* values array */
        );

/*
 * Delete an object
 */
NQ_STATUS                           /* error code */
ldDelete(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name        /* object DN */
        );

/*
 * Delete an attribute
 */
NQ_STATUS                           /* error code */
ldDeleteAttrib(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name,       /* object DN */
        const NQ_CHAR * attr        /* attribute name */
        );

/*
 * Start an add transaction
 */
LDTransactionHandle                 /* transaction handle or NULL */
ldAdd(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name,       /* object DN or just name if parent exists */
        const NQ_CHAR * objectClass /* object class name */
        );

/*
 * Start a modify transaction
 */
LDTransactionHandle                 /* transaction handle or NULL */
ldModify(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name        /* object DN or just name if parent exists */
        );

/*
 * Add/modify attribute value (string)
 */

NQ_STATUS                           /* error code */
ldAddAttributeString(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_CHAR * value       /* ASCII or UTF-8 null-terminated */
        );

/*
 * Add/modify attribute value (binary) 
 */
NQ_STATUS                           /* error code */
ldAddAttributeBinary(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_BYTE * value,      /* value */
        NQ_COUNT len                /* value length */
        );

/*
 * Delete attribute
 * - available only for Modify transaction 
 */
NQ_STATUS                           /* error code */
ldDeleteAttribute(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr        /* attribute name */
        );

/*
 * Perform transaction
 * - also clears the memory
 */
NQ_STATUS                           /* error code */
ldExecute(
        LDTransactionHandle tran,   /* transaction handle */
        NQ_BOOL releaseHandle       /* whether to release a transaction handle */
        );


/* Publish printer in LDAP database transaction */
NQ_STATUS                           /* error code */
ldPublishPrinterA(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_CHAR * domainName, /* domain name (may be NULL if parent not NULL)*/
        const NQ_CHAR * printerName /* printer name */
        );

/* Publish printer in LDAP database transaction */
NQ_STATUS                            /* error code */
ldPublishPrinterW(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_WCHAR * parent,     /* where to publish in directory (may be NULL if domainName not NULL) */
        const NQ_WCHAR * domainName, /* domain name (may be NULL if parent not NULL)*/
        const NQ_WCHAR * printerName /* printer name */
        );

#ifdef UD_CM_UNICODEAPPLICATION
    #define ldPublishPrinter ldPublishPrinterW
#else
    #define ldPublishPrinter ldPublishPrinterA
#endif

/* Add printer property with string value */
NQ_STATUS
ldAddPrinterPropertyStringA(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_CHAR *printerName, /* printer name */
        const NQ_CHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_CHAR *name,        /* property/attribute name */
        const NQ_CHAR *value        /* property/attribute value */
        );

/* Add printer property with string value */
NQ_STATUS
ldAddPrinterPropertyStringW(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_WCHAR *printerName, /* printer name */
        const NQ_WCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_WCHAR *name,        /* property/attribute name */
        const NQ_WCHAR *value        /* property/attribute value */
        );

#ifdef UD_CM_UNICODEAPPLICATION
    #define ldAddPrinterPropertyString ldAddPrinterPropertyStringW
#else
    #define ldAddPrinterPropertyString ldAddPrinterPropertyStringA
#endif

/* Add printer property with binary value */
NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryA(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_CHAR *printerName, /* printer name */
        const NQ_CHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_CHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,       /* property/attribute value */
        NQ_UINT length              /* property/attribute value length */
        );

/* Add printer property with binary value */
NQ_STATUS                           /* error code */
ldAddPrinterPropertyBinaryW(
        LDConnectionHandle handle,   /* LDAP handle */
        const NQ_WCHAR *printerName, /* printer name */
        const NQ_WCHAR *domainName,  /* domain name (may be NULL if printerName has ldap syntax */
        const NQ_WCHAR *name,        /* property/attribute name */
        const NQ_BYTE *value,        /* property/attribute value */
        NQ_UINT length               /* property/attribute value length */
        );

#ifdef UD_CM_UNICODEAPPLICATION
    #define ldAddPrinterPropertyBinary ldAddPrinterPropertyBinaryW
#else
    #define ldAddPrinterPropertyBinary ldAddPrinterPropertyBinaryA
#endif


/* Get cover page info (full name, address and fax number) for particular user */
/* Caller should allocate buffers and pass their lengths.
   In case of insufficient buffer length error code LDAP_MOREDATA is returned and required length 
   put by corresponding pointer for subsequent call with reallocated buffers */
NQ_STATUS                           /* error code */
ldGetUserCoverPageInfoA(
        LDConnectionHandle handle, /* LDAP handle */
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
        );

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
        );

#ifdef UD_CM_UNICODEAPPLICATION
    #define ldGetUserCoverPageInfo ldGetUserCoverPageInfoW
#else
    #define ldGetUserCoverPageInfo ldGetUserCoverPageInfoA
#endif
        
#endif /* UD_NQ_INCLUDELDAPCLIENT */

#endif /* _LDAPI_H_ */
