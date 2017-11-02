
#ifndef _SYLDAP_H_
#define _SYLDAP_H_

#include "ldapi.h"

#ifdef UD_CC_INCLUDELDAP

#define SY_LDAP_MAX_TRANS_NUM               5   /*  max number of transactions */
#define SY_LDAP_ILLEGALID       (NQ_UINT16)-1   /* illegal value for <whatever>ID */
#define SY_LDAP_MAX_DN_NAME_LEN          1024   /* max DN string length */     

/* 
 * Start LDAP client
 * 
 */
NQ_STATUS                           /* error code */
syLdStart(
        );

/* 
 * Stop LDAP client
 * 
 */
void
syLdStop(
       );

/* connect to AD */
NQ_STATUS                           /* error code */
syLdConnect(
        const NQ_TCHAR * domain,    /* domain name */
        const NQ_TCHAR * user,      /* user account name */
        const NQ_TCHAR * password,  /* account password */ 
        void **  handle             /* resulted handle */ 
        );

/*
 * Disconnect from LDAP Server
 * - unbind + close
 */
NQ_STATUS                           /* error code */
syLdCloseConnection(
        LDConnectionHandle  handle /* LDAP handle */
        );

/*
 * Search the LDAP database
 * - this call creates a dynamic context, to release call 
 *   ldReleaseResult
 */
NQ_STATUS                           /* error code */
syLdSearch(
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
syLdReleaseResult(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */ 
        );

/*
 * Get number of entries
 */
NQ_INT                              /* number of entries */
syLdGetNumEntries(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */ 
        );

/*
 * Get entry by its position in result
 * This call tries to enumerate entries using result context
 */
LDEntryHandle                       /* entry handle or NULL on wrong index */
syLdGetEntry(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result,      /* message handle */
        NQ_INT index                /* entry index */
        );

/*
 * Get DN of the entry's object 
 */
void                     
syLdEntryName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_CHAR *dn,                /* buffer for DN name */ 
        NQ_UINT lenDn               /* length of DN buffer */
        );        

/*
 * Get number of attributes
 */
NQ_COUNT                            /* number of attributes */
syLdGetNumAttribs(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry         /* entry handle */         
        );

/*
 * Get attribute index in result by its name
 */
NQ_INT                              /* index or LDAP_ERROR */
syLdGetAttrIndexByName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        const NQ_CHAR * attr        /* attribute name */
        );

/*
 * Get attribute name in result by its index  (caller must call ldFreeAttrName () to free memory)
 */
const NQ_CHAR *                     /* name or NULL */
syLdGetAttrNameByIndex(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        );

/*
 * Free attribute name in result   (after ldGetAttrNameByIndex())
 */
void                     
syLdFreeAttrName(
        const NQ_CHAR * name        /* entry handle */
        );

/*
 * Get number of attribute values
 */
NQ_COUNT                            /* number of attribute values or LDAP_ERROR on wrong index */
syLdGetNumValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        );

/*
 * Get attribute values pointer (caller must call ldFreeAttrValues() to free memory) 
 */
const LDValue **                    /* values pointer or NULL */
syLdGetAttrValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        );

/*
 * Free attribute values pointer (returned by ldGetAttrValues()) 
 */
void                   
syLdFreeAttrValues(
        const LDValue **values      /* values array */
        );

/*
 * Delete an object
 */
NQ_STATUS                           /* error code */
syLdDelete(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name        /* object DN */
        );

/*
 * Delete an attribute
 */
NQ_STATUS                           /* error code */
syLdDeleteAttrib(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name,       /* object DN */
        const NQ_CHAR * attr        /* attribute name */
        );

/*
 * Start an add transaction
 */
LDTransactionHandle                 /* transaction handle or NULL */
syLdAdd(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name,       /* object DN or just name if parent exists */
        const NQ_CHAR * objectClass /* object class name */
        );

/*
 * Start a modify transaction
 */
LDTransactionHandle                 /* transaction handle or NULL */
syLdModify(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name        /* object DN or just name if parent exists */
        );

/*
 * Add/modify attribute value (string)
 */

NQ_STATUS                           /* error code */
syLdAddAttributeString(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_CHAR * value       /* ASCII or UTF-8 null-terminated */
        );

/*
 * Add/modify attribute value (binary) 
 */
NQ_STATUS                           /* error code */
syLdAddAttributeBinary(
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
syLdDeleteAttribute(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr        /* attribute name */
        );

/*
 * Perform transaction
 * - also clears the memory
 */
NQ_STATUS                           /* error code */
syLdExecute(
        LDTransactionHandle tran,   /* transaction handle */
        NQ_BOOL releaseHandle       /* whether to release a transaction handle */
        );


#define SY_USEEXTERNALLDAP

#endif /* UD_CC_INCLUDELDAP */

#endif /* _SYLDAP_H_  */
