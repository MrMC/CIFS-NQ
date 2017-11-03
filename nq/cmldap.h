#ifndef _CMLDAP_H_
#define _CMLDAP_H_

#include "udapi.h"

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

#endif /* UD_CC_INCLUDELDAP */

#endif /* _CMLDAP_H_ */
