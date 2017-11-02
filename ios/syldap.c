#include "syldap.h"

#if defined(UD_CC_INCLUDELDAP) && defined(SY_USEEXTERNALLDAP)

#include "nsapi.h"
#include "cmfinddc.h"

#include <ldap.h>     
#include <lber.h>
#include <sasl/sasl.h>


typedef struct _sytransaction {
    NQ_INT id;                 /* transaction id */
    NQ_INT type;               /* type: add, modify, delete */
    NQ_CHAR *dn;               /* entry distinguished name */
    LDAP* connHandle;          /* open ldap connection handle */
    LDAPMod **mods;            /* open ldap modifications array (null terminated) */
    NQ_COUNT modsCount;        /* current number of modifications in mods array */
}syLDTransaction;


typedef struct _sasl_defaults {
    char *mech;
    char *realm;
    char *authcid;
    char *passwd;
    char *authzid;
    char **resps;
    int nresps;
} SASLdefaults;


typedef struct
{
    syLDTransaction transactions[SY_LDAP_MAX_TRANS_NUM];
}
StaticData;

static StaticData* staticData = NULL;


static syLDTransaction *getNewTrans();
static void releaseTrans(syLDTransaction *tran);
static syLDTransaction *getTrans(void *p);

static
void
freeModifications(
    syLDTransaction *trns,
    NQ_BOOL freeItself
    );

extern int ldap_simple_bind_s(LDAP *ld, const char *who, const char *passwd);

/* 
 * Start LDAP client
 * 
 */
NQ_STATUS                               /* error code */
syLdStart(
        )
{        
    int i;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);
    
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error allocating data");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
         
    for (i = 0; i < SY_LDAP_MAX_TRANS_NUM; i++)
    {
        staticData->transactions[i].id = SY_LDAP_ILLEGALID;
        staticData->transactions[i].connHandle = NULL;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return NQ_SUCCESS;
}


/* 
 * Stop LDAP client
 * 
 */
void
syLdStop(
        )
{
    int i;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);
    /* free transactions array */
    /* release memory */
    if (NULL != staticData)
    {
        for (i = 0; i < SY_LDAP_MAX_TRANS_NUM; i++)
        {
            if (staticData->transactions[i].mods != NULL) 
            {
                freeModifications(&staticData->transactions[i], TRUE);    
            }
        }

        syFree(staticData);
    }
    staticData = NULL;
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);  
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
syLdConnect(
        const NQ_TCHAR * domainT,    /* domain name */
        const NQ_TCHAR * userT,      /* user account name */
        const NQ_TCHAR * passwordT,  /* account password */ 
        LDConnectionHandle * handle  /* resulted handle */ 
        )
{
    LDAP *ld = NULL;
    int desiredVersion = 3;
    NQ_STATIC NQ_CHAR ldapUri[CM_NQ_HOSTNAMESIZE + 7];
    int result; 
    int debuglevel = 0; /* all - 0xffff, none - 0 */
    char *sasl_secprops = "maxssf=1";/* "maxssf=0"; */
    char **mechanisms;
    char * sasl_mechanism; 
    char user[CM_USERNAMELENGTH];
    char pwd[64];
    char domain[CM_NQ_HOSTNAMESIZE];

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    if (!userT || !passwordT)
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"invalid input" );
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }

    cmTcharToAnsi(user, userT);
    cmTcharToAnsi(pwd, passwordT);
    cmTcharToAnsi(domain, domainT);
    /*udSetCredentials(user, pwd, domain);*/

    /* set ldap debug level */
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debuglevel); 
    
    /* set ldap url using PDC name */
    syStrcpy(ldapUri, "ldap://");
    if (cmGetDCName(&ldapUri[syStrlen(ldapUri)], NULL) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"cmGetDCName failed" );
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }

    /* initialize open ldap */
    if ((result = ldap_initialize(&ld, ldapUri)) != LDAP_SUCCESS) 
    {
        LOGERR(CM_TRC_LEVEL_ERROR, ldap_err2string(result));
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }

    /* set LDAP protocol version */
    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desiredVersion) != LDAP_OPT_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"ldap_set_option failed! LDAP_OPT_PROTOCOL_VERSION");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }
    
    /* set SASL security options */
    if (ldap_set_option(ld, LDAP_OPT_X_SASL_SECPROPS, (void *)sasl_secprops) != LDAP_OPT_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"ldap_set_option failed! LDAP_OPT_X_SASL_SECPROPS");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }   
        
    if (ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &sasl_mechanism) != LDAP_OPT_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"ldap_get_option failed! - LDAP_OPT_X_SASL_MECH");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }
    else
    {
        /*printf("\n SASL mechanism: %s\n", sasl_mechanism);*/
        ldap_memfree(sasl_mechanism);
    }    
    
    if (ldap_get_option(ld, LDAP_OPT_X_SASL_MECHLIST, &mechanisms) != LDAP_OPT_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR,"ldap_get_option failed! - LDAP_OPT_X_SASL_MECHLIST");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }
    else
    {
       /* printf("\n SASL mechanisms: \n");
        while (*mechanisms)
            printf("%s\n", *mechanisms++);
        printf("\n");*/
    }    

    if ((result = ldap_simple_bind_s(ld, user, pwd)) != LDAP_SUCCESS)  
    {
        LOGERR(CM_TRC_LEVEL_ERROR, ldap_err2string(result));
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return NQ_FAIL;
    }


    *handle = (LDConnectionHandle)ld;
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return NQ_SUCCESS;
}

/*
 * Disconnect from LDAP Server
 * - unbind + close
 */
NQ_STATUS                           /* error code */
syLdCloseConnection(
        LDConnectionHandle handle   /* LDAP handle */
        )
{
    NQ_STATUS status;
    
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);
    
    status = ldap_unbind_ext_s((LDAP*)handle, NULL, NULL) == LDAP_SUCCESS ? NQ_SUCCESS : NQ_FAIL;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return status;
}

/* Search, call syLdReleaseResult to release memory  */
NQ_STATUS                           /* error code */
syLdSearch(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * base,       /* root item to start search from */
        NQ_INT scope,               /* one of the SY_LDAPSCOPE contants above */
        const NQ_CHAR * filter,     /* search filter, may be NULL */
        const NQ_CHAR * attribs[],  /* pointer to an array of attribute names, NULL-terminated. 
                                       NULL means all attributes. */
        LDResultHandle * result     /* buffer for resulted message handle */
        )
{
    
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);
    
    status = ldap_search_ext_s((LDAP *)handle, base, scope, filter, (char **)attribs, 0, NULL, NULL, NULL, -1, (LDAPMessage **)result);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return status;
}

/*
 * Close a search result and free memory
 */
NQ_STATUS                           /* error code */
syLdReleaseResult(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */ 
        )
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);
    ldap_msgfree((LDAPMessage *)result); 
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return NQ_SUCCESS;
}

/*
 * Get number of entries
 */
NQ_INT                              /* number of entries or -1 on error */
syLdGetNumEntries(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result       /* message handle */ 
        )
{
    NQ_INT num;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    num = ldap_count_entries((LDAP *)handle, (LDAPMessage *)result);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return num;
}

/*
 * Get entry by its position in result
 * This call tries to enumerate entries using result context
 */
LDEntryHandle                       /* entry handle or NULL on wrong index */
syLdGetEntry(
        LDConnectionHandle handle,  /* LDAP handle */
        LDResultHandle result,      /* message handle */
        NQ_INT index                /* entry index */
        )
{
    int i;
    LDAPMessage  *entry;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    if (index < 0 || index >= ldap_count_entries((LDAP *)handle, (LDAPMessage *)result))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return NULL;
    }   
    
    entry = ldap_first_entry((LDAP *)handle, (LDAPMessage *)result);
    for (i = 0; entry != NULL; entry = ldap_next_entry((LDAP *)handle, entry), i++)  
    { 
        if (i == index)
        {
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return entry;
        }
    } 
    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return NULL;        
}


/*
 * Get DN of the entry's object  
 */

void                     
syLdEntryName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_CHAR *dn,                /* buffer for DN name */ 
        NQ_UINT lenDn               /* length of DN buffer */
        )
{
    char *name;
    unsigned int len;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    name = ldap_get_dn((LDAP *)handle, (LDAPMessage *)entry);
    len = (unsigned int)syStrlen(name) > lenDn - 1 ? lenDn - 1 : (unsigned int)syStrlen(name);
    syStrncpy(dn, name, len);
    dn[len] = '\0';
    ldap_memfree(name);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
}

/*
 * Get number of attributes  (no corresponding direct openldap api) 
 */
NQ_COUNT                            /* number of attributes */
syLdGetNumAttribs(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry         /* entry handle */ 
        )
{
    NQ_COUNT count;
    char *attr;
    BerElement *ber; 

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    attr = ldap_first_attribute((LDAP *)handle, entry, &ber);
    for (count = 0; attr != NULL; attr = ldap_next_attribute((LDAP *)handle, entry, ber))
    {
        count++;
        ldap_memfree(attr);
    }    
        
    if (ber != NULL) 
        ber_free(ber, 0); 

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return count;    
}


/*
 * Get attribute index in result by its name
 */
NQ_INT                              /* index or LDAP_ERROR */
syLdGetAttrIndexByName(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        const NQ_CHAR * attr        /* attribute name */
        )

{
    char *attrib;
    BerElement *ber;
    int i;
    unsigned int attrNum = ldGetNumAttribs(handle, entry);

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    attrib = ldap_first_attribute((LDAP *)handle, entry, &ber);
    for (i = 0 ; i < attrNum; attrib = ldap_next_attribute((LDAP *)handle, entry, ber), i++)
    {
        if (syStrcmp(attr, attrib) == 0)
        {
            ldap_memfree(attrib);
            break;
        }
        ldap_memfree(attrib);
    }    
        
    if (ber != NULL) 
        ber_free(ber, 0); 

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return i == attrNum ? LDAP_ERROR : i;    
}

/*
 * Get attribute name in result by its index (caller must free memory: ldFreeAttrName()) 
 */
const NQ_CHAR *                     /* name or NULL */
syLdGetAttrNameByIndex(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        )
{
    char *attr = NULL;
    BerElement *ber;
    int i;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    if (index < 0 || index >= ldGetNumAttribs(handle, entry))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return NULL;
    }
        
    attr = ldap_first_attribute((LDAP *)handle, entry, &ber);
    for (i = 0 ; attr != NULL; attr = ldap_next_attribute((LDAP *)handle, entry, ber), i++)
    {
        if (i == index)
        {
            /* caller must free memory */            
            break;
        }
        ldap_memfree(attr);
    }    
        
    if (ber != NULL) 
        ber_free(ber, 0); 

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return attr;    
}

/*
 * Free attribute name in result   (after ldGetAttrNameByIndex())
 */
void
syLdFreeAttrName(
        const NQ_CHAR * name  
        )
{
    ldap_memfree((void *)name);
}

/*
 * Get number of attribute values
 */
NQ_COUNT                            /* number of attribute values or LDAP_ERROR on wrong index */
syLdGetNumValues(
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        )
{
    char *attr;
    BerElement *ber;
    int i, valsnum = LDAP_ERROR;
    struct berval **values;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if (index < 0 || index >= ldGetNumAttribs(handle, entry))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return (NQ_COUNT)LDAP_ERROR;
    }
    
    attr = ldap_first_attribute((LDAP *)handle, entry, &ber);
    for (i = 0 ; attr != NULL; attr = ldap_next_attribute((LDAP *)handle, entry, ber), i++)
    {
        if (i == index)
        {
            if ((values = ldap_get_values_len((LDAP *)handle, entry, attr)) != NULL)
            {
                valsnum = ldap_count_values_len(values); 
                ldap_value_free_len(values);  
            }
            ldap_memfree(attr);
            break;
        }
        ldap_memfree(attr);
    }    
        
    if (ber != NULL) 
        ber_free(ber, 0); 

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return (NQ_COUNT)valsnum;    
}


/*
 * Get attribute values pointer (caller must free memory with ldFreeAttrValues)  
 */
const LDValue **                    /* values pointer or NULL */
syLdGetAttrValues( 
        LDConnectionHandle handle,  /* LDAP handle */
        LDEntryHandle entry,        /* entry handle */
        NQ_INT index                /* attribute index */
        )
{
    char *attr;
    BerElement *ber;
    int i;
    struct berval **values = NULL;
    /* struct berval *value = NULL; */

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    if (index < 0 || index >= ldGetNumAttribs(handle, entry))
    {
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_INVALIDHANDLE;
    }
    
    attr = ldap_first_attribute((LDAP *)handle, entry, &ber);
    for (i = 0 ; attr != NULL; attr = ldap_next_attribute((LDAP *)handle, entry, ber), i++)
    {
        if (i == index)
        {
            if ((values = ldap_get_values_len((LDAP *)handle, entry, attr)) != NULL)
            {
                /*for (j = 0; values[j]; j++) 
                {
                         value = values[j];
                         value->bv_val, value->bv_len
                 }*/
                 ldap_memfree(attr);
                break;
            }
        }
        ldap_memfree(attr);
    }    
        
    if (ber != NULL) 
        ber_free(ber, 0); 

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return (const LDValue **)values;    
}

/*
 * Free attribute values pointer (returned by ldGetAttrValues) 
 */
void                   
syLdFreeAttrValues(
        const LDValue **values      /* values array */
        )
{
    if (values)
        ldap_value_free_len((struct berval **)values);
}

/*
 * Start an add transaction, ldAddAttributeString()/ldAddAttributeBinary() must follow
 */
LDTransactionHandle                 /* transaction handle or NULL */
syLdAdd(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name,       /* object DN or just name if parent exists */
        const NQ_CHAR * objectClass /* object class name */
        )
{
    syLDTransaction *trns;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    if (!name || !handle || !objectClass || (trns = getNewTrans()) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transaction handle or input data");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_INVALIDHANDLE;
    }

    /* construct parent */
    if (parent)
    {
        trns->dn = (NQ_CHAR *)syCalloc((syStrlen(name) + syStrlen(parent) + 2), sizeof(NQ_CHAR));
        if (!trns->dn)
        {
            releaseTrans(trns);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory for DN");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_INVALIDHANDLE;
        }
        syStrcpy(trns->dn, name);
        syStrcat(trns->dn, ",");
        syStrcat(trns->dn, parent);
    }
    else
    {
        trns->dn = (NQ_CHAR *)syCalloc((syStrlen(name) + 1), sizeof(NQ_CHAR));
        if (!trns->dn)
        {
            releaseTrans(trns);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory for DN");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_INVALIDHANDLE;
        }
        syStrcpy(trns->dn, name);
    }

    trns->type = LDAP_MOD_ADD;
    trns->connHandle = handle;
    
    /* at least 1 attribute should be specified when adding new entry */
    /* allocate null terminated array of pointers to LDAP modifications */
    if ((trns->mods = (LDAPMod **)syCalloc(2, sizeof(LDAPMod *))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_INVALIDHANDLE;
    }

    if ((trns->mods[0] = (LDAPMod *)syCalloc(1, sizeof(LDAPMod))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_INVALIDHANDLE;
    }
    trns->mods[0]->mod_op = LDAP_MOD_ADD;
    trns->mods[0]->mod_type = (char *)syStrdup("objectClass");
    trns->mods[0]->mod_values = (char **)syCalloc(2, sizeof(char *));
    trns->mods[0]->mod_values[0] = (char *)syStrdup(objectClass);
    trns->mods[0]->mod_values[1] = NULL;
    trns->mods[1] = NULL; /* null terminated array */
    
    /* set modifications counter for transaction */
    trns->modsCount = 1;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return trns;
}


/*
 * Add/modify attribute value (string)
 */
NQ_STATUS                           /* error code */
syLdAddAttributeString(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_CHAR * value       /* ASCII or UTF-8 null-terminated */
        )
{
    syLDTransaction *trns;
    LDAPMod **mods;
    NQ_STATUS status = NQ_SUCCESS;
    NQ_COUNT i;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if ((trns = getTrans(tran)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transaction handle");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }  

    TRC("trns->modsCount %d", trns->modsCount);    

    /* allocate memory for existing items + new one */
    if ((mods = (LDAPMod **)syCalloc(trns->modsCount + 2, sizeof(LDAPMod *))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    /* copy existing items first (without the last null)*/
    for (i = 0; i < trns->modsCount; i++)
    {
        mods[i] = trns->mods[i];
    }

    /* add new one */
    if ((mods[i] = (LDAPMod *)syCalloc(1, sizeof(LDAPMod))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }    
    mods[i]->mod_op = LDAP_MOD_REPLACE;
    mods[i]->mod_type = (char *)syStrdup(attr);
    mods[i]->mod_values = (char **)syCalloc(2, sizeof(char *));
    mods[i]->mod_values[0] = (char *)syStrdup(value);
    mods[i]->mod_values[1] = NULL;

    /* copy last null */
    mods[i + 1] = (trns->modsCount == 0) ? NULL : trns->mods[i];

    ++trns->modsCount;

    /* free original and link with the new array */
    if (trns->mods) syFree(trns->mods);
    trns->mods = mods;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}

/*
 * Start a modify transaction
 */
LDTransactionHandle                 /* transaction handle or NULL */
syLdModify(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * parent,     /* may be NULL */
        const NQ_CHAR * name        /* object DN or just name if parent exists */
        )
{
    syLDTransaction *trns;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 
    
    if (!name || !handle || (trns = getNewTrans()) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transaction handle or input data");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_INVALIDHANDLE;
    }

    /* construct parent */
    if (parent)
    {
        trns->dn = (NQ_CHAR *)syCalloc((syStrlen(name) + syStrlen(parent) + 2), sizeof(NQ_CHAR));
        if (!trns->dn)
        {
            releaseTrans(trns);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory for DN");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_INVALIDHANDLE;
        }
        syStrcpy(trns->dn, name);
        syStrcat(trns->dn, ",");
        syStrcat(trns->dn, parent);
    }
    else
    {
        trns->dn = (NQ_CHAR *)syCalloc((syStrlen(name) + 1), sizeof(NQ_CHAR));
        if (!trns->dn)
        {
            releaseTrans(trns);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory for DN");
            LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
            return LDAP_INVALIDHANDLE;
        }
        syStrcpy(trns->dn, name);
    }

    trns->type = LDAP_MOD_REPLACE;
    trns->connHandle = handle;
    
    /* set modifications counter for transaction */
    trns->modsCount = 0;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return trns;
}

/*
 * Add/modify attribute value (binary) 
 */
NQ_STATUS                           /* error code */
syLdAddAttributeBinary(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr,       /* attribute name */
        const NQ_BYTE * value,      /* value */
        NQ_COUNT len                /* value length */
        )
{
    syLDTransaction *trns;
    LDAPMod **mods;
    NQ_STATUS status = NQ_SUCCESS;
    NQ_COUNT i;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    TRC("value length: %d", len);    

    if ((trns = getTrans(tran)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transaction handle");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }  

    TRC("trns->modsCount %d", trns->modsCount);    

    /* allocate memory for existing items + new one */
    if ((mods = (LDAPMod **)syCalloc(trns->modsCount + 2, sizeof(LDAPMod *))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    /* copy existing items first (without the last null)*/
    for (i = 0; i < trns->modsCount; i++)
    {
        mods[i] = trns->mods[i];
    }

    /* add new one */
    if ((mods[i] = (LDAPMod *)syCalloc(1, sizeof(LDAPMod))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }    
    mods[i]->mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mods[i]->mod_type = (char *)syStrdup(attr);
    mods[i]->mod_bvalues = (struct berval **)syCalloc(2, sizeof(struct berval *));
    mods[i]->mod_bvalues[0] = (struct berval *)syCalloc(1, sizeof(struct berval));
    mods[i]->mod_bvalues[0]->bv_len = len;
    mods[i]->mod_bvalues[0]->bv_val = (char *)syCalloc(1, len);
    syMemcpy(mods[i]->mod_bvalues[0]->bv_val, value, len);
    mods[i]->mod_bvalues[1] = NULL;

    /* copy last null */
    mods[i + 1] = (trns->modsCount == 0) ? NULL : trns->mods[i];

    ++trns->modsCount;

    /* free original and link with the new array */
    if (trns->mods) syFree(trns->mods);
    trns->mods = mods;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}

/*
 * Delete attribute
 * - available only for Modify transaction 
 */
NQ_STATUS                           /* error code */
syLdDeleteAttribute(
        LDTransactionHandle tran,   /* transaction handle */
        const NQ_CHAR * attr        /* attribute name */
        )
{
    syLDTransaction *trns;
    LDAPMod **mods;
    NQ_STATUS status = NQ_SUCCESS;
    NQ_COUNT i;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    if ((trns = getTrans(tran)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transaction handle");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }  

    TRC("trns->modsCount %d", trns->modsCount);    

    /* allocate memory for existing items + new one */
    if ((mods = (LDAPMod **)syCalloc(trns->modsCount + 2, sizeof(LDAPMod *))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }

    /* copy existing items first (without the last null)*/
    for (i = 0; i < trns->modsCount; i++)
    {
        mods[i] = trns->mods[i];
    }

    /* add new one */
    if ((mods[i] = (LDAPMod *)syCalloc(1, sizeof(LDAPMod))) == NULL)
    {
        releaseTrans(trns);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate memory");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return LDAP_ERROR;
    }    
    mods[i]->mod_op = LDAP_MOD_DELETE;
    mods[i]->mod_type = (char *)syStrdup(attr);
    mods[i]->mod_values = NULL;

    /* copy last null */
    mods[i + 1] = (trns->modsCount == 0) ? NULL : trns->mods[i];

    ++trns->modsCount;

    /* free original and link with the new array */
    if (trns->mods) syFree(trns->mods);
    trns->mods = mods;

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;

}

/*
 * Perform transaction
 * - also clears the memory
 */
NQ_STATUS                           /* error code */
syLdExecute(
        LDTransactionHandle tran,   /* transaction handle */
        NQ_BOOL releaseHandle       /* whether to release a transaction handle */
        )
{
    syLDTransaction *trns;
    int result;
    
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    if ((trns = getTrans(tran)) == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Invalid transaction handle");          
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
        return NQ_FAIL;
    }

    switch (trns->type)
    {
        case LDAP_MOD_ADD:
            result = ldap_add_ext_s(trns->connHandle, trns->dn, trns->mods, NULL, NULL);
            break;
        case LDAP_MOD_REPLACE:
        case LDAP_MOD_REPLACE | LDAP_MOD_BVALUES:
        case LDAP_MOD_DELETE:
            result = ldap_modify_ext_s(trns->connHandle, trns->dn, trns->mods, NULL, NULL);  
            break;
        default:
            LOGERR(CM_TRC_LEVEL_ERROR, "Invalid opcode");  
            result = LDAP_ERROR;
            break;         
    }
    
    /* free mods array */
    freeModifications(trns, TRUE);

    if (releaseHandle)
        releaseTrans(trns);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return result == 0 ? NQ_SUCCESS : NQ_FAIL;
}

/*
 * Delete an object
 */
NQ_STATUS                           /* 0 on success, error code on failure */
syLdDelete(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name        /* object DN */
        )
{
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    status = ldap_delete_ext_s((LDAP *)handle, name, NULL, NULL);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}


/*
 * Delete an attribute
 */
NQ_STATUS                           /* error code */
syLdDeleteAttrib(
        LDConnectionHandle handle,  /* LDAP handle */
        const NQ_CHAR * name,       /* object DN */
        const NQ_CHAR * attr        /* attribute name */
        )
{
    LDAPMod modifier;
    LDAPMod *mods[2];
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL); 

    modifier.mod_op = LDAP_MOD_DELETE;
    modifier.mod_type = (char *)syStrdup(attr);
    modifier.mod_values = NULL;
    modifier.mod_bvalues = NULL;
    mods[0] = &modifier;
    mods[1] = NULL;
    
    status = ldap_modify_ext_s((LDAP *)handle, name, mods, NULL, NULL);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL); 
    return status;
}

static 
syLDTransaction *
getNewTrans()
{
    int i;

    for (i = 0; i < SY_LDAP_MAX_TRANS_NUM; i++)
    {
        syLDTransaction *tr = &staticData->transactions[i];
        if (tr->id == SY_LDAP_ILLEGALID)
        {
            tr->id = i;
            return tr;
        }
    }
    return NULL;
}

static
void
releaseTrans(
    syLDTransaction *tran
    )
{
    TRCB();

    if (tran->dn)
        syFree(tran->dn);
    if (tran->mods != NULL)
        freeModifications(tran, TRUE);

    tran->id = SY_LDAP_ILLEGALID;

    TRCE();
}

static
syLDTransaction *
getTrans(void *p)
{
    int i;
    
    for (i = 0; i < SY_LDAP_MAX_TRANS_NUM; i++)
    {
        syLDTransaction *tran = &staticData->transactions[i];
        if (tran == p && tran->id != SY_LDAP_ILLEGALID)
        {
            return tran;
        }
    }
    return NULL;
}

static
void
freeModifications(
    syLDTransaction *trns,
    NQ_BOOL freeItself
    )
{
    TRCB();

    ldap_mods_free(trns->mods, freeItself);
    trns->mods = NULL;
    trns->modsCount = 0;
    
    TRCE();
}

#endif /* defined(UD_CC_INCLUDELDAP) && defined(SY_USEEXTERNALLDAP) */
