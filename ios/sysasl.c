/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : GSASL interface implementation
 *--------------------------------------------------------------------
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 11-Feb-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/
                
#include "cmapi.h"

#if defined(UD_CC_INCLUDEEXTENDEDSECURITY) && defined(UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS)

#include <krb5.h>

/*
 * some differences between Heimdal and MIT
 *
 */

//#define MIT
#define HEIMDAL

#ifdef HEIMDAL

#define krb5_auth_con_getlocalsubkey(_a, _b, _c)    krb5_auth_con_getlocalsubkey(_a, _b, _c)
#define krb5_set_default_tgs_ktypes(_a,_b)          krb5_set_default_in_tkt_etypes(_a, _b)
#define krb5_get_err_text(_c, _e)                   error_message(_e) /* krb5_get_err_text(_c, _e) */
#define KEYDATA(_k)                                 (_k)->keyvalue.data
#define KEYLEN(_k)                                  (_k)->keyvalue.length

#else /* HEIMDAL */
#ifdef MIT

#ifndef KRB5_DEPRECATED
#define krb5_auth_con_getlocalsubkey(_a, _b, _c)    krb5_auth_con_getlocalsubkey(_a, _b, _c)
#else
#define krb5_auth_con_getlocalsubkey(_a, _b, _c)    krb5_auth_con_getsendsubkey(_a, _b, _c)
#endif
#define krb5_set_default_tgs_ktypes(_a,_b)          krb5_set_default_tgs_enctypes(_a, _b)
#define krb5_get_err_text(_c, _e)                   error_message(_e)
#define KEYDATA(_k)                                 (_k)->contents
#define KEYLEN(_k)                                  (_k)->length

#else /* MIT */

#error Neither HEIMDAL nor MIT is defined

#endif /* MIT */
#endif /* HEIMDAL */

/*
 * Static functions and data
 *
 */

typedef struct _context
{
    krb5_context krbCtx;            /* Kerberos context */
    krb5_auth_context authCtx;      /* authentication context */
    krb5_creds *creds;              /* credentials to use */
    krb5_data in;                   /* incoming data */
    krb5_data out;                  /* generated data */
}
Context;

/*
 *====================================================================
 * PURPOSE: Security mechanism ID
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: pointer to the meachanism name
 *
 * NOTES:
 *====================================================================
 */

const NQ_CHAR*
sySaslGetSecurityMechanism(
    void
    )
{
    return "GSSAPI";
}

/*
 *====================================================================
 * PURPOSE: start SASL client
 *--------------------------------------------------------------------
 * PARAMS:  IN callback
 *
 * RETURNS: TRUE on success, FALSE on error
 *
 * NOTES:   the callback calls sySaslSetCredentials
 *====================================================================
 */

NQ_BOOL
sySaslClientInit(
    void* cb
    )
{
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: stop SASL client
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: TRUE on success, FALSE on error
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslClientStop(
    void
    )
{
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: create SASL context
 *--------------------------------------------------------------------
 * PARAMS:  IN principal name
 *          IN is smb2
 *          IN signing on/off
 *
 * RETURNS: SASL context or illegal handle on error
 *
 * NOTES:
 *====================================================================
 */

NQ_BYTE*
sySaslContextCreate(
    const NQ_CHAR* serverName,
    NQ_BOOL isSmb2,
    NQ_BOOL signingOn
    )
{
    Context* ctx;
    krb5_ccache cache = NULL;
    krb5_principal server;
    krb5_creds creds;
    int i;
    int ret;
    NQ_BOOL success;
    NQ_STATIC NQ_CHAR principal[200];

    TRCB();

    /*
     * Initialize contexts
     *
     */

    syStrcpy(principal, serverName);
    TRC1P("Principal: %s", principal);

    initialize_krb5_error_table();
                 
    ctx = (Context *)malloc(sizeof(*ctx));
    if (NULL == ctx)
    {
        TRCERR("Unable to allocate context");

        TRCE();
        return NULL;
    }
    ctx->authCtx = NULL;

    ret = krb5_init_context(&ctx->krbCtx);
    if (0 != ret)
    {
        TRCERR("Unable to initialize Kerberos context");
        TRC1P("error code: %d", ret);
        
        free(ctx);
        TRCE();
        return NULL;
    }
    ctx->creds = NULL;
    ctx->in.data = NULL;
    ctx->out.data = NULL;
    memset(&creds, 0, sizeof(creds));
    ret = krb5_cc_resolve(ctx->krbCtx, krb5_cc_default_name(ctx->krbCtx), &cache);
    if (0 != ret)
    {
        TRC1P("Failed to resolve default cache: %s", krb5_get_err_text(ctx->krbCtx, ret));
        krb5_cc_close(ctx->krbCtx, cache);

        krb5_free_context(ctx->krbCtx);
        free(ctx);
        TRCE();
        return NULL;
    }

    /* restrict encryption types for SMB1 connection with signing */
    TRC("smb%s, signing %s", isSmb2 ? "2" : "1", signingOn ? "on" : "off");
    if (!isSmb2 && signingOn)
    {
        const krb5_enctype enctypes[] = {   ENCTYPE_ARCFOUR_HMAC,
                                            ENCTYPE_DES_CBC_MD5, 
                                            ENCTYPE_DES_CBC_CRC, 
                                            ENCTYPE_NULL };

        ret = krb5_set_default_tgs_ktypes(ctx->krbCtx, enctypes);
        if (0 != ret)
        {
            TRC1P("Failed to restrict enctypes: %s", krb5_get_err_text(ctx->krbCtx, ret));
            krb5_cc_close(ctx->krbCtx, cache);

            krb5_free_context(ctx->krbCtx);
            free(ctx);
            TRCE();
            return NULL;
        }
    }
    /*
     * obtain ticket by credentials:
     *  - create authentication context
     *  - find principal in the cache
     *  - get credentials (ticket) from the cache/kdc (three attempts)
     */

    ret = krb5_parse_name(ctx->krbCtx, principal, &server);
    if (0 != ret)
    {
        TRC1P("Failed to parse server name: %s", krb5_get_err_text(ctx->krbCtx, ret));
        krb5_cc_close(ctx->krbCtx, cache);

        krb5_free_context(ctx->krbCtx);
        free(ctx);
        TRCE();
        return NULL;
    }
    ret = krb5_copy_principal(ctx->krbCtx, server, &creds.server);
    if (0 != ret)
    {
        TRC1P("Failed to copy server principal: %s", krb5_get_err_text(ctx->krbCtx, ret));
        krb5_free_principal(ctx->krbCtx, server);
        krb5_cc_close(ctx->krbCtx, cache);

        krb5_free_context(ctx->krbCtx);
        free(ctx);
        TRCE();
        return NULL;
    }
    ret = krb5_cc_get_principal(ctx->krbCtx, cache, &creds.client);
    if (0 != ret)
    {
        TRC1P("Failed to get client principal: %s", krb5_get_err_text(ctx->krbCtx, ret));
        krb5_free_cred_contents(ctx->krbCtx, &creds);
        krb5_free_principal(ctx->krbCtx, server);
        krb5_cc_close(ctx->krbCtx, cache);

        krb5_free_context(ctx->krbCtx);
        free(ctx);
        TRCE();
        return NULL;
    }
    success = FALSE;
    for (i = 0; i < 3; i ++)
    {
        const char *cacheType = krb5_cc_get_type(ctx->krbCtx, cache);

        ret = krb5_get_credentials(ctx->krbCtx, 0, cache, &creds, &ctx->creds);
        if (0 != ret)
        {
            TRC1P("Failed to get credentials: %s", krb5_get_err_text(ctx->krbCtx, ret));
            krb5_free_cred_contents(ctx->krbCtx, &creds);
            krb5_free_principal(ctx->krbCtx, server);
            krb5_cc_close(ctx->krbCtx, cache);

            krb5_free_context(ctx->krbCtx);
            free(ctx);
            TRCE();
            return NULL;
        }
        if (ctx->creds->times.starttime > time(NULL))
        {
            time_t t = time(NULL);

            int offset = (int)((unsigned)ctx->creds->times.starttime - (unsigned)t);
            krb5_set_real_time(ctx->krbCtx, t + offset + 1, 0);
        }
        TRC2P("system time: %ld, endtime: %ld", time(NULL), ctx->creds->times.endtime);
        if (ctx->creds->times.endtime <= (time(NULL) + 10)) /* expires in less then 10s */
        {
            if (0 != cmAStricmp(cacheType, "FILE"))
            {
                TRC("Ticket expired, removing from cache");
                ret = krb5_cc_remove_cred(ctx->krbCtx, cache, 0, ctx->creds);
                if (0 != ret)
                {
                    TRC1P("Failed to remove credentials from cache: %s", krb5_get_err_text(ctx->krbCtx, ret));
                }
            }
        }
        else
        {
            success = TRUE;
            break;
        }
    }
    if (!success)
    {
        TRCERR("ticket expired");
        TRC2P("system time: %ld, endtime: %ld", time(NULL), ctx->creds->times.endtime);
        krb5_free_cred_contents(ctx->krbCtx, &creds);
        krb5_free_principal(ctx->krbCtx, server);
        krb5_cc_close(ctx->krbCtx, cache);

        krb5_free_context(ctx->krbCtx);
        free(ctx);
        TRCE();
        return NULL;
    }
    
    /*
     * release resources
     *
     */

    krb5_free_cred_contents(ctx->krbCtx, &creds);
    krb5_free_principal(ctx->krbCtx, server);
    krb5_cc_close(ctx->krbCtx, cache);

    TRCE();
    return (NQ_BYTE*)ctx;
}

/*
 *====================================================================
 * PURPOSE: dispose SASL context
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *
 * RETURNS: TRUE on SUCCESS, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslContextDispose(
    NQ_BYTE* context
    )
{
   
    Context* ctx = (Context*)context;
    int ret;

    if (NULL == ctx)
        return FALSE;
    if (NULL == ctx->krbCtx)
        return FALSE;
    if (NULL != ctx->authCtx)
    {
        ret = krb5_auth_con_free(ctx->krbCtx, ctx->authCtx);
        if (0 != ret)
        {
            TRC1P("Failed to free auth context: %s", krb5_get_err_text(ctx->krbCtx, ret));
            return FALSE;
        }
    }

    if (NULL != ctx->creds)
    {
        krb5_free_creds(ctx->krbCtx, ctx->creds);
    }
    if (NULL != ctx->out.data)
    {
        krb5_free_data_contents(ctx->krbCtx, &ctx->out);
    }
    krb5_free_context(ctx->krbCtx);
    free(ctx);
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: set security mechanism for this context
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *          IN mechanism name
 *
 * RETURNS: TRUE on SUCCESS, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslClientSetMechanism(
    NQ_BYTE* context,
    const NQ_CHAR* name
    )
{
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: generate first client-side blob
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *          IN list fo security mechanisms
 *          OUT buffer for blob pointer
 *          OUT buffer for blob length
 *
 * RETURNS: TRUE on SUCCESS, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslClientGenerateFirstRequest(
    NQ_BYTE* context,
    const NQ_CHAR* mechList,
    NQ_BYTE** blob,
    NQ_COUNT* blobLen
    )
{
    Context* ctx = (Context*)context;
    int ret;

    TRCB();

    if (NULL != ctx->out.data)
    {
        krb5_free_data_contents(ctx->krbCtx, &ctx->out);
    }
    ctx->in.length = 0;
    ret = krb5_mk_req_extended(ctx->krbCtx, &ctx->authCtx, AP_OPTS_USE_SUBKEY, &ctx->in, ctx->creds, &ctx->out);
    if (0 != ret)
    {
        TRC1P("Failed to generate blob: %s", krb5_get_err_text(ctx->krbCtx, ret));

        TRCE();
        return FALSE;
    }
    *blob = (NQ_BYTE *)ctx->out.data;
    *blobLen = ctx->out.length;

    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: generate next client-side blob
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *          IN server response blob
 *          IN server response length
 *          OUT buffer for request blob pointer
 *          OUT buffer for request blob length
 *          IN connection pointer (no use)
 * RETURNS: TRUE on SUCCESS, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslClientGenerateNextRequest(
    NQ_BYTE* context,
    const NQ_BYTE* inBlob,
    NQ_COUNT inBlobLen,
    NQ_BYTE** outBlob,
    NQ_COUNT* outBlobLen,
    NQ_BYTE* con
    )
{
    Context* ctx = (Context*)context;
    int ret;

    TRCB();

    ctx->in.data = (char*)inBlob;
    ctx->in.length = inBlobLen;
    if (NULL != ctx->out.data)
    {
        krb5_free_data_contents(ctx->krbCtx, &ctx->out);
    }
    ret = krb5_mk_req_extended(ctx->krbCtx, &ctx->authCtx, AP_OPTS_USE_SUBKEY, &ctx->in, ctx->creds, &ctx->out);
    if (0 != ret)
    {
        TRC1P("Failed to generate blob: %s", krb5_get_err_text(ctx->krbCtx, ret));
        TRCE();
        return FALSE;
    }
    *outBlob = (NQ_BYTE *)ctx->out.data;
    *outBlobLen = ctx->out.length;

    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: encrypt packet according to negiotiated security rules
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *          IN/OUT packet to encrypt
 *          IN/OUT packet length
 *
 * RETURNS: TRUE on SUCCESS, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslEncode(
    NQ_BYTE* context,
    NQ_BYTE* packet,
    NQ_COUNT* len
    )
{
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: get session key
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *          IN buffer for session key
 *          IN buffer length, OUT key length
 *
 * RETURNS: TRUE on SUCCESS, FALSE on failure
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
sySaslGetSessionKey(
    NQ_BYTE* context,
    NQ_BYTE* buffer,
    NQ_COUNT* len
    )
{
    Context* ctx = (Context*)context;
    krb5_keyblock *krbKey = NULL;
    int ret;

    TRCB();

    ret = krb5_auth_con_getlocalsubkey(ctx->krbCtx, ctx->authCtx, &krbKey);
    if (0 != ret)
    {
        TRC1P("Failed to get session key: %s", krb5_get_err_text(ctx->krbCtx, ret));
        TRCE();
        return FALSE;
    }
    if (NULL != krbKey && NULL != KEYDATA(krbKey))
    {
        if (KEYLEN(krbKey) > *len)
        {
            TRC("Session key is too long, %d > %d", KEYLEN(krbKey), *len);
            /* copy session key up to *len size */
            memcpy(buffer, KEYDATA(krbKey), *len);
        }
        else
        {
            memcpy(buffer, KEYDATA(krbKey), KEYLEN(krbKey));
            *len = KEYLEN(krbKey);
        }
        TRCDUMP("session key", buffer, KEYLEN(krbKey));

        krb5_free_keyblock(ctx->krbCtx, krbKey);

        TRCE();
        return TRUE;
    }
    else
    {
        TRCE();
        return FALSE;
    }

}

/*
 *====================================================================
 * PURPOSE: check SASL context 
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *
 * RETURNS: TRUE on success, FALSE on error
 *
 * NOTES:
 *====================================================================
 */
NQ_BOOL
sySaslContextIsValid(
    NQ_BYTE* c
    )
{
    return c != NULL;
}    


/*
 *====================================================================
 * PURPOSE: invalidate SASL context
 *--------------------------------------------------------------------
 * PARAMS:  IN SASL context
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */
void
sySaslContextInvalidate(
    NQ_BYTE* c
    )
{
    c = NULL;
}    

#endif /* UD_CC_INCLUDEEXTENDEDSECURITY && UD_CC_INCLUDEEXTENDEDSECURITY_KERBEROS */

