/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#ifndef _AMAPI_H_ 
#define _AMAPI_H_

#include "cmapi.h"
#include "amapi.h"

/** -- Constants -- */

/* spnego negotiation statuses: */
#define AM_SPNEGO_SUCCESS	0	/* SPNEGO status: security exchange succeeded. */
#define AM_SPNEGO_NONE		1	/* SPNEGO status: security did not start yet. */
#define AM_SPNEGO_FAILED	2	/* SPNEGO status: security exchange failed. For instance - bad
                        	 	   format.                                                     */
#define AM_SPNEGO_CONTINUE	3	/* SPNEGO status: security exchange should be continued. */
#define AM_SPNEGO_DENIED	4	/* SPNEGO status: security exchange failed because server denied
                        	 	   logon.                                                        */

/* server parser statuses */
#define AM_STATUS_AUTHENTICATED             1   /* user was authenticated */
#define AM_STATUS_NOT_AUTHENTICATED         2   /* message parsed but user was not authenticated yet */
#define AM_STATUS_MORE_PROCESSING_REQUIRED  3   /* insufficient information, challenge created */
#define AM_STATUS_BAD_FORMAT                10  /* parse error */
#define AM_STATUS_GENERIC                   11  /* generic error */
#define AM_STATUS_INSUFFICIENT_RESOURCES    12  /* out of memory */

/* security levels: */
#define AM_MAXSECURITYLEVEL 4	/* Maximum security level. Security levels are counted from zero
                               	   to this value.                                                */

/* available encryption algorithms: */

/* Encryption is skipped. */
#define AM_CRYPTER_NONE		0	
/* Fixed-length 128-bit LM response. */
#define AM_CRYPTER_LM		1	
/* Fixed-length 192-bit NTLM response. */
#define AM_CRYPTER_NTLM		2		 
/* Fixed-length 128-bit LMv2 response. */
#define AM_CRYPTER_LM2		3	
/* Variable-length NTLMv2 response. */
#define AM_CRYPTER_NTLM2	4	

/* security mechanisms: */
#define AM_MECH_NTLMSSP     1	/* NTLMSSP security mechanism. This value is used in a security
                             	   mechanism mask (see <link amSpnegoDefineLevel@NQ_UINT@NQ_UINT@NQ_UINT@NQ_UINT32, amSpnegoDefineLevel()>). */
#define AM_MECH_KERBEROS    2   /* Kerberos security mechanism. This value is used in a security
                                   mechanism mask (see <link amSpnegoDefineLevel@NQ_UINT@NQ_UINT@NQ_UINT@NQ_UINT32, amSpnegoDefineLevel()>). */

/** -- Structures --*/ 

/* This structure is used for domain description. Two fields of this 
  structure compose together a fully qualified domain name. */
#ifdef UD_CM_UNICODEAPPLICATION
    #define AMDomain AMDomainW
#else
    #define AMDomain AMDomainA
#endif

/* ASCII domain data */
typedef struct {
    NQ_CHAR name[CM_BUFFERLENGTH(NQ_CHAR, 256)];     /* domain name */
    NQ_CHAR realm[CM_BUFFERLENGTH(NQ_CHAR, 256)];    /* domain realm name */
}
AMDomainA;  /* ASCII version */

/* UNICODE domain data */
typedef struct {
    NQ_WCHAR name[CM_BUFFERLENGTH(NQ_WCHAR, 256)];   /* domain name */
    NQ_WCHAR realm[CM_BUFFERLENGTH(NQ_WCHAR, 256)];  /* domain realm name */
}
AMDomainW;  /* UNICODE version */

/* This structure carries user credentials as used for
   authentication against server in the following cases:
     * SMB/SMB2 authentication
     * Domain join
     * Domain logon                                     */
#ifdef UD_CM_UNICODEAPPLICATION
    #define AMCredentials AMCredentialsW
#else
    #define AMCredentials AMCredentialsA
#endif

/* Account credentials (ASCII) */
typedef struct {
    AMDomainA domain;                                   /* domain name */
    NQ_CHAR user[CM_BUFFERLENGTH(NQ_CHAR, 257)];        /* user name */
    NQ_CHAR password[CM_BUFFERLENGTH(NQ_CHAR, 257)];    /* password as plain text ASCII */
}
AMCredentialsA; /* ASCII version */

/* Account credentials (UNICODE) */
typedef struct {
    AMDomainW domain;                                   /* domain name */
    NQ_WCHAR user[CM_BUFFERLENGTH(NQ_WCHAR, 257)];      /* user name */
    NQ_WCHAR password[CM_BUFFERLENGTH(NQ_WCHAR, 257)];  /* password as plain text UNICODE */
}
AMCredentialsW; /* Unicode version */

typedef struct 
{
    const NQ_BYTE* pLm;         /* LM blob pointer */
    const NQ_BYTE* pNtlm;       /* NTLM blob pointer */
    NQ_UINT16 lmLen;            /* LM blob length */
    NQ_UINT16 ntlmLen;          /* NTLM blob length */     
    NQ_BOOL isLmAuthenticated;  /* whether authentication performed using LM client response */  
    NQ_BOOL isNtlmAuthenticated;/* whether authentication performed using NTLM client response */
    NQ_UINT32 flags;            /* ntlm flags */
} 
AMNtlmDescriptor;

/* -- Functions -- */

/* Description
   This function initializes this module.
   Returns
   TRUE on success and FALSE on failure.  */
NQ_BOOL amSpnegoStart(void);

/* Description
   This function disposes resources used by this module.
   Returns
   None.                                                 */
void amSpnegoShutdown(void);

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* Description
   NQ Authentication module conveys authentication according to
   the required level of security.
   
   This function assigns parameters for one authentication
   level:
     * NQ combines two encryption algorithms in one
       authentication blob. User can choose between LM, NTLM and
       NTLMv2 encryptions.
     * User can choose security mechanisms for extended security
       negotiations. Currently, the available mechanisms are:
       NTLMSSP and Kerberos.
   Parameters
   level :      Authentication level to define. This value should
                be greater or equal to zero and it should not
                exceed the maximum security level as defined in <link AM_MAXSECURITYLEVEL>.
                An illegal value will have no effect.
   crypter1 :   The first encryption algorithm. Available values
                are\:\:
                * <link AM_CRYPTER_LM>
                * <link AM_CRYPTER_NTLM>
                * <link AM_CRYPTER_LM2>
                * <link AM_CRYPTER_NTLM2>
                * <link AM_CRYPTER_NONE>
   crypter2 :   The second encryption algorithm. Available values
                are\:
                * <link AM_CRYPTER_LM>
                * <link AM_CRYPTER_NTLM>
                * <link AM_CRYPTER_LM2>
                * <link AM_CRYPTER_NTLM2>
                * <link AM_CRYPTER_NONE>
   mehanisms :  Available security mechanisms. This value is a
                bit mask of the following\:
                * <link AM_MECH_KERBEROS>
                * <link AM_MECH_NTLMSSP>
                User can specify one of those masks, both or
                none. When two masks are specified, Kerberos is
                considered first.
   Returns
   None.
   Note
     * Level parameters are assigned globally so that two
       concurrent applications using the same level are sharing the
       same parameters. If one of them assigns new parameters this
       also affects the second one.
     * This function is not thread&#45;safe.
     * The default per&#45;level parameters are:
   <table>
   Level   Crypter 1   Crypter 2   NTLMSSP   KERBEROS
   ------  ----------  ----------  --------  ---------
   0       LM          none                  
   1       LM          NTLM                  
   2       LM          NTLM        Yes       Yes
   3       LMv2        NTLMv2      Yes       
   4       LMv2        NTLMv2      Yes       Yes
   </table>                                                                                 */
void amSpnegoDefineLevel(NQ_UINT level, NQ_UINT crypter1, NQ_UINT crypter2, NQ_UINT32 mehanisms);

/* Description
   This function frees memory of a previously allocated key.
   Parameters
   key :  Pointer to a blob with a previously allocated session
          key. This value can be NULL.
   Returns
   None.
   See Also
   <link amSpnegoClientLogon@void *@NQ_WCHAR *@AMCredentialsW *@NQ_BOOL@CMBlob *@CMBlob *@CMBlob *@AMSpnegoClientExchange, amSpnegoClientLogon()>
   
   <link amSpnegoGeneratePasswordBlobs@AMCredentialsW *@NQ_INT@CMBlob *@CMBlob *@CMBlob *@CMBlob *, amSpnegoGeneratePasswordBlobs()>              */
void amSpnegoFreeKey(CMBlob * key);

/* Description
   This function generates encrypted passwords for low-security
   logon, when extended security was not negotiated.
   
   The two blobs will be generated by the crypters by the
   designated <i>level</i>. The list of crypters per level can
   be modified by calling <link amSpnegoDefineLevel@NQ_UINT@NQ_UINT@NQ_UINT@NQ_UINT32, amSpnegoDefineLevel()>.
   Parameters
   credentials :    Pointer to user logon credentials.
   level :          Security level. This value should be greater
                    or equal to zero and it should not exceed the
                    maximum security level as defined in <link AM_MAXSECURITYLEVEL>.
                    An illegal value is replaced with <link AM_MAXSECURITYLEVEL>.
   pass1 :          Pointer to the first blob. Upon successful
                    return, NQ places the first blob into this
                    structure. It is caller's responsibility to
                    free this blob data.
   pass2 :          Pointer to the second blob. Upon successful
                    return, NQ places the first blob into this
                    structure. It is caller's responsibility to
                    free this blob data.
   sessionKey :     On entry, this blob should contain session
                    key provided by server. Upon successful
                    return, NQ places message signing challenge
                    (aka \- response) key into this structure. It
                    is caller's responsibility to free this blob
                    data.
   macSessionKey :  Pointer to the signature key to be created.
                    Upon successful return, NQ places mac session
                    key (aka message signing key) into this
                    structure. It is caller's responsibility to
                    free this blob data.
   Returns
   One of the constants defined in this module.                                                                */
NQ_STATUS amSpnegoGeneratePasswordBlobs(const AMCredentialsW * credentials, NQ_INT level, CMBlob *pass1, CMBlob * pass2, CMBlob * sessionKey, CMBlob * macSessionKey);

/* Description
   AM module uses external function for SPNEGO exchange. This
   prototype designates a function which performs one step of
   SPNEGO exchange.
   
   It should transmit a blob to the authenticating server and
   receive a response blob from it.
   Parameters
   context :        Pointer to SPNEGO context.
   pass1 :          Pointer to the first blob. Upon successful
                    return, NQ places the first blob into this
                    structure. It is caller's responsibility to
                    free this blob data.
   pass2 :          Pointer to the second blob. Upon successful
                    return, NQ places the first blob into this
                    structure. It is caller's responsibility to
                    free this blob data.
   sessionKey :     Pointer to the session key. On entry, this
                    blob should contain session key provided by
                    server. Upon successful return, NQ places
                    session key into this structure. It is
                    caller's responsibility to free this blob
                    data.
   macSessionKey :  Pointer to the signature key to be created.
                    Upon successful return, NQ places session key
                    into this structure. It is caller's
                    responsibility to free this blob data.
   Returns
   One of the constants defined in this module.                   */
typedef NQ_STATUS (* AMSpnegoClientExchange)(void * context, const CMBlob * send, CMBlob * receive);

/* Description
   This function performs SPNEGO negotiation process.
   
   It repeatedly executes the exchange callback as designated by
   the 'exchange' parameter until the process either succeeds or
   fails.
   
   The two blobs will be generated by the crypters. NQ is
   starting from the highest level and descends to the least
   level until authentication succeeds. The list of crypters per
   level can be modified by calling <link amSpnegoDefineLevel@NQ_UINT@NQ_UINT@NQ_UINT@NQ_UINT32, amSpnegoDefineLevel()>.  
   Parameters
   callingContext :     Pointer to an abstract context. When
                        exchange is needed, this function calls
                        the the <link AMSpnegoClientExchange>
                        callback and passes this pointer to it.
   serverName :         Name of the authenticating server. 
   credentials :        User credentials to use.
   restrictCrypters :   TRUE to restrict crypters for Kerberos
                        exchange only, FALSE for all crypters.
                        The TRUE value is used with message
                        signing only since some Kerberos
                        implementations do not provide message
                        signing keys for some crypters. 
   firstSecurityBlob :  The blob obtained during negotiation, for
                        instance \- during SMB Negotiate. This
                        blob is expected to contain the list of
                        security mechanisms. It can be NULL in
                        which case NTLMSSP will be used by
                        default. 
   sessionKey :         On entry, this blob should contain
                        session key provided by server. Upon
                        successful return, NQ places message
                        signing challenge (sometimes referenced
                        as response) key into this structure. It
                        is caller's responsibility to free this
                        blob data.
   macKey :             Pointer to the signature key to be
                        created. Upon successful return, NQ
                        places mac session key (sometimes
                        referenced as message signing key) into
                        this structure. It is caller's
                        responsibility to free this blob data.
   exchange :           The callback to be used for security
                        exchange. See <link AMSpnegoClientExchange>.                                                     
   Returns
   One of the constants defined in this module.*/
NQ_STATUS amSpnegoClientLogon(
    void * callingContext,                            
    const NQ_WCHAR * serverName,
    const AMCredentialsW * credentials, 
    NQ_BOOL restrictCrypters, 
    const CMBlob * firstSecurityBlob, 
    CMBlob * sessionKey, 
    CMBlob * macKey, 
    AMSpnegoClientExchange exchange
    );
#endif /* UD_NQ_INCLUDECIFSCLIENT */

#ifdef UD_NQ_INCLUDECIFSSERVER

/* Description
   This function generates the list of supported security mechanisms (e..g, to use in SMB Negotiate response). 
   
   Returns
   A blob with the list of security mechanisms. It is callers responsibility to release this blob.                                                                                   */
CMBlob amSpnegoServerGenerateMechList(void);

/* Description
   This server function parses incoming blob and according to
   its context performs one of the following operations:
     * If the incoming blob carries an SPNEGO Negotiate, this
       fucntion generates SPNEGO Challenge;
     * If the incoming blob carries SPNEGO Response, this
       fucntion composes tries to authenticate user.
   Parameters
   mechs :     A blob with the list of mechanisms as available
               after negotiiation (e.g., \- SMB Negotiate).
   inBlob :    Incoming blob. It is expected to contains either
               SPNEGO Negotiate or SPNEGO Response.
   outBlob :   Pointer to blob to be filled with outgoing
               payload. it is caller's responsibility to release
               that blob.
   userName :  A buffer for user name. Should be of 256
               characters at least.
   pDomain :   A double pointer to domain name. On SPNEGO Response it will point to the domain name in
               the incoming blob.
   pSessionKey : A double pointer to the session key (sometimes referenced as message signing key).  On SPNEGO Response this pointer will refer to the key. 
   ntlmDescr : Pointer to a descriptor to be filled with hashed passwords.
   Returns
   One of the constants defined in this module.                   */
#ifdef UD_CM_UNICODEAPPLICATION
    #define amSpnegoServerAcceptBlob amSpnegoServerAcceptBlobW
#else
    #define amSpnegoServerAcceptBlob amSpnegoServerAcceptBlobA
#endif

/* Unicode version */
NQ_UINT32 amSpnegoServerAcceptBlobW(
    const void ** pMechBuf,
    CMBlob * inBlob,      
    CMBlob * outBlob,            
    NQ_WCHAR * userName,
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey,  
    AMNtlmDescriptor * ntlmDescr
    );   

/* ASCII version */
NQ_UINT32 amSpnegoServerAcceptBlobA(
    const void ** pMechBuf,
    CMBlob * inBlob,      
    CMBlob * outBlob,            
    NQ_CHAR * userName,  
    const NQ_WCHAR ** pDomain,
    const NQ_BYTE ** pSessionKey,
    AMNtlmDescriptor * ntlmDescr
    );   
#endif /* UD_NQ_INCLUDECIFSSERVER */

#endif /* _AMAPI_H_ */
