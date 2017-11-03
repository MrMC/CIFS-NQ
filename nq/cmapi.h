/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Entire CM functionality
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMAPI_H_
#define _CMAPI_H_

#include "udparams.h"       /* user defined compilation parameters */
#include "udadjust.h"
#include "syapi.h"          /* system-dependent */
#include "cmcommon.h"       /* basic types */
#include "cmparams.h"       /* parameters */
#include "cmutils.h"        /* more common functionality for all modules */
#include "cmlist.h"			/* linked list */
#include "cmmemory.h"		/* dynamic memory */
#include "cmselfip.h"       /* IP configuration */
#include "cmresolver.h"		/* name to IP resolver */
#include "cmthread.h"		/* thread management */
#ifdef UD_NQ_INCLUDECODEPAGE
#include "cmcp.h"           /* Code pages */
#endif /* UD_NQ_INCLUDECODEPAGE */
#include "cmunicod.h"       /* ANSI to UNICODE and v/v */
#include "cmstring.h"       /* mapping of string manipulation */
#include "cmnbapi.h"        /* NetBIOS */
#include "cmfsapi.h"        /* CIFS */
#include "cmrpcdef.h"       /* DCERPC */
#include "cmsdescr.h"       /* Security Descriptors */
#include "cmvalida.h"       /* Validation of cross-dependencies */
#include "cmtrace.h"        /* traces */
#include "cmbufman.h"
#ifdef UD_NQ_INCLUDESMBCAPTURE
#include "cmcapture.h"
#endif /* UD_NQ_INCLUDESMBCAPTURE */
#include "cmrepository.h"

/* CM library initialization */
NQ_STATUS
cmInit(
    void
    );

/* CM library shutdown */
void
cmExit(
    void
    );

#define NQ_RESOLVER_IPV4        4   /* The resolved address is IPV4. */
#define NQ_RESOLVER_IPV6        6   /* The resolved address is IPV6. */
#define NQ_RESOLVER_NONE        0   /* No address resolved. This value designates a resolution
                                       failure.                                                */

#define NQ_RESOLVER_DNS         1   /* mechanism type is DNS. */
#define NQ_RESOLVER_NETBIOS     2   /* mechanism type is NetBIOS. */
#define NQ_RESOLVER_EXTERNAL_METHOD 5 /* mechanism type not known. external method set by the user.*/
#define NQ_RESOLVER_DNS_DC      8   /* mechanism type is DNS DC. */
#define NQ_RESOLVER_NETBIOS_DC  10  /* mechanism type is NetBIOS DC. */

/* This structure defines code page parameters. */
typedef struct
{
    NQ_INT  id;                                                                                 /* Unique id value for this codepage. Code page is identified
                                                                                                   by this value. It is recommended to use respective Microsoft
                                                                                                   code page numbers (see Notes).
                                                                                                   Note
                                                                                                   For Microsoft code page numbers see <extlink http://msdn.microsoft.com/en-us/library/dd317756(VS.85).aspx>http://msdn.microsoft.com/en-us/library/dd317756(VS.85).aspx</extlink> */
    NQ_INT  (*toAnsi)   ( NQ_CHAR*,  const NQ_WCHAR*, NQ_INT, NQ_INT );                         /* Codepage-specific function for Unicode to ANSI conversion */
    NQ_INT  (*toUnicode)( NQ_WCHAR*, const NQ_CHAR*,  NQ_INT, NQ_INT );                         /* Codepage-specific function for ANSI to Unicode conversion */
    NQ_INT  (*toUpper)  ( NQ_CHAR*,  const NQ_CHAR* );                                          /* Codepage-specific function for capitalizing conversion */
    void    (*ansiToFs) ( NQ_CHAR*, NQ_INT, const NQ_BYTE*, const NQ_BYTE*, NQ_INT, NQ_INT );   /* Codepage-specific function for converting ANSI to the
                                                                                                   encoding used in the local FS                         */
    void    (*fsToAnsi) ( NQ_CHAR*, NQ_INT, const NQ_BYTE*, const NQ_BYTE*, NQ_INT, NQ_INT );   /* Codepage-specific function for converting the encoding used
                                                                                                   in the local FS into ANSI                                   */
    const NQ_WCHAR* a2uTab;                                                                     /* Fast ANSI to Unicode conversion table. Using this table
                                                                                                   avoids calling the functions defined in this structure. It is
                                                                                                   only used for single-byte encodings like
                                                                                                   Hebrew/Russian/Turkish/Greek/etc. This pointer may be NULL. It
                                                                                                   should be NULL for multiple-byte encodings.                    */  
}
CMCodepage;     

/* Description
   A descriptor of one resolver method. Use this structure to
   register a resolution method using the <link cmResolverRegisterExternalMethod@CMResolverRegisteredMethodDescription *, cmResolverRegisterExternalMethod Function> */
typedef struct
{
	 /* This parameter may have one of the following values:
	      1. Activate registered method before all other methods.
	      2. Activate registered method after the existing NQ unicast
	         methods and before existing NQ multicast methods. In this
	         case registered method will be activated only if existing NQ
	         unicast methods failed to resolve name or IP
	      3. Activate registered method only if all other methods
	         failed.                                                      */
	NQ_INT activationPriority;
	/* Timeout in seconds to use with this method */
	NQ_UINT32 timeout;
    /* IP of the server to perform resolution with. This value is
       only sued by Unicast methods.                              */
    NQ_IPADDRESS *serverIP;
    /* Routine for composing and sending a name resolution request
       Parameters:
        socket :    Socket handle to use for sending
        name :      Name to resolve
        context :   Pointer to a method-specific context. This value may be NULL on the first call.
        serverIp :  Pointer to the IP of the server to query or NULL for multicast
       Return:
       NQ_SUCCESS   request sent
       n            A positive number refers to number of requests that were sent.
       NQ_ERR_<*>   error
     */
    NQ_STATUS (* requestByName)(SYSocketHandle socket, const NQ_WCHAR * name, void * context, const NQ_IPADDRESS * serverIp);
    /* Routine for receiving and parsing a name resolution response
       Parameters
       socket :    Socket handle to use for sending
       pAddressArray : Address of the pointer which this call sets to an array of
                        resolved IP addresses. It is caller's responsibility to release this array.
                        On error, this pointer remains untouched.
       numIps :    Pointer to the number of resolved IPs.
       pContext :  Double pointer to a method-specific context. Method may dispose
                    context and create a new one.
       Return:
       NQ_SUCCESS           name successfully resolved
       NQ_ERR_MOREDATA      more exchange expected
       NQ_ERR_NOACCESS      more comprehensive method with the same code should be used
       NQ_ERR_<*>           error
     */
    NQ_STATUS (* responseByName)(SYSocketHandle socket, NQ_IPADDRESS ** pAddressArray, NQ_INT * numIps, void ** pContext);
    /* Routine for composing and sending an IP resolution request
       Parameters:
        socket :    Socket handle to use for sending
        ip :        Pointer to the IP address to resolve.
        context :   Pointer to a method-specific context. This value may be NULL on the first call.
        serverIp :  Pointer to  the IP of the server to query or NULL for multicast
       Return:
       NQ_SUCCESS   request sent
       n            A positive number refers to number of requests that were sent.
       NQ_ERR_<*>   error
     */
    NQ_STATUS (* requestByIp)(SYSocketHandle socket, const NQ_IPADDRESS * ip, void * context, const NQ_IPADDRESS * serverIp);
    /* Routine for receiving and parsing a name resolution response

       Parameters
        socket :    Socket handle to use for sending
        pName :     Double pointer to the resolved name. On success, this variable will
                    point to a newly allocated name. Its is caller's responsibility to release it later.
        pContext :  Double pointer to a method-specific context. Method may dispose
                    context and create a new one.

       Return:
       NQ_SUCCESS           name successfully resolved
       NQ_ERR_MOREDATA      more exchange expected
       NQ_ERR_NOACCESS      more comprehensive method with the same code should be used
       NQ_ERR_<*>           error
     */
    NQ_STATUS (* responseByIp)(SYSocketHandle socket, const NQ_WCHAR ** pName, void ** pContext);
}
CMResolverRegisteredMethodDescription;

/* function prototypes */
/***********************/

/* Description
   This function installs code page for another language.
   
   Code page is identified by the '<i>id</i>' value of its
   descriptor. Duplicate installation overwrite the previous
   one.
   
   Once successfully installed, the code page becomes available
   by its '<i>id</i>' number through the <i>udGetCodePage()</i>
   function call (see NQ Integration And Porting Guide in <link References, Referenced Documents>).
   
   This function may be used for one the following purposes:
     * Installing new code page.
     * Replacing one of previously installed code pages.
     * Replacing one of precompiled code pages (see NQ
       Integration And Porting Guide in <link References, Referenced Documents>).
   Parameters
   codePage :  Pointer to codepage descriptor
   Returns
   NQ_TRUE on success and NQ_FALSE on error. Application may
   analyze error reason by reading the last system error. It may
   be NQ_ERR_NOMEM on codepage table overflow.                                                       */
NQ_BOOL cmCodepageAdd(const CMCodepage * codePage);
 
/* Description
   This function removes code page.
   
   This call will either remove a code page previously installed
   by calling <link cmCodepageAdd@CMCodepage *, cmCodepageAdd()>
   or it may remove a a pre-compiled page (see NQ Integration
   And Porting Guide in <link References, Referenced Documents>).
   Parameters
   codePage :  Pointer to codepage descriptor as <link CMCodepage, CMCodepage structure>.
               NQ uses only the '<i>id'</i> field and ignores
               others.
   Returns
   NQ_TRUE on success and NQ_FALSE on error. Application may
   analyze error reason by reading the last system error. It may
   be NQ_ERR_NOTFOUND when this codepage does not exist.                                  */
NQ_BOOL cmCodepageRemove(const CMCodepage * codePage);

/* Description
   This function prototype designates an abstract cryptographic
   hash algorithm. It is used to replace internal NQ encryption
   with an external one.
   Parameters
   dataIn :   Pointer to the data to encrypt.
   dataOut :  Pointer to the buffer for encrypted.
   length :   Length of the incoming data and also the length of
              the encrypted data.
   Returns
   None.                                                         */
typedef void (* CMAbstractHasher)(const NQ_BYTE * dataIn, NQ_BYTE * dataOut, NQ_COUNT length);

/* Description
   This function prototype designates an abstract cryptographic
   algorithm using a cryptographic key. It is used to replace
   \internal NQ encryption with an external one.
   Parameters
   key :            Pointer to the encryption key descriptor.
                    Some algorithms do not use this value.
   key1 :           Pointer to the auxiliary key descriptor. This
                    value may be NULL. Also the data pointer may
                    be null as well as the blob length may be
                    zero. In either of those cases the auxiliary
                    key is ignored. Some algorithms may ignore
                    this value anyway.
   dataFragments :  A pointer to the array of data fragment
                    descriptors. For encryption algorithms which
                    allow encrypting multiple fragments, this
                    array may contain more than one element. For
                    other algorithms, only the first element is
                    used. An element may be NULL. Also a data
                    pointer in an element may be NULL as well as
                    blob length may be zero. In either of those
                    cases the respective fragment is ignored.
   numFragments :   Number of data fragments (see above).
   buffer :         Place holder for hash result.
   bufferSize :     The expected length of the encrypted data
   Returns
   None.                                                          */
typedef void (* CMAbstractCipher)(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize);

/* Description
   This function prototype designates an abstract cryptographic
   algorithm for both encryption and producing authentication
   data (CCM) . It is used to replace internal NQ encryption
   with an external one.
   
   This algorithm assumes that there are two blocks of data:
     1. A prefix that is preserved as is
     2. The messages itself that is to be encrypted
   The authentication is a production of both blocks.
   Parameters
   key :      Pointer to the encryption key descriptor. Some
              algorithms do not use this value.
   key1 :     Pointer to the auxiliary key descriptor. This value
              may be NULL. Also the data pointer may be null as
              well as the blob length may be zero. In either of
              those cases the auxiliary key is ignored. Some
              algorithms may ignore this value anyway.
   prefix :   A pointer to the message prefix descriptor. This
              data participate in authentication but remains as
              is, without encryption.
   message :  Pointer to the message descriptor. This message
              will be encrypted in\-place.
   auth :     Pointer to the authentication data. It will be
              filled as the result of the algorithm.
   Returns
   None.                                                          */

typedef void (* CMAbstractHasher512)(const CMBlob * key, const CMBlob * key1, const CMBlob dataFragments[], NQ_COUNT numFragments, NQ_BYTE * buffer, NQ_COUNT bufferSize, NQ_BYTE *ctxBuff);

/* Description
   This function prototype designates an abstract cryptographic
   algorithm for producing authentication data. It is used to 
   replace internal NQ encryption with an external one.
   The authentication (hash result) is a product of all data blocks.
 
   Parameters
   key :            Pointer to the encryption key descriptor.
                    Some algorithms do not use this value.
   key1 :           Pointer to the auxiliary key descriptor. This
                    value may be NULL. Also the data pointer may
                    be null as well as the blob length may be
                    zero. In either of those cases the auxiliary
                    key is ignored. Some algorithms may ignore
                    this value anyway.
   dataFragments :  A pointer to the array of data fragment
                    descriptors. For encryption algorithms which
                    allow encrypting multiple fragments, this
                    array may contain more than one element. For
                    other algorithms, only the first element is
                    used. An element may be NULL. Also a data
                    pointer in an element may be NULL as well as
                    blob length may be zero. In either of those
                    cases the respective fragment is ignored.
   numFragments :   Number of data fragments (see above).
   buffer :         Place holder for hash result.
   bufferSize :     The expected length of the encrypted data  
   ctxBuff :  Buffer for context data. if this buffer is null,
   	   	   	  context buffer will be allocated in function.
   Returns
   None.                                                        */
typedef void (* CMAbstractCcmEncryption)(const CMBlob * key, const CMBlob * key1, const CMBlob * prefix, CMBlob * message, NQ_BYTE * auth);

/* Description
   This function prototype designates an abstract cryptographic
   algorithm for both decryption and authentication (CCM) . It
   is used to replace internal NQ encryption with an external
   one.
   
   This algorithm assumes that there are two blocks of data:
     1. A prefix that is preserved as is
     2. The messages itself that is to be encrypted
   The authentication is a production of both blocks.
   Parameters
   key :      Pointer to the encryption key descriptor. Some
              algorithms do not use this value.
   key1 :     Pointer to the auxiliary key descriptor. This value
              may be NULL. Also the data pointer may be null as
              well as the blob length may be zero. In either of
              those cases the auxiliary key is ignored. Some
              algorithms may ignore this value anyway.
   prefix :   A pointer to the message prefix descriptor. This
              data participate in authentication but remains as
              is, without encryption.
   message :  Pointer to the message descriptor. This message
              will be encrypted in\-place.
   auth :     Pointer to the authentication data. This value is
              be used to authenticate.
   Returns
   TRUE if authenticated, FALSE if not.                           */
typedef NQ_BOOL (* CMAbstractCcmDecryption)(const CMBlob * key, const CMBlob * key1, const CMBlob * prefix, CMBlob * message, const NQ_BYTE * auth);


/* Description
   This function prototype designates an abstract cryptographic
   algorithm for both encryption and producing authentication
   data (GCM) . It is used to replace internal NQ encryption
   with an external one.

   This algorithm assumes that there are two blocks of data:
     1. A prefix that is preserved as is
     2. The messages itself that is to be encrypted
   The authentication is a production of both blocks.
   Parameters
   key :      Pointer to the encryption key descriptor. Some
              algorithms do not use this value.
   key1 :     Pointer to the auxiliary key descriptor. This value
              may be NULL. Also the data pointer may be null as
              well as the blob length may be zero. In either of
              those cases the auxiliary key is ignored. Some
              algorithms may ignore this value anyway.
   prefix :   A pointer to the message prefix descriptor. This
              data participate in authentication but remains as
              is, without encryption.
   message :  Pointer to the message descriptor. This message
              will be encrypted in\-place.
   auth :     Pointer to the authentication data. It will be
              filled with the result of the algorithm.
   keyBuffer: Optional buffer for usage in key calculations.
   	   	   	  If NULL a buffer will be allocated per function call.
   	   	   	  size - AES_PRIV_SIZE
   encMsgBuffer: Optional buffer for the message encryption which
    		  is not done in place. If NULL a buffer will be
   	   	   	  allocated per function call.
    		  size: message size.
   Returns
   None.                                                          */
typedef void (* CMAbstractGcmEncryption)(const CMBlob *key, const CMBlob *key1, const CMBlob *prefix, CMBlob *message, NQ_BYTE *auth, NQ_BYTE *keyBuffer, NQ_BYTE *encMsgBuffer);

/* Description
   This function prototype designates an abstract cryptographic
   algorithm for both decryption and authentication (GCM). It
   is used to replace internal NQ encryption with an external
   one.

   This algorithm assumes that there are two blocks of data:
     1. A prefix that is preserved as is
     2. The messages itself that is to be encrypted
   The authentication is a production of both blocks.
   Parameters
   key :      Pointer to the encryption key descriptor. Some
              algorithms do not use this value.
   key1 :     Pointer to the auxiliary key descriptor. This value
              may be NULL. Also the data pointer may be null as
              well as the blob length may be zero. In either of
              those cases the auxiliary key is ignored. Some
              algorithms may ignore this value anyway.
   prefix :   A pointer to the message prefix descriptor. This
              data participate in authentication but remains as
              is, without encryption.
   message :  Pointer to the message descriptor. This message
              will be encrypted in\-place.
   auth :     Pointer to the authentication data. This value is
              be used to authenticate.
   keyBuffer: Optional buffer for usage in key calculations.
   	   	   	  If NULL a buffer will be allocated per function call.
   	   	   	  size - AES_PRIV_SIZE
   msgBuffer: Optional buffer for the message decryption which
    		  is not done in place. If NULL a buffer will be
   	   	   	  allocated per function call.
   	   	   	  Size - message size.
   Returns
   TRUE if authenticated, FALSE if not.                           */
typedef NQ_BOOL (* CMAbstractGcmDecryption)(const CMBlob * key, const CMBlob *key1, const CMBlob *prefix, CMBlob *message, const NQ_BYTE *auth, NQ_BYTE *keyBuffer, NQ_BYTE *msgBuffer);


/* Description
   This structure designates a list of cryptographic algorithms
   currently used by NQ. It is used to replace existing
   cryptographic algorithms.
   
   If a particular cryptographic algorithm is NULL, it is not
   replaced.                                                    */
typedef struct
{
	CMAbstractHasher md4;			/* MD4 hasher */
	CMAbstractCipher md5;			/* MD5 hasher */
	CMAbstractCipher hmacmd5;		/* HMACMD5 crypter */
	CMAbstractCipher sha256;		/* SHA-256 crypter */
	CMAbstractCipher aes128cmac;	/* AES-CMAC crypter */
	CMAbstractHasher512 sha512;		/* SHA-512 crypter */
	CMAbstractCcmEncryption aes128ccmEncryption;	/* AES-CCM encryption algorithm */
	CMAbstractCcmDecryption aes128ccmDecryption;	/* AES-CCM decryption algorithm */
	CMAbstractGcmEncryption aes128gcmEncryption;	/* AES-GCM encryption algorithm */
	CMAbstractGcmDecryption aes128gcmDecryption;	/* AES-GCM decryption algorithm */
} 
CMCrypterList;

/* Description
   This function replaces internal NQ cryptographic algorithms
   with external ones.
   Parameters
   crypters :  A pointer to the list of internal ciphers. Only
               non\-NULL values are applied.
   Returns
   None.                                                       */
void cmSetExternalCrypters(const CMCrypterList * crypters);

/* Description
   This function reverts the list of cryptographic algorithms to
   \internal algorithms only.
   Returns
   None.                                                         */
void cmResetExternalCrypters(void);

/* Description
   This function prototype designates a callback for resolving
   host IP address by its name. NQ uses this callback for
   external resolution. This call is a triplet call (see <link Summary>).
   Parameters
   name :   The name of the host to resolve. 
   index :  Index of the resolved IP address. External resolver
            may resolve multiple IP addresses for the same name.
            When external resolution is required, NQ subsequently
            calls this function with <i>'index'</i> values
            incrementing, starting from zero. External resolver
            should return the appropriate IP address or it should
            should fail the call when an <i>'index'</i> result is
            not available.
   Returns
   One of the following values:
     * <link NQ_RESOLVER_IPV4>. This means that <i>'index'</i>
       designates an IPv4 address.
     * <link NQ_RESOLVER_IPV6>. This means that <i>'index'</i>
       designates an IPv6 address.
     * <link NQ_RESOLVER_NONE>. This means that either
       resolution failed of the <i>'index'</i> value is out of
       range.                                                             */
#ifdef UD_CM_UNICODEAPPLICATION
    #define CMResolverNameToIp CMResolverNameToIpW
#else
    #define CMResolverNameToIp CMResolverNameToIpA
#endif
typedef NQ_INT (*CMResolverNameToIpA)(const NQ_CHAR * name, void * ip, NQ_COUNT index);   /* ASCII version */
typedef NQ_INT (*CMResolverNameToIpW)(const NQ_WCHAR * name, void * ip,  NQ_COUNT index); /* UNICODE version */

/* Description
   This function prototype designates a callback for resolving
   host name by its IP address. NQ uses this callback for
   external resolution. This call is a triplet call (see <link Summary>).
   Parameters
   name :  Buffer for the resolved name.
   ip :    Pointer to IP address. This pointer designates either <link NQ_IPADDRESS4, NQ_IPADDRESS4 type>
           or <link NQ_IPADDRESS6, NQ_IPADDRESS6 type> depending
           on the <i>'type' </i>argument below. 
   type :  IP address type. This value can be either <link NQ_RESOLVER_IPV4>
           or <link NQ_RESOLVER_IPV6>. It defines the format of
           the <i>'ip'</i> argument.
   Returns
   TRUE on success, FALSE on failure.                                                                     */
#ifdef UD_CM_UNICODEAPPLICATION
    #define CMResolverIpToName CMResolverIpToNameW
#else
    #define CMResolverIpToName CMResolverIpToNameA
#endif
typedef NQ_BOOL (*CMResolverIpToNameA)(NQ_CHAR * name, const void * ip, NQ_INT ipType);   /* ASCII version */
typedef NQ_BOOL (*CMResolverIpToNameW)(NQ_WCHAR * name, const void * ip, NQ_INT ipType);  /* UNICODE version */

/* Description
   This function extends NQ's name-to-IP and IP-to-name
   resolver. NQ attempts to use its internal resolution methods
   first:
     * NetBIOS Naming Service;
     * DNS;
     * LLMNR.
   If none of the above succeeds, NQ attempts an external
   resolver. By calling this function application can enable or
   disable an external resolving mechanism.
   
   This call is a triplet call. Since its triplet nature
   concerns callback pointers (see Parameters), rather than the
   call itself, its approach differs from the standard triplet
   behavior as explained in <link Summary>. NQ uses callback
   pointers as follows:
     * First, NQ attempts internal methods. If at least one of
       them succeeded, the external method is not used.
     * If a Unicode callback was specified, it is used.
     * If a Unicode callback pointer was not specified or its
       pointer was set to NULL, NQ uses ASCII callback.
     * If neither Unicode nor ASCII callback were specified or
       both pointers are NULL, NQ skips external resolution.
     * The approach above applies independently to each of
       name&#45;to&#45;IP and IP&#45;to&#45;name resolution.
   Parameters
   nameToIp :  Pointer to a function that resolves host IP by its
               name. This function signature should conform to
               the <link CMResolverNameToIp> prototype. This
               value can be NULL. In this case, NQ will fail
               external name\-to\-IP resolution.
   ipToName :  Pointer to a function that resolves host name by
               its IP. This function signature should conform to
               the <link CMResolverIpToName> prototype. This
               value can be NULL. In this case, NQ will fail
               external IP\-to\-name resolution.
   Returns
   None.
   Note
   This function is deprecated. Use the <link cmResolverRegisterExternalMethod@CMResolverRegisteredMethodDescription *, cmResolverRegisterExternalMethod Function>
   instead.                                                                                                                                                        */
#ifdef UD_CM_UNICODEAPPLICATION
    #define cmResolverSetExternal cmResolverSetExternalW  
#else
    #define cmResolverSetExternal cmResolverSetExternalA
#endif
void cmResolverSetExternalA(CMResolverNameToIpA nameToIp, CMResolverIpToNameA ipToName);  /* ASCII version */
void cmResolverSetExternalW(CMResolverNameToIpW nameToIp, CMResolverIpToNameW ipToName);  /* UNICODE version */

/* Description
   This function resolves host by its IP and return its name.
   
   Host name is created in allocated memory so that it is
   caller's responsibility to free this memory.
   
   NQ uses several unicast and multicast methods for this
   resolution. First, it attempts all unicast methods
   concurrently. Depending on compilation parameters those
   methods may be:
     * DNS queries to one or more DNS servers;
     * NetBIOS query to one or more WINS.
   If none of the above succeeded, NQ concurrently attempts
   multicast methods as:
     * LLMNR;
     * NetBIOS broadcasts.
   If those methods did not succeed, NQ calls external method if
   this method has been installed in <link cmResolverSetExternal>()
   call.
   Parameters
   ip :  Pointer to host IP address.
   Returns
   Pointer to newly created host name or NULL on failure.
   Note
   It is caller's responsibility to release this name.              */
const NQ_WCHAR * cmResolverGetHostName(const NQ_IPADDRESS * ip);

/* Description
   This function resolves host by its name and returns its IP
   addresses.
   
   The array of IP addresses is created in allocated memory so
   that it is caller's responsibility to free this memory.
   
   NQ uses several unicast and multicast methods for this
   resolution. First, it attempts all unicast methods
   concurrently. Depending on compilation parameters those
   methods may be:
     * DNS queries to one or more DNS servers;
     * NetBIOS query to one or more WINS.
   If none of the above succeeded, NQ concurrently attempts
   multicast methods as:
     * LLMNR;
     * NetBIOS broadcasts.
   If those methods did not succeed, NQ calls external method if
   this method has been installed in <link cmResolverSetExternal>()
   call.
   Parameters
   host :    Pointer to host name to resolve.
   numIps :  Pointer to variable that on exit gets the number of
             resolved IP addresses.
   Returns
   Pointer to an array of IP addresses or NULL on error. The
   size of array is placed into the variable pointed by <i>numIps</i>.
   Note
   It is caller's responsibility to release this array. To release this array the caller need to call the <i>cmMemoryFree()</i> function. */
const NQ_IPADDRESS * cmResolverGetHostIps(const NQ_WCHAR * host, NQ_INT * numIps);

/* Description
   This function resolves domain's DC and return its name.
   
   DC name is created in allocated memory so that it is
   caller's responsibility to free this memory.
   
   NQ uses several unicast and multicast methods for this
   resolution. First, it attempts all unicast methods
   concurrently. Depending on compilation parameters those
   methods may be:
     * DNS queries to one or more DNS servers;
     * NetBIOS query to one or more WINS.
   If none of the above succeeded, NQ concurrently attempts
   multicast methods as:
     * NetBIOS broadcasts.
   If those methods did not succeed, NQ calls external method if
   this method has been installed in <link cmResolverSetExternal>()
   call.
   Parameters
   domain :  Pointer to domain name.
   numDCs :  Pointer to variable that on exit gets the number of
             resolved DC names.
   Returns
   Pointer to newly created DC name or NULL on failure.
   Note
   It is caller's responsibility to release this name. To release the name call <i>cmMemoryFree()</i>             */
const NQ_WCHAR * cmResolverGetDCName(const NQ_WCHAR * domain, NQ_INT * numDCs);

/* Description
   Resolver uses different methods (mechanisms) to resolve host
   IP(s) by name or to resolve host name by IP. Each mechanism
   may use either unicasts or multicasts. NQ attempts all
   possible unicasts first. Then, if unicasts failed, it
   attempts multicasts. Currently, the following mechanisms are
   available::
   <table>
   Method           DNS                NetBIOS
   ---------------  -----------------  ----------------
   <i>Unicast</i>   DNS server query   WINS query
   Multicast        LLMNR              local broadcast
   </table>
   All methods are initially enabled on NQ startup. This
   function allows to enable or disable a particular one in
   run-time..
   Parameters
   type :       Resolution type. This may be one of <link NQ_RESOLVER_DNS>
                or <link NQ_RESOLVER_NETBIOS>.
   unicast :    When this parameter is <i>TRUE</i>, NQ enables
                unicast method (s) of the given type. When this
                parameter is <i>FALSE., </i>NQ disables unicast
                method(s).
   multicast :  When this parameter is <i>TRUE</i>, NQ enables
                multicast method(s) of the given type. When this
                parameter is <i>FALSE., </i>NQ disables multicast
                method(s).
   Returns
   None.                                                                   */  
void cmResolverEnableMethod(NQ_INT type, NQ_BOOL unicast, NQ_BOOL multicast);

/* Description
   Resolver uses DNS and NET BIOS to resolve host IP(s) by name
   or to resolve host name by IP. This function enables adding
   another resolution method. A method is defined using the <link CMResolverRegisteredMethodDescription, CMResolverRegisteredMethodDescription Structure>.
   See structure description with different members. Not all
   functions have to be defined, but notice following
   guidelines:
     1. Must define at least one request function - request by
        name or request by IP
     2. If a request function is defined, then the corresponding
        response function must be defined as well.
     3. If defined timeout value is too long it might cause a
        delay in setup process.
     4. Resolver methods are not executed all at once.
        Registered method will be executed according to defined
        priority. See the <link CMResolverRegisteredMethodDescription, CMResolverRegisteredMethodDescription Structure>.
   Returns
   TRUE - on registration success. FALSE otherwise.                                                                                                        */
NQ_BOOL cmResolverRegisterExternalMethod(const CMResolverRegisteredMethodDescription * pMethod);

/* Description
   This function enables run time control on the order of
   resolver methods execution. In resolver point of view three
   groups of methods exist: unicast methods, multicast methods,
   external methods. External methods are all methods that were
   registered by the user. Each group of methods is executed
   separately and if no reply is received the next group is
   executed.
   Parameters
   requiredPriority :  This parameter takes the following values\:
                       1. Execute external methods before all
                          other methods.
                       2. Execute external methods after unicast
                          methods and before multicast methods.
                       3. Execute external methods only if all
                          other resolution methods failed.
   Returns
   <i>TRUE</i> - on success. <i>FALSE</i> otherwise.               */
NQ_BOOL cmResolverUpdateExternalMethodsPriority(NQ_INT requiredPriority);

/* Description
   After startup NQ uses the list of DNS servers as defined in
   the NQ configuration. By calling this function application
   replaces the initial list with a new one.
   Parameters
   servers :  Pointer to the new list of DNS servers. This list
              is a string of IP addresses, delimited by a
              semicolon. Each address may have a form of IPv4 or
              IPv6 address. This pointer can be NULL. In this
              case NQ will not query DNS servers. 
   Returns
   None.                                                         */
#ifdef UD_CM_UNICODEAPPLICATION
    #define cmDnsSetServers cmDnsSetServersW  
#else
    #define cmDnsSetServers cmDnsSetServersA
#endif
void cmDnsSetServersA(const NQ_CHAR * servers);    /* ASCII version */
void cmDnsSetServersW(const NQ_WCHAR * servers);   /* UNICODE version */

/* Description
   After startup NQ uses the WINS IP as defined in the NQ
   configuration. By calling this function application replaces
   the initial WINS with a list of new ones.
   Parameters
   servers :  Pointer to the list of new WINS servers. This list
              is a string of IP addresses, delimited by a
              semicolon. Each address should have a form of IPv4
              address. This pointer can be NULL, in this case NQ
              will not query WINS.
   Returns
   None.
   Note
   WINS addresses set over this function affect only name-to-IP
   and IP-to-name resolution. They do not affect name
   registration, which is always performed against the default
   WINS. We assume that in a case of multiple WINS they
   replicate name registered in just one of them.                */
#ifdef UD_CM_UNICODEAPPLICATION
    #define cmNetBiosSetWins cmNetBiosSetWinsW  
#else
    #define cmNetBiosSetWins cmNetBiosSetWinsA
#endif
void cmNetBiosSetWinsA(const NQ_CHAR * servers);    /* ASCII version */
void cmNetBiosSetWinsW(const NQ_WCHAR * servers);   /* UNICODE version */

/* Description
   After startup NQ uses the domain name as defined in the NQ
   configuration. By calling this function application replaces
   the initial domain name with a new ones.
   
   This name becomes available for subsequent operations.
   Parameters
   domainName :  New domain name. It should contain more than one
                 symbol and it should not be longer than
                 UD_NQ_HOSTNAMESIZE
   Returns
   NQ_SUCCESS on success or NQ_FAIL when the domain name is NULL
   or it is too long or too short.                                */
#ifdef UD_CM_UNICODEAPPLICATION
    #define cmDnsSetDomain cmDnsSetDomainW  
#else
    #define cmDnsSetDomain cmDnsSetDomainA
#endif
NQ_STATUS cmDnsSetDomainA(const NQ_CHAR * domainName);   /* ASCII version */
NQ_STATUS cmDnsSetDomainW(const NQ_WCHAR * domainName);  /* UNICODE version */

/* Description
	Conversion of Wide Characters string into Multi Byte.
	Parameters
	strMultiByte :  Pointer to result multi byte string
	strWideChar:  Pointer to wide char string to convert
	Returns
	None.                                */
void
cmWideCharToMultiByte(
    NQ_CHAR *strMultiByte,
    const NQ_WCHAR* strWideChar
    );

/* Description
	Conversion of Multi Byte string into Wide Characters.
	Parameters
	strWideChar:  Pointer to result wide char string 
	strMultiByte :  Pointer to multi byte string to convert
	Returns
	None.                                */
void
cmMultiByteToWideChar(
    NQ_WCHAR* strWideChar,
    const NQ_CHAR *strMultiByte
    );

/* Description
	Get the number of available transports.
	Parameters
    None.
    Returns
	Number of available transports.                              */
NQ_UINT
cmGetNumOfAvailableTransports(
    void
    );

/* Description
	Get the list of transports by their priorities.
	Parameters
    pBuf: Pointer to array of transports following by zero
    Returns
	None.                              */
void
cmGetTransportPriorities(
    NQ_UINT	*	pBuf
    );


#endif  /* _CMAPI_H_ */
