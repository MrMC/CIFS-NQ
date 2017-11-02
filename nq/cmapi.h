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

/* CM library initialization */

NQ_STATUS
cmInit(
    void
    );

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

/** ------------- function prototypes */

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
     * Replacing one of pre&#45;compiled code pages (see NQ
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
   None.                                                          */
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
   It is caller's responsibility to release this array.                */  
const NQ_IPADDRESS * cmResolverGetHostIps(const NQ_WCHAR * host, NQ_INT * numIps);

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
NQ_STATUS cmDnsSetDomainW(const NQ_WCHAR * domainName);/* UNICODE version */

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

#endif  /* _CMAPI_H_ */
