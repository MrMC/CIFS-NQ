/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Compile-dependent definitions for the SY module
 *                 This file is expected to be modified during porting
 *--------------------------------------------------------------------
 * MODULE        : SY - System-dependent
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _SYCOMPIL_H_
#define _SYCOMPIL_H_

/*
    C calling convention
    --------------------
 This is essentual when compiled with C++ compiler
 you may use either of the two definitions depending on your compiler

 */

#if defined(__cplusplus) || defined(c_plusplus)

#define SY_STARTAPI extern "C" {
#define SY_ENDAPI }

#else

#define SY_STARTAPI
#define SY_ENDAPI

#endif

/*
    Byte order conversion
    ---------------------
 if your compiler does not support this - define according to the
 BYTE_ORDER of the target

 */

#define syNtoh32(x)    ntohl(x)
#define syNtoh16(x)    ntohs(x)
#define syHton32(x)    htonl(x)
#define syHton16(x)    htons(x)

/*
    Structure packing
    -----------------
 */
#define SY_COMPILERPACK           /* Comment/uncomment this definition if the */
                                  /* compiler not-supports/supports structure packing */

#ifdef SY_COMPILERPACK

/*
  packed structures are defined in code as follows:

  #ifdef SY_PRAGMAPACK_DEFINED
  #pragma pack(1)
  #endif
  typedef struct
  {
  ...
  } SY_PACK_ATTR myStructure;
  ...
  typedef struct
  {
  ...
  } SY_PACK_ATTR myStructure;
  #ifdef SY_PRAGMAPACK_DEFINED
  #pragma pack()
  #endif

  Only one of two symbols should be defined:
  SY_PRAGMAPACK_DEFINED
  SY_PACK_ATTR
 */

/* #define SY_PRAGMAPACK_DEFINED */
#define SY_PACK_ATTR   __attribute__((packed))

#else /* SY_COMPILERPACK */

#define SY_PACK_ATTR

#endif /* SY_COMPILERPACK */

/*
    String & Memory manipulation
    ----------------------------

 The most effective OS methods for manipulating with strings and memory blocks
 */

#define syMemcpy(_to, _from, _size)         memcpy(((void*)(_to)), ((const void*)(_from)), ((size_t)(_size)))
#define syMemmove(_to, _from, _size)        memmove(_to, _from, _size)
#define syMemset(_to, _val, _size)          memset(_to, _val, _size)
#define syMemcmp(_blk1, _blk2, _size)       memcmp(_blk1, _blk2, ((size_t)(_size)))

#define syStrlen(_s)                        strlen(_s)
#define syStrcpy(_to, _from)                strcpy(_to, _from)
#define syStrncpy(_to, _from, _n)           strncpy(_to, _from, _n)
#define syStrcmp(_s1, _s2)                  strcmp(_s1, _s2)
#define syStrcat(_s1, _s2)                  strcat(_s1, _s2)
#define syStrncmp(_s1, _s2, _n)             strncmp(_s1, _s2, (size_t)(_n))
#define syStrncat(_to, _from, _num)         strncat(_to, _from, _num)
#define syToupper(_c)                       ((char)toupper((int)(_c)))
#define syStrchr(_str, _chr)                strchr(_str, (int)_chr)
#define syStrrchr(_str, _chr)               strrchr(_str, (int)_chr)
#define syStrdup(_str)                      strdup(_str)

/*
    Manipulating with UNICODE strings
    ---------------------------------

  By default we map some of those calls on the NQ implementation of the UNICODE opartions
  Change this to your OS routines if the target OS implements this better
 */

#define syWStrlen   cmWStrlen
#define syWStrcpy   cmWStrcpy
#define syWStrcat   cmWStrcat
#define syWStrncpy  cmWStrncpy
#define syWStrcmp   cmWStrcmp
#define syWStrncmp  cmWStrncmp
#define syWStricmp  cmWStricmp
#define syWStrchr   cmWStrchr
#define syWStrrchr  cmWStrrchr
#define syUnicodeToAnsi(_to, _from) cmUnicodeToAnsi(_to, _from)
#define syAnsiToUnicode(_to, _from) cmAnsiToUnicode(_to, _from)
#define syUnicodeToAnsiN(_to, _from, _size) cmUnicodeToAnsiN(_to, _from, (2*(_size)))
#define syAnsiToUnicodeN(_to, _from, _size) cmAnsiToUnicodeN(_to, _from, _size)

#define syStrtol(_start, _end, _radix)  strtol(_start, _end, _radix)

/*
    Error
    -----

 Obtaining error code may be different in different compilers
 */

#define syGetLastError()       errno
#define sySetLastError(_err)   errno = (int)_err;

/*
    Debug mode
    ----------

 Debug mode is differently defined in different compilers.
 NQ sources use the following condition blocks:

 #if SY_DEBUGMODE
    <debug code>
 #endif

 */

#define SY_DEBUGMODE   defined(NQ_DEBUG)

/*
    Dynamic memory
    --------------

    Define SY_FORCEALLOCATION to allocate tables and buffers from heap rather
    then defining them statically.

 */

//#define SY_FORCEALLOCATION


/*
    Stack saving option
    The next definition controls stakc usage. When defined
    it presumes that stack is big enough (about 10K required on stack).
    When commented it saves stack by defining some data as static

 */

/* #define SY_BIGSTACK */

#define syCalloc(_num, _size)   calloc(_num, _size)
#define syFree(_ptr)            free(_ptr)


/*
    64-bit support
    Define SY_INT32 if on your platform sizeof(long) != 4

*/

#define SY_INT32 int

#endif  /* _SYCOMPIL_H_ */
