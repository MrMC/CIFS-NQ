/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Server late response context
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 29-June-2008
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSLATERS_H_
#define _CSLATERS_H_

#include "nsapi.h"
#include "csapi.h"
#include "cs2crtcx.h"

/* late response context */

typedef struct
{
    union _PROTOCOL_
    {
        struct 
        {
            NQ_UINT16 tid;                /* TID to respond on (in LBO) */
            NQ_UINT16 uid;                /* UID to respond on (in LBO) */
            NQ_UINT16 mid;                /* MID to respond on (in LBO) */
            NQ_UINT16 pid;                /* PID to respond on (in LBO) */
            NQ_UINT16 pidHigh;            /* high bits of PID to respond on (in LBO) */
            NQ_BYTE command;              /* command to respond */
            NQ_BYTE flags;                /* saved 'flags' field */
            NQ_UINT16 flags2;             /* saved 'flags2' field */
            union _COMMANDDATA1_              /* switch by command */
            {
                struct                    /* WRITE */
                {
                    NQ_UINT32 dataCount;  /* number of bytes */
                } write;   
                struct                    /* BREAK */
                {
                    NQ_UINT16               fid;
                    NQ_UINT32               createAction;
                    SYFileInformation       fileInfo;
                    NQ_BYTE                 oplock;
                } lockingAndX;                               
            } commandData;
        } smb1;
        struct 
        {
            NQ_UINT32 flags;              /* flags */
            NQ_UINT32 tid;                /* TID to respond on (in LBO) */
            NQ_UINT64 sid;                /* UID to respond on (in LBO) */
            NQ_UINT64 mid;                /* MID to respond on (in LBO) */
            NQ_UINT32 pid;                /* PID to respond on (in LBO) */
            NQ_UINT64 aid;                /* AID of the respective interim response */
            NQ_BYTE command;              /* command to respond */
            union _COMMANDDATA2_              /* switch by command */
            {
                struct                    /* IOCTL */
                {
                    NQ_UINT32 ctlCode;    /* control code */
                    NQ_UINT16 fid;        /* fid */
                } ioctl;
                struct                    /* WRITE */
                {
                    NQ_UINT32 dataCount;  /* number of bytes */
                } write;
                struct                    /* BREAK */
                {
                    NQ_UINT16               fid;      
                    NQ_UINT32               createAction;
                    SYFileInformation       fileInfo; 
                    CSCreateContext         context;
                } oplockBreak;                 
            } commandData;
        } smb2;
    }prot;
    NQ_STATUS status;             /* response status */
    NQ_BOOL isSmb2;               /* TRUE for SMB2 */
    NQ_BOOL isRpc;                /* TRUE when RPC involved */
    NSSocketHandle socket;        /* socket to respond over */
    NQ_BYTE* commandData;         /* pointer to command data buffer */
    NQ_COUNT commandDataSize;     /* room for command data */
    void * file;                  /* context file */
#ifdef UD_CS_MESSAGESIGNINGPOLICY
    NQ_UINT32 sequenceNum;        /* saved sequence number for delayed response (message signing)*/
#endif
#ifdef UD_NQ_INCLUDESMB3
    NQ_BOOL doEncrypt;
#endif
}
CSLateResponseContext;

#endif  /* _CSLATERS_H_ */

