

/* this ALWAYS GENERATED file contains the IIDs and CLSIDs */

/* link this file in with the server and any clients */


 /* File created by MIDL compiler version 8.00.0603 */
/* at Sat Nov 11 08:20:23 2023
 */
/* Compiler settings for IAsynFrame.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.00.0603 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


#ifdef __cplusplus
extern "C"{
#endif 


#include <rpc.h>
#include <rpcndr.h>

#ifdef _MIDL_USE_GUIDDEF_

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        DEFINE_GUID(name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8)

#else // !_MIDL_USE_GUIDDEF_

#ifndef __IID_DEFINED__
#define __IID_DEFINED__

typedef struct _IID
{
    unsigned long x;
    unsigned short s1;
    unsigned short s2;
    unsigned char  c[8];
} IID;

#endif // __IID_DEFINED__

#ifndef CLSID_DEFINED
#define CLSID_DEFINED
typedef IID CLSID;
#endif // CLSID_DEFINED

#define MIDL_DEFINE_GUID(type,name,l,w1,w2,b1,b2,b3,b4,b5,b6,b7,b8) \
        const type name = {l,w1,w2,{b1,b2,b3,b4,b5,b6,b7,b8}}

#endif !_MIDL_USE_GUIDDEF_

MIDL_DEFINE_GUID(IID, IID_IObjectHolder,0xF8CE1A45,0x9316,0x430a,0xBA,0xE5,0xD9,0x05,0x20,0x1C,0xC1,0x80);


MIDL_DEFINE_GUID(IID, IID_ISpeedController,0x6A420A5D,0x1198,0x44fc,0xAC,0xFF,0x7B,0xEC,0x93,0x4F,0xE7,0xD5);


MIDL_DEFINE_GUID(IID, IID_IOsTime,0x9508E64D,0x1F80,0x43fd,0x9E,0x27,0xD3,0x9D,0x20,0x39,0x4E,0xCF);


MIDL_DEFINE_GUID(IID, IID_IAsynMessageEvents,0x636E17D7,0x3713,0x4a36,0x98,0xA7,0x6B,0x09,0x71,0x47,0x60,0x67);


MIDL_DEFINE_GUID(IID, IID_IAsynMessageObject,0x58EDD852,0x2FCC,0x4ea8,0x80,0x69,0x3D,0xF6,0xE1,0xD9,0x68,0x66);


MIDL_DEFINE_GUID(IID, IID_IThreadMessagePump,0x5D5B45AA,0xE96D,0x4856,0xB0,0x29,0xDC,0x83,0xEE,0x2C,0x21,0xBB);


MIDL_DEFINE_GUID(IID, IID_IThread,0xB9811E66,0x30E4,0x4D9C,0xBF,0x5F,0x15,0xEC,0x25,0x29,0x38,0x40);


MIDL_DEFINE_GUID(IID, IID_IThreadPool,0x91209092,0x33B1,0x4ED1,0xA4,0x0E,0x0D,0x16,0x2F,0xA0,0x93,0x8D);


MIDL_DEFINE_GUID(IID, IID_IMemoryPool,0x33A4526F,0x4260,0x4a9d,0xB9,0xBE,0xBA,0xCB,0xFE,0xAF,0x0D,0x62);


MIDL_DEFINE_GUID(IID, IID_IBuffer,0x4CB3BD65,0xB69F,0x4d25,0x82,0xAA,0x10,0xD7,0x22,0x57,0xC6,0x1D);


MIDL_DEFINE_GUID(IID, IID_IOsCommand,0xB090FA6F,0x9712,0x4fd7,0xA9,0xC2,0x4E,0x5D,0x11,0x4D,0x74,0x79);


MIDL_DEFINE_GUID(IID, IID_IAsynIoOperation,0x0C34146C,0xC1CE,0x4c8c,0xA6,0x7F,0x32,0x03,0x90,0x09,0xFA,0xD7);


MIDL_DEFINE_GUID(IID, IID_IAsynIoOperationFactory,0x6655485B,0x7257,0x4e33,0x87,0x14,0x12,0x09,0x11,0xD6,0x20,0xEF);


MIDL_DEFINE_GUID(IID, IID_IDataTransmit,0x51DAEFEC,0x4B50,0x43C5,0xBE,0xB1,0x26,0x6F,0xD6,0x13,0x62,0xA3);


MIDL_DEFINE_GUID(IID, IID_IDataRwInvoke,0xCE91B4EF,0xB499,0x4778,0xAF,0x25,0x2D,0x33,0x58,0xDC,0x5B,0xA1);


MIDL_DEFINE_GUID(IID, IID_IDataProvider,0xBC3598EB,0x758F,0x4363,0xBA,0x80,0xE7,0x26,0x39,0x34,0xCD,0x9D);


MIDL_DEFINE_GUID(IID, IID_IAsynIoDevice,0xCBFDC32B,0x6AC7,0x4dd6,0xBB,0x9D,0xE8,0x24,0x83,0x66,0x24,0x9A);


MIDL_DEFINE_GUID(IID, IID_IAsynIoBridge,0x7BA6B23B,0xFF8B,0x4b2f,0x9D,0x6F,0xE0,0xB5,0xB1,0xB5,0xB6,0x30);


MIDL_DEFINE_GUID(IID, IID_IAsynFrame,0x9F16D983,0x8774,0x4daa,0x92,0x39,0xE3,0xB2,0xF9,0xE9,0xE1,0x99);


MIDL_DEFINE_GUID(IID, IID_IAsynFrameThread,0x0B5E89FF,0xD258,0x4443,0x80,0x96,0xC3,0xBC,0xCB,0x2D,0xDC,0xBA);


MIDL_DEFINE_GUID(IID, IID_IAsynFrameThreadFactory,0x1A00D0BF,0xC0A0,0x455b,0x8A,0x86,0x83,0xAB,0x6E,0xD7,0x63,0x0D);


MIDL_DEFINE_GUID(IID, IID_InstancesManager,0xAB2CD54D,0x2BCB,0x41c8,0x97,0x57,0x99,0xB4,0x3F,0x20,0x20,0x24);


MIDL_DEFINE_GUID(IID, IID_IAsynFramePlugin,0xE28ADF6E,0xBC0E,0x4561,0x88,0xDF,0xE3,0xE6,0x10,0xC5,0x9B,0x8F);

#undef MIDL_DEFINE_GUID

#ifdef __cplusplus
}
#endif



