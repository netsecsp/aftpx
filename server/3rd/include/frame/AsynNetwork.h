#if !defined(AFX_ASYNNETWORK_H__88966194_6F5D_4303_8670_7EAE695A32B3__INCLUDED_)
#define AFX_ASYNNETWORK_H__88966194_6F5D_4303_8670_7EAE695A32B3__INCLUDED_
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 01/15/2024
http://asynframe.sf.net

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
copyright notice, this list of conditions and the
following disclaimer.

* Redistributions in binary form must reproduce the
above copyright notice, this list of conditions
and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "AsynCore.h"
#include "asm/IAsynNetwork.h"
#include "net/Utility.h"
NAMESPACE_BEGIN(asynsdk)

/////////////////////////////////////////////////////////////////////////////////
//IAsynNetwork(InstanceName)
#define IN_AsynNetwork "com.frame.asynsock"

/////////////////////////////////////////////////////////////////////////////////
BEGIN_ASYN_IOERROR(IAsynNetwork)
    USER_ERROR(UNREACHABLE) //网络不可达/主机不可达
    USER_ERROR(EXPIRED)     //TTL 超时
    USER_ERROR(NOPARSE)     //无法解析
END_ASYN_IOERROR()

/////////////////////////////////////////////////////////////////////////////////
//IAsynNetwork.IObjectHolder(lType)
#define DT_GetAsynTcplinkManager (100) //获取内部的IAsynTcplinkManager

#define DT_SetmDNSService        (101) //设置/获取mDNS服务
#define DT_GetmDNSService        (101)

/////////////////////////////////////////////////////////////////////////////////
//IAsynDnsResolver.IObjectHolder(lType)
#define DT_GetDnsHostZone        ( 1 ) //获取IAsynDnsResolver内部IDnsHostZone

/////////////////////////////////////////////////////////////////////////////////
//IAppService.Control(action)
#define ST_ActStop               ( 0 ) //停止服务
#define ST_ActStart              ( 1 ) //启动服务
#define ST_ActPause              ( 2 ) //暂停服务
#define ST_GetState              ( 3 ) //返回服务状态: 0-stopped 1-running 2-paused

/////////////////////////////////////////////////////////////////////////////////
//SetSockopt/GetSockopt的定义level
#define EXT_SOCKET               (0xffffffff)

//SetSockopt/GetSockopt的定义optname
#define NET_SNDIO                ( 0 ) //是否同步发送UDP数据
#define NET_MTU                  ( 1 )
#define NET_WAN                  ( 2 ) //格式: port[2B]addr[4|16B]

NAMESPACE_END(asynsdk)

#endif // !defined(AFX_ASYNNETWORK_H__88966194_6F5D_4303_8670_7EAE695A32B3__INCLUDED_)