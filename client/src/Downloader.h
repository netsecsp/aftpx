#ifndef __DOWNLOADER_H__
#define __DOWNLOADER_H__
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 05/01/2022
http://aftpx.sf.net

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
#include <frame/AsynFile_internal.h>
#include <frame/AsynNetwork_internal.h>
#include <frame/asm/INet.h>
#include <frame/asm/IProxy.h>
#include "setting.h"
using namespace asynsdk;

class CDownloader : public asyn_message_events_impl
{
public:
    CDownloader(HANDLE hNotify, InstancesManager *lpInstanceManager, IAsynFrameThread *lpAsynFrameThread, uint32_t af = AF_INET)
	  : m_af(af), m_hNotify(hNotify), m_setsfile("config.txt")
    {
        m_spInstanceManager = lpInstanceManager;
        m_spAsynFrameThread = lpAsynFrameThread;
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetwork), IID_IAsynNetwork, (void **)&m_spAsynNetwork);
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CDownloader)
    HRESULT OnIomsgNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnEventNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lAction, IUnknown **objects );

public:
    bool Start(const std::string &url, bool ssl_explicit, uint64_t startpos)
    {
        m_spInstanceManager->Require(STRING_from_string(IN_AsynFileSystem), 0);
        if( m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynFileSystem), IID_IAsynFileSystem, (void **)&m_spAsynFileSystem) != S_OK )
        {
            printf("can't load plugin: %s\n", IN_AsynFileSystem);
            return false;
        }
        
        //url格式， protocol://[user:password@]host[:port]/path/[;parameters][?query]#fragment
        std::string::size_type pos1 = url.find("://");
        if( pos1 == std::string::npos )
        {
            printf("fail to parse %s\n", url.c_str());
            return false;
        }
        std::string schema = url.substr(0, pos1);
        pos1 += 3/*skip "://" */;
        _strlwr_s((char *)schema.c_str(), schema.size() + 1);
        if( schema != "ftp" &&
            schema != "ftps" )
        {
            printf("fail to parse %s\n", url.c_str());
            return false;
        }

        std::string::size_type pos2 = url.find('/', pos1);
        if( pos2 == std::string::npos )
        {
            printf("fail to parse %s\n", url.c_str());
            return false;
        }

        std::string hostport = url.substr(pos1, pos2 - pos1); //[user:password@]host[:port]
        std::string::size_type pos3 = hostport.find('@');
        if( pos3 == std::string::npos )
        {
            pos3 = 0;
        }
        else
        {
            pos3 += 1;
        }
        std::string::size_type pos4 = hostport.find(':', pos3);
        if( pos4 == std::string::npos )
        {
            m_host = hostport.substr(pos3);
            m_port = schema == "ftp" || ssl_explicit? 21 : 990;
        }
        else
        {
            m_host = hostport.substr(pos3, pos4 - pos3);
            m_port = atoi(hostport.substr(pos4 + 1).c_str());
        }

        std::string::size_type pos5 = url.rfind('/');
        m_filename = url.substr(pos5 + 1); //等于空表示下载目录
        m_filepath = url.substr(pos2, pos5 - pos2);
        m_startpos = startpos;
        if( m_filename.empty() )
            m_savename = "dir.list";
        else
            m_savename = m_setsfile.get_string("session", "filename", m_filename);

        m_prxyname = m_setsfile.get_string("proxy", "protocol", "none");
        if( m_prxyname != "none" &&
            m_prxyname != "http" &&
            m_prxyname != "ftp" &&
            m_prxyname != "socks" )
        {
            printf("not support proxy: %s\n", m_prxyname.c_str());
            return false;
        }

        CComPtr<IAsynRawSocket> spAsynInnSocket;
        m_spAsynNetwork->CreateAsynTcpSocket((IAsynTcpSocket**)&spAsynInnSocket);

        if( m_prxyname == "none" ) 
        {// 没有配置代理的情况: none
            if( schema != "ftp" && ssl_explicit == 0 )
            {
                CComPtr<IAsynRawSocket> spAsynPtlSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynPtlSocket);
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: ssl\n");
                    return false;
                }

                spAsynInnSocket = spAsynPtlSocket;

                m_bssl = false;
            }
            else
            {
                m_bssl = schema == "ftps";
            }
        
            CComPtr<IAsynRawSocket> spAsynPtlSocket;
            m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ftp"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(schema == "ftp" ? "tcp" : "tls"/*tcp：表示ftp tls：表示ftps*/), &spAsynPtlSocket);
            if( spAsynPtlSocket == NULL )
            {
                printf("can't load plugin: ftp\n");
                return false;
            }

            spAsynPtlSocket->QueryInterface(IID_INet, (void **)&m_spCtrlTcpSocket);
        }
        else
		{// 已经配置代理的情况: ftp/http/socks proxy
            if( m_prxyname == "ftp")
			{// ftp proxy	
                if( schema != "ftp" && ssl_explicit == 0 )
                {
                    CComPtr<IAsynRawSocket> spAsynPtlSocket;
                    m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynPtlSocket);
                    if( spAsynPtlSocket == NULL )
                    {
                        printf("can't load plugin: ssl\n");
                        return false;
                    }

                    spAsynInnSocket = spAsynPtlSocket;
                }

                CComPtr<IAsynRawSocket> spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(schema + "/" + m_setsfile.get_string("proxy", "version", "1.0")), &spAsynTmpSocket);
                if( spAsynTmpSocket == NULL )
                {
                    printf("can't load plugin: proxy.%s\n", schema.c_str());
                    return false;
                }

                CComPtr<IAsynProxySocket> spProxy;
                spAsynTmpSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);
                
                asynsdk::CKeyvalSetter params(1);
                params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), schema == "ftp" || ssl_explicit != 0? (PORT)m_setsfile.get_long("proxy", "port", 2121) : (PORT)m_setsfile.get_long("proxy", "port_2", 2990), STRING_EX::null, &params);

                spAsynTmpSocket->QueryInterface(IID_INet, (void **)&m_spCtrlTcpSocket);
                m_bssl = false;
            }
            else
			{// http/socks proxy
                CComPtr<IAsynRawSocket> spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("proxy"), (IUnknown **)&spAsynInnSocket.p, STRING_from_string(m_prxyname + "/" + m_setsfile.get_string("proxy", "version", "1.0")), &spAsynTmpSocket);
                if( spAsynTmpSocket == NULL )
                {
                    printf("can't load plugin: proxy.%s\n", schema.c_str());
                    return false;
                }

                CComPtr<IAsynProxySocket> spProxy;
                spAsynTmpSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                if( m_prxyname == "http" )
                {
                    asynsdk::CKeyvalSetter params(1);
                    params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                    HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", 8080), STRING_EX::null, &params);
					CComPtr<IHttpTxTunnel> spDataTxTunnel; spProxy->QueryInterface(IID_IHttpTxTunnel, (void **)&spDataTxTunnel);
                    spDataTxTunnel->SetEnabled(1); //强制直接代理
                }
                else
                {
                    asynsdk::CKeyvalSetter params(1);
                    params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                    HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", 1080), STRING_EX::null, &params);
                }

                CComPtr<IAsynRawSocket> spAsynPtlSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ftp"), (IUnknown **)&spAsynTmpSocket.p, STRING_from_string(schema == "ftp" ? "tcp" : "tls"/*tcp：表示ftp tls：表示ftps*/), &spAsynPtlSocket);
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: ftp");
                    return false;
                }

                spAsynPtlSocket->QueryInterface(IID_INet, (void **)&m_spCtrlTcpSocket);
                m_bssl = schema == "ftps";
            }
        }

        CComPtr<IAsynTcpSocket> spAsynTcpSocket;
        m_spCtrlTcpSocket->QueryInterface( IID_IAsynTcpSocket, (void **)&spAsynTcpSocket);
        spAsynTcpSocket->Open( m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP );

        //开始连接...
        crStateV(0);

        if( m_prxyname == "none" )
            printf("start to tcp.connect %s:%d\n", m_host.c_str(), m_port);
        else
            printf("start to tcp.connect %s:%d via proxy: %s[%s:%d]\n", m_host.c_str(), m_port, m_prxyname.c_str(), m_setsfile.get_string("proxy", "host", "127.0.0.1").c_str(), m_setsfile.get_long("proxy", "port", 1080));

        CComPtr<IAsynNetIoOperation> spAsynIoOperation;
        m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, m_af, 0, IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
        HRESULT r2 = spAsynIoOperation->SetOpParam1(0/*控制链接*/);
        spAsynTcpSocket->Connect(STRING_from_string(m_host), m_port, 0, spAsynIoOperation, m_setsfile.get_long("session", "connect_timeout", 5000/*5sec*/));
        return true;
    }

    void Shutdown()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;
    }

protected:
    DECLARE_ASYN_CRSTATE(CDownloader)
    CComPtr<InstancesManager> m_spInstanceManager;
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;
    CComPtr<IAsynNetwork    > m_spAsynNetwork;
    CComPtr<IAsynFileSystem > m_spAsynFileSystem;
    HANDLE m_hNotify;

    CComPtr<ISpeedController> m_spSpeedController;
    uint32_t m_starttime;

    CComPtr<IAsynTcpSocketListener> m_spDataTcpSocketListener;
    CComPtr<IAsynRawSocket  > m_spDataTcpSocket;
    CComPtr<INet            > m_spCtrlTcpSocket;
    uint32_t m_af; //ipv4/ipv6

    CComPtr<IAsynIoBridge   > m_spAsynIoBridge;
    std::string   m_host;
    PORT          m_port;
    bool		  m_bssl; //是否是ssl

    std::string   m_prxyname;

    setting       m_setsfile;
    std::string   m_filename;
    std::string   m_filepath;
    std::string   m_savename;
    uint64_t      m_datasize; //尚未接收数据的长度
    uint64_t 	  m_startpos; //从０开始
};

#endif//__DOWNLOADER_H__
