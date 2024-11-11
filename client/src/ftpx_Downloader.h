#ifndef __FTPXDOWNLOADER_H__
#define __FTPXDOWNLOADER_H__
/*****************************************************************************
Copyright (c) netsecsp 2012-2032, All rights reserved.

Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated 01/15/2024
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
#include <frame/AsynFile.h>
#include <frame/AsynNetwork.h>
#include <frame/asm/INet.h>
#include <frame/asm/IProxy.h>
using namespace asynsdk;

class CFtpxDownloader : public asyn_message_events_impl
{
public:
    CFtpxDownloader(InstancesManager *lpInstanceManager, IAsynFrameThread *lpAsynFrameThread)
      : m_pasv(1), m_af(AF_INET), m_startpos(0), m_hNotify(::CreateEvent(0, 1, 0, 0))
    {
        m_setsfile.from(lpInstanceManager);
        m_spInstanceManager = lpInstanceManager;
        m_spAsynFrameThread = lpAsynFrameThread;
        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynNetwork), IID_IAsynNetwork, (IUnknown **)&m_spAsynNetwork);
        CreateAsynFrame(m_spAsynFrameThread, 0, &m_spAsynFrame);
    }
    virtual ~CFtpxDownloader()
    {
        CloseHandle(m_hNotify);
    }

public: // interface of asyn_message_events_impl
    DECLARE_ASYN_MESSAGE_MAP(CFtpxDownloader)
    HRESULT OnIomsgNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnEventNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation );
    HRESULT OnQueryResult( uint64_t lParam1, uint64_t lAction, IUnknown **objects );

public:
    const char *Parse(int argc, const char *argv[])
    {
        const char *ftpxurl = 0;
        for(int i = 1; i < argc; ++ i)
        {
            if( strcmp(argv[i], "/?") == 0 || 
                strcmp(argv[i], "--help") == 0 )
            {
                ftpxurl = 0;
                break;
            }

            if( argv[i][0] == '-' )
            {
                if( strcmp(argv[i], "-port") == 0 )
                {
                    m_pasv = 0;
                    continue;
                }
                if( strcmp(argv[i], "-pasv") == 0 )
                {
                    m_pasv = 1;
                    continue;
                }
                if( strcmp(argv[i], "-4") == 0 )
                {
                    m_af = AF_INET;
                    continue;
                }
                if( strcmp(argv[i], "-6") == 0 )
                {
                    m_af = 23;
                    continue;
                }
                if( strcmp(argv[i], "-e") == 0 )
                {
                    m_ssle = 1;
                    continue;
                }
                if( strcmp(argv[i], "-c") == 0 )
                {
                    if( argc > ++ i)
                        m_startpos = _atoi64(argv[i]);
                    continue;
                }
                if( strcmp(argv[i], "-s") == 0 )
                {
                    if( argc > ++ i)
                        m_setsfile.setString("ssl.algo", argv[i]);
                    continue;
                }
                if( strcmp(argv[i], "-o") == 0 )
                {
                    if( argc > ++ i)
                        m_savename = argv[i];
                    continue;
                }
                if( strcmp(argv[i], "-u") == 0 )
                {
                    if( argc > ++ i)
                    {// protocol://[user:password@]host[:port]/ver?params
                        std::string tmpurl = argv[i];

                        std::string::size_type pos1 = tmpurl.find("://");
                        if( pos1 == std::string::npos )
                        {
                            continue;
                        }

                        std::string schema = tmpurl.substr(0, pos1);
                        _strlwr_s((char*)schema.c_str(), schema.size() + 1);
                        if( schema != "ftp" &&
                            schema != "http" &&
                            schema != "socks" ) 
                        {
                            continue;
                        }
                        else
                        {
                            pos1 += 3;
                        }

                        m_setsfile.setString("proxy.protocol", schema);

                        std::string::size_type pos2 = tmpurl.find('/', pos1);
                        std::string hostport; //[user:password@]host[:port]

                        if( pos2 == std::string::npos )
                        {
                            hostport = tmpurl.substr(pos1);
                        }
                        else
                        {// ver?method=v&ssl=v
                            hostport = tmpurl.substr(pos1, pos2 - pos1);

                            pos2 += 1;
                            std::string::size_type post = tmpurl.find_first_of("?=", pos2);
                            if( post == std::string::npos )
                            {
                                m_setsfile.setString("proxy.version", tmpurl.substr(pos2));
                            }
                            else
                            {
                                std::string params;
                                if( tmpurl[post] != '?' )
                                {
                                    params = tmpurl.substr(pos2);
                                }
                                else
                                {
                                    params = tmpurl.substr(post + 1);
                                    m_setsfile.setString("proxy.version", tmpurl.substr(pos2, post - pos2));
                                }

                                std::map<std::string, std::string> t;
                                const char *s = params.c_str(), *e = s + params.size(), *i;
                                do{
                                    i = strchr(s, '=');
                                    if(!i ) break;

                                    std::string key(s, i - s);

                                    s = i + 1; //skip '='

                                    i = strchr(s, '&');

                                    t[key] = std::string(s, i? (i - s) : (e - s));

                                    if(!i ) break;

                                    s = i + 1; //skip '&'
                                }while(1);

                                m_setsfile.setString("proxy.method", t["method"]);
                                m_setsfile.setString("proxy.ssl", t["ssl"]);
                            }
                        }

                        std::string::size_type pos3 = hostport.find('@');
                        if( pos3 != std::string::npos )
                        {
                            std::string account = hostport.substr(0, pos3);
                            hostport.erase(0, pos3 + 1);

                            std::string::size_type post = account.find(':');
                            if( post == std::string::npos )
                            {
                                m_setsfile.setString("proxy.user", account);
                            }
                            else
                            {
                                m_setsfile.setString("proxy.user", account.substr(0, post));
                                m_setsfile.setString("proxy.password", account.substr(post + 1));
                            }
                        }

                        std::string::size_type pos4 = hostport.find(':');
                        if( pos4 == std::string::npos )
                        {
                            m_setsfile.setString("proxy.host", hostport);
                        }
                        else
                        {
                            m_setsfile.setString("proxy.host", hostport.substr(0,  pos4));
                            m_setsfile.setString("proxy.port", hostport.substr(pos4 + 1));
                        }
                    }
                    continue;
                }
            }
            else
            {
                std::string tmpurl = argv[i];

                std::string::size_type pos1 = tmpurl.find("://");
                if( pos1 == std::string::npos )
                {
                    continue;
                }

                std::string schema = tmpurl.substr(0, pos1);
                _strlwr_s((char*)schema.c_str(), schema.size() + 1);
                if( schema != "ftp" &&
                    schema != "ftps" )
                {
                    continue;
                }
                else
                {
                    ftpxurl = argv[i];
                }
            }
        }
        return ftpxurl;
    }

    bool Start(std::string url)
    {// url格式， protocol://[user:password@]host[:port]/path/[;parameters][?query]#fragment
        if( m_spInstanceManager->Require(STRING_from_string(IN_AsynFileSystem)) != S_OK )
        {
            printf("can't load plugin: %s\n", IN_AsynFileSystem);
            return false;
        }

        m_spInstanceManager->GetInstance(STRING_from_string(IN_AsynFileSystem), IID_IAsynFileSystem, (IUnknown **)&m_spAsynFileSystem);
        m_spInstanceManager->NewInstance(0, 0, IID_ISpeedController, (IUnknown **)&m_spSpeedController);

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
        if( pos3 != std::string::npos )
        {
            std::string account = hostport.substr(0, pos3);
            hostport.erase(0, pos3 + 1);
            
            std::string::size_type post = account.find(':');
            if( post == std::string::npos )
            {
                m_user = account;
            }
            else
            {
                m_user = account.substr(0, post);
                m_password = account.substr(post + 1);
            }
        }
        if( m_user.empty())
            m_user = "anonymous";
        if( m_password.empty())
            m_password = "IEUser@";

        std::string::size_type pos4 = hostport.find(':');
        if( pos4 == std::string::npos )
        {
            m_host = hostport;
            m_port = schema == "ftp" || m_ssle? 21 : 990;
        }
        else
        {
            m_host = hostport.substr(0, pos4);
            m_port = (PORT)atoi(hostport.substr(pos4 + 1).c_str());
        }

        std::string::size_type pos5 = url.rfind('/');
        m_filename = url.substr(pos5 + 1); //等于空表示下载目录
        m_filepath = url.substr(pos2, pos5 - pos2);
        m_bssl = schema == "ftps";

        if( m_savename.empty())
        {
            m_savename = m_filename.empty()? "dir.list" : m_filename;
        }

        m_prxyname = m_setsfile.getString("proxy.protocol", "none");
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

        CComPtr<IAsynRawSocket> spAsynPtlSocket;
        if( m_prxyname == "none" ) 
        {// 没有配置代理的情况: none
            if( m_bssl &&
                m_ssle == 0 )
            {
                CComPtr<IAsynRawSocket> spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spAsynInnSocket, 0, STRING_from_string(m_setsfile.getString("ssl.algo", "tls/1.0")), &spAsynTmpSocket);
                if( spAsynTmpSocket == NULL )
                {
                    printf("can't load plugin: ssl\n");
                    return false;
                }
                else
                {
                    spAsynInnSocket = spAsynTmpSocket;
                }
            }

            m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ftp"), spAsynInnSocket, 0, STRING_from_string(m_bssl==false? "tcp" : m_setsfile.getString("ssl.algo", "tls/1.0")), &spAsynPtlSocket);
            if( spAsynPtlSocket == NULL )
            {
                printf("can't load plugin: ftp\n");
                return false;
            }
        }
        else
        {// 已经配置代理的情况: ftp/http/socks proxy
            if( m_prxyname == "ftp")
            {// ftp proxy
                std::string ver = m_setsfile.getString("proxy.version");
                if(!ver.empty())
                    ver.insert(0, "/");

                std::string ssl = m_setsfile.getString("proxy.ssl");
                if(!ssl.empty())
                    ssl.insert(0, ":");
                else
                    m_bssl = false; //force ftpt

                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("proxy"), spAsynInnSocket, 0, STRING_from_string(m_prxyname + ver + ssl), &spAsynPtlSocket);
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: proxy.%s\n", schema.c_str());
                    return false;
                }

                CComPtr<IAsynProxySocket> spProxy;
                spAsynPtlSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                asynsdk::CKeyvalSetter    params(1);
                params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.getString("proxy.user") + ":" + m_setsfile.getString("proxy.password")));
                HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.getString("proxy.host", "127.0.0.1")), (PORT)m_setsfile.getNumber("proxy.port", 2121), STRING_from_string(m_setsfile.getString("proxy.method", "")), &params);
            }
            else
            {// http/socks proxy
                std::string ver = m_setsfile.getString("proxy.version");
                if(!ver.empty())
                    ver.insert(0, "/");

                std::string ssl = m_prxyname == "socks"? "" : m_setsfile.getString("proxy.ssl");
                if(!ssl.empty())
                    ssl.insert(0, ":");

                CComPtr<IAsynRawSocket> spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("proxy"), spAsynInnSocket, 0, STRING_from_string(m_prxyname + ver + ssl), &spAsynTmpSocket);
                if( spAsynTmpSocket == NULL )
                {
                    printf("can't load plugin: proxy.%s\n", schema.c_str());
                    return false;
                }
                else
                {
                    spAsynInnSocket = spAsynTmpSocket;
                }

                CComPtr<IAsynProxySocket> spProxy;
                spAsynInnSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                asynsdk::CKeyvalSetter    params(1);
                params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.getString("proxy.user") + ":" + m_setsfile.getString("proxy.password")));

                if( m_prxyname == "http" )
                {
                    CComPtr<IHttpTxTunnel> spDataTxTunnel; spProxy->QueryInterface(IID_IHttpTxTunnel, (void **)&spDataTxTunnel);
                    spDataTxTunnel->SetEnabled(1); //强制直接代理

                    HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.getString("proxy.host", "127.0.0.1")), (PORT)m_setsfile.getNumber("proxy.port", 8080), STRING_from_string(m_setsfile.getString("proxy.method", "")), &params);
                    m_pasv = true; //force pasv
                }
                else
                {
                    HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.getString("proxy.host", "127.0.0.1")), (PORT)m_setsfile.getNumber("proxy.port", 1080), STRING_from_string(m_setsfile.getString("proxy.method", "")), &params);
                }

                if( m_bssl &&
                    m_ssle == 0 )
                {
                    CComPtr<IAsynRawSocket> spAsynTmpSocket;
                    m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spAsynInnSocket, 0, STRING_from_string(m_setsfile.getString("ssl.algo", "tls/1.0")), &spAsynTmpSocket);
                    if( spAsynTmpSocket == NULL )
                    {
                        printf("can't load plugin: ssl\n");
                        return false;
                    }
                    else
                    {
                        spAsynInnSocket = spAsynTmpSocket;
                    }
                }

                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ftp"), spAsynInnSocket, 0, STRING_from_string(m_bssl==false? "tcp" : m_setsfile.getString("ssl.algo", "tls/1.0")), &spAsynPtlSocket);
                if( spAsynPtlSocket == NULL )
                {
                    printf("can't load plugin: ftp");
                    return false;
                }
            }
        }

        spAsynPtlSocket->QueryInterface(IID_INet, (void **)&m_spCtrlTcpSocket);
        CComPtr<IAsynTcpSocket> spAsynTcpSocket;
        spAsynPtlSocket->QueryInterface(IID_IAsynTcpSocket, (void **)&spAsynTcpSocket);
        spAsynTcpSocket->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);

        //开始连接...
        crStateV(0);

        if( m_prxyname == "none" )
        {
            printf("start to connect %s:%d\n", m_host.c_str(), m_port);
        }
        else
        {
            const PORT port = (PORT)m_setsfile.getNumber("proxy.port", 0);
            if( port )
                printf("start to connect %s:%d via %s-proxyserver[%s:%d]\n", m_host.c_str(), m_port, m_prxyname.c_str(), m_setsfile.getString("proxy.host", "127.0.0.1").c_str(), port);
            else
                printf("start to connect %s:%d via %s-proxyserver[%s]\n", m_host.c_str(), m_port, m_prxyname.c_str(), m_setsfile.getString("proxy.host", "127.0.0.1").c_str());
        }

        CComPtr<IAsynNetIoOperation> spAsynIoOperation; m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, 0, 0, IID_IAsynNetIoOperation, (IUnknown **)&spAsynIoOperation);
        spAsynIoOperation->SetOpParam1(0/*控制链接*/);
        spAsynTcpSocket->Connect(STRING_from_string(m_host), m_port, 0, spAsynIoOperation, m_setsfile.getNumber("session.connect_timeout", 2000/*2sec*/));
        return true;
    }

    void Shutdown()
    {
        asyn_message_events_impl::Stop(m_spAsynFrame);
        m_spAsynFrame = NULL;
    }

protected:
    DECLARE_ASYN_CRSTATE(CFtpxDownloader)
    CComPtr<InstancesManager> m_spInstanceManager;
    CComPtr<IAsynFrameThread> m_spAsynFrameThread;
    CComPtr<IAsynFrame      > m_spAsynFrame;
    CComPtr<IAsynNetwork    > m_spAsynNetwork;
    CComPtr<IAsynFileSystem > m_spAsynFileSystem;

    CComPtr<ISpeedController> m_spSpeedController;
    uint32_t m_starttime;

    CComPtr<IAsynTcpSocketListener> m_spDataTcpSocketListener;
    CComPtr<IAsynRawSocket  > m_spDataTcpSocket;
    CComPtr<INet            > m_spCtrlTcpSocket;
    uint32_t m_af; //ipv4/ipv6

    CComPtr<IAsynIoBridge   > m_spAsynIoBridge;
    std::string   m_host;
    PORT          m_port;
    bool          m_bssl; //是否是ssl
    bool          m_pasv;
    bool          m_ssle;
  
    std::string   m_user;
    std::string   m_password;

    std::string   m_prxyname;

    asynsdk::CSetting m_setsfile;

    std::string   m_filename;
    std::string   m_filepath;
    std::string   m_savename;
    uint64_t      m_datasize; //尚未接收数据的长度
    uint64_t      m_startpos; //从０开始

public:
    HANDLE m_hNotify;
};

#endif//__FTPXDOWNLOADER_H__
