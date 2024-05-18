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
#include "stdafx.h"
#include "ftpx_Downloader.h"

BEGIN_ASYN_MESSAGE_MAP(CFtpxDownloader)
    ON_IOMSG_NOTIFY(OnIomsgNotify)
    ON_EVENT_NOTIFY(OnEventNotify, IAsynIoOperation)
    ON_QUERY_RESULT(OnQueryResult, IUnknown)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CFtpxDownloader::OnQueryResult( uint64_t lParam1, uint64_t lParam2, IUnknown **objects )
{
    if( lParam1 == EN_SystemEvent ||
        m_spAsynIoBridge != (IAsynIoBridge *)lParam1) return E_NOTIMPL;

    #ifdef _DEBUG
    printf("transmit: %I64d\n", lParam2);
    #endif
    m_datasize -= lParam2;

    return m_datasize != 0 ? S_OK : S_FALSE;
}

HRESULT CFtpxDownloader::OnIomsgNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    CComPtr<IAsynNetIoOperation> spAsynIoOperation;
    CComPtr<INetmsg> spNetmsg;

    uint32_t lErrorCode = NO_ERROR, lTransferedBytes;
    asynsdk::CStringSetter host(1);
    STRING   Status, Params;
    std::string status, params, hostport;
    PORT  port;
    std::string::size_type ipos, pos1, pos2;
    char  temp[64];
    HRESULT hr;
    CComPtr<IAsynFile> spAsynFile;
    CComPtr<IAsynTcpSocket> spAsynTcpSocket;

    lpAsynIoOperation->GetCompletedResult(&lErrorCode, &lTransferedBytes, 0);

    crStartV(0);

    //1.连接结果
    if( lErrorCode != NO_ERROR )
    {
        printf("connect, error: %d\n", lErrorCode);
        SetEvent(m_hNotify);
        return S_OK;
    }
    lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
    spAsynIoOperation->GetPeerAddress(&host, 0, &port, &m_af);
    printf("connect %s:%d[%s]\n", host.m_val.c_str(), port, m_af==AF_INET? "ipv4" : "ipv6");

    lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
    spNetmsg->Getline(&Status, &Params, 0, 0 );
    status = string_from_STRING(Status);
    params = string_from_STRING(Params);
    printf("recv stat ack: %s %s\n", status.c_str(), params.c_str());
    lErrorCode = atoi(status.c_str());
    if( lErrorCode / 100 != 2 )
    {
        SetEvent(m_hNotify);
        return E_NOTIMPL;
    }

    //2.发送user
    printf("send user req: USER %s\n", m_user.c_str());
    m_spCtrlTcpSocket->SendPacket(STRING_from_string("USER"), STRING_from_string(m_user), 0, 0);
    crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
    if( lErrorCode != NO_ERROR )
    {
        printf("recv user ack, error: %d\n", lErrorCode);
        SetEvent(m_hNotify);
        return S_OK;
    }
    lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
    spNetmsg->Getline(&Status, &Params, 0, 0 );
    status = string_from_STRING(Status);
    params = string_from_STRING(Params);
    printf("recv user ack: %s %s\n", status.c_str(), params.c_str());
    lErrorCode = atoi(status.c_str());
    if( lErrorCode / 100 != 2 )
    {
        if( lErrorCode / 100 != 3 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }
        else
        {// need send password
            printf("send pass req: PASS %s\n", m_password.c_str());
            m_spCtrlTcpSocket->SendPacket(STRING_from_string("PASS"), STRING_from_string(m_password), 0, 0);
            crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
            if( lErrorCode != NO_ERROR )
            {
                printf("recv pass ack, error: %d\n", lErrorCode);
                SetEvent(m_hNotify);
                return E_NOTIMPL;
            }
            lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
            spNetmsg->Getline(&Status, &Params, 0, 0 );
            status = string_from_STRING(Status);
            params = string_from_STRING(Params);
            printf("recv pass ack: %s %s\n", status.c_str(), params.c_str());
            lErrorCode = atoi(status.c_str());
            if( lErrorCode / 100 != 2 )
            {
                SetEvent(m_hNotify);
                return S_OK;
            }
        }
    }

    if( m_bssl )
    {
        printf("send pbsz req: PBSZ 0\n");
        m_spCtrlTcpSocket->SendPacket(STRING_from_string("PBSZ"), STRING_from_string("0"), 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv pbsz ack, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv pbsz ack: %s %s\n", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }

        printf("send prot req: PROT P\n");
        m_spCtrlTcpSocket->SendPacket(STRING_from_string("PROT"), STRING_from_string("P"), 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv prot ack, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv prot ack: %s %s\n", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }
    }

    if( m_filepath.empty()== false )
    {// 改变路径
        printf("send  cwd req: CWD  %s\n", m_filepath.c_str());
        m_spCtrlTcpSocket->SendPacket(STRING_from_string( "CWD"), STRING_from_string(m_filepath), 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv  cwd ack, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv  cwd ack: %s %s\n", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }
    }

    if( m_filename.empty()!= false )
    {// 下载目录, 不必设置type
        m_datasize = _UI64_MAX; //数据大小未知
    }
    else
    {// 下载文件
        printf("send size req: SIZE %s\n", m_filename.c_str());
        m_spCtrlTcpSocket->SendPacket(STRING_from_string("SIZE"), STRING_from_string(m_filename), 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv size ack, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv size ack: %s %s\n", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }

        m_datasize = _atoi64(params.c_str());
        if( m_datasize == 0 )   //filesize is zero
        {
            printf("%s is zero\n", m_filename.c_str());
            SetEvent(m_hNotify);
            return S_OK;
        }
    }

    printf("send type req: TYPE I\n");
    m_spCtrlTcpSocket->SendPacket(STRING_from_string("TYPE"), STRING_from_string("I"), 0, 0);
    crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
    if( lErrorCode != NO_ERROR)
    {
        printf("recv type ack, error: %d\n", lErrorCode);
        SetEvent(m_hNotify);
        return E_NOTIMPL;
    }
    lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
    spNetmsg->Getline(&Status, &Params, 0, 0 );
    status = string_from_STRING(Status);
    params = string_from_STRING(Params);
    printf("recv type ack: %s %s\n", status.c_str(), params.c_str());
    lErrorCode = atoi(status.c_str());
    if( lErrorCode / 100 != 2 )
    {
        SetEvent(m_hNotify);
        return S_OK;
    }

    if(!m_pasv )
    {// 主动模式
        {
            CComPtr<IAsynTcpSocketListener> spDataTcpSocketListener;
            m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spDataTcpSocketListener);
            if( m_prxyname == "socks" )
            {
                std::string ver = m_setsfile.get_string("proxy", "version");
                if(!ver.empty())
                    ver.insert(0, "/");

                CComPtr<IAsynRawSocket  > spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("proxy"), spDataTcpSocketListener, 0, STRING_from_string(m_prxyname + ver), &spAsynTmpSocket);

                CComPtr<IAsynProxySocket> spProxy;
                spAsynTmpSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);
                asynsdk::CKeyvalSetter    params(1);
                params.Set(STRING_from_string(";account"), 1, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                HRESULT r1 = spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", 1080), STRING_from_string(m_setsfile.get_string("proxy", "method", "")), &params);

                spDataTcpSocketListener = 0;
                spProxy->QueryInterface(IID_IAsynTcpSocketListener, (void **)&spDataTcpSocketListener);
            }

            if( m_bssl )
            {
                CComPtr<IAsynRawSocket  > spAsynTmpSocket;
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spDataTcpSocketListener, 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynTmpSocket);
                spAsynTmpSocket->QueryInterface(IID_IAsynTcpSocketListener, (void **)&m_spDataTcpSocketListener);
            }
            else
            {
                m_spDataTcpSocketListener = spDataTcpSocketListener;
            }
        }

        m_spDataTcpSocketListener->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);

        m_spAsynFrameThread->BindAsynIoOperation(lpAsynIoOperation, 0, 0, 5000/*5sec*/); //设定io超时
        crReturn(m_spDataTcpSocketListener->Bind(STRING_EX::null, 0, FALSE, lpAsynIoOperation));
        if( lErrorCode != NO_ERROR)
        {
            printf("tcp.bind, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
        spAsynIoOperation->GetPeerAddress(&host, 0, &port, 0);
        if( host.m_val.empty() != false ) m_spCtrlTcpSocket->GetSockAddress(&host, 0, 0, 0);
        printf("tcp.bind %s:%d\n", host.m_val.c_str(), port);

        if( m_af != AF_INET )
        {// ipv6
            sprintf_s(temp, 64, "|2|%s|%d|", host.m_val.c_str(), port);
            printf("send eprt req: EPRT %s\n", temp);
            m_spCtrlTcpSocket->SendPacket(STRING_from_string("EPRT"), STRING_from_string(temp), 0, 0);
        }
        else
        {// ipv4
            ipos = host.m_val.find('.');
            while(ipos != std::string::npos)
            {
                host.m_val[ipos] = ',';
                ipos = host.m_val.find('.', ipos);
            }

            sprintf_s(temp, 64, "%s,%d,%d", host.m_val.c_str(), port / 256, port % 256);
            printf("send port req: PORT %s\n", temp);
            m_spCtrlTcpSocket->SendPacket(STRING_from_string("PORT"), STRING_from_string(temp), 0, 0);
        }

        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv %s ack, error: %d\n", m_af == AF_INET? "port" : "eprt", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv %s ack: %s %s\n", m_af == AF_INET ? "port" : "eprt", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }

        m_spAsynFrameThread->BindAsynIoOperation(lpAsynIoOperation, 0, 0, 5000/*5sec*/); //设定io超时
        crReturn(m_spDataTcpSocketListener->Accept(lpAsynIoOperation));
        m_spDataTcpSocketListener = 0;
        if( lErrorCode != NO_ERROR )
        {
            printf("accept data connection, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
        spAsynIoOperation->GetPeerAddress(&host, 0, &port, 0);
        printf("accept data connection from %s:%d\n", host.m_val.c_str(), port);

        //设置接收数据速度: B/s
        lpAsynIoOperation->GetCompletedObject(1, IID_IAsynTcpSocket, (IUnknown**)&m_spDataTcpSocket);
        asynsdk::SetSpeedController(m_spDataTcpSocket, Io_recv, -1, m_spSpeedController);
    }
    else
    {// 被动模式
        printf("send %s req: %s\n", m_af == AF_INET ? "pasv" : "epsv", m_af == AF_INET? "PASV" : "EPSV");
        m_spCtrlTcpSocket->SendPacket(STRING_from_string(m_af == AF_INET? "PASV" : "EPSV"), STRING_EX::null, 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv %s ack, error: %d\n", m_af == AF_INET? "pasv" : "epsv", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv %s ack: %s %s\n", m_af == AF_INET ? "pasv" : "epsv", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }

        pos1 = params.find( '(' );
        if( pos1 == std::string::npos)
        {
            SetEvent(m_hNotify);
            return S_OK;
        }
        pos2 = params.find( ')', pos1);
        if( pos2 == std::string::npos ||
            pos1 >= pos2 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }

        hostport = params.substr(pos1, pos2 + 1 - pos1);
        if( m_af == AF_INET )
        {// ipv4
            uint32_t a = 0, b = 0, c = 0, d = 0, h = 0, l = 0;
            sscanf_s(hostport.c_str(), "(%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &h, &l);
            sprintf_s(temp, sizeof(temp), "%d.%d.%d.%d", a, b, c, d);

            host.m_val = temp;
            port = h * 256 + l;
        }
        else
        {// ipv6
            std::string::size_type pos1 = hostport.find( '|' );
            if( pos1 == std::string::npos )
            {
                SetEvent(m_hNotify);
                return S_OK;
            }

            pos1 = hostport.find( '|', pos1 + 1 );
            if( pos1 == std::string::npos )
            {
                SetEvent(m_hNotify);
                return S_OK;
            }

            pos1 += 1;
            std::string::size_type pos2 = hostport.find( '|', pos1 );
            if( pos2 == std::string::npos )
            {
                SetEvent(m_hNotify);
                return S_OK;
            }

            host.m_val = pos2 == pos1 ? m_host : hostport.substr(pos1, pos2 - pos1);
            port = atoi(hostport.c_str() + pos2 + 1);
        }

        {// 创建数据连接对象
            CComPtr<IAsynRawSocket  > spDataTcpSocket;
            if( m_prxyname == "none" ||
                m_prxyname == "ftp" )
            {
                m_spAsynNetwork->CreateAsynTcpSocket((IAsynTcpSocket**)&spDataTcpSocket );
            }
            else
            {// http/socks.proxy
                std::string ver = m_setsfile.get_string("proxy", "version");
                if(!ver.empty())
                    ver.insert(0, "/");

                std::string ssl = m_prxyname == "socks"? "" : m_setsfile.get_string("proxy", "ssl");
                if(!ssl.empty())
                    ssl.insert(0, ":");

                CComPtr<IAsynTcpSocket  > spAsynInnSocket;
                m_spAsynNetwork->CreateAsynTcpSocket(&spAsynInnSocket );

                m_spAsynNetwork->CreateAsynPtlSocket( STRING_from_string("proxy"), spAsynInnSocket, 0, STRING_from_string(m_prxyname + ver + ssl), &spDataTcpSocket);

                CComPtr<IAsynProxySocket> spProxy;
                spDataTcpSocket->QueryInterface(IID_IAsynProxySocket, (void **)&spProxy);

                asynsdk::CKeyvalSetter    params(1);
                params.Set(STRING_from_string(";account"), 0, STRING_from_string(m_setsfile.get_string("proxy", "user") + ":" + m_setsfile.get_string("proxy", "password")));
                if( m_prxyname == "http" )
                {
                    CComPtr<IHttpTxTunnel> spDataTxTunnel; spProxy->QueryInterface(IID_IHttpTxTunnel, (void **)&spDataTxTunnel);
                    spDataTxTunnel->SetEnabled(1); //强制直接代理

                    spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", 8080), STRING_from_string(m_setsfile.get_string("proxy", "method", "")), &params);
                }
                else
                {
                    spProxy->SetProxyContext(STRING_from_string(m_setsfile.get_string("proxy", "host", "127.0.0.1")), (PORT)m_setsfile.get_long("proxy", "port", 1080), STRING_from_string(m_setsfile.get_string("proxy", "method", "")), &params);
                }
            }

            if( m_bssl )
            {
                m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spDataTcpSocket, 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &m_spDataTcpSocket);
            }
            else
            {
                m_spDataTcpSocket = spDataTcpSocket;
            }
        }

        m_spDataTcpSocket->QueryInterface(IID_IAsynTcpSocket, (void **)&spAsynTcpSocket);
        spAsynTcpSocket->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);

        //设置接收数据速度: B/s
        asynsdk::SetSpeedController(spAsynTcpSocket, Io_recv, -1, m_spSpeedController);

        if( m_prxyname == "none" ||
            m_prxyname == "ftp" )
            printf("start to connect %s:%d\n", host.m_val.c_str(), port);
        else
            printf("start to connect %s:%d via %s-proxyserver[%s]\n", host.m_val.c_str(), port, m_prxyname.c_str(), m_setsfile.get_string("proxy", "host", "127.0.0.1").c_str());

        crReturn(spAsynTcpSocket->Connect(STRING_from_string(host.m_val), port, 0, lpAsynIoOperation, 5000)); //必须使用异步连接
        if( lErrorCode != NO_ERROR )
        {
            printf("data connection connect, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return S_OK;
        }
        lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
        spAsynIoOperation->GetPeerAddress(&host, 0, &port, &m_af);
        printf("data connection connect %s:%d[%s]\n", host.m_val.c_str(), port, m_af == AF_INET ? "ipv4" : "ipv6");
    }

    if( m_filename.empty()!= false )
    { //下载目录
        printf("send list req: LIST\n");
        m_spCtrlTcpSocket->SendPacket(STRING_from_string("LIST"), STRING_EX::null, 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv list ack, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv list ack: %s %s\n", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 1 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }
    }
    else
    { //下载文件
        if( m_startpos != 0 )
        {
            _i64toa_s(m_startpos, temp, sizeof(temp), 10);
            printf("send rest req: REST %s\n", temp);
            m_spCtrlTcpSocket->SendPacket(STRING_from_string("REST"), STRING_from_string(temp), 0, 0);
            crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));

            if( lErrorCode / 100 != 3 ) m_startpos = 0; //不支持断点续传
        }

        printf("send retr req: RETR %s\n", m_filename.c_str());
        m_spCtrlTcpSocket->SendPacket(STRING_from_string("RETR"), STRING_from_string(m_filename), 0, 0);
        crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
        if( lErrorCode != NO_ERROR )
        {
            printf("recv retr ack, error: %d\n", lErrorCode);
            SetEvent(m_hNotify);
            return E_NOTIMPL;
        }
        lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
        spNetmsg->Getline(&Status, &Params, 0, 0 );
        status = string_from_STRING(Status);
        params = string_from_STRING(Params);
        printf("recv retr ack: %s %s\n", status.c_str(), params.c_str());
        lErrorCode = atoi(status.c_str());
        if( lErrorCode / 100 != 1 )
        {
            SetEvent(m_hNotify);
            return S_OK;
        }
    }

    m_spAsynFileSystem->CreateAsynFile(&spAsynFile );
    hr = spAsynFile->Open( m_spAsynFrameThread,
                           STRING_from_string(m_savename),
                           GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    if( hr != S_OK )
    {
        printf("open %s, error: %d\n", m_savename.c_str(), hr);
        SetEvent(m_hNotify);
        return S_OK;
    }

    m_spAsynFrameThread->CreateAsynIoBridge(m_spDataTcpSocket, spAsynFile, 0, &m_spAsynIoBridge);
    if( m_startpos )
    {
        CComPtr<IAsynFileIoOperation> spAsynIoOperation; m_spAsynIoBridge->Get(BT_GetTargetIoOperation, 0, IID_IAsynFileIoOperation, (IUnknown**)&spAsynIoOperation);
        spAsynIoOperation->SetPosition(m_startpos); //设置开始写入数据时文件的偏移
        m_datasize -= m_startpos;
    }

    m_starttime = ::GetTickCount();
    m_spAsynIoBridge->Invoke(0, asyn_message_events_impl::GetAsynMessageEvents()); //开始接收数据并写入文件的处理

    crReturn(m_spCtrlTcpSocket->Read(lpAsynIoOperation));
    if( lErrorCode != NO_ERROR )
    {
        printf("recv retr ack, error: %d\n", lErrorCode);
        SetEvent(m_hNotify);
        return E_NOTIMPL;
    }
    lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown**)&spNetmsg);
    spNetmsg->Getline(&Status, &Params, 0, 0 );
    status = string_from_STRING(Status);
    params = string_from_STRING(Params);
    printf("recv retr ack: %s %s\n", status.c_str(), params.c_str());
    lErrorCode = atoi(status.c_str());
    if( lErrorCode / 100 != 2 )
    {
        SetEvent(m_hNotify);
        return S_OK;
    }

    crFinish(S_OK);
}

HRESULT CFtpxDownloader::OnEventNotify( uint64_t lParam1, uint64_t lParam2, IAsynIoOperation *lpAsynIoOperation )
{
    if( m_spAsynIoBridge != (IAsynIoBridge *)lParam1) return S_OK;

    if( lParam2 == NO_ERROR || //下载文件
        lParam2 == AE_RESET && m_filename.empty() != false ) //下载目录
    {
        uint32_t speed;
        m_spSpeedController->GetPostIoBytes(0, &speed);
        printf("%s is saved, speed: %.2fKB/s, cost: %dms\n", m_savename.c_str(), speed / 1024.0, ::GetTickCount() - m_starttime);
    }
    else
    {
        CComPtr<IAsynFileIoOperation> spAsynIoOperation; m_spAsynIoBridge->Get(BT_GetTargetIoOperation, 0, IID_IAsynFileIoOperation, (IUnknown**)&spAsynIoOperation);
        spAsynIoOperation->GetPosition(&m_startpos );
        lpAsynIoOperation->GetOpParams( 0, 0, &lParam1);

        if( m_filename.empty() )
        {
            if( lParam1 == Io_recv )
                printf("recv, error: %I64d\n", lParam2);
            else
                printf("save, error: %I64d\n", lParam2);
        }
        else
        {
            if( lParam1 == Io_recv )
                printf("recv %s on position: %I64d, error: %I64d\n", m_savename.c_str(), m_startpos, lParam2);
            else
                printf("save %s on position: %I64d, error: %I64d\n", m_savename.c_str(), m_startpos, lParam2);
        }
    }

    HRESULT r1 = m_spCtrlTcpSocket->Close(0); //Close能够自动发送QUIT
    SetEvent(m_hNotify);
    return S_OK;
}
