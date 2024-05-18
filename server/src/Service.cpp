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
#include "Service.h"
#include <frame/asm/ISsl.h>

BEGIN_ASYN_MESSAGE_MAP(CService)
	ON_IOMSG_NOTIFY(OnIomsgNotify)
	ON_QUERY_RESULT(OnQueryResult, IKeyvalSetter)
END_ASYN_MESSAGE_MAP()
/////////////////////////////////////////////////////////////////////////////
HRESULT CService::OnQueryResult( uint64_t lparam1, uint64_t lparam2, IKeyvalSetter **ppKeyval )
{
    if( lparam1 != EN_SystemEvent) return E_NOTIMPL;
 
    asynsdk::CStringSetter d(1);
    ppKeyval[0]->Get(STRING_from_string(";dattype"), 0, 0, &d);

    std::string::size_type ipos;
    if((ipos=d.m_val.rfind("cert.get"   )) != std::string::npos)
    {// cert.get
        if( m_cert_p12.empty()) return S_FALSE;
        ISsl *pSsl = (ISsl *)lparam2;
        STRING certandpasswd[2];
        certandpasswd[0] = STRING_from_string(m_cert_p12);
        certandpasswd[1] = STRING_from_string(m_password);
        pSsl->SetCryptContext(0, 0, certandpasswd);
        ppKeyval[0]->Set(STRING_from_string(";version"), 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")));
        return S_OK;
    }

    if((ipos=d.m_val.rfind("cert.verify")) != std::string::npos)
    {// cert.verify
        return S_OK;
    }

    if((ipos=d.m_val.rfind("stat.verify")) != std::string::npos)
    {
        static const char *stat = "Copyright (c) netsecsp 2012-2032, All rights reserved.\n"
                                  "Developer: Shengqian Yang, from China, E-mail: netsecsp@hotmail.com, last updated " STRING_UPDATETIME "\n"
                                  "http://aftpx.sf.net";

        ppKeyval[0]->Set(STRING_from_string(";context"), 0, STRING_from_string(stat));
        return S_OK;
    }
    return E_NOTIMPL;
}

HRESULT CService::OnIomsgNotify( uint64_t lParam1, uint64_t lAction, IAsynIoOperation *lpAsynIoOperation )
{
    uint32_t lErrorCode = NO_ERROR, lTransferedBytes;
    lpAsynIoOperation->GetCompletedResult(&lErrorCode, &lTransferedBytes, 0);

    switch(lAction)
    {
    case Io_acceptd:
    {
        if( lErrorCode != NO_ERROR )
        {
            if( lParam1 == 2 )
            {// 数据连接接入失败
                printf("accept data connection, error: %d\n", lErrorCode);
                userinfo *info = m_arOp2Userinfos[lpAsynIoOperation];
                printf("remove client: %s\n", info->skey.c_str());
                m_arOp2Userinfos.erase(lpAsynIoOperation);
                m_arId2Userinfos.erase(info->skey);
                break;
            }
            else
            {// 控制连接接入失败
                #ifdef _DEBUG
                printf("accept ctrl connection, error: %d\n", lErrorCode);
                #endif
                return m_spAsynTcpSocketListener[lParam1]->Accept(lpAsynIoOperation);
            }
        }
        else
        {
            std::string host; asynsdk::CStringSetterRef temp(1, &host);
            PORT        port;
            CComPtr<IAsynNetIoOperation> spAsynIoOperation;
            lpAsynIoOperation->QueryInterface(IID_IAsynNetIoOperation, (void **)&spAsynIoOperation);
            spAsynIoOperation->GetPeerAddress(&temp, 0, &port, 0);
            printf("accepted %s connection from %s:%d\n", lParam1 == 2 ? "data" : "ctrl", host.c_str(), port);

            CComPtr<IAsynTcpSocket     > spAsynNewSocket;
            lpAsynIoOperation->GetCompletedObject(1, IID_IAsynTcpSocket, (IUnknown**)&spAsynNewSocket);

            if( lParam1 == 2 )
            {// 数据连接接入成功
                userinfo *info = m_arOp2Userinfos[lpAsynIoOperation];

                info->spDataTcpSocket = spAsynNewSocket;
                info->spDataTcpSocketListener = 0; //关闭临时监听端口
                info->startipos = 0;//必须复位

                asynsdk::SetSpeedController(info->spDataTcpSocket, Io_recv, -1, info->spDataSpeedController[Io_recv]);
                asynsdk::SetSpeedController(info->spDataTcpSocket, Io_send, -1, info->spDataSpeedController[Io_send]);

                return info->spCtrlTcpSocket->Read(lpAsynIoOperation); //继续接收客户端请求
            }
            else
            {// 控制连接接入成功
                m_spAsynTcpSocketListener[lParam1]->Accept(lpAsynIoOperation);

                char skey[64]; sprintf_s(skey, 64, "%s:%d", host.c_str(), port);
                userinfo &info = m_arId2Userinfos[ skey ];
                info.skey = skey;
                info.utf8 = true;
                spAsynNewSocket->QueryInterface(IID_INet, (void **)&info.spCtrlTcpSocket);

                CComPtr<IAsynIoOperation> spRecvIoOperation;
                m_spAsynNetwork->CreateAsynIoOperation(m_spAsynFrame, m_af, 0, IID_IAsynIoOperation, (IUnknown **)&spRecvIoOperation);
                m_arOp2Userinfos[spRecvIoOperation] = &info;

                return info.spCtrlTcpSocket->Read(spRecvIoOperation); //继续接收ftp报文头部
            }
        }
    }

    case Io_send:
    {
        userinfo *info = m_arOp2Userinfos[lpAsynIoOperation];
        if( lErrorCode != NO_ERROR )
        {// 文件发送失败
            printf("send, error: %d\n", lErrorCode);
            printf("remove client: %s\n", info->skey.c_str());
            m_arOp2Userinfos.erase(lpAsynIoOperation);
            m_arId2Userinfos.erase(info->skey);
            break;
        }
        else
        {// 文件发送完成
            info->spCtrlTcpSocket->SendPacket(STRING_from_string("226"), STRING_from_string("Transfer complete"), 0, 0);
            info->tranfile = 0;
            info->spDataTcpSocket = NULL;

            uint32_t speed = 0;
            info->spDataSpeedController[Io_send]->GetPostIoBytes(0, &speed);
            printf("tansmit completed, speed: %.2fKB/s, cost: %dms\n", speed / 1024.0, ::GetTickCount() - info->starttime);

            return info->spCtrlTcpSocket->Read(lpAsynIoOperation); //继续接收ftp报文头部
        }
    }

    case Io_recv:
    {
        userinfo *info = m_arOp2Userinfos[lpAsynIoOperation];
        if( lErrorCode != NO_ERROR )
        {
            if( lErrorCode != AE_RESET ) printf("recv, error: %d\n", lErrorCode);
            printf("remove client: %s\n", info->skey.c_str());
            m_arOp2Userinfos.erase(lpAsynIoOperation);
            m_arId2Userinfos.erase(info->skey);
            break;
        }
        else
        {
            //接收来自客户端的ftp请求
            CComPtr<INetmsg> spReqmsg;
            lpAsynIoOperation->GetCompletedObject(1, IID_INetmsg, (IUnknown **)&spReqmsg);

            STRING Method;
            STRING Params;
            spReqmsg->Getline(&Method, &Params, 0, 0 );
            std::string method = string_from_STRING(Method);
            std::string params = string_from_STRING(Params);

#ifdef _DEBUG
            if( params.empty() == false )
                printf("%s %s\n", method.c_str(), params.c_str());
            else
                printf("%s\n", method.c_str());
#endif

            /*				 220 欢迎访问
            				 USER anonymous
            				 331 Please specify the password.
            				 PASS 123456
            				 230 Login successful.
            				 SYST
            				 215 Windows_NT
            				 FEAT
            				 211-Extended features supported:
            				 LANG EN*
            				 UTF8
            				 SIZE
            				 MDTM
            				 REST STREAM
            				 211 END
            				 OPTS UTF8 ON
            				 200 OPTS UTF8 command successful - UTF8 encoding now ON.
            				 CWD /1/2/3
            				 250 CWD command successful.
            				 PWD
            				 257 "/1/2/3" is current directory.
            				 LIST
            				 150 Opening BINARY mode data connection.
            				 226 Transfer complete.
            				 SIZE 1.jpg
            				 213 12345
            				 TYPE I
            				 200 Type set to I
            				 PASV
            				 227 Entering Passive Mode (192,168,1,101,170,57).
            				 RETR 1.jpg
            				 150 Opening BINARY mode data connection.
            				 226 Transfer complete
            				 QUIT
            				 221 Goodbye. */
            if( method == "USER")
            {
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("331"), STRING_from_string("Please specify the password."), 0, 0);
                info->user = params;
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "PASS")
            {
                if( params.empty() != false ||
                    m_setsfile.is_exist(info->user, "home") == false || //没有配置用户帐号
                    info->user != "anonymous" && m_setsfile.get_string(info->user, "password") != params )   //密码错误
                {
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("530"), STRING_from_string("User can't login."), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                info->spCtrlTcpSocket->SendPacket(STRING_from_string("203"), STRING_from_string("Login successful."), 0, 0);

                //初始化用户的主目录
                info->root = m_setsfile.get_string(info->user, "home");
                info->path = "/"; //根目录
                info->mode = "A"; //传输类型

                //控制数据连接速度: B/s
                m_spInstanceManager->NewInstance(0, 0, IID_ISpeedController, (IUnknown **)&info->spDataSpeedController[Io_recv]);
                m_spInstanceManager->NewInstance(0, 0, IID_ISpeedController, (IUnknown **)&info->spDataSpeedController[Io_send]);
                info->spDataSpeedController[Io_recv]->SetMaxSpeed(m_setsfile.get_long(info->user, "max_recvspeed", -1));
                info->spDataSpeedController[Io_send]->SetMaxSpeed(m_setsfile.get_long(info->user, "max_sendspeed", -1));
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "OPTS")
            {
                std::string::size_type ipos = params.find("UTF8 ");
                if( ipos != std::string::npos )
                {
                    info->utf8 = params.substr(ipos + 5) == "ON";
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("200"), STRING_from_string(std::string("OPTS UTF8 command successful - UTF8 encoding now ") + (info->utf8? "ON" : "OFF")), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }
            }

            if( method == "FEAT")
            {
                info->spCtrlTcpSocket->SendPacket(STRING_EX::null, STRING_from_string("211-Extended features supported:\nSIZE\nREST STREAM\nUTF8\r\n211 END"), 0, 0);
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( info->root.empty() != false )  //检查帐号是否已经登陆
            {
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("530"), STRING_from_string("Please login first"), 0, 0);
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "CDUP")
            {
                std::string::size_type ipos = info->path.rfind('/');
                if( ipos ) info->path = info->path.substr(0, ipos);
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("250"), STRING_from_string("CDUP command successful."), 0, 0);
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "CWD" )
            {
                asynsdk::CStringSetterRef v(1, &params);
                spReqmsg->Get(STRING_from_string(";value_ansi"), 0, 0, &v); //获取params的CP_ACP编码格式

                if( params.empty( ) == false &&
                    params != "/" )
                {

                    if( params == "..")   //后退
                    {
                        std::string::size_type ipos = info->path.rfind('/');
                        params = ipos == 0 ? info->path : info->path.substr(0, ipos);
                    }
                    else if( params[0] != '/')  //前进
                    {
                        params.insert(0, info->path == "/" ? ("/") : (info->path + "/"));
                    }

                    WIN32_FIND_DATA data;
                    HANDLE handle = FindFirstFile((info->root + params).c_str(), &data );
                    if( handle != INVALID_HANDLE_VALUE) CloseHandle(handle);

                    if((handle == INVALID_HANDLE_VALUE) ||
                       (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                    {
                        info->spCtrlTcpSocket->SendPacket(STRING_from_string("550"), STRING_from_string("The system cannot find the path specified."), 0, 0);
                        return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                    }
                }

                info->spCtrlTcpSocket->SendPacket(STRING_from_string("250"), STRING_from_string("CWD command successful."), 0, 0);
                info->path = params;
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "PWD" )
            {
                std::string path;
                if( info->utf8 )
                    asynsdk::Convert(CP_ACP, info->path.c_str(), info->path.size(), CP_UTF8, path);    
                else
                    path = info->path;
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("257"), STRING_from_string("\"" + path + "\" is current directory."), 0, 0);
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "SIZE")
            {
                asynsdk::CStringSetterRef v(1, &params);
                spReqmsg->Get(STRING_from_string(";value_ansi"), 0, 0, &v); //获取params的CP_ACP编码格式

                std::string filename = info->root;
                if( params.empty() != false || params[0] != '/' ) filename += (info->path == "/" ? ("/") : (info->path + "/"));
                filename += params;

                HANDLE hFile = ::CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
                if( hFile == INVALID_HANDLE_VALUE )
                {
                    printf("open %s, error: %d\n", filename.c_str(), ::GetLastError( ));
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("550"), STRING_from_string("Not Found"), 0, 0);
                }
                else
                {
                    LARGE_INTEGER filesize;
                    filesize.LowPart = ::GetFileSize(hFile, (LPDWORD)&filesize.HighPart);
                    ::CloseHandle( hFile );
                    char out[32];
                    _i64toa_s(filesize.QuadPart, out, sizeof(out), 10);
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("213"), STRING_from_string(out), 0, 0);
                }
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "TYPE")
            {
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("200"), STRING_from_string("Type set to " + params), 0, 0);
                info->mode = params;
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "PROT" &&
                m_setsfile.get_long("ssl", "prot", 1)) //for curl client
            {
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("200"), STRING_from_string("OK"), 0, 0);
                info->prot = params;
                return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
            }

            if( method == "EPSV")
            {
                if( m_af == AF_INET )   //ipv6
                {
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("522"), STRING_from_string("use PASV"), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;
                m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spAsynTcpSocketListener);

                if( info->prot == "P" )
                {
                     CObjPtr<IAsynRawSocket> spAsynSslSocket;
                     m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spAsynTcpSocketListener, 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynSslSocket.p);
                     spAsynSslSocket->QueryInterface(IID_IAsynTcpSocketListener, (void**)&info->spDataTcpSocketListener);
                }
                else
                {
                    info->spDataTcpSocketListener = spAsynTcpSocketListener;
                }

                info->spDataTcpSocketListener->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);
                info->spDataTcpSocketListener->Bind(STRING_EX::null, 0, 0, 0); //同步bind
                std::string host; asynsdk::CStringSetterRef temp(1, &host);
                PORT 		port;
                info->spCtrlTcpSocket->GetSockAddress(&temp, 0, 0, 0);
                info->spDataTcpSocketListener->GetSockAddress(0, 0, &port, 0);
                //格式化EPSV响应命令参数
                char tmpx[128]; sprintf_s(tmpx, 128, "Entering Extended Passive Mode (|||%d|)", port);
                //发送响应
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("229"), STRING_from_string(tmpx), 0, 0);

                printf("wait to accept data connection to %s:%d\n", host.c_str(), port);
                //注意：不能提交读请求，此时需要等待客户端连接进来
                m_spAsynFrameThread->BindAsynIoOperation(lpAsynIoOperation, 0, 0, 5000/*5sec超时*/); //设定io超时
                lpAsynIoOperation->SetOpParam1(2/*数据连接接入*/);
                return info->spDataTcpSocketListener->Accept(lpAsynIoOperation);
            }

            if( method == "PASV")
            {
                if( m_af != AF_INET )   //ipv4
                {
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("522"), STRING_from_string("use EPSV"), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                CComPtr<IAsynTcpSocketListener> spAsynTcpSocketListener;
                m_spAsynNetwork->CreateAsynTcpSocketListener(0, &spAsynTcpSocketListener);

                if( info->prot == "P" )
                {
                     CObjPtr<IAsynRawSocket> spAsynSslSocket;
                     m_spAsynNetwork->CreateAsynPtlSocket(STRING_from_string("ssl"), spAsynTcpSocketListener, 0, STRING_from_string(m_setsfile.get_string("ssl", "algo", "tls/1.0")), &spAsynSslSocket.p);
                     spAsynSslSocket->QueryInterface(IID_IAsynTcpSocketListener, (void**)&info->spDataTcpSocketListener);
                }
                else
                {
                    info->spDataTcpSocketListener = spAsynTcpSocketListener;
                }

                info->spDataTcpSocketListener->Open(m_spAsynFrameThread, m_af, SOCK_STREAM, IPPROTO_TCP);
                info->spDataTcpSocketListener->Bind(STRING_EX::null, 0, 0, 0); //同步bind
                std::string host; asynsdk::CStringSetterRef temp(1, &host);
                PORT 		port;
                info->spCtrlTcpSocket->GetSockAddress(&temp, 0, 0, 0);
                info->spDataTcpSocketListener->GetSockAddress(0, 0, &port, 0);
                //格式化PASV响应命令参数
                std::string data = "Entering Passive Mode (" + host;
                std::string::size_type ipos = data.find('.', 22);
                while(ipos != std::string::npos)
                {
                    data[ipos] = ',';
                    ipos = data.find('.', ipos);
                }
                char tmpx[32]; sprintf_s(tmpx, 32, ",%d,%d", port / 256, port % 256);
                data += tmpx;
                data += ")";
                //发送响应
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("227"), STRING_from_string(data), 0, 0);

                printf("wait to accept data connection to %s:%d\n", host.c_str(), port);
                //注意：不能提交读请求，此时需要等待客户端连接进来
                m_spAsynFrameThread->BindAsynIoOperation(lpAsynIoOperation, 0, 0, 5000/*5sec超时*/); //设定io超时
                lpAsynIoOperation->SetOpParam1(2/*数据连接接入*/);
                return info->spDataTcpSocketListener->Accept(lpAsynIoOperation);
            }

            if( method == "LIST")
            {
                if( info->spDataTcpSocket == NULL )
                {
                    printf("no data connection to transfer\n");
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("500"), STRING_from_string("no data connection to transfer"), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                std::string ret; MakeListResult(info->root + info->path, ret);
                if( ret.empty() != false )
                {
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("550"), STRING_from_string("The system cannot find the file specified."), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                if( info->utf8 ) asynsdk::Convert(CP_ACP, ret.c_str(), ret.size(), CP_UTF8, ret);

                info->spCtrlTcpSocket->SendPacket(STRING_from_string("150"), STRING_from_string("Opening " + (info->mode == "A" ? std::string("ASCII") : std::string("BINARY")) + " mode data connection."), 0, 0);
                lpAsynIoOperation->NewIoBuffer(0, (BYTE *)ret.c_str(), 0, ret.size(), ret.size(), 0);
                lpAsynIoOperation->SetIoParams(0, ret.size(), ret.size());
                info->starttime = ::GetTickCount();
                return info->spDataTcpSocket->Write(lpAsynIoOperation);
            }

            if( method == "REST")
            {
                if( info->tranfile == NULL &&
                    info->spDataTcpSocket != NULL )   //在PASV/RETR之间
                {
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("350"), STRING_from_string("Restarting at " + params + "."), 0, 0);
                    info->startipos = _atoi64(params.c_str());
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }
            }

            if( method == "RETR")
            {
                if( info->spDataTcpSocket == NULL )
                {
                    printf("no data connection to transfer\n");
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("500"), STRING_from_string("no data connection to transfer"), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                asynsdk::CStringSetterRef v(1, &params);
                spReqmsg->Get(STRING_from_string(";value_ansi"), 0, 0, &v); //获取params的CP_ACP编码格式

                std::string filename = info->root;
                if( params.empty() != false || params[0] != '/') filename += (info->path == "/" ? ("/") : (info->path + "/"));
                filename += params;

				CComPtr<IAsynFile> spAsynFile;
                m_spAsynFileSystem->CreateAsynFile(&spAsynFile );
                HRESULT r1 = spAsynFile->Open( m_spAsynFrameThread,
                                       STRING_from_string(filename),
                                       GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
                if( r1 != S_OK )
                {
                    printf("open %s, error: %d\n", filename.c_str(), ::GetLastError( ));
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("550"), STRING_from_string("Not Found"), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                uint64_t filesize; spAsynFile->GetFileSize(&filesize );
                if( filesize &&
                    filesize <= info->startipos )
                {
                    printf("offset: %I64d/%I64d is invalid\n", info->startipos, filesize);
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("403"), STRING_from_string("Forbidden"), 0, 0);
                    return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
                }

                lpAsynIoOperation->SetOpParams(AF_IOMSG_NOTIFY, 0, Io_send); //设置传输完成通知事件

                if(!filesize )   //文件大小等于0的情况: 模拟发送完成
                {
                    info->spCtrlTcpSocket->SendPacket(STRING_from_string("150"), STRING_from_string("Opening " + (info->mode == "A" ? std::string("ASCII") : std::string("BINARY")) + " mode data connection."), 0, 0);
                    info->starttime = ::GetTickCount();
                    return asynsdk::PostAsynIoOperation(lpAsynIoOperation, NO_ERROR);
                }

                printf("start to send file: %s from %I64d/%I64d\n", filename.c_str(), info->startipos, filesize);
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("150"), STRING_from_string("Opening " + (info->mode == "A" ? std::string("ASCII") : std::string("BINARY")) + " mode data connection."), 0, 0);

                CComPtr<IAsynIoBridge> spAsynIoBridge;
                m_spAsynFrameThread->CreateAsynIoBridge(spAsynFile, info->spDataTcpSocket, 0, &spAsynIoBridge);
                if( info->startipos )
                {
                    CComPtr<IAsynFileIoOperation> spAsynIoOperation; spAsynIoBridge->Get(BT_GetSourceIoOperation, 0, IID_IAsynFileIoOperation, (IUnknown**)&spAsynIoOperation);
					spAsynIoOperation->SetPosition(info->startipos); //设置开始读取数据时文件的偏移
                }
                info->tranfile.reset(new CTranfile(spAsynIoBridge, lpAsynIoOperation));
                info->starttime = ::GetTickCount();
                return info->tranfile->Start(0);
            }

            if( method == "QUIT")
            {
                info->spCtrlTcpSocket->SendPacket(STRING_from_string("221"), STRING_from_string("Goodbye."), 0, 0);
                printf("remove client: %s\n", info->skey.c_str());
                m_arOp2Userinfos.erase(lpAsynIoOperation);
                m_arId2Userinfos.erase(info->skey);
                break;
            }

            info->spCtrlTcpSocket->SendPacket(STRING_from_string("500"), STRING_from_string("Not Support"), 0, 0);
            if( info->tranfile == NULL ) info->spDataTcpSocket = NULL;
            return info->spCtrlTcpSocket->Read(lpAsynIoOperation);
        }
    }
    }
    return E_NOTIMPL; //通知系统释放lpAsynIoOperation
}

void CService::MakeListResult(const std::string &path, std::string &o_val)
{
    WIN32_FIND_DATA data;
    HANDLE handle = FindFirstFile((path + "/*.*").c_str(), &data);
    if( handle == INVALID_HANDLE_VALUE ) return;

    char temp[1024];

    do
    {
        if( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
        {
            if( strcmp(data.cFileName, "." ) == 0 || strcmp(data.cFileName, "..") == 0 ) continue;
        }

        SYSTEMTIME st; FileTimeToSystemTime(&data.ftLastWriteTime, &st);
        int offset = sprintf_s(temp, 1024, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        if( data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
        {
            sprintf_s(temp + offset, 1024 - offset, "\t%-20s\t%s\n", "<DIR>", data.cFileName);
        }
        else
        {
            sprintf_s(temp + offset, 1024 - offset, "\t%20I64d\t%s\n", (((uint64_t)data.nFileSizeHigh) << 32) + data.nFileSizeLow, data.cFileName);
        }

        o_val += temp;
    }
    while(FindNextFile(handle, &data) != 0);

    FindClose(handle);
}
