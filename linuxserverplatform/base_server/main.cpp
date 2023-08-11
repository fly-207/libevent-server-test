// login.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "TCPServerManager.h"

//服务器网络服务接口 
class ServerSocketHander : public IServerSocketHander
{
    ///接口函数
public:
    //网络关闭处理
    virtual bool OnSocketCloseEvent(int nServerType, int nSocket)
    {
        return true;
    }

    //网络消息处理
    virtual bool OnSocketReadEvent(int nServerType, int nSocket, NetMessageHead* pNetHead, void* pData, int nSize)
    {
        return true;
    }
};

int main()
{
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    CTCPServerManager a(4);

    ServerSocketHander b;

    a.init(&b, 10, 39999, "0.0.0.0", 0);
    a.Start();

    Sleep(5000000);

    return 0;
}
