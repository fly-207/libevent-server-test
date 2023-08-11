// login.cpp : ���ļ����� "main" ����������ִ�н��ڴ˴���ʼ��������
//

#include "TCPServerManager.h"

//�������������ӿ� 
class ServerSocketHander : public IServerSocketHander
{
    ///�ӿں���
public:
    //����رմ���
    virtual bool OnSocketCloseEvent(int nServerType, int nSocket)
    {
        return true;
    }

    //������Ϣ����
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
