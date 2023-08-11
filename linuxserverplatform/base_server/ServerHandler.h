#ifndef _SERVER_HANDLER_HEADER
#define _SERVER_HANDLER_HEADER
#pragma once

#include "NetMessage.h"

//�������������ӿ� 
class IServerSocketHander
{
    ///�ӿں���
public:
    //����رմ���
    virtual bool OnSocketCloseEvent(int nServerType, int nSocket) = 0;
    //������Ϣ����
    virtual bool OnSocketReadEvent(int nServerType, int nSocket, NetMessageHead* pNetHead, void* pData, int nSize) = 0;
};




#endif