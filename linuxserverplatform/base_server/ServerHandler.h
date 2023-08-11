#ifndef _SERVER_HANDLER_HEADER
#define _SERVER_HANDLER_HEADER
#pragma once

#include "NetMessage.h"

//服务器网络服务接口 
class IServerSocketHander
{
    ///接口函数
public:
    //网络关闭处理, 该函数会被多线程调用, 应该在内部添加一个事件到队列即可, 由另外的线程来处理事件
    virtual bool OnSocketCloseEvent(int nServerType, int nSocket) = 0;
    //网络消息处理, 该函数会被多线程调用, 应该在内部添加一个事件到队列即可, 由另外的线程来处理事件
    virtual bool OnSocketReadEvent(int nServerType, int nSocket, NetMessageHead* pNetHead, void* pData, int nSize) = 0;
};




#endif