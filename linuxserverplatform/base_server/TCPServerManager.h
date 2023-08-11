#ifndef _TCP_SERVER_HEADER_
#define _TCP_SERVER_HEADER_
#pragma once

#include "ServerHandler.h"
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <deque>
#include <thread>
#include <event2/util.h>
#include <mutex>
#include <string>

struct event_base;
struct event;
struct evconnlistener;
class CTCPServerManager;


//
struct ListenThreadInfo
{
    event_base* base;
    evconnlistener* listener;
};

// 工作线程信息
struct WorkThreadInfo
{
    std::thread thread;
    struct event_base* base;
    struct event* user_event;
    CTCPServerManager* pThis;

    std::mutex mtx;
    std::vector<int> vecFd;
};

// TCP信息
struct bufferevent;
struct SocketInfo
{
    int last_msg_time;
    bufferevent* bev;
};

class CTCPServerManager
{
public:
    //
    CTCPServerManager(int nWorkSize);
    //
    ~CTCPServerManager();

public:
    // 初始化
    bool init(IServerSocketHander* pService, int maxCount, int port, const char* ip, int socketType);
    // 开始服务
    bool Start();
    // 停止服务
    bool Stop();

protected:
    // SOCKET 连接应答线程
    static void ThreadAccept(CTCPServerManager* pThreadData);
    // SOCKET 数据接收线程
    static void ThreadRSSocket(WorkThreadInfo* pThreadData);
    // 外部需要发送的消息, 由此线程写入 buff
    static void ThreadSendMsg(CTCPServerManager* pThreadData);

protected:
    // 新的连接到来，ThreadAccept线程函数
    static void ListenerCB(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* sa, int socklen, void* user_data);
    // 新的数据到来，ThreadRSSocket线程函数
    static void ReadCB(struct bufferevent*, void*);
    // 连接关闭等等错误消息，ThreadRSSocket线程函数
    static void EventCB(struct bufferevent*, short, void*);
    // accept失败，ThreadAccept线程函数
    static void AcceptErrorCB(struct evconnlistener* listener, void*);
    // 新的连接到来，ThreadRSSocket线程函数
    static void ThreadLibeventProcess(evutil_socket_t readfd, short which, void* arg);

private:
    // 获取当前socket连接总数
    int GetCurSocketSize() const;
    // 添加TCPSocketInfo
    void AddTCPSocketInfo(int fd, WorkThreadInfo* workInfo);
    // 最底层处理收到的数据函数
    virtual bool RecvData(bufferevent* bev);

private:
    // 返回 socket 本地的 xx.xx.xx.xx:xxxx 形式的字符串串
    static std::string GetSocketNameIpAndPort(int fd);
    // 返回 socket 对端的 xx.xx.xx.xx:xxxx 形式的字符串串
    static std::string GetSocketPeerIpAndPort(int fd);

private:
    // 处理 socket 事件
    IServerSocketHander* m_pService;

    // 最大成功建立连接数
    int m_uMaxSocketSize;

    // 当前已经建立 accept 数量
    std::mutex m_mtxSocketSize;
    int m_uCurSocketSize;

    // bind ip
    char m_bindIP[48];

    // bind port
    int m_port;

    // 建立 listen 的服务类型, 一个进程可能有多个 listen 服务
    char m_nSocketType;

    // 工作线程信息
    std::vector<WorkThreadInfo> m_workBaseVec;

    // 外部只用 fd 和 CTCPServerManager 交互, 这里需要一个 fd 能找到对应连接信息的结构
    std::unordered_map<int, SocketInfo> m_mapFd2SocketInfo;

    // m_mapFd2SocketInfo 在监听线程会更改, 在 sendMsg 中可能会关闭连接时更改
    std::mutex m_mtxFd2SocketInfo;

    // 监听相关记录, base 之类的信息可以通过接口获取
    ListenThreadInfo m_listenThreadInfo;

    // accept 线程信息
    std::thread m_threadAccept;

    // 
    std::thread m_threadSendMsg;
};


#endif
