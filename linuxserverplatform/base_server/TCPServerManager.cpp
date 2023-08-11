#include "TCPServerManager.h"
#include "log.h"
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <map>

CTCPServerManager::CTCPServerManager(int nWorkSize):
    m_workBaseVec(nWorkSize)
{
    m_uCurSocketSize = 0;
}

CTCPServerManager::~CTCPServerManager()
{
    m_threadAccept.join();
    m_threadSendMsg.join();
}

bool CTCPServerManager::init(IServerSocketHander* pService, int maxCount, int port, const char* ip, int socketType)
{
    INFO_LOG("service CTCPServerManager init begin...");

    if (!pService || maxCount <= 0 || port <= 1000)
    {
        ERROR_LOG("invalid params input pService=%p maxCount=%d port=%d", pService, maxCount, port);
        return false;
    }

    m_pService = pService;
    m_uMaxSocketSize = maxCount;
    if (ip && strlen(ip) < sizeof(m_bindIP))
    {
        strcpy(m_bindIP, ip);
    }
    m_port = port;
    m_nSocketType = socketType;

    return true;
}

bool CTCPServerManager::Start()
{
    INFO_LOG("service TCPSocketManage start begin...");

    // 接收客户端连接消息, 并向外部服务转发消息
    m_threadAccept = std::thread(ThreadAccept, this);


    // 外部服务写入客户端的消息在此线程写入到 buffer
    m_threadSendMsg = std::thread(ThreadSendMsg, this);

    return true;
}

bool CTCPServerManager::Stop()
{
    INFO_LOG("service TCPSocketManage stop begin...");

    event_base_loopbreak(evconnlistener_get_base(m_listenThreadInfo.listener));
    for (size_t i = 0; i < m_workBaseVec.size(); i++)
    {
        event_base_loopbreak(m_workBaseVec[i].base);
    }

    INFO_LOG("service TCPSocketManage stop end...");

    return true;
}

void CTCPServerManager::ThreadAccept(CTCPServerManager* pThis)
{
    INFO_LOG("ThreadAccept thread begin...");

    pThis->m_listenThreadInfo.base = event_base_new();
    if (!pThis->m_listenThreadInfo.base)
    {
        CON_ERROR_LOG("TCP Could not initialize libevent!");
        exit(1);
    }

    // 开始监听
    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(pThis->m_port);
    sin.sin_addr.s_addr = strlen(pThis->m_bindIP) == 0 ? INADDR_ANY : inet_addr(pThis->m_bindIP);

    pThis->m_listenThreadInfo.listener = evconnlistener_new_bind(pThis->m_listenThreadInfo.base,
        ListenerCB,
        (void*)pThis,
        LEV_OPT_REUSEABLE | LEV_OPT_REUSEABLE_PORT | LEV_OPT_CLOSE_ON_FREE,
        -1,
        (struct sockaddr*)&sin,
        sizeof(sin)
    );

    if (!pThis->m_listenThreadInfo.listener) {
        printf("Could not create a listener! 尝试换个端口或者稍等一会。");
        exit(1);
    }

    evconnlistener_set_error_cb(pThis->m_listenThreadInfo.listener, AcceptErrorCB);

    // 初始工作线程信息
    for (auto &_item: pThis->m_workBaseVec)
    {
        _item.base = event_base_new();
        if (!_item.base)
        {
            CON_ERROR_LOG("TCP Could not initialize libevent!");
            exit(1);
        }

        _item.user_event = evuser_new(_item.base, ThreadLibeventProcess, &_item);
        if (!_item.user_event)
        {
            CON_ERROR_LOG("TCP Could not create event!");
            exit(1);
        }

        _item.thread = std::thread(ThreadRSSocket, &_item);
    }

    event_base_dispatch(pThis->m_listenThreadInfo.base);

    evconnlistener_free(pThis->m_listenThreadInfo.listener);
    event_base_free(pThis->m_listenThreadInfo.base);
    for (auto& _item : pThis->m_workBaseVec)
    {
        event_base_free(_item.base);
        evuser_del(_item.user_event);
    }

    INFO_LOG("ThreadAccept thread exit.");
}

void CTCPServerManager::ThreadRSSocket(WorkThreadInfo* pThreadData)
{
    // 处于监听状态
    event_base_dispatch(pThreadData->base);

    //
    event_base_free(pThreadData->base);
}

void CTCPServerManager::ThreadSendMsg(CTCPServerManager* pThreadData)
{

}

void CTCPServerManager::ListenerCB(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* sa, int socklen, void* user_data)
{
    CTCPServerManager* pThis = (CTCPServerManager*)user_data;

    {
        struct sockaddr_in listendAddr = {}, connectedAddr = {}, peerAddr = {};
        int listendAddrLen = sizeof(listendAddr), connectedAddrLen = sizeof(connectedAddr), peerLen = sizeof(peerAddr);

        int ret = getsockname(fd, (struct sockaddr*)&connectedAddr, &connectedAddrLen);
        if (ret != 0)
        {
            perror("获取本地地址错误");
        }
        else
        {
            printf("connected address = %s:%d\n", inet_ntoa(connectedAddr.sin_addr), ntohs(connectedAddr.sin_port));
        }

        ret = getpeername(fd, (struct sockaddr*)&peerAddr, &peerLen);
        if (ret != 0)
        {
            perror("获取对端址错误");
        }
        else
        {
            printf("peerAddr address = %s:%d\n", inet_ntoa(peerAddr.sin_addr), ntohs(peerAddr.sin_port));
        }
    }

    // 最大连接数判断
    if (pThis->GetCurSocketSize() >= pThis->m_uMaxSocketSize)
    {
        ERROR_LOG("服务器已经满：fd=%Id [%s][人数：%u/%u]", fd, CTCPServerManager::GetSocketNameIpAndPort(fd).c_str(), pThis->GetCurSocketSize(), pThis->m_uMaxSocketSize);

        // 分配失败
        NetMessageHead netHead = {};
        netHead.uMessageSize = sizeof(NetMessageHead);
        netHead.uMainID = 100;
        netHead.uAssistantID = 3;
        netHead.uHandleCode = 15;//服务器人数已满

        send(fd, (char*)&netHead, sizeof(NetMessageHead), 0);

        evutil_closesocket(fd);

        return;
    }

    //
    static int lastThreadIndex = 0;
    lastThreadIndex = lastThreadIndex % pThis->m_workBaseVec.size();

    // 投递到接收线程
    do
    {
        std::lock_guard<std::mutex> lck(pThis->m_workBaseVec[lastThreadIndex].mtx);
        pThis->m_workBaseVec[lastThreadIndex].vecFd.push_back(fd);
    } while (false);

    evuser_trigger(pThis->m_workBaseVec[lastThreadIndex].user_event);

    lastThreadIndex++;
}

void CTCPServerManager::ReadCB(struct bufferevent*bev, void* data)
{
    WorkThreadInfo* pWorkInfo = (WorkThreadInfo*)data;
    CTCPServerManager* pThis = pWorkInfo->pThis;

    // 处理数据，包头解析
    pThis->RecvData(bev);
}

void CTCPServerManager::EventCB(struct bufferevent*, short, void*)
{

}

void CTCPServerManager::AcceptErrorCB(struct evconnlistener* listener, void*)
{

}

void CTCPServerManager::ThreadLibeventProcess(evutil_socket_t readfd, short which, void* arg)
{
    /*
        该函数会被多个线程执行
    */

    WorkThreadInfo* workInfo = (WorkThreadInfo*)arg;

    std::vector<int> vecFd;
    do 
    {
        std::lock_guard<std::mutex> lck(workInfo->mtx);
        vecFd = workInfo->vecFd;
        workInfo->vecFd.clear();

    } while (false);

    for (auto fd : vecFd)
    {
        // 处理连接
        workInfo->pThis->AddTCPSocketInfo(fd, workInfo);
    }
}

int CTCPServerManager::GetCurSocketSize() const
{
    return m_uCurSocketSize;
}

void CTCPServerManager::AddTCPSocketInfo(int fd, WorkThreadInfo*workInfo)
{
    /*
        该函数会被多个线程执行
    */
    struct event_base* base = workInfo->base;


    struct bufferevent * bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE| BEV_OPT_THREADSAFE);
    if (!bev)
    {
        ERROR_LOG("Error constructing bufferevent!,fd=%d,ip=%s", fd, CTCPServerManager::GetSocketNameIpAndPort(fd).c_str());
        evutil_closesocket(fd);
        return;
    }

    // 添加事件，并设置好回调函数
    bufferevent_setcb(bev, ReadCB, NULL, EventCB, (void*)workInfo);
    if (bufferevent_enable(bev, EV_READ | EV_ET) < 0)
    {
        ERROR_LOG("add event fail!!!,fd=%d,ip=%s", fd, CTCPServerManager::GetSocketNameIpAndPort(fd).c_str());
        evutil_closesocket(fd);
        bufferevent_free(bev);
        return;
    }

    // 设置读超时, 即使是内部连接也需要心跳来判断是否还存活(进程没有卡死)
    timeval tvRead;
    tvRead.tv_sec = 15 * 3;
    tvRead.tv_usec = 0;
    bufferevent_set_timeouts(bev, &tvRead, NULL);

    // 保存信息
    {
        SocketInfo sock_info;
        sock_info.bev = bev;

        std::lock_guard<std::mutex> lck(workInfo->pThis->m_mtxFd2SocketInfo);
        m_mapFd2SocketInfo[fd] = std::move(sock_info);
    }

    {
        std::lock_guard<std::mutex> lck(workInfo->pThis->m_mtxSocketSize);
        m_uCurSocketSize++;

    }
}

bool CTCPServerManager::RecvData(bufferevent* bev)
{
    if (bev == NULL)
    {
        ERROR_LOG("RecvData error bev == NULL");
        return false;
    }

    struct evbuffer* input = bufferevent_get_input(bev);

    // 当前读取位置, 方便后面一次性更新
    evbuffer_ptr buff_ptr = {};

    // 总的字节数
    size_t nAllSize = evbuffer_get_length(input);

    char buff[MAX_PACKAGE_SIZE] = {};

    while (true)
    {
        // 剩余字节小于包头
        if (nAllSize- buff_ptr.pos < sizeof(NetMessageHead))
            break;

        // 消息头
        NetMessageHead tmpHead = {};

        // 先读取消息头
        size_t head_size = evbuffer_copyout_from(input, &buff_ptr, &tmpHead, sizeof(NetMessageHead));
        if (head_size <= sizeof(NetMessageHead))
            break;


        // 包体超过最大长度限制
        if (tmpHead.uMessageSize > MAX_PACKAGE_SIZE)
        {
            CloseSocket(bev);
            return false;
        }

        // 包体未完全接收
        if(nAllSize-buff_ptr.pos-sizeof(NetMessageHead) < tmpHead.uMessageSize)
            break;

        evbuffer_ptr _tmp_ptr = {};
        _tmp_ptr.pos = sizeof(NetMessageHead) + buff_ptr.pos;


        // 读取包体
        size_t body_size = evbuffer_copyout_from(input, &_tmp_ptr, &buff, tmpHead.uMessageSize);
        if (body_size <= tmpHead.uMessageSize)
            break;


        // 粘包处理
        while (handleRemainSize >= sizeof(NetMessageHead) && handleRemainSize >= pNetHead->uMessageSize)
        {
            unsigned int messageSize = pNetHead->uMessageSize;
            if (messageSize > MAX_TEMP_SENDBUF_SIZE)
            {
                // 消息格式不正确
                CloseSocket(index);
                ERROR_LOG("close socket 超过单包数据最大值,index=%d,messageSize=%u", index, messageSize);
                return false;
            }

            int realSize = messageSize - sizeof(NetMessageHead);
            if (realSize < 0)
            {
                // 数据包不够包头
                CloseSocket(index);
                ERROR_LOG("close socket 数据包不够包头");
                return false;
            }

            void* pData = NULL;
            if (realSize > 0)
            {
                // 没数据就为NULL
                pData = (void*)(buf + realAllSize - handleRemainSize + sizeof(NetMessageHead));
            }

            // 派发数据
            DispatchPacket(bev, index, pNetHead, pData, realSize);

            handleRemainSize -= messageSize;

            pNetHead = (NetMessageHead*)(buf + realAllSize - handleRemainSize);
        }

        evbuffer_drain(input, realAllSize - handleRemainSize);

        return true;
    }
}

std::string CTCPServerManager::GetSocketNameIpAndPort(int fd)
{
    struct sockaddr_in addr = {};
    int addr_len = sizeof(addr);

    int ret = getsockname(fd, (struct sockaddr*)&addr, &addr_len);

    char out[1024] = {};
    int realLen = snprintf(out, sizeof(out), "connected address = %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return out;
}

std::string CTCPServerManager::GetSocketPeerIpAndPort(int fd)
{
    struct sockaddr_in addr = {};
    int addr_len = sizeof(addr);

    int ret = getpeername(fd, (struct sockaddr*)&addr, &addr_len);

    char out[1024] = {};
    int realLen = snprintf(out, sizeof(out), "connected address = %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    return out;
}


bool CTCPServerManager::CloseSocket(bufferevent *bev)
{
    int fd = bufferevent_getfd(bev);

    {
        std::lock_guard<std::mutex> lck(m_mtxSocketSize);
        m_uCurSocketSize--;

    }

    {
        std::lock_guard<std::mutex> lck(m_mtxFd2SocketInfo);
        m_mapFd2SocketInfo.erase(fd);
    }

    bufferevent_free(bev);


    // 回调业务层
    if (m_pService)
    {
        m_pService->OnSocketCloseEvent(m_nSocketType, fd);
    }

    return true;
}
