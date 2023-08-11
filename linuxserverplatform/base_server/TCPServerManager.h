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

// �����߳���Ϣ
struct WorkThreadInfo
{
    std::thread thread;
    struct event_base* base;
    struct event* user_event;
    CTCPServerManager* pThis;

    std::mutex mtx;
    std::vector<int> vecFd;
};

// TCP��Ϣ
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
    // ��ʼ��
    bool init(IServerSocketHander* pService, int maxCount, int port, const char* ip, int socketType);
    // ��ʼ����
    bool Start();
    // ֹͣ����
    bool Stop();

protected:
    // SOCKET ����Ӧ���߳�
    static void ThreadAccept(CTCPServerManager* pThreadData);
    // SOCKET ���ݽ����߳�
    static void ThreadRSSocket(WorkThreadInfo* pThreadData);
    // �ⲿ��Ҫ���͵���Ϣ, �ɴ��߳�д�� buff
    static void ThreadSendMsg(CTCPServerManager* pThreadData);

protected:
    // �µ����ӵ�����ThreadAccept�̺߳���
    static void ListenerCB(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* sa, int socklen, void* user_data);
    // �µ����ݵ�����ThreadRSSocket�̺߳���
    static void ReadCB(struct bufferevent*, void*);
    // ���ӹرյȵȴ�����Ϣ��ThreadRSSocket�̺߳���
    static void EventCB(struct bufferevent*, short, void*);
    // acceptʧ�ܣ�ThreadAccept�̺߳���
    static void AcceptErrorCB(struct evconnlistener* listener, void*);
    // �µ����ӵ�����ThreadRSSocket�̺߳���
    static void ThreadLibeventProcess(evutil_socket_t readfd, short which, void* arg);

private:
    // ��ȡ��ǰsocket��������
    int GetCurSocketSize() const;
    // ���TCPSocketInfo
    void AddTCPSocketInfo(int fd, WorkThreadInfo* workInfo);
    // ��ײ㴦���յ������ݺ���
    virtual bool RecvData(bufferevent* bev);

private:
    // ���� socket ���ص� xx.xx.xx.xx:xxxx ��ʽ���ַ�����
    static std::string GetSocketNameIpAndPort(int fd);
    // ���� socket �Զ˵� xx.xx.xx.xx:xxxx ��ʽ���ַ�����
    static std::string GetSocketPeerIpAndPort(int fd);

private:
    // ���� socket �¼�
    IServerSocketHander* m_pService;

    // ���ɹ�����������
    int m_uMaxSocketSize;

    // ��ǰ�Ѿ����� accept ����
    std::mutex m_mtxSocketSize;
    int m_uCurSocketSize;

    // bind ip
    char m_bindIP[48];

    // bind port
    int m_port;

    // ���� listen �ķ�������, һ�����̿����ж�� listen ����
    char m_nSocketType;

    // �����߳���Ϣ
    std::vector<WorkThreadInfo> m_workBaseVec;

    // �ⲿֻ�� fd �� CTCPServerManager ����, ������Ҫһ�� fd ���ҵ���Ӧ������Ϣ�Ľṹ
    std::unordered_map<int, SocketInfo> m_mapFd2SocketInfo;

    // m_mapFd2SocketInfo �ڼ����̻߳����, �� sendMsg �п��ܻ�ر�����ʱ����
    std::mutex m_mtxFd2SocketInfo;

    // ������ؼ�¼, base ֮�����Ϣ����ͨ���ӿڻ�ȡ
    ListenThreadInfo m_listenThreadInfo;

    // accept �߳���Ϣ
    std::thread m_threadAccept;

    // 
    std::thread m_threadSendMsg;
};


#endif
