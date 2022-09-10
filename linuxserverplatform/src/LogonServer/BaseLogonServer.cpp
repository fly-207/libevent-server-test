#include "CommonHead.h"
#include "BaseLogonServer.h"


//处理线程启动结构
struct HandleThreadStartStruct
{
	//变量定义
	CFIFOEvent* pFIFO;						//启动事件
	CBaseLogonServer* pMainManage;			//数据管理指针
};

/*****************************************************************************************************************/
CBaseLogonServer::CBaseLogonServer()
{
	m_bInit = false;
	m_bRun = false;
	m_hHandleThread = 0;
	m_connectCServerHandle = 0;
	::memset(&m_DllInfo, 0, sizeof(m_DllInfo));
	::memset(&m_InitData, 0, sizeof(m_InitData));
	::memset(&m_KernelData, 0, sizeof(m_KernelData));

	m_pRedis = NULL;
	m_pRedisPHP = NULL;
	m_pTcpConnect = NULL;
	m_pServerTimer = NULL;
	m_pMysqlHelper = nullptr;
}

CBaseLogonServer::~CBaseLogonServer()
{
	SAFE_DELETE(m_pRedis);
	SAFE_DELETE(m_pRedisPHP);
	SAFE_DELETE(m_pTcpConnect);
	SafeDeleteArray(m_pServerTimer);
}

//初始化函数 
bool CBaseLogonServer::Init(ManageInfoStruct* pInitData, IDataBaseHandleService* pDataHandleService)
{
	INFO_LOG("CBaseLogonServer Init begin...");

	if (m_bInit == true)
	{
		ERROR_LOG("is already have been inited...");
		return false;
	}

	if (!pInitData || !pDataHandleService)
	{
		ERROR_LOG("invalid params input pInitData=%p pDataHandleService=%p", pInitData, pDataHandleService);
		return false;
	}

	if (m_bInit == true)
	{
		ERROR_LOG("is already been inited");
		return false;
	}

	//设置数据
	m_InitData = *pInitData;

	bool ret = false;

	// 加载参数
	ret = PreInitParameter(&m_InitData, &m_KernelData);
	if (!ret)
	{
		ERROR_LOG("PreInitParameter failed");
		return false;
	}

	// redis 相关
	m_pRedis = new CRedisLogon;
	if (!m_pRedis)
	{
		ERROR_LOG("create redis object failed");
		return false;
	}

	ret = m_pRedis->Init();
	if (!ret)
	{
		ERROR_LOG("连接redis失败");
		return false;
	}

	// redis 相关
	m_pRedisPHP = new CRedisPHP;
	if (!m_pRedisPHP)
	{
		ERROR_LOG("create m_pRedisPHP object failed");
		return false;
	}

	ret = m_pRedisPHP->Init();
	if (!ret)
	{
		ERROR_LOG("连接PHP redis失败");
		return false;
	}

	// 初始化TCP网络
	ret = m_TCPSocket.Init(this, m_InitData.uMaxPeople, m_InitData.uListenPort);
	if (!ret)
	{
		ERROR_LOG("TCPSocket Init failed");
		return false;
	}

	// 判断id是否配置
	int logonID = ConfigManage()->GetLogonServerConfig().logonID;
	LogonBaseInfo* pLogonBaseInfo = ConfigManage()->GetLogonBaseInfo(logonID);
	if (pLogonBaseInfo == nullptr)
	{
		ERROR_LOG("logonID 不存在，需要在数据库中配置该id");
		return false;
	}

	// 初始化websocket网络
	if (ConfigManage()->m_logonServerConfig.webSocket)
	{
		ret = m_WebSocket.Init(this, pLogonBaseInfo->maxWebSocketPeople, pLogonBaseInfo->webSocketPort, NULL, SOCKET_TYPE_WEBSOCKET);
		if (!ret)
		{
			ERROR_LOG("WebSocket Init failed");
			return false;
		}
	}
	
	// DB相关
	ret = pDataHandleService->SetParameter(this, &m_SQLDataManage, &m_InitData, &m_KernelData);
	if (!ret)
	{
		ERROR_LOG("DataHandleService SetParameter failed");
		return false;
	}

	ret = m_SQLDataManage.Init(&m_InitData, &m_KernelData, pDataHandleService, this);
	if (!ret)
	{
		ERROR_LOG("SQLDataManage Init failed");
		return false;
	}

	m_pMysqlHelper = new CMysqlHelper;
	if (!m_pMysqlHelper)
	{
		ERROR_LOG("create m_pMysqlHelper object failed");
		return false;
	}

	// 中心服务器连接
	m_pTcpConnect = new CTcpConnect;
	if (!m_pTcpConnect)
	{
		throw new CException("CBaseLogonServer::Init new CTcpConnect failed", 0x43A);
	}

	// 初始化定时器
	int iServerTimerNums = Min_(MAX_TIMER_THRED_NUMS, ConfigManage()->GetCommonConfig().TimerThreadNumber);
	iServerTimerNums = iServerTimerNums <= 0 ? 1 : iServerTimerNums;
	m_KernelData.uTimerCount = iServerTimerNums;
	m_pServerTimer = new CServerTimer[iServerTimerNums];
	if (!m_pServerTimer)
	{
		ERROR_LOG("CServerTimer Init failed");
		return false;
	}

	ret = OnInit(&m_InitData, &m_KernelData);
	if (!ret)
	{
		ERROR_LOG("OnInit failed");
		return false;
	}

	m_bInit = true;

	INFO_LOG("CBaseLogonServer Init end");

	return true;
}

//取消初始化函数 
bool CBaseLogonServer::UnInit()
{
	//停止服务
	if (m_bRun)
	{
		Stop();
	}

	m_bInit = false;
	m_TCPSocket.UnInit();
	if (ConfigManage()->m_logonServerConfig.webSocket)
	{
		m_WebSocket.UnInit();
	}
	m_SQLDataManage.UnInit();

	//设置数据
	memset(&m_DllInfo, 0, sizeof(m_DllInfo));
	memset(&m_InitData, 0, sizeof(m_InitData));
	memset(&m_KernelData, 0, sizeof(m_KernelData));

	//释放redis
	m_pRedis->Stop();
	SAFE_DELETE(m_pRedis);
	m_pRedisPHP->Stop();
	SAFE_DELETE(m_pRedisPHP);

	//删除定时器
	SafeDeleteArray(m_pServerTimer);

	//调用接口
	OnUnInit();

	SAFE_DELETE(m_pTcpConnect);
	SafeDelete(m_pMysqlHelper);

	return true;
}

//启动函数
bool CBaseLogonServer::Start()
{
	INFO_LOG("CBaseLogonServer Start begin...");

	if (m_bInit == false || m_bRun == true)
	{
		ERROR_LOG("CBaseLogonServer already been inited or running");
		return false;
	}

	m_bRun = true;
	bool ret = false;

	// 创建管道
	CFIFOEvent fifo("./CBaseLogonServer-Start-fifo");

	// 启动DB模块
	ret = m_SQLDataManage.Start();
	if (!ret)
	{
		ERROR_LOG("SQLDataManage start failed");
		return false;
	}

	// 同步读写数据库模块
	m_pMysqlHelper->init(ConfigManage()->GetDBConfig(DB_TYPE_COMMON).ip, ConfigManage()->GetDBConfig(DB_TYPE_COMMON).user,
		ConfigManage()->GetDBConfig(DB_TYPE_COMMON).passwd, ConfigManage()->GetDBConfig(DB_TYPE_COMMON).dbName, "", ConfigManage()->GetDBConfig(DB_TYPE_COMMON).port);
	try
	{
		m_pMysqlHelper->connect();
	}
	catch (MysqlHelper_Exception & excep)
	{
		ERROR_LOG("连接主数据库失败:%s", excep.errorInfo.c_str());
		return false;
	}

	// 启动TCP网络模块
	ret = m_TCPSocket.Start(SERVICE_TYPE_LOGON);
	if (!ret)
	{
		ERROR_LOG("TCPSocket Start failed");
		return false;
	}

	// 启动websocket网络模块
	if (ConfigManage()->m_logonServerConfig.webSocket)
	{
		ret = m_WebSocket.Start(SERVICE_TYPE_LOGON);
		if (!ret)
		{
			ERROR_LOG("TCPSocket Start failed");
			return false;
		}
	}

	// 启动与中心服务器连接模块
	const CenterServerConfig& centerServerConfig = ConfigManage()->GetCenterServerConfig();
	ret = m_pTcpConnect->Start(&m_DataLine, centerServerConfig.ip, centerServerConfig.port, SERVICE_TYPE_LOGON, ConfigManage()->GetLogonServerConfig().logonID);		// TODO	
	if (!ret)
	{
		throw new CException("CBaseLogonServer::m_pTcpConnect.Start 连接模块启动失败", 0x433);
	}
	int err = pthread_create(&m_connectCServerHandle, NULL, TcpConnectThread, (void*)this);
	if (err != 0)
	{
		SYS_ERROR_LOG("TcpConnectThread failed");
		throw new CException("CBaseLogonServer::m_pTcpConnect.Start 连接线程函数启动失败", 0x434);
	}

	// 关联日志文件
	GameLogManage()->AddLogFile(m_connectCServerHandle, THREAD_TYPE_RECV, m_InitData.uRoomID);

	// 启动定时器
	for (int i = 0; i < m_KernelData.uTimerCount; i++)
	{
		// 一秒执行一次
		if (!m_pServerTimer[i].Start(&m_DataLine, 1000))
		{
			ERROR_LOG("CBaseLogonServer::m_pServerTimer.Start 定时器启动失败");
			return false;
		}
	}

	//调用接口
	ret = OnStart();
	if (!ret)
	{
		ERROR_LOG("OnStart failed");
		return false;
	}

	//启动处理线程
	HandleThreadStartStruct	ThreadStartData;
	ThreadStartData.pMainManage = this;
	ThreadStartData.pFIFO = &fifo;
	err = pthread_create(&m_hHandleThread, NULL, LineDataHandleThread, (void*)&ThreadStartData);
	if (err != 0)
	{
		SYS_ERROR_LOG("pthread_create LineDataHandleThread failed");
		return false;
	}

	// 关联大厅业务逻辑线程与对应日志文件
	GameLogManage()->AddLogFile(m_hHandleThread, THREAD_TYPE_LOGIC);

	// 等待子线程读取线程参数
	fifo.WaitForEvent();

	INFO_LOG("CBaseLogonServer Start end.");

	return true;
}

//停止服务
bool CBaseLogonServer::Stop()
{
	INFO_LOG("CBaseLogonServer Stop begin...");

	if (m_bRun == false)
	{
		ERROR_LOG("is not running...");
		return false;
	}

	m_bRun = false;

	// 先关闭网络模块
	m_TCPSocket.Stop();
	if (ConfigManage()->m_logonServerConfig.webSocket)
	{
		m_WebSocket.Stop();
	}

	//关闭与中心服务器的连接
	m_pTcpConnect->Stop();

	//退出处理线程
	if (m_hHandleThread)
	{
		pthread_cancel(m_hHandleThread);
		m_hHandleThread = 0;
	}

	// 关闭中心服连接线程
	if (m_connectCServerHandle)
	{
		pthread_cancel(m_connectCServerHandle);
		m_connectCServerHandle = 0;
	}

	// 上层接口
	OnStop();		// 主线程关闭并清理资源(这里需要依赖redis和db)

	// 关闭DB模块
	m_SQLDataManage.Stop();

	//关闭定时器
	for (int i = 0; i < m_KernelData.uTimerCount; i++)
	{
		m_pServerTimer[i].Stop();
	}

	//清理队列数据
	m_DataLine.CleanLineData();

	INFO_LOG("CBaseLogonServer Stop end.");

	return true;
}

//网络关闭处理
bool CBaseLogonServer::OnSocketCloseEvent(ULONG uAccessIP, UINT uIndex, UINT uConnectTime, BYTE socketType)
{
	SocketCloseLine SocketClose;
	SocketClose.uConnectTime = uConnectTime;
	SocketClose.uIndex = uIndex;
	SocketClose.uAccessIP = uAccessIP;
	SocketClose.socketType = socketType;
	return (m_DataLine.AddData(&SocketClose.LineHead, sizeof(SocketClose), HD_SOCKET_CLOSE) != 0);
}

//网络消息处理
bool CBaseLogonServer::OnSocketReadEvent(BYTE socketType, NetMessageHead* pNetHead, void* pData, UINT uSize, UINT uIndex)
{
	if (!pNetHead)
	{
		return false;
	}

	SocketReadLine SocketRead;

	SocketRead.uHandleSize = uSize;
	SocketRead.uIndex = uIndex;
	SocketRead.socketType = socketType;
	SocketRead.uAccessIP = 0;		//TODO
	SocketRead.netMessageHead = *pNetHead;
	return m_DataLine.AddData(&SocketRead.LineHead, sizeof(SocketRead), HD_SOCKET_READ, pData, uSize) != 0;
}

//异步线程结果处理
bool CBaseLogonServer::OnAsynThreadResultEvent(UINT uHandleKind, UINT uHandleResult, const void* pData, UINT uResultSize, UINT uIndex, UINT uMsgID)
{
	AsynThreadResultLine resultData;

	//包装数据
	resultData.uHandleResult = uHandleResult;
	resultData.uHandleKind = uHandleKind;
	resultData.uIndex = uIndex;
	resultData.uMsgID = uMsgID;

	//加入队列
	return (m_DataLine.AddData(&resultData.LineHead, sizeof(resultData), HD_ASYN_THREAD_RESULT, pData, uResultSize) != 0);
}

//设定定时器
bool CBaseLogonServer::SetTimer(UINT uTimerID, UINT uElapse, BYTE timerType/* = SERVERTIMER_TYPE_PERISIST*/)
{
	if (!m_pServerTimer)
	{
		ERROR_LOG("no timer run");
		return false;
	}

	int iTimerCount = m_KernelData.uTimerCount;
	if (iTimerCount <= 0 || iTimerCount > MAX_TIMER_THRED_NUMS)
	{
		ERROR_LOG("timer error");
		return false;
	}

	m_pServerTimer[uTimerID % iTimerCount].SetTimer(uTimerID, uElapse, timerType);

	return true;
}

//清除定时器
bool CBaseLogonServer::KillTimer(UINT uTimerID)
{
	if (!m_pServerTimer)
	{
		ERROR_LOG("no timer run");
		return false;
	}

	int iTimerCount = m_KernelData.uTimerCount;
	if (iTimerCount <= 0 || iTimerCount > MAX_TIMER_THRED_NUMS)
	{
		ERROR_LOG("timer error");
		return false;
	}

	m_pServerTimer[uTimerID % iTimerCount].KillTimer(uTimerID);

	return true;
}

//队列数据处理线程
void* CBaseLogonServer::LineDataHandleThread(void* pThreadData)
{
	HandleThreadStartStruct* pData = (HandleThreadStartStruct*)pThreadData;
	CBaseLogonServer* pThis = pData->pMainManage;
	CDataLine* pDataLine = &pThis->m_DataLine;
	CFIFOEvent* pCFIFOEvent = pData->pFIFO;

	//线程数据读取完成
	pCFIFOEvent->SetEvent();

	sleep(1);

	INFO_LOG("业务逻辑线程启动成功...");

	//数据缓存
	DataLineHead* pDataLineHead = NULL;

	while (pThis->m_bRun)
	{
		try
		{
			//获取数据
			unsigned int bytes = pDataLine->GetData(&pDataLineHead);
			if (bytes == 0 || pDataLineHead == NULL)
			{
				continue;
			}

			switch (pDataLineHead->uDataKind)
			{
			case HD_SOCKET_READ:		// socket 数据读取
			{
				SocketReadLine* pSocketRead = (SocketReadLine*)pDataLineHead;
				void* pBuffer = NULL;
				unsigned int size = pSocketRead->uHandleSize;
				if (size > 0)
				{
					pBuffer = (void*)(pSocketRead + 1);			// 移动一个SocketReadLine
				}

				if (!pThis->OnSocketRead(&pSocketRead->netMessageHead, pBuffer, size, pSocketRead->socketType, pSocketRead->uIndex, pSocketRead->pBufferevent))
				{
					ERROR_LOG("OnSocketRead failed mainID=%d assistID=%d", pSocketRead->netMessageHead.uMainID, pSocketRead->netMessageHead.uAssistantID);
					if (ConfigManage()->m_logonServerConfig.webSocket && pSocketRead->socketType)
					{
						pThis->m_WebSocket.CloseSocket(pSocketRead->uIndex);
					}
					else
					{
						pThis->m_TCPSocket.CloseSocket(pSocketRead->uIndex);
					}
				}
				break;
			}
			case HD_SOCKET_CLOSE:		// socket 关闭
			{
				SocketCloseLine* pSocketClose = (SocketCloseLine*)pDataLineHead;
				pThis->OnSocketClose(pSocketClose->uAccessIP, pSocketClose->uIndex, pSocketClose->uConnectTime, pSocketClose->socketType);
				break;
			}
			case HD_ASYN_THREAD_RESULT://异步线程处理结果
			{
				AsynThreadResultLine* pDataRead = (AsynThreadResultLine*)pDataLineHead;
				void* pBuffer = NULL;
				unsigned int size = pDataRead->LineHead.uSize;

				if (size < sizeof(AsynThreadResultLine))
				{
					ERROR_LOG("AsynThreadResultLine data error !!!");
					break;
				}

				if (size > sizeof(AsynThreadResultLine))
				{
					pBuffer = (void*)(pDataRead + 1);
				}

				pThis->OnAsynThreadResult(pDataRead, pBuffer, size - sizeof(AsynThreadResultLine));

				break;
			}
			case HD_TIMER_MESSAGE:		// 定时器消息
			{
				ServerTimerLine* pTimerMessage = (ServerTimerLine*)pDataLineHead;
				pThis->OnTimerMessage(pTimerMessage->uTimerID);
				break;
			}
			case HD_PLATFORM_SOCKET_READ:	// 中心服消息
			{
				PlatformDataLineHead* pPlaformMessageHead = (PlatformDataLineHead*)pDataLineHead;
				int size = pPlaformMessageHead->platformMessageHead.MainHead.uMessageSize - sizeof(PlatformMessageHead);
				UINT msgID = pPlaformMessageHead->platformMessageHead.AssHead.msgID;
				int userID = pPlaformMessageHead->platformMessageHead.AssHead.userID;
				void* pBuffer = NULL;
				if (size > 0)
				{
					pBuffer = (void*)(pPlaformMessageHead + 1);
				}

				if (!pThis->OnCenterServerMessage(msgID, &pPlaformMessageHead->platformMessageHead.MainHead, pBuffer, size, userID))
				{
					ERROR_LOG("处理中心服务器出错,msgID=%d", msgID);
				}

				break;
			}
			default:
				ERROR_LOG("HD_PLATFORM_SOCKET_READ invalid linedata type, type=%d", pDataLineHead->uDataKind);
				break;
			}

			// 释放内存
			if (pDataLineHead)
			{
				free(pDataLineHead);
			}
		}

		catch (int iCode)
		{
			ERROR_LOG("[ LogonServer 编号：%d ] [ 描述：如果有dump文件，请查看dump文件 ] [ 源代码位置：未知 ]", iCode);
			continue;
		}

		catch (...)
		{
			ERROR_LOG("#### 未知崩溃。####");
			continue;
		}
	}

	pthread_exit(NULL);
}

//////////////////////////////////////////////////////////////////////////
// 中心服连接线程
void* CBaseLogonServer::TcpConnectThread(void* pThreadData)
{
	CBaseLogonServer* pThis = (CBaseLogonServer*)pThreadData;
	if (!pThis)
	{
		std::cout << "thread param is null" << "{func=" << __FUNCTION__ << " line=" << __LINE__ << "}\n";
		pthread_exit(NULL);
	}

	sleep(1);

	INFO_LOG("TcpConnectThread start...");

	while (pThis->m_bRun && pThis->m_pTcpConnect)
	{
		pThis->m_pTcpConnect->CheckConnection();
		pThis->m_pTcpConnect->EventLoop();
	}

	pthread_exit(NULL);
}