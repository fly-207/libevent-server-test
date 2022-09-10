#include "CommonHead.h"
#include "Exception.h"
#include "log.h"
#include "PlatformMessage.h"
#include "configManage.h"
#include "Util.h"
#include "BaseMainManage.h"

int CBaseMainManage::g_jemallocProfileRoom = 0;

//处理线程启动结构
struct HandleThreadStartStruct
{
	//变量定义
	CFIFOEvent* pFIFO;						//启动事件
	CBaseMainManage* pMainManage;			//数据管理指针
};

//构造函数
CBaseMainManage::CBaseMainManage()
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
	m_pGServerConnect = NULL;
	m_pServerTimer = NULL;
}

CBaseMainManage::~CBaseMainManage()
{
	SAFE_DELETE(m_pRedis);
	SAFE_DELETE(m_pRedisPHP);
	SAFE_DELETE(m_pTcpConnect);
	SAFE_DELETE(m_pGServerConnect);
	SafeDeleteArray(m_pServerTimer);
}

bool CBaseMainManage::Init(ManageInfoStruct* pInitData, IDataBaseHandleService* pDataHandleService)
{
	if (!pInitData || !pDataHandleService)
	{
		ERROR_LOG("invalid input params pInitData=%p pDataHandleService=%p", pInitData, pDataHandleService);
		return false;
	}

	if (m_bInit)
	{
		ERROR_LOG("already inited");
		return false;
	}

	m_InitData = *pInitData;

	bool ret = false;

	ret = PreInitParameter(&m_InitData, &m_KernelData);
	if (!ret)
	{
		throw new CException("CBaseMainManage::Init PreInitParameter 参数调节错误", 0x41A);
	}

	m_pRedis = new CRedisLoader;
	if (!m_pRedis)
	{
		return false;
	}

	ret = m_pRedis->Init();
	if (!ret)
	{
		throw new CException("CBaseMainManage::Init redis初始化失败（可能是redis服务器未启动）", 0x401);
	}

	//vip房间才需要连接php redis
	if (m_InitData.iRoomType != ROOM_TYPE_GOLD)
	{
		m_pRedisPHP = new CRedisPHP;
		if (!m_pRedisPHP)
		{
			return false;
		}

		ret = m_pRedisPHP->Init();
		if (!ret)
		{
			throw new CException("CBaseMainManage::Init redisPHP初始化失败（可能是redis PHP服务器未启动）", 0x402);
		}
	}

	ret = pDataHandleService->SetParameter(this, &m_SQLDataManage, &m_InitData, &m_KernelData);
	if (!ret)
	{
		throw new CException("CBaseMainManage::Init pDataHandleService->SetParameter失败", 0x41C);
	}

	ret = m_SQLDataManage.Init(&m_InitData, &m_KernelData, pDataHandleService, this);
	if (!ret)
	{
		throw new CException("CBaseMainManage::Init m_SQLDataManage 初始化失败", 0x41D);
	}

	m_pTcpConnect = new CTcpConnect;
	if (!m_pTcpConnect)
	{
		throw new CException("CBaseMainManage::Init new CTcpConnect failed", 0x43A);
	}

	m_pGServerConnect = new CGServerConnect;
	if (!m_pGServerConnect)
	{
		throw new CException("CBaseMainManage::Init new CGServerConnect failed", 0x43A);
	}

	int iServerTimerNums = Min_(MAX_TIMER_THRED_NUMS, ConfigManage()->GetCommonConfig().TimerThreadNumber);
	iServerTimerNums = iServerTimerNums <= 0 ? 1 : iServerTimerNums;
	m_KernelData.uTimerCount = iServerTimerNums;
	m_pServerTimer = new CServerTimer[iServerTimerNums];
	if (!m_pServerTimer)
	{
		throw new CException("CBaseMainManage::Init new CServerTimer failed", 0x43A);
	}

	ret = OnInit(&m_InitData, &m_KernelData);
	if (!ret)
	{
		throw new CException("CBaseMainManage::Init OnInit 函数错误", 0x41B);
	}

	m_bInit = true;

	return true;
}

//取消初始化函数 
bool CBaseMainManage::UnInit()
{
	//停止服务
	if (m_bRun)
	{
		Stop();
	}

	//调用接口
	OnUnInit();

	//取消初始化
	m_bInit = false;
	m_SQLDataManage.UnInit();

	//设置数据
	memset(&m_DllInfo, 0, sizeof(m_DllInfo));
	memset(&m_InitData, 0, sizeof(m_InitData));
	memset(&m_KernelData, 0, sizeof(m_KernelData));

	//释放redis
	m_pRedis->Stop();
	SAFE_DELETE(m_pRedis);
	if (m_pRedisPHP)
	{
		m_pRedisPHP->Stop();
		SAFE_DELETE(m_pRedisPHP);
	}

	SAFE_DELETE(m_pTcpConnect);
	SAFE_DELETE(m_pGServerConnect);
	SafeDeleteArray(m_pServerTimer);

	return true;
}

//启动函数
bool CBaseMainManage::Start()
{
	if (!m_bInit || m_bRun)
	{
		return false;
	}

	m_bRun = true;

	// 创建管道
	CFIFOEvent fifo("./CBaseMainManage-Start-fifo");

	bool ret = true;
	ret = m_SQLDataManage.Start();
	if (!ret)
	{
		throw new CException("CBaseMainManage::m_SQLDataManage.Start 数据库模块启动失败", 0x420);
	}

	//////////////////////////////////建立与中心服的连接////////////////////////////////////////
	const CenterServerConfig& centerServerConfig = ConfigManage()->GetCenterServerConfig();
	ret = m_pTcpConnect->Start(&m_DataLine, centerServerConfig.ip, centerServerConfig.port, SERVICE_TYPE_LOADER, m_InitData.uRoomID);
	if (!ret)
	{
		throw new CException("CBaseMainManage::m_pTcpConnect.Start 连接模块启动失败", 0x433);
	}

	int err = pthread_create(&m_connectCServerHandle, NULL, TcpConnectThread, (void*)this);
	if (err != 0)
	{
		SYS_ERROR_LOG("TcpConnectThread failed");
		throw new CException("CBaseMainManage::m_pTcpConnect.Start 连接线程函数启动失败", 0x434);
	}

	// 关联日志文件
	GameLogManage()->AddLogFile(m_connectCServerHandle, THREAD_TYPE_RECV, m_InitData.uRoomID);

	//////////////////////////////////建立与网关的连接////////////////////////////////////////
	ret = m_pGServerConnect->Start(&m_DataLine, m_InitData.uRoomID, SERVICE_TYPE_LOADER, true);
	if (!ret)
	{
		throw new CException("CBaseMainManage::m_pGServerConnect.Start 连接模块启动失败", 0x433);
	}

	//////////////////////////////////启动定时器////////////////////////////////////////

	for (int i = 0; i < m_KernelData.uTimerCount; i++)
	{
		if (!m_pServerTimer[i].Start(&m_DataLine))
		{
			throw new CException("CBaseMainManage::m_pServerTimer.Start 定时器启动失败", 0x433);
		}
	}

	//////////////////////////////////////////////////////////////////////////

	g_jemallocProfileRoom = m_InitData.uRoomID;

	ret = OnStart();
	if (!ret)
	{
		throw new CException("CBaseMainManage::Start OnStart 函数错误", 0x422);
	}

	//启动处理线程
	HandleThreadStartStruct	ThreadStartData;
	ThreadStartData.pMainManage = this;
	ThreadStartData.pFIFO = &fifo;
	err = pthread_create(&m_hHandleThread, NULL, LineDataHandleThread, (void*)&ThreadStartData);
	if (err != 0)
	{
		SYS_ERROR_LOG("LineDataHandleThread failed");
		throw new CException("CBaseMainManage::Start LineDataHandleThread 线程启动失败", 0x41E);
	}

	// 关联游戏业务逻辑线程与对应日志文件
	GameLogManage()->AddLogFile(m_hHandleThread, THREAD_TYPE_LOGIC, m_InitData.uRoomID);

	// 等待子线程读取线程参数
	fifo.WaitForEvent();

	return true;
}

//停止服务
bool CBaseMainManage::Stop()
{
	if (m_bRun == false)
	{
		return true;
	}

	OnStop();

	m_bRun = false;

	m_SQLDataManage.Stop();

	if (m_pTcpConnect)
	{
		m_pTcpConnect->Stop();
	}

	if (m_pGServerConnect)
	{
		m_pGServerConnect->Stop();
	}

	// 关闭中心服连接线程
	if (m_connectCServerHandle)
	{
		pthread_cancel(m_connectCServerHandle);
		m_connectCServerHandle = 0;
	}

	//退出处理线程
	if (m_hHandleThread)
	{
		pthread_cancel(m_hHandleThread);
		m_hHandleThread = 0;
	}

	//关闭定时器
	for (int i = 0; i < m_KernelData.uTimerCount; i++)
	{
		m_pServerTimer[i].Stop();
	}

	//清理队列数据
	m_DataLine.CleanLineData();

	return true;
}

//刷新服务
bool CBaseMainManage::Update()
{
	return OnUpdate();
}

//异步线程结果处理
bool CBaseMainManage::OnAsynThreadResultEvent(UINT uHandleKind, UINT uHandleResult, const void* pData, UINT uResultSize, UINT uIndex, UINT uMsgID)
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
bool CBaseMainManage::SetTimer(UINT uTimerID, UINT uElapse, BYTE timerType/* = SERVERTIMER_TYPE_PERISIST*/)
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
bool CBaseMainManage::KillTimer(UINT uTimerID)
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
void* CBaseMainManage::LineDataHandleThread(void* pThreadData)
{
	//数据定义
	HandleThreadStartStruct* pData = (HandleThreadStartStruct*)pThreadData;		//线程启动数据指针
	CBaseMainManage* pMainManage = pData->pMainManage;							//数据管理指针
	CDataLine* pDataLine = &pMainManage->m_DataLine;							//数据队列指针
	CFIFOEvent* pCFIFOEvent = pData->pFIFO;

	//线程数据读取完成
	pCFIFOEvent->SetEvent();

	sleep(1);

	INFO_LOG("业务逻辑线程启动成功...");

	//数据缓存
	DataLineHead* pDataLineHead = NULL;

	while (pMainManage->m_bRun)
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
			case HD_SOCKET_READ://SOCKET数据读取
			{
				SocketReadLine* pSocketRead = (SocketReadLine*)pDataLineHead;
				if (pMainManage->OnSocketRead(&pSocketRead->netMessageHead,
					pSocketRead->uHandleSize ? pSocketRead + 1 : NULL,
					pSocketRead->uHandleSize, pSocketRead->uAccessIP,
					pSocketRead->uIndex) == false)
				{
					//ERROR_LOG("OnSocketRead failed mainID=%d assistID=%d", pSocketRead->NetMessageHead.uMainID, pSocketRead->NetMessageHead.uAssistantID);
				}
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

				pMainManage->OnAsynThreadResult(pDataRead, pBuffer, size - sizeof(AsynThreadResultLine));

				break;
			}
			case HD_TIMER_MESSAGE://定时器消息
			{
				ServerTimerLine* pTimerMessage = (ServerTimerLine*)pDataLineHead;
				pMainManage->OnTimerMessage(pTimerMessage->uTimerID);
				break;
			}
			case HD_PLATFORM_SOCKET_READ:	// 中心服务器发过来的消息
			{
				PlatformDataLineHead* pPlaformMessageHead = (PlatformDataLineHead*)pDataLineHead;
				int sizeCenterMsg = pPlaformMessageHead->platformMessageHead.MainHead.uMessageSize - sizeof(PlatformMessageHead);
				UINT msgID = pPlaformMessageHead->platformMessageHead.AssHead.msgID;
				int userID = pPlaformMessageHead->platformMessageHead.AssHead.userID;
				void* pBuffer = NULL;
				if (sizeCenterMsg > 0)
				{
					pBuffer = (void*)(pPlaformMessageHead + 1);
				}

				pMainManage->OnCenterServerMessage(msgID, &pPlaformMessageHead->platformMessageHead.MainHead, pBuffer, sizeCenterMsg, userID);
				break;
			}
			default:
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
			ERROR_LOG("[ LoaderServer 编号：%d ] [ 描述：如果有core文件，请查看core文件 ] [ 源代码位置：未知 ]", iCode);
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
void* CBaseMainManage::TcpConnectThread(void* pThreadData)
{
	CBaseMainManage* pThis = (CBaseMainManage*)pThreadData;
	if (!pThis)
	{
		CON_ERROR_LOG("pThis==NULL");
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