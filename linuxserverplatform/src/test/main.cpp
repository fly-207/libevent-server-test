#include <jemalloc/jemalloc.h>
#include "CommonHead.h"
#include "Lock.h"
#include "basemessage.h"
#include "comstruct.h"
#include "KernelDefine.h"
#include "INIFile.h"
#include "configManage.h"
#include "Function.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include "log.h"
#include "GServerConnect.h"
#include "DataLine.h"
#include "Util.h"
#include "MyCurl.h"
#include "Define.h"
#include "json/json.h"
#include "RedisCenter.h"
#include "Xor.h"
#include "NewMessageDefine.h"
#include "test.pb.h"
#include "ServerTimer.h"
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "HttpServer.h"
#include "shmem.h"

using namespace test;

static timeval g_lasttime;

class FIFOEvent
{
public:
	FIFOEvent(const char* filename);
	~FIFOEvent(){}
	void WaitForEvent();
	void SetEvent();
private:
	const char* m_fifoName;
};
FIFOEvent::FIFOEvent(const char* filename)
{
	m_fifoName = filename;

	int res = 0;

	if (access(m_fifoName, F_OK) == -1)
	{
		res = mkfifo(m_fifoName, 0777);
		if (res != 0)
		{
			printf("could not create fifo:%s\n", strerror(errno));
			m_fifoName = NULL;
		}
	}
}
void FIFOEvent::WaitForEvent()
{
	if (!m_fifoName)
	{
		return;
	}

	int fifoFd = open(m_fifoName, O_RDONLY);
	int res = 0;

	if (fifoFd != -1)
	{
		char chTemp;
		res = read(fifoFd, &chTemp, sizeof(chTemp));
		if (res == -1)
		{
			printf("read error:%s\n", strerror(errno));
		}

		close(fifoFd);
	}
	else
	{
		printf("open error:%s\n", strerror(errno));
	}
}
void FIFOEvent::SetEvent()
{
	if (!m_fifoName)
	{
		return;
	}

	int fifoFd = open(m_fifoName, O_WRONLY);
	int res = 0;

	if (fifoFd != -1)
	{
		char chTemp = 123;
		res = write(fifoFd, &chTemp, sizeof(chTemp));
		if (res == -1)
		{
			printf("write error:%s\n", strerror(errno));
		}

		close(fifoFd);
	}
	else
	{
		printf("open error:%s\n", strerror(errno));
	}
}

void* FIFOFunc(void*param)
{
	printf("测试管道\n");
	
	FIFOEvent* p = (FIFOEvent*)param;

	p->SetEvent();
}

CSignedLock	m_csLock;

void fun()
{
	
	int i = 0;

	for (i = 0; i < 1000000; i++)
	{
		m_csLock.Notify();
	}

	printf("%d=======\n", i);
}


void* Thread(void*p)
{
	void* p1 = malloc(10000);

	printf("%p\n", p1);

	free(p1);


	p1 = malloc(10000);

	printf("%p\n", p1);

	free(p1);

	p1 = malloc(8000);

	printf("%p\n", p1);

	return p1;
}

void do_something(size_t i)
{
	// Leak some memory.
	malloc(i * 100);
}
class ABBB
{
public:
	ABBB()
	{
		printf("ABBB\n");
	}
};

extern int TestShm();
extern int TestUnLockQueue();

int main(int argc, char** argv)
{
	TestShm();
	sleep(3);
	return 0;

	int param = 8;
	for (int i = 0; i < 10000; i++)
	{
		if ((i % param) == (i & (param - 1)))
		{
			continue;
		}
		else
		{
			printf("sdfsdfsdf\n");
			break;
		}
	}
	


	//测试基础版共享内存
	CShmem testmem;
	char* p1 = (char *)testmem.CreateShmem(0x930319, 4, 6325, __FILE__, __LINE__);
	//*p1 = 'a';

	while (1)
	{
		sleep(1);
	}
	

	char* p2 = (char*)testmem.CreateShmem(12345678, 102400, 1236, __FILE__, __LINE__);
	*p2 = 'b';

	char* p3 = (char*)testmem.CreateShmem(12345676, 10240, 136, __FILE__, __LINE__);
	*p3 = 'c';

	// 设置程序路径 , 创建日志目录
	CINIFile file(CINIFile::GetAppPath() + "config.ini");
	string logPath = file.GetKeyVal("COMMON", "logPath", "./log/");
	if (!CUtil::MkdirIfNotExists(logPath.c_str()))
	{
		printf("创建日志目录失败！！！ err=%s", strerror(errno));
		return -1;
	}
	GameLogManage()->SetLogPath(logPath);

	// 设置服务器类型
	ConfigManage()->SetServiceType(SERVICE_TYPE_LOADER);

	// 关联大厅主线程的log文件
	GameLogManage()->AddLogFile(GetCurrentThreadId(), THREAD_TYPE_MAIN);

	bool ret = false;

	// 加载基础配置
	ret = ConfigManage()->Init();
	if (!ret)
	{
		CON_ERROR_LOG("ConfigManage::Init error! 请查看启动日志 !!!");
		return -1;
	}

	TestUnLockQueue();
	//TestShm();
	return 0;

	// 测试http服务器
	CHttpServer httpserver;
	httpserver.Start();


	ABBB* pa = new ABBB[6];
	int i;
	for (i = 0; i < 1000; i++)
	{
		do_something(i);
	}
	mallctl("prof.dump", NULL, NULL, NULL, 0);


	struct timeval tv;
	gettimeofday(&tv, NULL);

	// 记录开始时间
	long long m_beginTime = tv.tv_sec * 1000000 + tv.tv_usec;

	fun();

	gettimeofday(&tv, NULL);
	long long m_endTime = tv.tv_sec * 1000000 + tv.tv_usec;

	printf("%lld\n", m_endTime - m_beginTime);

	//FIFOEvent fifo("/tmp/linuxserver-main-fifo");

	//// 开辟线程
	//pthread_t threadID2 = 0;
	//pthread_create(&threadID2, NULL, FIFOFunc, (void*)&fifo);
	//fifo.WaitForEvent();


	printf("罗潭\n");

	m_csLock.Notify();


	GOOGLE_PROTOBUF_VERIFY_VERSION;

	Team team;
	team.set_id(1);
	team.set_name("Rocket");
	Student* s1 = team.add_student(); // 添加repeated成员
	s1->set_id(1);
	s1->set_name("Mike");
	s1->set_sex(Sex::BOY);
	Student* s2 = team.add_student();
	s2->set_id(2);
	s2->set_name("Lily");
	s2->set_sex(Sex::GIRL);

	// encode --> bytes stream
	string out;
	team.SerializeToString(&out);

	// decode --> team structure
	Team t;
	t.ParseFromArray(out.c_str(), out.size()); // or parseFromString
	cout << t.DebugString() << endl;
	for (int i = 0; i < t.student_size(); i++) {
		Student s = t.student(i); // 按索引解repeated成员
		cout << s.name() << " " << s.sex() << endl;
	}





	//CUtil::MkdirIfNotExists("log/");
	//CUtil::MkdirIfNotExists(SAVE_JSON_PATH);
	//// 设置服务器类型
	//ConfigManage()->SetServiceType(SERVICE_TYPE_LOADER);
	//// 关联大厅主线程的log文件
	//GameLogManage()->AddLogFile(GetCurrentThreadId(), THREAD_TYPE_MAIN);
	//ConfigManage()->Init();


	//发送邮件接口
	MyCurl curl;
	std::vector<std::string> vUrlHeader;
	std::string postFields = "";
	std::string result = "";
	//组合生成URL
	std::string url = "http://api.androidhive.info/volley/person_object.json";
	curl.postUrlHttps(url, vUrlHeader, postFields, result);
	std::cout << result << endl;



	string strJsonContent = "{\"role_id\": 1,\"occupation\": \"paladin\",\"camp\": \"alliance\"}";
	int nRoleDd = 0;
	string strOccupation = "";
	string strCamp = "";
	Json::Reader reader;
	Json::Value root;
	if (reader.parse(strJsonContent, root))
	{
		nRoleDd = root["role_id"].asInt();
		strOccupation = root["occupation"].asString();
		strCamp = root["camp"].asString();
	}
	cout << "role_id is: " << nRoleDd << endl;
	cout << "occupation is: " << strOccupation << endl;
	cout << "camp is: " << strCamp << endl;


	LogonResponseLogon msg;
	strcpy(msg.name, "123456");
	msg.money = 963852741;
	Xor::Encrypt((unsigned char *)&msg, sizeof(msg));
	Xor::Decrypt((unsigned char*)& msg, sizeof(msg));

	

	printf("+++++++++++++++==\n"); 
	CSignedLock lock;
	CSignedLockObject testLock(&lock, false);

	testLock.Lock();
	testLock.Lock();
	printf("+++++++++++++++==\n");

	testLock.UnLock();
	testLock.UnLock();

	int    socket_fd, connect_fd;
	struct sockaddr_in     servaddr;
	char    buff[4096];
	int     n;
	//初始化Socket  
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	//初始化  
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);//IP地址设置成INADDR_ANY,让系统自动获取本机的IP地址。  
	servaddr.sin_port = htons(6666);//设置的端口为DEFAULT_PORT  

	//将本地地址绑定到所创建的套接字上  
	if (bind(socket_fd, (struct sockaddr*) & servaddr, sizeof(servaddr)) == -1) {
		printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	//开始监听是否有客户端连接  
	if (listen(socket_fd, 10) == -1) {
		printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}
	printf("======waiting for client's request======\n");
	while (1) {
		//阻塞直到有客户端连接，不然多浪费CPU资源。  
		if ((connect_fd = accept(socket_fd, (struct sockaddr*)NULL, NULL)) == -1) {
			printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
			continue;
		}
		//接受客户端传过来的数据  
		n = recv(connect_fd, buff, sizeof(buff), 0);
		//向客户端发送回应数据  
		if (!fork()) { /*紫禁城*/
			if (send(connect_fd, "Hello,you are connected!\n", 26, 0) == -1)
				perror("send error");
			close(connect_fd);
			exit(0);
		}
		buff[n] = '\0';
		printf("recv msg from client: %s\n", buff);
		close(connect_fd);
	}

	close(socket_fd);

    return 0;
}