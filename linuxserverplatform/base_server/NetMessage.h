#ifndef _NET_MESSAGE_HEADER_
#define _NET_MESSAGE_HEADER_
#pragma once

#pragma pack(1)

struct NetMessageHead
{
    unsigned int						uMessageSize;						///数据包大小
    unsigned int						uMainID;							///处理主类型
    unsigned int						uAssistantID;						///辅助处理类型 ID
    unsigned int						uHandleCode;						///数据包处理代码
    unsigned int						uIdentification;					///身份标识（不同的协议里面有不同的含义）

    NetMessageHead():
        uMessageSize(0),
        uMainID(0),
        uAssistantID(0),
        uHandleCode(0),
        uIdentification(0)
    {

    }
};


#pragma pack()

#endif
