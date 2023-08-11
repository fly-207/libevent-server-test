#ifndef _NET_MESSAGE_HEADER_
#define _NET_MESSAGE_HEADER_
#pragma once

#pragma pack(1)

struct NetMessageHead
{
    unsigned int						uMessageSize;						///���ݰ���С
    unsigned int						uMainID;							///����������
    unsigned int						uAssistantID;						///������������ ID
    unsigned int						uHandleCode;						///���ݰ��������
    unsigned int						uIdentification;					///��ݱ�ʶ����ͬ��Э�������в�ͬ�ĺ��壩

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
