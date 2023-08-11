#ifndef _LOG_HEADER_
#define _LOG_HEADER_

#pragma once

#include <stdio.h>


// ���������Ϣ ��ֻ������ļ�ϵͳ��
#define ERROR_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// ���������Ϣ ��ֻ������ļ�ϵͳ��
#define INFO_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// �����Ҫ������Ϣ ��ֻ������ļ�ϵͳ��
#define WARNNING_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// ���������Ϣ ��������ļ�ϵͳ�Ϳ���̨��
#define CON_ERROR_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// ���������Ϣ ��������ļ�ϵͳ�Ϳ���̨��
#define CON_INFO_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// ���ϵͳ������Ϣ��strerror(errno)����ȫ�ֵģ�����SYS_ERROR_LOG֮ǰ�����ܵ�������ϵͳ����
#define SYS_ERROR_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// ��ͨ��־������ļ����û��Զ���
#define FILE_LOG(filename, ...)	{ printf(__VA_ARGS__); printf("\n");}

#endif