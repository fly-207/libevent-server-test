#ifndef _LOG_HEADER_
#define _LOG_HEADER_

#pragma once

#include <stdio.h>


// 输出错误消息 【只输出到文件系统】
#define ERROR_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// 输出常规信息 【只输出到文件系统】
#define INFO_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// 输出重要警告信息 【只输出到文件系统】
#define WARNNING_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// 输出错误消息 【输出到文件系统和控制台】
#define CON_ERROR_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// 输出常规信息 【输出到文件系统和控制台】
#define CON_INFO_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// 输出系统错误信息，strerror(errno)函数全局的，调用SYS_ERROR_LOG之前，不能调用其它系统函数
#define SYS_ERROR_LOG(...)	{ printf(__VA_ARGS__); printf("\n");}

// 普通日志输出，文件名用户自定义
#define FILE_LOG(filename, ...)	{ printf(__VA_ARGS__); printf("\n");}

#endif