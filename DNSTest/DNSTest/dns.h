//DNS标准：RFC1035

#ifndef __DNS_H
#define __DNS_H

#include <stdio.h>
#include <string.h>
#include <winsock.h>
#pragma comment(lib,"wsock32.lib")

extern char ip_data[1024][2][256];
extern int ip_data_num;

class DNS_Data
{
public:
	//Header头部(12Byte)
	unsigned short id;//标识(2Byte)
	unsigned short sign;//标志(2Byte)
	unsigned short qusetion_num;//问题数(2Byte)
	unsigned short answer_num;//资源记录数(2Byte)
	unsigned short authority_num;//授权资源记录数(2Byte)
	unsigned short additional_num;//额外资源记录数(2Byte)
	//Question查询问题(长度可变)
	char qusetion_data_name[10][512];//查询名(长度可变)
	unsigned short qusetion_data_type[10];//查询类型(2Byte)
	unsigned short qusetion_data_class[10];//查询类(2Byte)
	//Answer问答(长度可变)
	bool answer_data_IsOffset[10];//域名是否压缩使用偏移值
	unsigned char answer_data_offset[10];//偏移量(0x0c+1Byte)
	char answer_data_name[10][512];//域名(长度可变)
	unsigned short answer_data_type[10];//类型(2Byte)
	unsigned short answer_data_class[10];//类(2Byte)
	unsigned int answer_data_ttl[10];//生存时间(4Byte)
	unsigned short answer_data_length[10];//资源数据长度(2Byte)
	char answer_data_data[10][512];//资源数据(长度可变)
	//Authority授权(长度可变)
	bool authority_data_IsOffset[10];//域名是否压缩使用偏移值
	unsigned char authority_data_offset[10];//偏移量(0x0c+1Byte)
	char authority_data_name[10][512];//域名(长度可变)
	unsigned short authority_data_type[10];//类型(2Byte)
	unsigned short authority_data_class[10];//类(2Byte)
	unsigned int authority_data_ttl[10];//生存时间(4Byte)
	unsigned short authority_data_length[10];//资源数据长度(2Byte)
	char authority_data_data[10][512];//资源数据(长度可变)
	//Additional额外信息(长度可变)
	bool additional_data_IsOffset[10];//域名是否压缩使用偏移值
	unsigned char additional_data_offset[10];//偏移量(0x0c+1Byte)
	char additional_data_name[10][512];//域名(长度可变)
	unsigned short additional_data_type[10];//类型(2Byte)
	unsigned short additional_data_class[10];//类(2Byte)
	unsigned int additional_data_ttl[10];//生存时间(4Byte)
	unsigned short additional_data_length[10];//资源数据长度(2Byte)
	char additional_data_data[10][512];//资源数据(长度可变)
	//其他
	char upper_server_ip[512];//上一级中继DNS服务器ip地址
	char data[512];//DNS数据报
	unsigned int length;//DNS数据报总长度
	DNS_Data();//构造函数
	bool Set();//设置DNS数据报(此函数在多数情况下分析处理数据有误，不能应对各种种类的报文，使得length长度分析错误)
	bool Get();//从DNS数据报中获取信息(此函数在多数情况下分析处理数据有误，不能应对各种种类的报文，使得length长度分析错误)
	bool CopyData(const char in_data[],int in_length);//复制数组内的数据
	bool Calculate(DNS_Data *out_data);//计算待查询的数据，生成结果数据报文
};

#endif