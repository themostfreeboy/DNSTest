#ifndef __DNSDATALIST_H
#define __DNSDATALIST_H

#include "dns.h"
#include "string.h"

class DNSDataList
{
public:
	DNS_Data *fromclient;
	unsigned short client_id;
	char client_ip[512];
	unsigned short client_port;
	DNS_Data *fromserver;
	unsigned short server_id;
	DNSDataList *next;
	DNSDataList();//构造函数
	bool Insert(const DNSDataList *dns_dlp);//插入
	bool Delete(const DNSDataList *dns_dlp);//删除
	DNSDataList* Find(unsigned short find_id);//按照id查找
};

#endif