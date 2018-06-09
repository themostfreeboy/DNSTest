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
	DNSDataList();//���캯��
	bool Insert(const DNSDataList *dns_dlp);//����
	bool Delete(const DNSDataList *dns_dlp);//ɾ��
	DNSDataList* Find(unsigned short find_id);//����id����
};

#endif