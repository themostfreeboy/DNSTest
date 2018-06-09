#pragma once

#include "DNSDataList.h"

DNSDataList::DNSDataList()//构造函数
{
	fromclient=new DNS_Data();
	client_id=0;
	memset(client_ip,0,512);
	client_port=0;
	fromserver=new DNS_Data();
	server_id=0;
	next=NULL;
}

bool DNSDataList::Insert(const DNSDataList *dns_dlp)//插入
{
	DNSDataList *dns_dlptemp=this;
	for(dns_dlptemp=this;dns_dlptemp->next!=NULL;dns_dlptemp=dns_dlptemp->next);
	dns_dlptemp->next=new DNSDataList();
	dns_dlptemp=dns_dlptemp->next;
	dns_dlptemp->fromclient->CopyData(dns_dlp->fromclient->data,dns_dlp->fromclient->length);
	dns_dlptemp->fromclient->Get();
	dns_dlptemp->client_id=dns_dlp->client_id;
	strcpy(dns_dlptemp->client_ip,dns_dlp->client_ip);
	dns_dlptemp->client_port=dns_dlp->client_port;
	dns_dlptemp->fromserver->CopyData(dns_dlp->fromserver->data,dns_dlp->fromserver->length);
	dns_dlptemp->fromserver->Get();
	dns_dlptemp->server_id=dns_dlp->server_id;
	return true;
}

bool DNSDataList::Delete(const DNSDataList *dns_dlp)//删除
{
	for(DNSDataList *dns_dlptemp=this;dns_dlptemp->next!=NULL;dns_dlptemp=dns_dlptemp->next)
	{
		if(dns_dlptemp->next==dns_dlp)
		{
			dns_dlptemp->next=dns_dlp->next;
			delete dns_dlp;
			return true;
		}
	}
	return false;
}

DNSDataList* DNSDataList::Find(unsigned short find_server_id)//按照id查找
{
	for(DNSDataList *dns_dlp=this->next;dns_dlp!=NULL;dns_dlp=dns_dlp->next)
	{
		if(dns_dlp->server_id==find_server_id)
		{
			return dns_dlp;
		}
	}
	return NULL;
}