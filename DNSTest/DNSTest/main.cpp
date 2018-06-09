#include <stdio.h>
#include <stdlib.h>
#include "MySocket.h"
#include "dns.h"
#include "DNSDataList.h"
#include <time.h>

char ip_data[1024][2][256];
int ip_data_num;

int main()
{
	ip_data_num=0;
	FILE *fp_read=NULL;
	errno_t err=fopen_s(&fp_read,"dns.txt","r");
	while(fscanf_s(fp_read,"%s",ip_data[ip_data_num][0],256)!=EOF)
	{
		if(fscanf_s(fp_read,"%s",ip_data[ip_data_num][1],256)==EOF)
		{
			printf("���ݶ�ȡ����\n");
			system("pause");
			return 0;
		}
		ip_data_num++;
		if(ip_data_num>=1024)
		{
			printf("����������\n");
			system("pause");
			return 0;
		}
	}
	printf("���ݶ�ȡ�ɹ�������ȡ����%d��\n",ip_data_num);
	char ip[256];
	GetLocalIP(ip);
	printf("server:local ip:%s\n",ip);
	MySocketServer *server=new MySocketServer();
	server->flag=UDP;
	server->server_port=53;
	server->StartThread();
	char receivebuf[1024];
	DNSDataList *dns_dlp_first=new DNSDataList();
	time_t t;
	srand((unsigned) time(&t));
	while(true)
	{
		int length=1024;
		int receivelength=-1;
		if(server->Receive(receivebuf,length,receivelength)==true)
		{
			DNS_Data *dns=new DNS_Data();
			strcpy(dns->upper_server_ip,"114.114.114.114");
			dns->CopyData(receivebuf,receivelength);
			dns->Get();
			printf("\n\n����Ϊ�յ��ı������ݣ�\n");
			printf("receivelength=%d\n",receivelength);
			printf("id=0x%04x\n",dns->id);
			printf("sign=0x%04x\n",dns->sign);
			printf("qusetion_num=%u\n",dns->qusetion_num);
			printf("answer_num=%u\n",dns->answer_num);
			printf("authority_num=%u\n",dns->authority_num);
			printf("additional_num=%u\n",dns->additional_num);
			printf("qusetion_data_name[0]=%s\n",dns->qusetion_data_name[0]);
			printf("qusetion_data_type[0]=%u\n",dns->qusetion_data_type[0]);
			printf("qusetion_data_class[0]=%u\n",dns->qusetion_data_class[0]);
			printf("length=%u\n",dns->length);
			if(((dns->sign>>15)&(0x01))==0)//��ѯ����
			{
				printf("����Ϊ�յ��Ĳ�ѯ���ģ�\n");
				DNS_Data *result=new DNS_Data();
				if(dns->Calculate(result)==true)//�ڱ����ҵ�
				{
					printf("���ϲ�ѯ�����ڱ����ҵ������\n");
					printf("�ڱ����ҵ��Ľ�����ݣ�\n");
					for(int i=0;i<result->length;i++)
					{
						printf("%02x ",(unsigned char)result->data[i]);
					}
					server->Send(result->data,result->length);
				}
				else//����δ�ҵ������ϼ��м̷�������������
				{
					printf("���ϲ�ѯ�����ڱ���δ�ҵ������\n");
					DNSDataList *dns_dlp=new DNSDataList();
					server->GetClientInfo();
					strcpy(dns_dlp->client_ip,server->client_ip);
					dns_dlp->client_port=server->client_port;
					dns_dlp->client_id=dns->id;
					unsigned short tempid=rand()%(0xffff);
					dns_dlp->server_id=tempid;
					dns->id=tempid;
					//dns->Set();//(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
					dns->data[0]=(tempid>>8)&(0xff);
					dns->data[1]=tempid&(0xff);
					dns_dlp->fromclient->CopyData(dns->data,receivelength);
					//dns_dlp->fromclient->Get();//(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
					dns_dlp_first->Insert(dns_dlp);
					strcpy(server->client_ip,dns->upper_server_ip);
					server->client_port=53;
					server->SetClientInfo();
					server->Send(dns_dlp->fromclient->data,dns->length);
					printf("����Ϊ���м̷��������͵ı������ݣ�\n");
					for(int i=0;i<dns->length;i++)
					{
						printf("%02x ",(unsigned char)dns_dlp->fromclient->data[i]);
					}
				}
			}
			else//��Ӧ����
			{
				printf("����Ϊ�յ�����Ӧ���ģ�\n");
				DNSDataList *dns_dlp=dns_dlp_first->Find(dns->id);
				if(dns_dlp!=NULL)
				{
					printf("��Ӧ�����������в��ҵ���Ӧ�\n");
					dns->id=dns_dlp->client_id;
					//dns->Set();//(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
					dns->data[0]=(dns_dlp->client_id>>8)&(0xff);
					dns->data[1]=dns_dlp->client_id&(0xff);
					dns_dlp->fromserver->CopyData(dns->data,receivelength);
					//dns_dlp->fromserver->Get();//(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
					strcpy(server->client_ip,dns_dlp->client_ip);
					server->client_port=dns_dlp->client_port;
					server->SetClientInfo();
					server->Send(dns_dlp->fromserver->data,receivelength);
					printf("����Ϊ���м̷��������صĲ�ѯ����ٷ��ظ��ͻ��˵����ݣ�\n");
					for(int i=0;i<receivelength;i++)
					{
						printf("%02x ",(unsigned char)dns_dlp->fromserver->data[i]);
					}
					dns_dlp_first->Delete(dns_dlp);
				}
			}
		}
	}
	server->Finish();
	delete server;
	system("pause");
	return 0;
}