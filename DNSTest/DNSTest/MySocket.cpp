#pragma once

#include "MySocket.h"

//MySocketClient//Socket���Client�ͻ�����
MySocketClient::MySocketClient()//���캯��
{
	flag=TCP;
	GetLocalIP(server_ip);
	server_port=12345;
	GetLocalIP(client_ip);
	client_port=23456;
}

bool MySocketClient::Start()//���client�ͻ���������ò���������
{
	WORD wVersionRequest;
	WSADATA wsadata;
	wVersionRequest=MAKEWORD(2,0);
	int err=WSAStartup(wVersionRequest,&wsadata);
	if(err!=0)
	{
		return false;//��������ʧ��
	}
	if(LOBYTE(wsadata.wVersion)!=2||(HIBYTE(wsadata.wVersion)!=0))
	{
		WSACleanup();
		return false;//��������ʧ��
	}
	if(flag==TCP)
	{
		sock_client=socket(AF_INET,SOCK_STREAM,0);
	}
	else if(flag==UDP)
	{
		sock_client=socket(AF_INET,SOCK_DGRAM,0);
	}
	else
	{
		return false;//��������ʧ��
	}
	if(sock_client==INVALID_SOCKET)
	{
		return false;//��������ʧ��
	}
	memset(&addrserver,0,sizeof(addrserver));
	addrserver.sin_addr.S_un.S_addr=inet_addr(server_ip);
	addrserver.sin_family=AF_INET;
	addrserver.sin_port=htons(server_port);
	for(int i=0;connect(sock_client,(SOCKADDR*)&addrserver,sizeof(SOCKADDR))!=0;i++)
	{
		Sleep(10);
		if(i==10)
		{
			return false;//����10����Ȼ����ʧ��
		}
	}
	return true;//�������ӳɹ�
}

bool MySocketClient::Finish()//�Ͽ������ͷ���Դ
{
	closesocket(sock_client);
	WSACleanup();
	return true;
}

bool MySocketClient::Send(const char sendbuf[],int length)//��Server��������������
{
	if(sendto(sock_client,sendbuf,length,0,(SOCKADDR*)&addrserver,sizeof(SOCKADDR))!=SOCKET_ERROR)
	{
		return true;//���ͳɹ�
	}
	return false;//����ʧ��
}

bool MySocketClient::SendClientIPPort()//��server����������client�ͻ��˵�ip��ַ�Ͷ˿ں�
{
	char sendbuf[256];
	strcpy(sendbuf,"@ip@");
	strcat(sendbuf,client_ip);
	strcat(sendbuf,"@port@");
	int num=strlen(sendbuf);
	int a=client_port/10000;
	int b=(client_port/1000)%10;
	int c=(client_port/100)%10;
	int d=(client_port/10)%10;
	int e=client_port%10;
	sendbuf[num++]=a+'0';
	sendbuf[num++]=b+'0';
	sendbuf[num++]=c+'0';
	sendbuf[num++]=d+'0';
	sendbuf[num++]=e+'0';
	sendbuf[num]='\0';
	bool result=Send(sendbuf,strlen(sendbuf)+1);
	return result;
}

bool MySocketClient::SendFile(const char filepath[],int sleeptime)//��server�����������ļ�
{
	errno_t err;
	FILE *fp_read=NULL;
	err=fopen_s(&fp_read,filepath,"rb");//�ȼ����ļ��Ƿ���ڲ����Դ�
	if(err!=0)
	{
		return false;//�ļ���ʧ��
	}
	fclose(fp_read);

	char filename[256];
	int filename_num=0;
	unsigned char md5[17];
	unsigned long filesize=md5_file_calc(filepath,md5);
	if(filesize==0)
	{
		return false;//�ļ�md5�Լ��ļ���С����ʧ��
	}
	for(int i=strlen(filepath)-1;i>=0;i--)
	{
		if(filepath[i]=='\\')
		{
			for(int j=i+1;filepath[j]!='\0';j++)
			{
				filename[filename_num++]=filepath[j];
			}
			filename[filename_num]='\0';
			break;
		}
		else if(i==0 && filepath[i]!='\\')
		{
			strcpy(filename,filepath);
			filename_num=strlen(filename);
		}
	}
	char sendbuf[1024];
	int sendbuf_num=0;
	strcpy(sendbuf,"@filestart@");
	strcat(sendbuf,"@filename@");
	strcat(sendbuf,filename);
	strcat(sendbuf,"@filesize@");
	sendbuf_num=strlen(sendbuf);
	for(int i=0;i<4;i++)
	{
		unsigned char  tempfilesize=(filesize>>(8*(3-i)))&(0xff);
		sendbuf[sendbuf_num++]=tempfilesize;
	}
	StringPlus(sendbuf,"@md5@",sendbuf_num);
	for(int i=0;i<16;i++)//����md5�����п��ܴ���0('\0')���Բ�����StringPlus
	{
		sendbuf[sendbuf_num++]=md5[i];
	}
	sendbuf[sendbuf_num++]='\0';
	Send(sendbuf,sendbuf_num);//�����ļ������ļ���С���ļ�md5У��ֵ
	Sleep(sleeptime);
	err=fopen_s(&fp_read,filepath,"rb");
	if(err!=0)
	{
		return false;//�ļ���ʧ��
	}
	char tempchar=0;
	for(int i=0;i<filesize/500;i++)
	{
		strcpy(sendbuf,"@datastart@");
		sendbuf_num=strlen(sendbuf);
		for(int j=0;j<500;j++)
		{
			if(fscanf(fp_read,"%c",&tempchar)!=EOF)
			{
				sendbuf[sendbuf_num++]=tempchar;
			}
			else
			{
				return false;//��ȡ���ݹ����г���
			}
		}
		StringPlus(sendbuf,"@dataend@",sendbuf_num);
		if(filesize%500==0)
		{
			StringPlus(sendbuf,"@fileend@",sendbuf_num);
		}
		Send(sendbuf,sendbuf_num);
		Sleep(sleeptime);
	}
	if(filesize%500!=0)
	{
		strcpy(sendbuf,"@datastart@");
		sendbuf_num=strlen(sendbuf);
		for(int i=0;i<filesize%500;i++)
		{
			if(fscanf(fp_read,"%c",&tempchar)!=EOF)
			{
				sendbuf[sendbuf_num++]=tempchar;
			}
			else
			{
				return false;//��ȡ���ݹ����г���
			}
		}
		StringPlus(sendbuf,"@dataend@",sendbuf_num);
		StringPlus(sendbuf,"@fileend@",sendbuf_num);
		Send(sendbuf,sendbuf_num);
		Sleep(sleeptime);
	}
	fclose(fp_read);
	return true;
}

//MySocketServer//Socket���Server��������
MySocketServer::MySocketServer()//���캯��
{
	flag=TCP;
	GetLocalIP(server_ip);
	server_port=12345;
	GetLocalIP(client_ip);
	client_port=23456;
	listening=true;
}

bool MySocketServer::StartThread()//������һ���߳���ִ��Start����
{
	HANDLE thread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)MySocketServer::ProcessForStart,this,0,NULL);//�������߳�
	return true;
}

bool MySocketServer::Finish()//�Ͽ������ͷ���Դ
{
	closesocket(sock_client);
	WSACleanup();
	return true;
}

bool MySocketServer::Receive(char receivebuf[],int length,int &receivelength)//��client�ͻ��˽�������
{
	if(flag==TCP)
	{
		if((receivelength=recv(sock_client,receivebuf,length,0))!=SOCKET_ERROR)
		{
			strcpy(client_ip,inet_ntoa(addrclient.sin_addr));
			client_port=ntohs(addrclient.sin_port);
			return true;//���ճɹ�
		}
		return false;//����ʧ��
	}
	else if(flag==UDP)
	{
		int size=sizeof(addrclient);
		if((receivelength=recvfrom(sock_server,receivebuf,length,0,(SOCKADDR*)&addrclient,&size))!=SOCKET_ERROR)
		{
			strcpy(client_ip,inet_ntoa(addrclient.sin_addr));
			client_port=ntohs(addrclient.sin_port);
			return true;//���ճɹ�
		}
		return false;//����ʧ��
	}
	else
	{
		return false;//����ʧ��
	}
}

bool MySocketServer::ReceiveClientIPPort()//��client�ͻ��˽���client�ͻ��˵�ip��ַ�Ͷ˿ں�
{
	char receivebuf[256];
	for(int i=0;i<10;i++);//����10��
	{
		int receivelength=-1;
		int result=Receive(receivebuf,256,receivelength);
		if(result==true)
		{
			char *tempstring1=new char[256];
			tempstring1=strstr(receivebuf,"@ip@");
			if(tempstring1==NULL)
			{
				return false;//������������
			}
			for(int j=0;tempstring1[j+4]!='\0';j++)
			{
				if((tempstring1[j+4]>='0' && tempstring1[j+4]<='9') || tempstring1[j+4]=='.')
				{
					client_ip[j]=tempstring1[j+4];
				}
				else if(tempstring1[j+4]=='@')
				{
					client_ip[j]='\0';
					break;
				}
				else
				{
					return false;//������������
				}
			}
			char *tempstring2=new char[256];
			tempstring2=strstr(tempstring1,"@port@");
			if(tempstring2==NULL)
			{
				return false;//������������
			}
			client_port=(tempstring2[6]-'0')*10000+(tempstring2[7]-'0')*1000+(tempstring2[8]-'0')*100+(tempstring2[9]-'0')*10+(tempstring2[10]-'0');
			return true;
		}
		Sleep(500);
	}
	return false;
}

bool MySocketServer::ReceiveFile(const char filepath[])//��client�ͻ��˽����ļ�
{
	char filename[256];
	int filename_num=0;
	char new_filepath[256];
	int new_filepath_num=0;
	unsigned char original_md5[17];
	unsigned long original_filesize=0;
	char receivebuf[1024];
	int receivelength=-1;
	while(Receive(receivebuf,1024,receivelength)==false);
	int num1=-1,num2=-1;
	if(StringCheck(receivebuf,"@filestart@",1024)!=0)
	{
		return false;//���ݸ�ʽ����
	}
	if(StringCheck(receivebuf,"@filename@",1024)!=11)
	{
		return false;//���ݸ�ʽ����
	}
	num1=StringCheck(receivebuf,"@filesize@",1024);
	num2=StringCheck(receivebuf,"@md5@",1024);
	if(num1==-1 || num2==-1)
	{
		return false;//���ݸ�ʽ����
	}
	if(num2-num1!=14)
	{
		return false;//���ݸ�ʽ����
	}
	if(receivebuf[num2+21]!='\0')
	{
		return false;//���ݸ�ʽ����
	}
	for(int i=21;i<num1;i++)
	{
		filename[filename_num++]=receivebuf[i];
	}
	filename[filename_num]='\0';
	strcpy(new_filepath,filepath);
	new_filepath_num=strlen(filepath);
	if(new_filepath[new_filepath_num-1]!='\\')
	{
		new_filepath[new_filepath_num]='\\';
		new_filepath[new_filepath_num+1]='\0';
	}
	strcat(new_filepath,filename);
	original_filesize=0;
	unsigned char tempfilesize=0;
	for(int i=0;i<4;i++)
	{
		tempfilesize=receivebuf[num1+10+i];
		original_filesize<<=8;
		original_filesize+=tempfilesize;
	}
	for(int i=0;i<16;i++)
	{
		original_md5[i]=receivebuf[num2+5+i];
	}
	errno_t err;
	FILE *fp_write=NULL;
	err=fopen_s(&fp_write,new_filepath,"wb");//�ȼ����ļ��Ƿ���ڲ����Դ�
	if(err!=0)
	{
		return false;//�ļ���ʧ��
	}
	for(int i=0;i<original_filesize/500;i++)
	{
		int receivelength=-1;
		while(Receive(receivebuf,1024,receivelength)==false);
		if(StringCheck(receivebuf,"@datastart@",1024)!=0)
		{
			return false;//���ݸ�ʽ����
		}
		if(StringCheck(receivebuf,"@dataend@",1024)!=511)
		{
			return false;//���ݸ�ʽ����
		}
		if(i==original_filesize/500-1 && original_filesize%500==0)
		{
			if(StringCheck(receivebuf,"@fileend@",1024)!=520)
			{
				return false;//���ݸ�ʽ����
			}
		}
		for(int j=0;j<500;j++)
		{
			fprintf(fp_write,"%c",receivebuf[j+11]);
		}
	}
	if(original_filesize%500!=0)
	{
		int receivelength=-1;
		while(Receive(receivebuf,1024,receivelength)==false);
		if(StringCheck(receivebuf,"@datastart@",1024)!=0)
		{
			return false;//���ݸ�ʽ����
		}
		if(StringCheck(receivebuf,"@dataend@",1024)!=11+original_filesize%500)
		{
			return false;//���ݸ�ʽ����
		}
		if(StringCheck(receivebuf,"@fileend@",1024)!=20+original_filesize%500)
		{
			return false;//���ݸ�ʽ����
		}
		for(int i=0;i<original_filesize%500;i++)
		{
			fprintf(fp_write,"%c",receivebuf[i+11]);
		}
	}
	fclose(fp_write);
	unsigned char real_md5[17];
	unsigned long real_filesize=0;
	real_filesize=md5_file_calc(new_filepath,real_md5);
	if(real_filesize!=original_filesize)
	{
		return false;//���ݴ�С����
	}
	for(int i=0;i<16;i++)
	{
		if(real_md5[i]!=original_md5[i])
		{
			return false;//����md5ֵ��������������
		}
	}
	return true;
}

bool MySocketServer::Send(const char sendbuf[],int length)//��client�ͻ��˷�������(ʹ�ô˺���ǰ������ʹ��Receive��ȡ��client�ͻ��˵�ip�Ͷ˿ںŵ���Ϣ)
{
	if(sendto(sock_server,sendbuf,length,0,(SOCKADDR*)&addrclient,sizeof(SOCKADDR))!=SOCKET_ERROR)
	{
		return true;//���ͳɹ�
	}
	return false;//����ʧ��
}

bool MySocketServer::GetClientInfo()//��ȡclient�ͻ��˵�ip�Ͷ˿ںŵ���Ϣ
{
	strcpy(client_ip,inet_ntoa(addrclient.sin_addr));
	client_port=ntohs(addrclient.sin_port);
	return true;
}

bool MySocketServer::SetClientInfo()//����client�ͻ��˵�ip�Ͷ˿ںŵ���Ϣ
{
	addrclient.sin_addr.S_un.S_addr=inet_addr(client_ip);
	addrclient.sin_family=AF_INET;
	addrclient.sin_port=htons(client_port);
	return true;
}

bool MySocketServer::Start()//���server������������ò���ʼ����
{
	WORD wVersionRequest;
	WSADATA wsadata;
	wVersionRequest=MAKEWORD(2,0);
	int err=WSAStartup(wVersionRequest,&wsadata);
	if(err!=0)
	{
		return false;//��������ʧ��
	}
	if(LOBYTE(wsadata.wVersion)!=2||(HIBYTE(wsadata.wVersion)!=0))
	{
		WSACleanup();
		return false;//��������ʧ��
	}
	if(flag==TCP)
	{
		sock_server=socket(AF_INET, SOCK_STREAM, 0);
	}
	else if(flag==UDP)
	{
		sock_server=socket(AF_INET, SOCK_DGRAM, 0);
	}
	else
	{
		return false;//��������ʧ��
	}
	if (sock_server==INVALID_SOCKET)
	{
		return false;//��������ʧ��
	}
	memset(&addrserver,0,sizeof(addrserver));
	addrserver.sin_addr.S_un.S_addr = (htonl(INADDR_ANY));
	addrserver.sin_family=AF_INET;
	addrserver.sin_port=htons(server_port);
	if(bind(sock_server,(SOCKADDR*)&addrserver,sizeof(SOCKADDR))==0)
	{
		if(flag==TCP)
		{
			int length=sizeof(addrclient);
			listen(sock_server,128);//��ʼ����
			while(listening==true)
			{
				sock_client=accept(sock_server,(SOCKADDR*)&addrclient,&length);
				if(sock_client==INVALID_SOCKET)
				{
					return false;//��������ʧ��
				}
			}
		}
	}
	return true;//�������ӳɹ�
}

UINT MySocketServer::ProcessForStart(LPVOID pParam)//Ϊ�˿���Start�����Ķ��̶߳��ӵĸ�������
{
	MySocketServer *server=(MySocketServer*)pParam;
	server->Start();
	return 0;
}

bool GetLocalIP(char ip[])//��ȡ����ip��ַ
{
	WORD wVersionRequest;
	WSADATA wsadata;
	wVersionRequest=MAKEWORD(2,0);
	int err=WSAStartup(wVersionRequest,&wsadata);
	if(err!=0)
	{
		return false;//����ʧ��
	}
	if(LOBYTE(wsadata.wVersion)!=2||(HIBYTE(wsadata.wVersion)!=0))
	{
		WSACleanup();
		return false;//����ʧ��
	}
	char szHostName[MAX_PATH+1];
    gethostname(szHostName,MAX_PATH);//��ñ���������
    hostent *hn;
    hn=gethostbyname(szHostName);//���ݱ����������õ�����IP
	if(hn==NULL)
    {
		return false;//��ȡʧ��
    }
    strcpy(ip,inet_ntoa(*(in_addr *)hn->h_addr_list[0]));//��ipת�����ַ�����ʽ
	return true;//��ȡ�ɹ�
}

bool StringPlus(char original_string[],const char plus_string[],int &num)//Ϊ�˱���original_string�������Ѿ�����0('\0')����strcatʧЧ
{
	for(int i=0;plus_string[i]!='\0';i++)
	{
		original_string[num++]=plus_string[i];
	}
	return true;
}

int StringCheck(const char original_string[],const char check_string[],const int num)//Ϊ�˱���original_string�������Ѿ�����0('\0')����strstrʧЧ
{
	bool flag=false;
	for(int i=0;i<num;i++)
	{
		for(int j=0;i+j<num&&check_string[j]!='\0';j++)
		{
			if(original_string[i+j]==check_string[j])
			{
				flag=true;
			}
			else
			{
				flag=false;
				break;
			}
		}
		if(flag==true)
		{
			return i;//�����ҵ��ĵ�һ��ƥ���ַ��������±�
		}
	}
	return -1;//δ�ҵ�
}