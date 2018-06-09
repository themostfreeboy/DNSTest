#ifndef __MYSOCKET_H
#define __MYSOCKET_H

#include <string>
#include <winsock.h>
#include "md5_file.h"
#pragma comment(lib,"wsock32.lib")

#define TCP 1
#define UDP 2

class MySocketClient//Socket���Client�ͻ�����
{
public:
	int flag;//flag=TCP(1)��flag=UDP(2)
	char server_ip[256];//server������ip��ַ
	int server_port;//server�������˿ں�
	char client_ip[256];//client�ͻ���ip��ַ
	int client_port;//client�ͻ��˶˿ں�
	SOCKET sock_client;//���ӵ�ָ��
	SOCKADDR_IN addrserver;//�洢server�������������Ϣ
	MySocketClient();//���캯��
	bool Start();//���client�ͻ���������ò���������
	bool Finish();//�Ͽ������ͷ���Դ
	bool Send(const char sendbuf[],int length);//��server��������������
	bool SendClientIPPort();//��server����������client�ͻ��˵�ip��ַ�Ͷ˿ں�
	bool SendFile(const char filepath[],int sleeptime);//��server�����������ļ�(����û��ͨ�ŷ�����������ļ��׶���)
};

class MySocketServer//Socket���Server��������
{
public:
	int flag;//flag=TCP(1)��flag=UDP(2)
	char server_ip[256];//server������ip��ַ
	int server_port;//server�������˿ں�
	char client_ip[256];//client�ͻ���ip��ַ
	int client_port;//client�ͻ��˶˿ں�
	bool listening;//���ڿ����Ƿ����
	SOCKET sock_server;//���ӵ�ָ��
	SOCKET sock_client;//���ӵ�ָ��
	SOCKADDR_IN addrclient;//�洢client�ͻ��˵������Ϣ
	SOCKADDR_IN addrserver;//�洢server�������������Ϣ
	MySocketServer();//���캯��
	bool StartThread();//������һ���߳���ִ��Start����
	bool Finish();//�Ͽ������ͷ���Դ
	bool Receive(char receivebuf[],int length,int &receivelength);//��client�ͻ��˽�������
	bool ReceiveClientIPPort();//��client�ͻ��˽���client�ͻ��˵�ip��ַ�Ͷ˿ں�
	bool ReceiveFile(const char filepath[]);//��client�ͻ��˽����ļ�(����û��ͨ�ŷ�����������ļ��׶���)
	bool Send(const char sendbuf[],int length);//��client�ͻ��˷�������(ʹ�ô˺���ǰ������ʹ��Receive��ȡ��client�ͻ��˵�ip�Ͷ˿ںŵ���Ϣ)
	bool GetClientInfo();//��ȡclient�ͻ��˵�ip�Ͷ˿ںŵ���Ϣ
	bool SetClientInfo();//����client�ͻ��˵�ip�Ͷ˿ںŵ���Ϣ
private:
	bool Start();//���server������������ò���ʼ����
	static UINT ProcessForStart(LPVOID pParam);//Ϊ�˿���Start�����Ķ��̶߳��ӵĸ�������
};

bool GetLocalIP(char ip[]);//��ȡ����ip��ַ
bool StringPlus(char original_string[],const char plus_string[],int &num);//Ϊ�˱���original_string�������Ѿ�����0('\0')����strcatʧЧ
int StringCheck(const char original_string[],const char check_string[],const int num);//Ϊ�˱���original_string�������Ѿ�����0('\0')����strstrʧЧ

#endif