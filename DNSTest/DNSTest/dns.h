//DNS��׼��RFC1035

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
	//Headerͷ��(12Byte)
	unsigned short id;//��ʶ(2Byte)
	unsigned short sign;//��־(2Byte)
	unsigned short qusetion_num;//������(2Byte)
	unsigned short answer_num;//��Դ��¼��(2Byte)
	unsigned short authority_num;//��Ȩ��Դ��¼��(2Byte)
	unsigned short additional_num;//������Դ��¼��(2Byte)
	//Question��ѯ����(���ȿɱ�)
	char qusetion_data_name[10][512];//��ѯ��(���ȿɱ�)
	unsigned short qusetion_data_type[10];//��ѯ����(2Byte)
	unsigned short qusetion_data_class[10];//��ѯ��(2Byte)
	//Answer�ʴ�(���ȿɱ�)
	bool answer_data_IsOffset[10];//�����Ƿ�ѹ��ʹ��ƫ��ֵ
	unsigned char answer_data_offset[10];//ƫ����(0x0c+1Byte)
	char answer_data_name[10][512];//����(���ȿɱ�)
	unsigned short answer_data_type[10];//����(2Byte)
	unsigned short answer_data_class[10];//��(2Byte)
	unsigned int answer_data_ttl[10];//����ʱ��(4Byte)
	unsigned short answer_data_length[10];//��Դ���ݳ���(2Byte)
	char answer_data_data[10][512];//��Դ����(���ȿɱ�)
	//Authority��Ȩ(���ȿɱ�)
	bool authority_data_IsOffset[10];//�����Ƿ�ѹ��ʹ��ƫ��ֵ
	unsigned char authority_data_offset[10];//ƫ����(0x0c+1Byte)
	char authority_data_name[10][512];//����(���ȿɱ�)
	unsigned short authority_data_type[10];//����(2Byte)
	unsigned short authority_data_class[10];//��(2Byte)
	unsigned int authority_data_ttl[10];//����ʱ��(4Byte)
	unsigned short authority_data_length[10];//��Դ���ݳ���(2Byte)
	char authority_data_data[10][512];//��Դ����(���ȿɱ�)
	//Additional������Ϣ(���ȿɱ�)
	bool additional_data_IsOffset[10];//�����Ƿ�ѹ��ʹ��ƫ��ֵ
	unsigned char additional_data_offset[10];//ƫ����(0x0c+1Byte)
	char additional_data_name[10][512];//����(���ȿɱ�)
	unsigned short additional_data_type[10];//����(2Byte)
	unsigned short additional_data_class[10];//��(2Byte)
	unsigned int additional_data_ttl[10];//����ʱ��(4Byte)
	unsigned short additional_data_length[10];//��Դ���ݳ���(2Byte)
	char additional_data_data[10][512];//��Դ����(���ȿɱ�)
	//����
	char upper_server_ip[512];//��һ���м�DNS������ip��ַ
	char data[512];//DNS���ݱ�
	unsigned int length;//DNS���ݱ��ܳ���
	DNS_Data();//���캯��
	bool Set();//����DNS���ݱ�(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
	bool Get();//��DNS���ݱ��л�ȡ��Ϣ(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
	bool CopyData(const char in_data[],int in_length);//���������ڵ�����
	bool Calculate(DNS_Data *out_data);//�������ѯ�����ݣ����ɽ�����ݱ���
};

#endif