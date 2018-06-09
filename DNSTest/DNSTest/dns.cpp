#pragma once

#include "dns.h"

DNS_Data::DNS_Data()//���캯��
{
	//Headerͷ��(12Byte)
	id=0;
	sign=0;
	qusetion_num=0;
	answer_num=0;
	authority_num=0;
	additional_num=0;
	for(int i=0;i<10;i++)
	{
		//Question��ѯ����(���ȿɱ�)
		memset(qusetion_data_name[i],0,512);
		qusetion_data_type[i]=0;
		qusetion_data_class[i]=0;
		//Answer�ʴ�(���ȿɱ�)
		answer_data_IsOffset[i]=false;
		answer_data_offset[i]=0x0c;
		memset(answer_data_name[i],0,512);
		answer_data_type[i]=0;
		answer_data_class[i]=0;
		answer_data_ttl[i]=0;
		answer_data_length[i]=0;
		memset(answer_data_data,0,512);
		//Authority��Ȩ(���ȿɱ�)
		authority_data_IsOffset[i]=false;
		authority_data_offset[i]=0x0c;
		memset(authority_data_name[i],0,512);
		authority_data_type[i]=0;
		authority_data_class[i]=0;
		authority_data_ttl[i]=0;
		authority_data_length[i]=0;
		memset(authority_data_data,0,512);
		//Additional������Ϣ(���ȿɱ�)
		additional_data_IsOffset[i]=false;
		additional_data_offset[i]=0x0c;
		memset(additional_data_name[i],0,512);
		additional_data_type[i]=0;
		additional_data_class[i]=0;
		additional_data_ttl[i]=0;
		additional_data_length[i]=0;
		memset(additional_data_data[i],0,512);
	}
	//����
	strcpy(upper_server_ip,"114.114.114.114");
	memset(data,0,512);
	length=0;
}

bool DNS_Data::Set()//����DNS���ݱ�(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
{
	data[0]=(id>>8)&(0xff);
	data[1]=id&(0xff);
	data[2]=(sign>>8)&(0xff);
	data[3]=sign&(0xff);
	data[4]=(qusetion_num>>8)&(0xff);
	data[5]=qusetion_num&(0xff);
	data[6]=(answer_num>>8)&(0xff);
	data[7]=answer_num&(0xff);
	data[8]=(authority_num>>8)&(0xff);
	data[9]=authority_num&(0xff);
	data[10]=(additional_num>>8)&(0xff);
	data[11]=additional_num&(0xff);
	length=12;
	for(int i=0;i<qusetion_num;i++)
	{
		const int start=length;
		int temp=-1;
		length++;
		for(int j=0;qusetion_data_name[i][j]!='\0';j++)
		{
			if((qusetion_data_name[i][j]>='a'&&qusetion_data_name[i][j]<='z') || (qusetion_data_name[i][j]>='A'&&qusetion_data_name[i][j]<='Z') || (qusetion_data_name[i][j]>='0'&&qusetion_data_name[i][j]<='9'))
			{
				data[start+1+j]=qusetion_data_name[i][j];
			}
			else if(qusetion_data_name[i][j]=='.')
			{
				data[start+1+temp]=j-temp-1;
				temp=j;
			}
			length++;
		}
		data[start+1+temp]=strlen(qusetion_data_name[i])-temp-1;
		data[length++]='\0';
		data[length++]=(qusetion_data_type[i]>>8)&(0xff);
		data[length++]=qusetion_data_type[i]&(0xff);
		data[length++]=(qusetion_data_class[i]>>8)&(0xff);
		data[length++]=qusetion_data_class[i]&(0xff);
	}
	for(int i=0;i<answer_num;i++)
	{
		if(answer_data_IsOffset[i]==false)//��ʹ��ѹ��ƫ��
		{
			const int start=length;
			int temp=-1;
			length++;
			for(int j=0;answer_data_name[i][j]!='\0';j++)
			{
				if((answer_data_name[i][j]>='a'&&answer_data_name[i][j]<='z') || (answer_data_name[i][j]>='A'&&answer_data_name[i][j]<='Z') || (answer_data_name[i][j]>='0'&&answer_data_name[i][j]<='9'))
				{
					data[start+1+j]=answer_data_name[i][j];
				}
				else if(answer_data_name[i][j]=='.')
				{
					data[start+1+temp]=j-temp-1;
					temp=j;
				}
				length++;
			}
			data[start+1+temp]=strlen(answer_data_name[i])-temp-1;
			data[length++]='\0';
		}
		else//ʹ��ѹ��ƫ��
		{
			data[length++]=0xc0;//ָ��ƫ��
			data[length++]=answer_data_offset[i]&(0xff);
		}
		data[length++]=(answer_data_type[i]>>8)&(0xff);
		data[length++]=answer_data_type[i]&(0xff);
		data[length++]=(answer_data_class[i]>>8)&(0xff);
		data[length++]=answer_data_class[i]&(0xff);
		data[length++]=(answer_data_ttl[i]>>24)&(0xff);
		data[length++]=(answer_data_ttl[i]>>16)&(0xff);
		data[length++]=(answer_data_ttl[i]>>8)&(0xff);
		data[length++]=answer_data_ttl[i]&(0xff);
		data[length++]=(answer_data_length[i]>>8)&(0xff);
		data[length++]=answer_data_length[i]&(0xff);
		if(answer_data_type[i]==1)//����Ϊip��ַ
		{
			unsigned long temp=inet_addr(answer_data_data[i]);
			data[length++]=temp&(0xff);
			data[length++]=(temp>>8)&(0xff);
			data[length++]=(temp>>16)&(0xff);
			data[length++]=(temp>>24)&(0xff);		
		}
	}
	for(int i=0;i<authority_num;i++)
	{
		if(authority_data_IsOffset[i]==false)//��ʹ��ѹ��ƫ��
		{
			const int start=length;
			int temp=-1;
			length++;
			for(int j=0;authority_data_name[i][j]!='\0';j++)
			{
				if((authority_data_name[i][j]>='a'&&authority_data_name[i][j]<='z') || (authority_data_name[i][j]>='A'&&authority_data_name[i][j]<='Z') || (authority_data_name[i][j]>='0'&&authority_data_name[i][j]<='9'))
				{
					data[start+1+j]=authority_data_name[i][j];
				}
				else if(authority_data_name[i][j]=='.')
				{
					data[start+1+temp]=j-temp-1;
					temp=j;
				}
				length++;
			}
			data[start+1+temp]=strlen(authority_data_name[i])-temp-1;
			data[length++]='\0';
		}
		else//ʹ��ѹ��ƫ��
		{
			data[length++]=0xc0;//ָ��ƫ��
			data[length++]=authority_data_offset[i]&(0xff);
		}
		data[length++]=(authority_data_type[i]>>8)&(0xff);
		data[length++]=authority_data_type[i]&(0xff);
		data[length++]=(authority_data_class[i]>>8)&(0xff);
		data[length++]=authority_data_class[i]&(0xff);
		data[length++]=(authority_data_ttl[i]>>24)&(0xff);
		data[length++]=(authority_data_ttl[i]>>16)&(0xff);
		data[length++]=(authority_data_ttl[i]>>8)&(0xff);
		data[length++]=authority_data_ttl[i]&(0xff);
		data[length++]=(authority_data_length[i]>>8)&(0xff);
		data[length++]=authority_data_length[i]&(0xff);
		if(authority_data_type[i]==1)//����Ϊip��ַ
		{
			unsigned long temp=inet_addr(authority_data_data[i]);
			data[length++]=temp&(0xff);
			data[length++]=(temp>>8)&(0xff);
			data[length++]=(temp>>16)&(0xff);
			data[length++]=(temp>>24)&(0xff);		
		}
	}
	for(int i=0;i<additional_num;i++)
	{
		if(additional_data_IsOffset[i]==false)//��ʹ��ѹ��ƫ��
		{
			const int start=length;
			int temp=-1;
			length++;
			for(int j=0;additional_data_name[i][j]!='\0';j++)
			{
				if((additional_data_name[i][j]>='a'&&additional_data_name[i][j]<='z') || (additional_data_name[i][j]>='A'&&additional_data_name[i][j]<='Z') || (additional_data_name[i][j]>='0'&&additional_data_name[i][j]<='9'))
				{
					data[start+1+j]=additional_data_name[i][j];
				}
				else if(additional_data_name[i][j]=='.')
				{
					data[start+1+temp]=j-temp-1;
					temp=j;
				}
				length++;
			}
			data[start+1+temp]=strlen(additional_data_name[i])-temp-1;
			data[length++]='\0';
		}
		else//ʹ��ѹ��ƫ��
		{
			data[length++]=0xc0;//ָ��ƫ��
			data[length++]=additional_data_offset[i]&(0xff);
		}
		data[length++]=(additional_data_type[i]>>8)&(0xff);
		data[length++]=additional_data_type[i]&(0xff);
		data[length++]=(additional_data_class[i]>>8)&(0xff);
		data[length++]=additional_data_class[i]&(0xff);
		data[length++]=(additional_data_ttl[i]>>24)&(0xff);
		data[length++]=(additional_data_ttl[i]>>16)&(0xff);
		data[length++]=(additional_data_ttl[i]>>8)&(0xff);
		data[length++]=additional_data_ttl[i]&(0xff);
		data[length++]=(additional_data_length[i]>>8)&(0xff);
		data[length++]=additional_data_length[i]&(0xff);
		if(additional_data_type[i]==1)//����Ϊip��ַ
		{
			unsigned long temp=inet_addr(additional_data_data[i]);
			data[length++]=temp&(0xff);
			data[length++]=(temp>>8)&(0xff);
			data[length++]=(temp>>16)&(0xff);
			data[length++]=(temp>>24)&(0xff);		
		}
	}
	return true;
}

bool DNS_Data::Get()//��DNS���ݱ��л�ȡ��Ϣ(�˺����ڶ�������·��������������󣬲���Ӧ�Ը�������ı��ģ�ʹ��length���ȷ�������)
{
	id=((unsigned char)data[0]<<8)|(unsigned char)data[1];
	sign=((unsigned char)data[2]<<8)|(unsigned char)data[3];
	qusetion_num=((unsigned char)data[4]<<8)|(unsigned char)data[5];
	answer_num=((unsigned char)data[6]<<8)|(unsigned char)data[7];
	authority_num=((unsigned char)data[8]<<8)|(unsigned char)data[9];
	additional_num=((unsigned char)data[10]<<8)|(unsigned char)data[11];
	length=12;
	for(int i=0;i<qusetion_num;i++)
	{
		const unsigned int templength=length;
		if(data[templength]>0 && data[templength]<=63)
		{
			length++;
			for(int j=templength+1;data[j]!='\0';j++)
			{
				if((data[j]>='a' && data[j]<='z') || (data[j]>='A' && data[j]<='Z') || (data[j]>='0' && data[j]<='9'))
				{
					qusetion_data_name[i][j-templength-1]=data[j];
				}
				else if(data[j]>0 && data[j]<=63)
				{
					qusetion_data_name[i][j-templength-1]='.';
				}
				length++;
			}
		}
		qusetion_data_name[i][length-templength-1]='\0';
		qusetion_data_type[i]=((unsigned char)data[length+1]<<8)|(unsigned char)data[length+2];
		qusetion_data_class[i]=((unsigned char)data[length+3]<<8)|(unsigned char)data[length+4];
		length=length+5;
	}
	for(int i=0;i<answer_num;i++)
	{
		if(data[length]==0xc0)//ѹ��ָ��ƫ��
		{
			answer_data_IsOffset[i]=true;
			length++;
			answer_data_offset[i]=data[length];
		}
		else if(data[length]>0&&data[length]<=63)//��ѹ��ָ��ƫ��
		{
			answer_data_IsOffset[i]=false;
			const unsigned int templength=length;
			if(data[templength]>0 && data[templength]<=63)
			{
				length++;
				for(int j=templength+1;data[j]!='\0';j++)
				{
					if((data[j]>='a' && data[j]<='z') || (data[j]>='A' && data[j]<='Z') || (data[j]>='0' && data[j]<='9'))
					{
						answer_data_name[i][j-templength-1]=data[j];
					}
					else if(data[j]>0 && data[j]<=63)
					{
						answer_data_name[i][j-templength-1]='.';
					}
					length++;
				}
			}
			answer_data_name[i][length-templength-1]='\0';
		}
		answer_data_type[i]=((unsigned char)data[length+1]<<8)|(unsigned char)data[length+2];
		answer_data_class[i]=((unsigned char)data[length+3]<<8)|(unsigned char)data[length+4];
		length=length+5;
	}
	for(int i=0;i<authority_num;i++)
	{
		if(data[length]==0xc0)//ѹ��ָ��ƫ��
		{
			authority_data_IsOffset[i]=true;
			length++;
			authority_data_offset[i]=data[length];
		}
		else if(data[length]>0&&data[length]<=63)//��ѹ��ָ��ƫ��
		{
			authority_data_IsOffset[i]=false;
			const unsigned int templength=length;
			if(data[templength]>0 && data[templength]<=63)
			{
				length++;
				for(int j=templength+1;data[j]!='\0';j++)
				{
					if((data[j]>='a' && data[j]<='z') || (data[j]>='A' && data[j]<='Z') || (data[j]>='0' && data[j]<='9'))
					{
						authority_data_name[i][j-templength-1]=data[j];
					}
					else if(data[j]>0 && data[j]<=63)
					{
						authority_data_name[i][j-templength-1]='.';
					}
					length++;
				}
			}
			authority_data_name[i][length-templength-1]='\0';
		}
		authority_data_type[i]=((unsigned char)data[length+1]<<8)|(unsigned char)data[length+2];
		authority_data_class[i]=((unsigned char)data[length+3]<<8)|(unsigned char)data[length+4];
		length=length+5;
	}
	for(int i=0;i<additional_num;i++)
	{
		if(data[length]==0xc0)//ѹ��ָ��ƫ��
		{
			additional_data_IsOffset[i]=true;
			length++;
			additional_data_offset[i]=data[length];
		}
		else if(data[length]>0&&data[length]<=63)//��ѹ��ָ��ƫ��
		{
			additional_data_IsOffset[i]=false;
			const unsigned int templength=length;
			if(data[templength]>0 && data[templength]<=63)
			{
				length++;
				for(int j=templength+1;data[j]!='\0';j++)
				{
					if((data[j]>='a' && data[j]<='z') || (data[j]>='A' && data[j]<='Z') || (data[j]>='0' && data[j]<='9'))
					{
						additional_data_name[i][j-templength-1]=data[j];
					}
					else if(data[j]>0 && data[j]<=63)
					{
						additional_data_name[i][j-templength-1]='.';
					}
					length++;
				}
			}
			additional_data_name[i][length-templength-1]='\0';
		}
		additional_data_type[i]=((unsigned char)data[length+1]<<8)|(unsigned char)data[length+2];
		additional_data_class[i]=((unsigned char)data[length+3]<<8)|(unsigned char)data[length+4];
		length=length+5;
	}
	return true;
}

bool DNS_Data::CopyData(const char in_data[],int in_length)//���������ڵ�����
{
	if(in_length>512)
	{
		return false;
	}
	for(int i=0;i<in_length;i++)
	{
		data[i]=in_data[i];
	}
	return true;
}

bool DNS_Data::Calculate(DNS_Data *out_data)//�������ѯ�����ݣ����ɽ�����ݱ���
{
	bool HaveFind=false;
	out_data->id=id;
	out_data->sign=0x8180;//QR=1(��Ӧ����)(1bit);opcode=0(��׼��ѯ)(4bit);AA=0(����Ȩ�ش�)(1bit);TC=0(���ɽض�)(1bit);RD=1(�����ݹ�)(1bit);RA=1(���õݹ�)(1bit);(zero)=0(3bit);rcode=0(û�в��)(4bit)
	out_data->qusetion_num=1;
	out_data->answer_num=1;
	out_data->authority_num=0;
	out_data->additional_num=0;
	for(int i=0;i<out_data->answer_num;i++)
	{
		if(qusetion_data_type[i]==1 && qusetion_data_class[i]==1)//��ѯ����Ϊip��ַ����ѯ��Ϊ��������ַ
		{
			for(int j=0;j<ip_data_num;j++)
			{
				if(strcmp(qusetion_data_name[i],ip_data[j][1])==0)
				{
					strcpy(out_data->qusetion_data_name[i],qusetion_data_name[i]);
					out_data->qusetion_data_type[i]=1;//ip��ַ
					out_data->qusetion_data_class[i]=1;//��������ַ
					answer_data_IsOffset[i]=false;//��ʹ��ѹ��ƫ��
					strcpy(out_data->answer_data_name[i],qusetion_data_name[i]);
					out_data->answer_data_type[i]=1;//ip��ַ
					out_data->answer_data_class[i]=1;//��������ַ
					out_data->answer_data_ttl[i]=172800;//2��(172800��)
					out_data->answer_data_length[i]=4;
					strcpy(out_data->answer_data_data[i],ip_data[j][0]);
					HaveFind=true;
					break;
				}
			}
		}
	}
	out_data->Set();
	return HaveFind;
}