#include <iostream>
#include <cstdio>
#include "pcap.h"


using namespace std;

pcap_if_t* alldevs;//��ʼ��ָ��pcap_if_t���͵�ָ�룬��������
pcap_if_t* d;//��ʼ��ָ����������
int idev = 0;//��¼�豸����
pcap_t* adhandle;//������������

char errbuf[PCAP_ERRBUF_SIZE];

int Find_device()
{
    //��ȡ���������������豸
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)//��������һ��pcap_if�ṹ������
    {
        cout << stderr << "Error in pcap_findalldevs_ex: " << endl << errbuf;
        return 1;//ԭ�ĵ�д��exit(1)�����д���ȼۣ���ʾ�쳣�˳�
    }

    //����豸����
    for (d = alldevs; d != NULL; d = d->next)//��ͷ��������
    {
        cout << "Device_" << idev + 1 << ":";
        cout << d->description << endl; ++idev;
    }

    if (idev == 0)
    {
        cout << "û���ҵ�����豸" << endl;
        return 1;
    }
    return 0;
}

//�������ݵ�һ���ṹ
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    //��ʱ���ת��Ϊ�ɶ�ģʽ
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    cout << timestr << " length:" << header->len << endl;
}

int main()
{
    int inum;//ѡ������������

    Find_device();
    cout << endl << "Please enter the interface number :";
    cin >> inum;
    if (inum < 1 || inum > idev)
    {
        cout << "input error!" << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, idev = 1; idev <= inum; d = d->next, idev++);//ָ��ָ��ѡ�е�adapter

    //��Ŀ��������
    adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
        //����2ʹ��ֵ65536�������ǿ������������MTU������ȷ��Ӧ�ó���ʼ�ս����������ݰ�
        //����3 PCAP_OPENFLAG_PROMISCUOUS ��ʾ�豸��������ģʽ
        //����4 ����ʱ

    //��ʧ�ܣ��ͷŵ��ռ�
    if (adhandle == NULL)
    {
        cout << endl << "Unable to open the adapter " << d -> description << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    cout << endl <<  "Listening on " << d->description << "....." << endl;
    
    //�ͷŸ�����ռ�еĿռ�
    pcap_freealldevs(alldevs);
    
    //��ʼ����
    pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}