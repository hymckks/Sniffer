#include <iostream>
#include <cstdio>
#include "pcap.h"


using namespace std;

pcap_if_t* alldevs;//初始化指向pcap_if_t类型的指针，代表链表
pcap_if_t* d;//初始化指针用来遍历
int idev = 0;//记录设备个数
pcap_t* adhandle;//适配器描述符

char errbuf[PCAP_ERRBUF_SIZE];

int Find_device()
{
    //获取本地网络适配器设备
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)//函数返回一个pcap_if结构的链表
    {
        cout << stderr << "Error in pcap_findalldevs_ex: " << endl << errbuf;
        return 1;//原文档写的exit(1)，与该写法等价，表示异常退出
    }

    //输出设备名称
    for (d = alldevs; d != NULL; d = d->next)//从头遍历链表
    {
        cout << "Device_" << idev + 1 << ":";
        cout << d->description << endl; ++idev;
    }

    if (idev == 0)
    {
        cout << "没有找到相关设备" << endl;
        return 1;
    }
    return 0;
}

//处理数据的一个结构
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    //将时间戳转化为可读模式
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    cout << timestr << " length:" << header->len << endl;
}

int main()
{
    int inum;//选择的适配器标号

    Find_device();
    cout << endl << "Please enter the interface number :";
    cin >> inum;
    if (inum < 1 || inum > idev)
    {
        cout << "input error!" << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, idev = 1; idev <= inum; d = d->next, idev++);//指针指向选中的adapter

    //打开目标适配器
    adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
        //参数2使用值65536高于我们可能遇到的最大MTU，可以确保应用程序始终接收整个数据包
        //参数3 PCAP_OPENFLAG_PROMISCUOUS 表示设备开到混杂模式
        //参数4 读超时

    //打开失败，释放掉空间
    if (adhandle == NULL)
    {
        cout << endl << "Unable to open the adapter " << d -> description << endl;
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    cout << endl <<  "Listening on " << d->description << "....." << endl;
    
    //释放该链表占有的空间
    pcap_freealldevs(alldevs);
    
    //开始捕获
    pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}