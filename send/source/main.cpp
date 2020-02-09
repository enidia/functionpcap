#include <stdio.h>
#define HAVE_REMOTE
#include "protocol.h"
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ws2tcpip.h>
#include <gtk/gtk.h>
#include <string>
#include <iostream>
#include <sstream>
#include <winsock.h>
#include <winsock2.h>   //该头文件定义了Socket编程的功能
#include <httpext.h>    //该头文件支持HTTP请求
#include <windef.h>     //该头文件定义了Windows的所有数据基本型态
#include <Nb30.h>
#include <vector>
#include <fstream>

using namespace std;
int size=0;
pcap_if_t *dev;
pcap_if_t *allDevs;
int count = 0;
int decide = 0;
string smac;
boolean flag = true;
string ips;//获取本机IP
unsigned  char *target[1000];
int line = 0;
int pro =0;
unsigned char Smac[6];
unsigned char Dmac[6]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
unsigned short Type = 0x0800;
unsigned char Ipd[4] = {0xFF,0xFF,0xFF,0xFF};
unsigned char Ips[4];

unsigned char Version;        //版本
unsigned char Ihl;            //首部长度
unsigned char Tos;              //服务类型
unsigned short Tot_len;         //总长度
unsigned short Id;              //标志
unsigned short Frag_off;        //分片偏移
unsigned char Ttl;              //生存时间
unsigned char Protocol;         //协议
unsigned short Chk_sum;

unsigned char *packet;//发送的数据包
GtkTextBuffer *ipvbuffer;
GtkTextBuffer *ihlbuffer;
GtkTextBuffer *tosbuffer;
GtkTextBuffer *tolbuffer;
GtkTextBuffer *idbuffer;
GtkTextBuffer *fragbuffer;
GtkTextBuffer *ttlbuffer;
GtkTextBuffer *probuffer;
GtkTextBuffer *ipsbuffer;
GtkTextBuffer *etherde;
GtkTextBuffer *typebuffer;
GtkTextBuffer *ipdbuffer;
GtkTextBuffer *etherso;
GtkTextBuffer *databuffer;
GtkTextBuffer *havebuffer;
GtkTextBuffer *buffer;

ip_hdr IPhead;

char errbuf[PCAP_ERRBUF_SIZE];
#define IPTOSBUFFERS    12
/*void CreatTxt(GtkButton *button,gpointer user_data)//创建txt文件
{
    char* pathName = "save.txt"; // 你要创建文件的路径
    ofstream fout(pathName);
    if (fout) { // 如果创建成功
        fout<<endl;
        for (int i = 0,j=0;packet[i]!='\0'; i++,j++)
        {
            if(j==6)
            {
                fout<<endl;
                j=6;
            }
            fout <<" "<<packet[i]<<endl; // 使用与cout同样的方式进行写入
        }
        fout << endl;
        fout.close();  // 执行完操作后关闭文件句柄
    }
}*/
USHORT CheckSum(USHORT *buffer, int size)//校验和
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size)
    {
        cksum += *(UCHAR*)buffer;
    }
    /*对每个16bit进行二进制反码求和*/
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (USHORT)(~cksum);
}
int SplitString(const std::string& s,
                std::vector<std::string>& v,const std::string& c)
{
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while(std::string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2-pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if(pos1 != s.length())
        v.push_back(s.substr(pos1));
    if(v.size()<2)
        return -1;
    else return 0;
}
unsigned char String2Hex(const string& p)
{
    long long result;
    return result = strtoll(p.c_str(), nullptr, 16);
}
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
int changeMtoH(unsigned char *mac,string &macstr)
{
    vector<string> v;
    SplitString(macstr, v, "-");
    for(int i = 0; i < 6; i++)
        mac[i] = String2Hex(v[i]);
}
int changeItoH(unsigned char *ip,string &str)
{
    vector<string> v;
    SplitString(str, v, ".");
    for(int i = 0; i < 4; i++)
        ip[i] = atoi(v[i].c_str());
}
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif


    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   addrlen,
                   NULL,
                   0,
                   NI_NUMERICHOST) != 0) address = NULL;

    return address;
}
void Search(GtkButton *button,gpointer user_data) {
    stringstream ss;
        int i = 1;
        for (pcap_if_t *d = allDevs; d!= NULL; d = d->next, i++) {
            pcap_addr_t *a;
            char ip6str[128];
            ss << "第" << i << "个网卡:"<<endl;
            ss << "设备名:" << d->name << "\n";

            if (d->description)
                ss << d->description << "\n";

            /* IP addresses */
            for (a = d->addresses; a; a = a->next) {
                switch (a->addr->sa_family) {
                    case AF_INET:
                        ss << "Address Family Name: AF_INET\n";
                        if (a->addr) {
                            ss << "the IPV4 is :\n" << iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr) << "\n";
                        }
                        if (a->netmask)
                            ss << "Netmask:\n" << iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr) << "\n";
                        break;

                    case AF_INET6:
                        ss << "Address Family Name: AF_INET6\n";
                        if (a->addr) {
                            ss << "the Ipv6 is\n";
                            ss << ip6tos(a->addr, ip6str, sizeof(ip6str)) << "\n";
                        }
                        break;

                    default:
                        ss << "Address Family Name: Unknown\n";
                        break;
                }
            }
            ss << "\n";
        }
        count = i - 1;
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(user_data), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data),ss.str().c_str(),ss.str().size());
    //  gtk_text_buffer_insert(GTK_TEXT_BUFFER(user_data), &end, ss.str().c_str(), ss.str().size());
}
void LOOPSEND(GtkButton *button,gpointer user_data){

    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(havebuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(havebuffer),"0000",-1);//

        for (; pro <= line; pro++) {
            pcap_t *fp;
            char errbuf[PCAP_ERRBUF_SIZE];
            int count = size;
            int time = 1000;
            if ((fp = pcap_open(dev->name,            // 设备名
                                count,                // 要捕获的部分 (只捕获前100个字节)
                                PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                                time,               // 读超时时间
                                NULL,               // 远程机器验证
                                errbuf              // 错误缓冲
            )) == NULL) {
                printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
            }
            if (pcap_sendpacket(fp, target[pro], count) != 0) {
            }
        }
}
void Re(GtkButton *button,gpointer user_data)
{
    line = 0;
    pro = 0;
    GtkTextIter start,end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(havebuffer), &start, &end);
    char text[10];
    sprintf(text, "%05X", line-pro);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(havebuffer),text,-1);
}//刷新程序
void Ensure(GtkButton *button,gpointer user_data){
    gchar *buffer;
    GtkTextIter start,end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(user_data),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(user_data),&start,&end,FALSE);
    for(int i=0;buffer[i] != '\0';i++)
        if (!isdigit(buffer[i])) {
            GtkTextIter start, end;
            gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(user_data), &start, &end);
            gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data),"不要随意输入",-1);
            return;
        }
    if(count == 0)
    {
        GtkTextIter start, end;
        gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(user_data), &start, &end);
        gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data),"请先搜索",-1);
        return;
    }
    decide = atoi (buffer);
    if(decide>count||decide<1) {
        decide = 0;
        GtkTextIter start, end;
        gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(user_data), &start, &end);
        gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data),"请输入正确的数字",-1);
        return;
    }
    int charge = count + 1 - decide;
    for(dev=allDevs;charge != count ;charge++,dev=dev->next);
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(user_data), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data),"确认成功",-1);
    for (pcap_addr_t *a = dev->addresses; a; a = a->next) {
        if (a->addr->sa_family == AF_INET)
            if (a->addr) {
                ips = iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr);
            }
    }
}
void CheckIP(void)    //定义checkIP函数，用于取本机的ip地址
{
    WSADATA wsaData;
    char name[155];      //定义用于存放获得主机名的变量
    PHOSTENT hostinfo;

//调用MAKEWORD()获得Winsocl版本的正确值，用于下面的加载Winscok库
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) == 0)
    {   //加载Winsock库，如果WSAStartup()函数返回值为0，说明加载成功，程序可以继续往下执行
        if (gethostname(name, sizeof(name)) == 0)
        { //如果成功，将本地主机名存放入由name参数指定的缓冲区中
            if ((hostinfo = gethostbyname(name)) != NULL)
            { //这是获取主机，如果获得主机名成功的话，将返回一个指针，指向hostinfo,hostinfo为PHOSTENT型的变量。
               // ips = inet_ntoa(*(struct in_addr *)*hostinfo->h_addr_list);
//inet_addr()函数把地址串转换为IP地址
//调用inet_ntoa()函数,将hostinfo结构变量中的h_addr_list转化为标准的IP地址(如202.197.11.12.)
                //printf(" IP地址: %s/n", ip);        //输出IP地址
            }
        }
        WSACleanup();         //卸载Winsock库，并释放所有资源
    }
}
int getMAC()     //用NetAPI来获取网卡MAC地址
{
    NCB ncb;     //定义一个NCB(网络控制块)类型的结构体变量ncb
    typedef struct _ASTAT_     //自定义一个结构体_ASTAT_
    {
        ADAPTER_STATUS   adapt;
        NAME_BUFFER   NameBuff[30];
    }ASTAT, *PASTAT;
    ASTAT Adapter;

    typedef struct _LANA_ENUM     //自定义一个结构体_LANA_ENUM
    {
        UCHAR length;
        UCHAR lana[MAX_LANA];     //存放网卡MAC地址
    }LANA_ENUM;
    LANA_ENUM lana_enum;

//   取得网卡信息列表
    UCHAR uRetCode;
    memset(&ncb, 0, sizeof(ncb));     //将已开辟内存空间ncb 的值均设为值 0
    memset(&lana_enum, 0, sizeof(lana_enum));     //清空一个结构类型的变量lana_enum，赋值为0
//对结构体变量ncb赋值
    ncb.ncb_command = NCBENUM;     //统计系统中网卡的数量
    ncb.ncb_buffer = (unsigned char *)&lana_enum; //ncb_buffer成员指向由LANA_ENUM结构填充的缓冲区
    ncb.ncb_length = sizeof(LANA_ENUM);
//向网卡发送NCBENUM命令，以获取当前机器的网卡信息，如有多少个网卡，每个网卡的编号（MAC地址）
    uRetCode = Netbios(&ncb); //调用netbois(ncb)获取网卡序列号
    if (uRetCode != NRC_GOODRET)
        return uRetCode;

//对每一个网卡，以其网卡编号为输入编号，获取其MAC地址
    for (int lana = 0; lana < lana_enum.length; lana++)
    {
        ncb.ncb_command = NCBRESET;   //对网卡发送NCBRESET命令，进行初始化
        ncb.ncb_lana_num = lana_enum.lana[lana];
        uRetCode = Netbios(&ncb);
    }
    if (uRetCode != NRC_GOODRET)
        return uRetCode;

//   准备取得接口卡的状态块取得MAC地址
    memset(&ncb, 0, sizeof(ncb));
    ncb.ncb_command = NCBASTAT;    //对网卡发送NCBSTAT命令，获取网卡信息
    ncb.ncb_lana_num = lana_enum.lana[0];     //指定网卡号，这里仅仅指定第一块网卡，通常为有线网卡
    strcpy((char*)ncb.ncb_callname, "*");     //远程系统名赋值为*
    ncb.ncb_buffer = (unsigned char *)&Adapter; //指定返回的信息存放的变量
    ncb.ncb_length = sizeof(Adapter);
//接着发送NCBASTAT命令以获取网卡的信息
    uRetCode = Netbios(&ncb);
//   取得网卡的信息，并且如果网卡正常工作的话，返回标准的冒号分隔格式。
    if (uRetCode != NRC_GOODRET)
        return uRetCode;
//把网卡MAC地址格式转化为常用的16进制形式,输出到字符串mac中
    char t_mac[18];
    sprintf(t_mac, "%02X-%02X-%02X-%02X-%02X-%02X",
            Adapter.adapt.adapter_address[0],
            Adapter.adapt.adapter_address[1],
            Adapter.adapt.adapter_address[2],
            Adapter.adapt.adapter_address[3],
            Adapter.adapt.adapter_address[4],
            Adapter.adapt.adapter_address[5]
    );
    smac=t_mac;
    return 0;
}
int GetMac(void)   //主函数，程序的入口
{
    CheckIP();       //调用CheckIP()函数获得，输出IP地址
    getMAC();   //调用getMAC()函数获得，输出MAC地址
    return 0;
}
void Ipo(GtkButton *button,gpointer user_data){
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(havebuffer), &start, &end);
    char text[10];
    sprintf(text, "%05X", line-pro);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(havebuffer),text,-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipvbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(ipvbuffer),"4",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ihlbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(ihlbuffer),"5",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(tosbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(tosbuffer),"00",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(tolbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(tolbuffer),"20",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(idbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(idbuffer),"0000",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(fragbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(fragbuffer),"0000",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ttlbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(ttlbuffer),"128",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(probuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(probuffer),"06",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(etherde), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(etherde),"FF-FF-FF-FF-FF-FF",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(etherso), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(etherso),smac.c_str(),-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipsbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(ipsbuffer),ips.c_str(),-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(typebuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(typebuffer),"0800",-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipdbuffer), &start, &end);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(ipdbuffer),"255.255.255.255",-1);
}
void Cpo(GtkButton *button,gpointer user_data){
    gchar *buffer;
    GtkTextIter start,end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(havebuffer), &start, &end);
    char text[10];
    sprintf(text, "%05X", line-pro+1);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(havebuffer),text,-1);//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipvbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(ipvbuffer),&start,&end,FALSE);
    string tipv = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ihlbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(ihlbuffer),&start,&end,FALSE);
    string tihl = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(tosbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(tosbuffer),&start,&end,FALSE);
    string ttos = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(tolbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(tolbuffer),&start,&end,FALSE);
    string ttol = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(idbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(idbuffer),&start,&end,FALSE);
    string tid = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(fragbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(fragbuffer),&start,&end,FALSE);
    string tfrag = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ttlbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(ttlbuffer),&start,&end,FALSE);
    string tttl = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(probuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(probuffer),&start,&end,FALSE);
    string tpro = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(etherde),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(etherde),&start,&end,FALSE);
    string tethd = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(etherso),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(etherso),&start,&end,FALSE);
    string teths = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipsbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(ipsbuffer),&start,&end,FALSE);
    string tips = buffer;
    if(tips.size()<7||tips.size()>15)
    {
        gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipsbuffer), &start, &end);
        gtk_text_buffer_set_text(GTK_TEXT_BUFFER(ipsbuffer),"请写入源IP地址！",-1);//
        return;
    }
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(typebuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(typebuffer),&start,&end,FALSE);
    string ttype = buffer;//
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(ipdbuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(ipdbuffer),&start,&end,FALSE);
    string tipd = buffer;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(databuffer),&start,&end);
    buffer = gtk_text_buffer_get_text(GTK_TEXT_BUFFER(databuffer),&start,&end,FALSE);
    string data = buffer;

    Tot_len = data.size() + 20;
    packet=new unsigned char[Tot_len+14];

    changeMtoH(packet,tethd);
    changeMtoH(packet+6,teths);
    string first = ttype.substr(0,2);
    string follow = ttype.substr(2,2);
    packet[12] = String2Hex(first);
    packet[13] = String2Hex(follow);
    packet[14] = (atoi(tipv.c_str()) << 4 | atoi(tihl.c_str()));
    packet[15] = String2Hex(ttos);
    packet[16] = Tot_len >>  8;
    packet[17] = Tot_len | 0x0F;
    first = tid.substr(0,2);
    follow = tid.substr(2,2);
    packet[18] = String2Hex(first);
    packet[19] = String2Hex(follow);

    first = tfrag.substr(0,2);
    follow = tfrag.substr(2,2);
    packet[20] = String2Hex(first);
    packet[21] = String2Hex(follow);

    packet[22]=atoi(tttl.c_str());
    packet[23]=atoi(tpro.c_str());

    Chk_sum = CheckSum((USHORT*)packet,atoi(tihl.c_str()));
    packet[24] = Chk_sum >>  8;
    packet[25] = Chk_sum | 0x0F;

    changeItoH(packet+26,tips);
    changeItoH(packet+30,tipd);

    target[line]=packet;
    line++;
    for(int i = 34;i<Tot_len+14;i++)
    {
        packet[i] = (char)data[i];
    }
    size = Tot_len+14;
    return;
}
void Exit(GtkButton *button,gpointer user_data){//退出系统
    exit(0);
}
void Signel(GtkButton *button,gpointer user_data){//dev为要发送的网络端口
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(havebuffer), &start, &end);
    char text[10];
    sprintf(text, "%05X", line-pro-1);
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(havebuffer),text,-1);//
    gchar *buffer;

    //for(int i=pro;i<line;i++) {
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];
        int count = size;
        int time = 1000;
        if ((fp = pcap_open(dev->name,            // 设备名
                            count,                // 要捕获的部分 (只捕获前100个字节)
                            PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                            time,               // 读超时时间
                            NULL,               // 远程机器验证
                            errbuf              // 错误缓冲
        )) == NULL) {
            printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
        }
        if (pcap_sendpacket(fp, target[pro],count ) != 0) {
            printf("\nError sending the packet: \n");
            gtk_text_buffer_set_text(GTK_TEXT_BUFFER(havebuffer),"No package",-1);
        }
  //  }
   pro++;
}
int main(int argc, char **argv)
{
    if(pcap_findalldevs(&allDevs,errbuf)>0){//获取网卡的链表
        printf("can not find!");
        return -1;
    }
    GetMac();
    gtk_init(&argc,&argv);
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);//初始化一个window窗口
    gtk_window_set_title(GTK_WINDOW(window),"数据包发送工具");
    gtk_window_set_default_size(GTK_WINDOW(window),1400,900);
    g_signal_connect_swapped(G_OBJECT(window),"destroy",G_CALLBACK(gtk_main_quit),NULL);

    GtkWidget *fixed = gtk_fixed_new();
    gtk_container_add(GTK_CONTAINER(window),fixed);//创建容器


    GtkWidget *box = gtk_text_view_new();
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(box));
    gtk_fixed_put(GTK_FIXED(fixed),box,20,20);
    gtk_widget_set_size_request(box,600,850);//用于用户网卡信息显示

    GtkWidget *ethd = gtk_text_view_new();
    etherde = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ethd));
    gtk_fixed_put(GTK_FIXED(fixed),ethd,900,20);
    gtk_widget_set_size_request(ethd,160,40);//制作的以太帧

    GtkWidget *label_one = gtk_label_new("对方MAC地址,默认广播");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_one,900,70);

    GtkWidget *label_two = gtk_label_new("本机MAC地址,默认网口");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_two,1100,70);

    GtkWidget *type = gtk_text_view_new();
    typebuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(type));
    gtk_fixed_put(GTK_FIXED(fixed),type,900,100);
    gtk_widget_set_size_request(type,160,40);//输入对应协议

    GtkWidget *label_five = gtk_label_new("协议类型:");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_five,900,160);

    GtkWidget *ipdes = gtk_text_view_new();
    ipdbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ipdes));
    gtk_fixed_put(GTK_FIXED(fixed),ipdes,900,190);
    gtk_widget_set_size_request(ipdes,160,40);//输入对方IP


    GtkWidget *label_y = gtk_label_new("拥有发送次数");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_y,900,460);

    GtkWidget *have = gtk_text_view_new();
    havebuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(have));
    gtk_fixed_put(GTK_FIXED(fixed),have,900,490);
    gtk_widget_set_size_request(have,100,40);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    GtkWidget *label_six = gtk_label_new("IP version");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_six,1200,160);

    GtkWidget *ipver = gtk_text_view_new();
    ipvbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ipver));
    gtk_fixed_put(GTK_FIXED(fixed),ipver,1200,190);
    gtk_widget_set_size_request(ipver,80,40);//输入版本

    GtkWidget *label_seven = gtk_label_new("首部长度");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_seven,1200,220);

    GtkWidget *ihl = gtk_text_view_new();
    ihlbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ihl));
    gtk_fixed_put(GTK_FIXED(fixed),ihl,1200,250);
    gtk_widget_set_size_request(ihl,80,40);//首部

    GtkWidget *label_eight = gtk_label_new("服务类型");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_eight,1200,280);

    GtkWidget *tos = gtk_text_view_new();
    tosbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tos));
    gtk_fixed_put(GTK_FIXED(fixed),tos,1200,310);
    gtk_widget_set_size_request(tos,80,40);//服务类型

    GtkWidget *label_night = gtk_label_new("总长度");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_night,1200,340);

    GtkWidget *tol = gtk_text_view_new();
    tolbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tol));
    gtk_fixed_put(GTK_FIXED(fixed),tol,1200,370);
    gtk_widget_set_size_request(tol,80,40);//总长

    GtkWidget *label_ten = gtk_label_new("标志位");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_ten,1200,400);

    GtkWidget *id = gtk_text_view_new();
    idbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(id));
    gtk_fixed_put(GTK_FIXED(fixed),id,1200,430);
    gtk_widget_set_size_request(id,80,40);//标记

    GtkWidget *label_ele = gtk_label_new("分片偏移");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_ele,1200,460);

    GtkWidget *frag = gtk_text_view_new();
    fragbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(frag));
    gtk_fixed_put(GTK_FIXED(fixed),frag,1200,490);
    gtk_widget_set_size_request(frag,80,40);//分片偏移

    GtkWidget *label_twl = gtk_label_new("生存时间");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_twl,1200,520);

    GtkWidget *ttl = gtk_text_view_new();
    ttlbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ttl));
    gtk_fixed_put(GTK_FIXED(fixed),ttl,1200,550);
    gtk_widget_set_size_request(ttl,80,40);//生存时间

    GtkWidget *label_thi = gtk_label_new("下一协议");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_thi,1200,580);

    GtkWidget *pro = gtk_text_view_new();
    probuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(pro));
    gtk_fixed_put(GTK_FIXED(fixed),pro,1200,610);
    gtk_widget_set_size_request(pro,80,40);//传输层

    GtkWidget *label_data = gtk_label_new("用户数据");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_data,950,650);

    GtkWidget *data = gtk_text_view_new();
    databuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(data));
    gtk_fixed_put(GTK_FIXED(fixed),data,800,700);
    gtk_widget_set_size_request(data,400,150);//传输层

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    GtkWidget *label_three = gtk_label_new("对方的IP,默认255.255.255.255");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_three,900,260);

    GtkWidget *ipsor = gtk_text_view_new();
    ipsbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ipsor));
    gtk_fixed_put(GTK_FIXED(fixed),ipsor,900,290);
    gtk_widget_set_size_request(ipsor,160,40);//输入本机Ip

    GtkWidget *label_four = gtk_label_new("本机的IP,默认IPV4");	// 创建标签
    gtk_fixed_put(GTK_FIXED(fixed), label_four,900,360);

    GtkWidget *eths = gtk_text_view_new();
    etherso = gtk_text_view_get_buffer(GTK_TEXT_VIEW(eths));
    gtk_fixed_put(GTK_FIXED(fixed),eths,1100,20);
    gtk_widget_set_size_request(eths,160,40);//制作的以太帧

    GtkWidget *choose = gtk_text_view_new();
    GtkTextBuffer *bufferchoose = gtk_text_view_get_buffer(GTK_TEXT_VIEW(choose));
    gtk_fixed_put(GTK_FIXED(fixed),choose,640,20);
    gtk_widget_set_size_request(choose,100,40);//用于用户选择网卡

    GtkWidget *button4 = gtk_button_new_with_label("确认选择网卡");
    gtk_fixed_put(GTK_FIXED(fixed),button4,640,140);
    g_signal_connect(button4,"pressed",G_CALLBACK(Ensure),bufferchoose);
    gtk_widget_set_size_request(button4,80,40);

    GtkWidget *button3 = gtk_button_new_with_label("搜索网卡");//搜索网卡的按钮
    gtk_fixed_put(GTK_FIXED(fixed),button3,640,80);
    g_signal_connect(button3,"pressed",G_CALLBACK(Search),buffer);
    gtk_widget_set_size_request(button3,80,40);
    /*按钮创建*/
    GtkWidget *button5 = gtk_button_new_with_label("默认");//编辑以太帧
    gtk_fixed_put(GTK_FIXED(fixed),button5,640,200);
    g_signal_connect(button5,"pressed",G_CALLBACK(Ipo),NULL);
    gtk_widget_set_size_request(button5,80,40);

    GtkWidget *button1 = gtk_button_new_with_label("发送数据包");//发送数据包的按钮点击
    gtk_fixed_put(GTK_FIXED(fixed),button1,640,320);
    g_signal_connect(button1,"pressed",G_CALLBACK(Signel),NULL);
    gtk_widget_set_size_request(button1,80,40);

    GtkWidget *button6 = gtk_button_new_with_label("编辑完成");//编辑IP帧
    gtk_fixed_put(GTK_FIXED(fixed),button6,640,260);
    g_signal_connect(button6,"pressed",G_CALLBACK(Cpo),NULL);
    gtk_widget_set_size_request(button6,80,40);

    GtkWidget *button7 = gtk_button_new_with_label("全部发送");//保存数据帧
    gtk_fixed_put(GTK_FIXED(fixed),button7,640,380);
    g_signal_connect(button7,"pressed",G_CALLBACK(LOOPSEND),NULL);
    gtk_widget_set_size_request(button7,80,40);

    GtkWidget *button8 = gtk_button_new_with_label("退出系统");//退出
    gtk_fixed_put(GTK_FIXED(fixed),button8,640,500);
    g_signal_connect(button8,"pressed",G_CALLBACK(Exit),NULL);
    gtk_widget_set_size_request(button8,80,40);

    GtkWidget *button2 = gtk_button_new_with_label("刷新发包区");//关闭系统的退出按钮
    gtk_fixed_put(GTK_FIXED(fixed),button2,640,440);
    g_signal_connect(button2,"pressed",G_CALLBACK(Re),NULL);
    gtk_widget_set_size_request(button2,80,40);

    gtk_widget_show_all(window);
    gtk_main();

    pcap_freealldevs(dev);
    pcap_freealldevs(allDevs);
}