#ifndef WINPCAP_PROCOL_H
#define WINPCAP_PROCOL_H

//Mac头部，总长度14字节
typedef struct ether_header {
    unsigned char dstmac[6]; //目标mac地址
    unsigned char srcmac[6]; //源mac地址
    unsigned short eth_type; //以太网类型
} eth_hdr;

//arp头部
typedef struct arp_header {
    unsigned short htype;       //硬件类型
    unsigned short ptype;       //协议类型
    unsigned char hlen;         //硬件地址长度
    unsigned char plen;         //协议长度
    unsigned short oper;        //操作类型
    unsigned char sourceMac[6]; //源mac地址
    unsigned char sourceIP[4];  //源ip地址
    unsigned char destMac[6];   //目标mac
    unsigned char destIP[4];    //目标IP
} arp_hdr;

//IP头部，总长度20字节
typedef struct ipv4_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ihl:4;            //首部长度
    unsigned char version:4;        //版本 
#else
    unsigned char version:4;        //版本
    unsigned char ihl:4;            //首部长度
#endif
    unsigned char tos;              //服务类型
    unsigned short tot_len;         //总长度
    unsigned short id;              //标志
    unsigned short frag_off;        //分片偏移
    unsigned char ttl;              //生存时间
    unsigned char protocol;         //协议
    unsigned short chk_sum;         //检验和
    unsigned char sourceIP[4];      //源IP地址
    unsigned char destIP[4];        //目的IP地址
} ip_hdr;

typedef struct ipv6_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char priority:4;              //优先级（8 bit）
    unsigned char version:4;             //版本号（4 bit）
    unsigned char flow_lbl0:4;
    unsigned char priority1:4;
#else
    unsigned char version:4,
    unsigned char priority;
#endif
    unsigned short flow_lbl;                //流标签（20 bit）
    unsigned short payload_len;          //报文长度（16 bit）
    unsigned char nexthdr;               //下一头部（8 bit）
    unsigned char hop_limit;             //跳数限制（8 bit）

    unsigned char Srcv6[16];             //源IPv6地址（128 bit）
    unsigned char Destv6[16];            //目的IPv6地址（128 bit）
}ipv6_hdr;

//TCP头部，总长度20字节
typedef struct tcp_header {
    unsigned short src_port;     //源端口号
    unsigned short dst_port;     //目的端口号
    unsigned int seq_no;         //序列号
    unsigned int ack_no;         //确认号
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char reserved_1:4; //保留6位中的4位首部长度
    unsigned char thl:4;        //tcp头部长度
    unsigned char flag:6;       //6位标志
    unsigned char reseverd_2:2; //保留6位中的2位
#else
    unsigned char thl:4;        //tcp头部长度
    unsigned char reserved_1:4; //保留6位中的4位首部长度
    unsigned char reseverd_2:2; //保留6位中的2位
    unsigned char flag:6;       //6位标志 
#endif
    unsigned short wnd_size;    //16位窗口大小
    unsigned short chk_sum;     //16位TCP检验和
    unsigned short urgt_p;      //16为紧急指针
} tcp_hdr;

//UDP头部，总长度8字节
typedef struct udp_header {
    unsigned short src_port; //远端口号
    unsigned short dst_port; //目的端口号
    unsigned short uhl;      //udp头部长度
    unsigned short chk_sum;  //16位udp检验和
} udp_hdr;

//ICMP头部，总长度4字节
typedef struct icmp_header {
    unsigned char icmp_type;    //类型
    unsigned char code;         //代码
    unsigned short chk_sum;     //16位检验和
} icmp_hdr;

#endif //WINPCAP_PROCOL_H
