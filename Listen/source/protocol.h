//Mac头部，总长度14字节
typedef struct _eth_hdr {
    unsigned char dstmac[6]; //目标mac地址
    unsigned char srcmac[6]; //源mac地址
    unsigned short eth_type; //以太网类型
} eth_hdr;

//arp头部
typedef struct _arp_hdr {
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
typedef struct _ipv4_hdr {
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

typedef struct _ipv6_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char priority0:4;              //优先级（8 bit）
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
typedef struct _tcp_hdr {
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
typedef struct _udp_hdr {
    unsigned short src_port; //远端口号
    unsigned short dst_port; //目的端口号
    unsigned short uhl;      //udp头部长度
    unsigned short chk_sum;  //16位udp检验和
} udp_hdr;

typedef struct _dns_hdr {

};

//ICMP头部，总长度4字节
typedef struct _icmp_hdr {
    unsigned char icmp_type;    //类型
    unsigned char code;         //代码
    unsigned short chk_sum;     //16位检验和
    //下面是回显头
    unsigned short icmp_id; //用来惟一标识此请求的ID号，通常设置为进程ID
    unsigned short  icmp_sequence; //序列号
} icmp_hdr;

typedef struct __icmp6_hdr {
    unsigned char     icmp6_type;   /* type field */
    unsigned char     icmp6_code;   /* code field */
    unsigned short    icmp6_cksum;  /* checksum field */
    union {
        unsigned int    icmp6_un_data32[1]; /* type-specific field */
        unsigned short  icmp6_un_data16[2]; /* type-specific field */
        unsigned char   icmp6_un_data8[4];  /* type-specific field */
    } icmp6_dataun;
}icmp6_hdr;

typedef struct __dns_hdr{
    unsigned short trans_id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answer_rrs;
    unsigned short authority_rrs;
    unsigned short additional_rrs;
}dns_hdr;
