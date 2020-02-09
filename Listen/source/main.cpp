#include <gtkmm.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <stdio.h>
#include <thread>
#define WINVER 0x0501
#define HAVE_REMOTE
#include <pcap.h>
#include <ws2tcpip.h>

#include "packet.h"
#include "Model.h"

#define PKTLIMIT 2000
using namespace std;

ModelColumns Columns;
treeColumns treeColumns;
Glib::RefPtr<Gtk::ListStore> m_refListModel;
Glib::RefPtr<Gtk::TreeStore> m_refTreeModel;
Glib::RefPtr<Gtk::TextBuffer> m_refTextBuffer;

Gtk::ScrolledWindow *m_ScrolledWindow1;
Gtk::ComboBoxText* Combo;
Gtk::Entry *Entry_Filter ;
Gtk::Button *Button_toggle;
Gtk::TextView *Textview;
Gtk::TreeModel::Row row_list;

packet pktlist[PKTLIMIT];
vector <string> if_list;
pcap_if_t *alldevs;
u_int netmask;
int curNumb = 0;
pcap_t *adhandle;
thread *t = nullptr;
string applayer;

int list_if(vector <string> &list);
int select_if(int inum, int count_if);
int setfilter(const string&);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void print(stringstream& ss, const u_char *pkt_data, int len) {
    //显示数据帧内容
    for (int i = 0; i < (int) len; ++i) {
        if (i != 0 && i % 16 == 0) {
            ss << "        ";
            for (int j = i - 16; j < i; ++j) {
                if(i-j == 8) ss << " ";
                unsigned char c = (pkt_data[j] > 32 && pkt_data[j] < 127) ? pkt_data[j] : '.';
                ss << c;
            }
            ss << "\n";
        }
        if (i % 16 == 0){
            ss << "0x" << setw(4) << setfill('0') << hex << i << "  ";
        }
        if(i%8 == 0) ss << " ";
        ss << setw(2) << setfill('0') << hex << (int)pkt_data[i] << " ";
        if (len - 1 == i) {
            for (int j = 0; j < 15 - i % 16; ++j) {
                ss << "   ";
            }
            ss << "        ";
            for (int j = i - i % 16; j <= i; ++j) {
                if(i-j == i%8) ss << " ";
                unsigned char c = (pkt_data[j] > 32 && pkt_data[j] < 127) ? pkt_data[j] : '.';
                ss << c;
            }
            ss << endl;
        }
    }
}

void run() {
    /* 开始捕捉 */
    pcap_loop(adhandle, 0, packet_handler, (u_char *) adhandle);
};

void on_button_start() {
    if(t!= nullptr ){
        delete t;
        t = nullptr;
        if(curNumb < PKTLIMIT) {
            pcap_breakloop(adhandle);
        }
        Button_toggle->set_label("start");
    }
    else {
        m_refListModel->clear();
        m_refTreeModel->clear();
        m_refTextBuffer->set_text("");
        Textview->set_buffer(m_refTextBuffer);
        curNumb = 0;

        string filterString = Entry_Filter->get_text();

        if(filterString == "dns"){
            applayer = filterString;
            filterString = "";
        }else applayer = "";
        if (setfilter(filterString) != -1) {
            t = new thread(run);
            t->detach();
            Button_toggle->set_label("stop");
        }
    }
}

void on_treeview_row_activated(const Gtk::TreeModel::Path& path,
                               Gtk::TreeViewColumn* /* column */)
{
    Gtk::TreeModel::iterator iter = m_refListModel->get_iter(path);
    if(iter)
    {
        Gtk::TreeModel::Row row = *iter;
        unsigned int selected = row[Columns.NO];

        //TODO

        createTree(m_refTreeModel, treeColumns, pktlist[selected-1]);

        stringstream ss;
        print(ss, pktlist[selected-1].pkt_data, pktlist[selected-1].len);

        m_refTextBuffer->set_text(ss.str());
        Textview->set_buffer(m_refTextBuffer);
        //print(it->pkt_data, it->len);
    }
}
void ScrollToEnd (int width, int height, int baseline)
{
    //adj->set_value (adj->get_upper());
}

void on_combo_changed()
{
    if(t!= nullptr ){
        delete t;
        t = nullptr;
        if(curNumb < PKTLIMIT) {
            pcap_breakloop(adhandle);
        }
        Button_toggle->set_label("start");
    }
    select_if(Combo->get_active_row_number() + 1, static_cast<int>(if_list.size()));
    //std::cout << "on_combo_changed(): Row=" << Combo->get_active_row_number() + 1 << endl;
}

int main(int argc, char **argv) {
    auto app = Gtk::Application::create(argc, argv, "WinpcapSniffer");

    char errbuf[PCAP_ERRBUF_SIZE];
    int count_if = 0;
    /* 获得设备列表 */
    if (pcap_findalldevs( &alldevs, errbuf) == -1) {
        char temp[300] = {'\0'};
        sprintf(temp, "Error in pcap_findalldevs: %s", errbuf);
        m_refTextBuffer->set_text(temp);
        Textview->set_buffer(m_refTextBuffer);
        exit(1);
    }
    for (pcap_if_t *d = alldevs; d; d = d->next)
        count_if++;

    list_if(if_list);

    Gtk::Window myWindow;
    Gtk::Box m_HBox(Gtk::ORIENTATION_HORIZONTAL);
    Gtk::Box m_VBox(Gtk::ORIENTATION_VERTICAL);
    Gtk::TreeView Listview;
    Gtk::TreeView Treeview ;

    //Gtk::ScrolledWindow m_ScrolledWindow1;
    Gtk::ScrolledWindow m_ScrolledWindow2;
    Gtk::ScrolledWindow m_ScrolledWindow3;
    Gtk::Label label("Filter: ");
    //Gtk::Button Button_start("Start");
    Textview = new Gtk::TextView();
    Button_toggle = new Gtk::Button("start");
    Entry_Filter = new Gtk::Entry();
    Combo = new Gtk::ComboBoxText(false);
    m_ScrolledWindow1 = new Gtk::ScrolledWindow();


    myWindow.set_title("winpcap sniffer");
    myWindow.set_border_width(5);
    myWindow.set_resizable(false);
    myWindow.set_default_size(700, 860);
    m_ScrolledWindow1->set_border_width(5);
    m_ScrolledWindow1->set_size_request(-1, 300);
    m_ScrolledWindow2.set_border_width(5);
    m_ScrolledWindow2.set_size_request(-1, 250);
    m_ScrolledWindow3.set_border_width(5);
    m_ScrolledWindow3.set_size_request(-1, 200);
    m_ScrolledWindow1->set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
    m_ScrolledWindow2.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
    m_ScrolledWindow3.set_policy(Gtk::POLICY_AUTOMATIC, Gtk::POLICY_AUTOMATIC);
    Textview->set_editable(false);
    Textview->set_monospace(true);
    m_HBox.set_border_width(5);
    m_HBox.set_spacing(5);
    Entry_Filter->set_size_request(500,-1);

    for (const auto &s:if_list)
        Combo->append(s.c_str());
    Combo->set_active(0);
    select_if(1, static_cast<int>(if_list.size()));

    myWindow.add(m_VBox);

    m_ScrolledWindow1->add(Listview);
    m_ScrolledWindow2.add(Treeview);
    m_ScrolledWindow3.add(*Textview);

    m_VBox.add(*Combo);
    m_VBox.pack_start(m_HBox);
    m_HBox.pack_start(label);
    m_HBox.pack_start(*Entry_Filter);
    m_HBox.pack_start(*Button_toggle);
    m_VBox.pack_start(*m_ScrolledWindow1);
    m_VBox.pack_start(m_ScrolledWindow2);
    m_VBox.pack_start(m_ScrolledWindow3);

    //Create the list model:
    m_refListModel = Gtk::ListStore::create(Columns);
    m_refTextBuffer = Gtk::TextBuffer::create();
    Listview.set_model(m_refListModel);

    //Create the Tree model:
    m_refTreeModel = Gtk::TreeStore::create(treeColumns);
    Treeview.set_model(m_refTreeModel);

    //All the items to be reordered with drag-and-drop:
    Treeview.set_reorderable();

    Listview.append_column("NO", Columns.NO);
    Listview.append_column("Time", Columns.Time);
    Listview.append_column("SrcIP", Columns.SrcIP);
    Listview.append_column("DstIP", Columns.DstIP);
    Listview.append_column("Protocol", Columns.Protocol);

    //Add the TreeView's view columns:
    Treeview.append_column("", treeColumns.str);


    //Button_start.signal_clicked().connect( sigc::ptr_fun(&on_button_start));
    Button_toggle->signal_clicked().connect( sigc::ptr_fun(&on_button_start));
    Listview.signal_row_activated().connect(sigc::ptr_fun(&on_treeview_row_activated) );
    Combo->signal_changed().connect(sigc::ptr_fun(&on_combo_changed) );

    myWindow.show_all_children();
    app->run(myWindow);


    return 0;
}


int list_if(vector <string> &list) {
    int i = 0;
    stringstream ss;
    /* 打印列表 */
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        i++;
        string str, temp;
        ss << i <<  ". " ;
        ss >> str;
        //str += d->name;
        if (d->description){
            str += " ";
            str += d->description;
        }
        else
            str += " (No description available)";
        str += " ";
        //char ip6str[128];
        for(auto a=d->addresses;a;a=a->next) {
            switch(a->addr->sa_family)
            {
                case AF_INET:
                    if (a->addr)
                        str += iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                    break;
                case AF_INET6:
                    //if (a->addr) str += ip6tos(a->addr, ip6str, sizeof(ip6str));
                    break;
                default:
                    break;
            }
        }
        list.push_back(str);
    }
    if (i == 0) {
        m_refTextBuffer->set_text("No interfaces found! Make sure WinPcap is installed ");
        Textview->set_buffer(m_refTextBuffer);
        return -1;
    }
    return 0;
}

int select_if(int inum, const int count_if) {
    int i = count_if;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (inum < 1 || inum > count_if) {
        m_refTextBuffer->set_text("Interface number out of range ");
        Textview->set_buffer(m_refTextBuffer);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    pcap_if_t *d;
    /* 跳转到已选设备 */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* 打开适配器 */
    if ((adhandle = pcap_open_live(d->name,  // 设备名
                              65536,     // 要捕捉的数据包的部分
            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              1,         // 混杂模式
                              1000,      // 读取超时时间
                              errbuf     // 错误缓冲池
    )) == nullptr) {
        char temp[500] = {'\0'};
        sprintf(temp, "Unable to open the adapter. %s is not supported by WinPcap", d->name);
        m_refTextBuffer->set_text(temp);
        Textview->set_buffer(m_refTextBuffer);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    if (d->addresses != nullptr)
        /* 获得接口第一个地址的掩码 */
        netmask = ((struct sockaddr_in *) (d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* 如果接口没有地址，那么我们假设一个C类的掩码 */
        netmask = 0xffffff;

    return 0;
}

int setfilter(const string &packet_filter) {
    struct bpf_program fcode{};

    //input the design filter
    if (pcap_compile(adhandle, &fcode, packet_filter.c_str(), 1, netmask) < 0) {
        m_refTextBuffer->set_text("Unable to compile the packet filter. Check the syntax.");
        Textview->set_buffer(m_refTextBuffer);
        return -1;
    }

    //设置过滤器
    if (pcap_setfilter(adhandle, &fcode) < 0) {
        m_refTextBuffer->set_text("Error setting the filter.");
        Textview->set_buffer(m_refTextBuffer);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    return 0;
}

/* 回调函数，当收到每一个数据包时会被libpcap所调用 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);


    if(curNumb < PKTLIMIT){

        cppkt(header->len, pkt_data, pktlist[curNumb]);
        pktlist[curNumb].no = curNumb+1;
        pktlist[curNumb].time = timestr;
        headle_pkt(pktlist[curNumb]);

        m_ScrolledWindow1->get_vadjustment()->set_value(m_ScrolledWindow1->get_vadjustment()->get_upper());

        string src = getSrcIPAddr(pktlist[curNumb]);
        string dst = getDstIPAddr(pktlist[curNumb]);
        string proto = pktlist[curNumb].cur_protocol;

        if(applayer == "" ||(applayer == "dns" && pktlist[curNumb].cur_protocol == "DNS"))
        {
            row_list = *(m_refListModel->append());
            row_list[Columns.NO] = ++curNumb;
            row_list[Columns.Time] = timestr;
            row_list[Columns.SrcIP] = src;
            row_list[Columns.DstIP] = dst;
            row_list[Columns.Protocol] = proto;
        }





        //cout << ++curNumb << " " << timestr << endl;//" " << src << " " << dst << " " << proto << endl;
    }
    else{
        pcap_breakloop((pcap_t*)param);
    }
}

/* 将数字类型的IP地址转换成字符串类型的 */
char *iptos(u_long in) {
    static char output[12][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = static_cast<short>(which + 1 == 12 ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen) {
    socklen_t sockaddrlen;

#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if(getnameinfo(sockaddr,
                   sockaddrlen,
                   address,
                   static_cast<DWORD>(addrlen),
                   nullptr,
                   0,
                   NI_NUMERICHOST) != 0) address = nullptr;

    return address;
}