#include "protocol.h"
#include <iostream>
#include <string>
#include <gtkmm.h>
#include <pcap.h>
#include <sstream>
#include <list>

using namespace std;

class treeColumns;
typedef struct packet {
    int no;
    string time;
    unsigned char *pkt_data;
    unsigned int len;
    unsigned int mac_size, ip_size, trans_size;
    string cur_protocol;


}packet;

string getSrcIPAddr(packet &pkt);
string getDstIPAddr(packet &pkt);
void cppkt(unsigned int L, const unsigned char *p, packet &pkt);
void headle_pkt(packet &pkt);
void createTree(Glib::RefPtr<Gtk::TreeStore> m_refTreeModel, treeColumns &treeColumns, packet &pkt);
