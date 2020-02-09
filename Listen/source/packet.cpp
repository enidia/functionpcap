#include <iomanip>
#include "packet.h"
#include "Model.h"
#include <ws2tcpip.h>


void cppkt(unsigned int L, const unsigned char *p, packet &pkt) {
    if(pkt.pkt_data!=nullptr)
        delete [] pkt.pkt_data;
    pkt.len = L;
    pkt.pkt_data = new unsigned char[L];
    for (int i = 0; i < (int) L; i++)
        pkt.pkt_data[i] = p[i];
}
string macaddr2string(unsigned char *macaddr) {
    char temp[20] = {'\0'};
    sprintf(temp, "%02X-%02X-%02X-%02X-%02X-%02X",
            macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    string str = temp;
    return str;
}

string ipaddr2string(unsigned char *ipaddr, int IP_TYPE) {
    char address[40] = {'\0'};
    string str = "";
    switch (IP_TYPE) {
        case 0: {
            sprintf(address, "%d.%d.%d.%d",
                    ipaddr[0], ipaddr[1],
                    ipaddr[2], ipaddr[3]);
            str = address;
            break;
        }
        case 1: {
            bool flag = false;
            for (int i = 0; i < 16; i = i + 2) {
                if (ipaddr[i] == 0 && ipaddr[i + 1] != 0) {
                    if (flag) {
                        flag = false;
                        sprintf(address, ":");
                        str += address;
                    }
                    sprintf(address, "%x", ipaddr[i + 1]);
                    str += address;
                    if (i < 14) {
                        sprintf(address, ":");
                        str += address;
                    }
                } else if (ipaddr[i] != 0) {
                    if (flag) {
                        flag = false;
                        sprintf(address, ":");
                        str += address;
                    }
                    sprintf(address, "%x%02x", ipaddr[i], ipaddr[i + 1]);
                    str += address;
                    if (i < 14) {
                        sprintf(address, ":");
                        str += address;
                    }
                } else flag = true;
            }
            break;
        }
    }
    return str;
}

string getSrcIPAddr(packet &pkt) {
    string str = "";
    auto eth_header = (eth_hdr *) pkt.pkt_data;
    auto ip_header = (ip_hdr *) (pkt.pkt_data + pkt.mac_size);
    auto ipv6_header = (ipv6_hdr *) (pkt.pkt_data + pkt.mac_size);
    switch (ntohs(eth_header->eth_type)) {
        case 0x0800: {
            str = ipaddr2string(ip_header->sourceIP, 0);
            break;
        }
        case 0x86DD: {
            str = ipaddr2string(ipv6_header->Srcv6, 1);
            break;
        }
    }
    return str;
}

string getDstIPAddr(packet &pkt) {
    string str = "";
    auto eth_header = (eth_hdr *) pkt.pkt_data;
    auto ip_header = (ip_hdr *) (pkt.pkt_data + pkt.mac_size);
    auto ipv6_header = (ipv6_hdr *) (pkt.pkt_data + pkt.mac_size);
    switch (ntohs(eth_header->eth_type)) {
        case 0x0800: {
            str = ipaddr2string(ip_header->destIP, 0);
            break;
        }
        case 0x86DD: {
            str = ipaddr2string(ipv6_header->Destv6, 1);
            break;
        }
    }
    return str;
}

string getstring(unsigned char* data, int len){
    stringstream ss;
    for (int i = 0; i < len; i++)
        ss << data[i];
    return ss.str();
}

void headle_pkt(packet &pkt) {
    auto eth_header = (eth_hdr *) pkt.pkt_data;
    pkt.mac_size = 14;
    pkt.cur_protocol = "etherII";

    switch (ntohs(eth_header->eth_type)) {
        case 0x0800: {
            auto ip_header = (ip_hdr *) (pkt.pkt_data + pkt.mac_size);
            pkt.ip_size = static_cast<unsigned int>(ip_header->ihl * 4);
            pkt.cur_protocol = "IPv4";
            break;
        }
        case 0x86DD: {
            auto ipv6_header = (ipv6_hdr *) (pkt.pkt_data + pkt.mac_size);
            pkt.ip_size = 40 * sizeof(unsigned char);
            pkt.cur_protocol = "IPv6";
            break;
        }
        case 0x0806: {
            pkt.ip_size += sizeof(arp_hdr);
            pkt.cur_protocol = "ARP";
            return;
        }
    }

    unsigned char trans = 0xFF;
    if (ntohs(eth_header->eth_type) == 0x0800) {
        auto ip_header = (ip_hdr *) (pkt.pkt_data + pkt.mac_size);
        trans = ip_header->protocol;
    }
    else if (ntohs(eth_header->eth_type) == 0x86DD) {
        auto ipv6_header = (ipv6_hdr *) (pkt.pkt_data + pkt.mac_size);
        trans = ipv6_header->nexthdr;
    }

    switch (trans) {
        case 1: {
            pkt.trans_size = sizeof(icmp_hdr);
            pkt.cur_protocol = "ICMP";
            return;
        }
        case 6: {
            auto tcp_header = (tcp_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size);
            pkt.trans_size = static_cast<unsigned int>(tcp_header->thl * 4);
            pkt.cur_protocol = "TCP";
            if(ntohs(tcp_header->src_port) == 53 || ntohs(tcp_header->dst_port) == 53) //dns
            {
                pkt.cur_protocol = "DNS";
            }
            break;
        }
        case 17: {
            auto udp_header = (udp_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size);
            pkt.trans_size = sizeof(udp_hdr);
            pkt.cur_protocol = "UDP";
            if(ntohs(udp_header->src_port) == 53 || ntohs(udp_header->dst_port) == 53) //dns
            {
                pkt.cur_protocol = "DNS";
            }
            break;
        }
        case 58: {
            pkt.trans_size = sizeof(icmp6_hdr);
            pkt.cur_protocol = "ICMPv6";
            return;
        }
    }
}

void createTree(Glib::RefPtr<Gtk::TreeStore> m_refTreeModel, treeColumns &treeColumns, packet &pkt) {
    m_refTreeModel->clear();
    char temp[200] = {'\0'};
    Gtk::TreeModel::Row row_tree, childrow;

    row_tree = *(m_refTreeModel->append());
    row_tree[treeColumns.str] = "Ethernet II";

    auto eth_header = (eth_hdr *) pkt.pkt_data;

    sprintf(temp, "Destination : (%02X-%02X-%02X-%02X-%02X-%02X)",
            eth_header->dstmac[0], eth_header->dstmac[1], eth_header->dstmac[2],
            eth_header->dstmac[3], eth_header->dstmac[4], eth_header->dstmac[5]);
    childrow = *(m_refTreeModel->append(row_tree.children()));
    childrow[treeColumns.str] = temp;

    sprintf(temp, "Source : (%02X-%02X-%02X-%02X-%02X-%02X)",
            eth_header->srcmac[0], eth_header->srcmac[1], eth_header->srcmac[2],
            eth_header->srcmac[3], eth_header->srcmac[4], eth_header->srcmac[5]);
    childrow = *(m_refTreeModel->append(row_tree.children()));
    childrow[treeColumns.str] = temp;

    switch (ntohs(eth_header->eth_type)) {
        case 0x0800:
            sprintf(temp, "Type : IPv4 (0x%04X)", ntohs(eth_header->eth_type));
            break;
        case 0x86DD:
            sprintf(temp, "Type : IPv6 (0x%04X)", ntohs(eth_header->eth_type));
            break;
        case 0x0806:
            sprintf(temp, "Type : ARP (0x%04X)", ntohs(eth_header->eth_type));
            break;
    }
    childrow = *(m_refTreeModel->append(row_tree.children()));
    childrow[treeColumns.str] = temp;

    switch (ntohs(eth_header->eth_type)) {
        case 0x0800: {
            auto ip_header = (ip_hdr *) (pkt.pkt_data + pkt.mac_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "Internet Protocol Version 4";

            sprintf(temp, "Vserion: %d", ip_header->version);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;

            sprintf(temp, "Header Length: %d", ip_header->ihl);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Differenntiated Services Field: 0x%02X", ip_header->tos);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Total Length: %d", ntohs(ip_header->tot_len));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Identification: 0x%04x", ntohs(ip_header->id));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Flags: 0x%04x", ntohs(ip_header->frag_off));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            //TODO CHILDROW

            sprintf(temp, "Time to live: %d", ip_header->ttl);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            switch (ip_header->protocol) {
                case 1:
                    sprintf(temp, "Prorocol: ICMP (%d)", ip_header->protocol);
                    break;
                case 6:
                    sprintf(temp, "Prorocol: TCP (%d)", ip_header->protocol);
                    break;
                case 17:
                    sprintf(temp, "Prorocol: UDP (%d)", ip_header->protocol);
                    break;
                default:
                    sprintf(temp, "Prorocol: UNKNOW(%d)", ip_header->protocol);
            }
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;

            sprintf(temp, "Header checksum: 0x%04x", ntohs(ip_header->chk_sum));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Source: %s", getSrcIPAddr(pkt).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Destination: %s", getDstIPAddr(pkt).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            break;
        }
        case 0x86DD: {
            //TODO
            auto ipv6_header = (ipv6_hdr *) (pkt.pkt_data + pkt.mac_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "Internet Protocol Version 6";

            sprintf(temp, "Vserion: %d", ipv6_header->version);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Traffic Class: 0x%02x",
                    u_char(ipv6_header->priority0) << 4 | u_char(ipv6_header->priority1));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Flow Lable: 0x%05x",
                    u_int(ipv6_header->flow_lbl0) << 16 | u_int(ntohs(ipv6_header->flow_lbl)));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Payload Length: %d", ntohs(ipv6_header->payload_len));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            switch (ipv6_header->nexthdr) {
                case 6:
                    sprintf(temp, "Next Header: TCP (%d)", ipv6_header->nexthdr);
                    break;
                case 17:
                    sprintf(temp, "Next Header: UDP (%d)", ipv6_header->nexthdr);
                    break;
                case 58:
                    sprintf(temp, "Next Header: ICMPv6 (%d)", ipv6_header->nexthdr);
                    break;
            }
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Hop Limit: %d", ntohs(ipv6_header->hop_limit));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Source: %s", getSrcIPAddr(pkt).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Destination: %s", getDstIPAddr(pkt).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            break;
        }
        case 0x0806:
            //TODO
            auto arp_header = (arp_hdr *) (pkt.pkt_data + pkt.mac_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "Address Resolution Protocol ";

            sprintf(temp, "Hardware type: {0x%04x}", ntohs(arp_header->htype));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Protocol type: {0x%04x}", ntohs(arp_header->ptype));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Hardware size: %d", arp_header->hlen);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Protocol size: %d", arp_header->plen);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Opcode: {0x%04x}", ntohs(arp_header->oper));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Sender MAC address: (%s)", macaddr2string(arp_header->sourceMac).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Sender IP address: (%s)", ipaddr2string(arp_header->sourceIP, 0).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Target MAC address: (%s)", macaddr2string(arp_header->destMac).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Target IP address: (%s)", ipaddr2string(arp_header->destIP, 0).c_str());
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            return;
    }

    unsigned char trans = 0xFF;
    if (ntohs(eth_header->eth_type) == 0x0800) {
        auto ip_header = (ip_hdr *) (pkt.pkt_data + pkt.mac_size);
        trans = ip_header->protocol;
    }
    else if (ntohs(eth_header->eth_type) == 0x86DD) {
        auto ipv6_header = (ipv6_hdr *) (pkt.pkt_data + pkt.mac_size);
        trans = ipv6_header->nexthdr;
    }


    stringstream ss;
    int length = pkt.len - pkt.mac_size - pkt.ip_size - pkt.trans_size;
    for (int i = pkt.len - length; i < ((length > 24) ? (pkt.len - length + 24) : pkt.len); i++)
        ss << setw(2) << setfill('0') << hex << (int) pkt.pkt_data[i];
    if (length > 24) ss << "...";

    //解析协议类型
    switch (trans) {
        case 1: {
            // "ICMP";
            auto icmp_header = (icmp_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "Internet Control Message Protocol";
            sprintf(temp, "Type: %d", icmp_header->icmp_type);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Code: %d", icmp_header->code);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Checksum: 0x%04x", ntohs(icmp_header->chk_sum));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Identifier: 0x%04x", ntohs(icmp_header->icmp_id));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Sequence: %d", ntohs(icmp_header->icmp_sequence));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Data (%d bytes)", length);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Data: %s", ss.str().c_str());
            row_tree = *(m_refTreeModel->append(childrow.children()));
            row_tree[treeColumns.str] = temp;
            sprintf(temp, "[Length: %d]", length);
            row_tree = *(m_refTreeModel->append(childrow.children()));
            row_tree[treeColumns.str] = temp;
            return;
        }
        case 6: {
            //"TCP";
            auto tcp_header = (tcp_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "Transmission Control Protocol";
            sprintf(temp, "Source Port: %d", ntohs(tcp_header->src_port));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Destination Port: %d", ntohs(tcp_header->dst_port));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Sequence number: %ld", ntohl(tcp_header->seq_no));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Acknowledgment number: %ld", ntohl(tcp_header->ack_no));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Acknowledgment number: %ld", ntohl(tcp_header->ack_no));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Header Length: %d bytes (%d)", 4 * tcp_header->thl, tcp_header->thl);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Flags: 0x%03x",
                    u_short(tcp_header->reserved_1) << 8 | u_short(tcp_header->reserved_1) << 6 |
                    u_short(tcp_header->flag));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            //TODO

            sprintf(temp, "Window size value: %d", ntohs(tcp_header->wnd_size));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Checksum: 0x%04x", ntohs(tcp_header->chk_sum));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Urgent pointer: %d", ntohs(tcp_header->urgt_p));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "TCP payload (%d bytes)", pkt.len - pkt.mac_size - pkt.ip_size);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            break;
        }
        case 17: {
            //"UDP";
            auto udp_header = (udp_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "User Datagram Protocol";
            sprintf(temp, "Source Port: %d", ntohs(udp_header->src_port));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Destination Port: %d", ntohs(udp_header->dst_port));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Header Length: %d", ntohs(udp_header->uhl));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Checksum : 0x%04x", ntohs(udp_header->chk_sum));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            break;
        }
        case 58: {
            //"ICMPv6";
            auto icmp6_header = (icmp6_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size);
            row_tree = *(m_refTreeModel->append());
            row_tree[treeColumns.str] = "Internet Control Message Protocol v6";

            sprintf(temp, "Type: %d", icmp6_header->icmp6_type);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Code: %d", icmp6_header->icmp6_code);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Checksum: 0x%04x", ntohs(icmp6_header->icmp6_cksum));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Identifier: 0x%04x", ntohs(icmp6_header->icmp6_dataun.icmp6_un_data16[0]));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Sequence: %d", ntohs(icmp6_header->icmp6_dataun.icmp6_un_data16[1]));
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Data (%d bytes)", length);
            childrow = *(m_refTreeModel->append(row_tree.children()));
            childrow[treeColumns.str] = temp;
            sprintf(temp, "Data: %s", ss.str().c_str());
            row_tree = *(m_refTreeModel->append(childrow.children()));
            row_tree[treeColumns.str] = temp;
            sprintf(temp, "[Length: %d]", length);
            row_tree = *(m_refTreeModel->append(childrow.children()));
            row_tree[treeColumns.str] = temp;
            return;
        }
    }


    if(pkt.cur_protocol != "DNS"){
        sprintf(temp, "Data (%d bytes)", length);
        row_tree = *(m_refTreeModel->append());
        row_tree[treeColumns.str] = temp;
        sprintf(temp, "Data: %s", ss.str().c_str());
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        sprintf(temp, "[Length: %d]", length);
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
    }
    else{
        auto dns_header = (dns_hdr *) (pkt.pkt_data + pkt.mac_size + pkt.ip_size + pkt.trans_size);
        row_tree = *(m_refTreeModel->append());
        row_tree[treeColumns.str] = "Domain Name System";

        sprintf(temp, "Transaction ID: 0x%04x", ntohs(dns_header->trans_id));
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        sprintf(temp, "Flags: 0x%04x", ntohs(dns_header->flags));
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        sprintf(temp, "Questions: %d", ntohs(dns_header->questions));
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        sprintf(temp, "Answer RRs: %d", ntohs(dns_header->answer_rrs));
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        sprintf(temp, "Authority RRs: %d", ntohs(dns_header->authority_rrs));
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        sprintf(temp, "Additional RRs: %d", ntohs(dns_header->additional_rrs));
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = temp;
        childrow = *(m_refTreeModel->append(row_tree.children()));
        childrow[treeColumns.str] = "Queries";

        unsigned char* cur = pkt.pkt_data+pkt.mac_size+pkt.ip_size+pkt.trans_size+sizeof(dns_hdr);
        int nextlen, domainlen;
        string domain = "";
        for(int nextlen = *cur; nextlen != 0; nextlen = *cur){
            domainlen += nextlen;
            cur++;
            domain += getstring(cur, nextlen);
            cur += nextlen;
            if(*cur == 0) break;
            domain += ".";
        }
        cur++;
        sprintf(temp, "Name: %s", domain.c_str());
        row_tree = *(m_refTreeModel->append(childrow.children()));
        row_tree[treeColumns.str] = temp;
        unsigned short num0 = *cur;
        unsigned short num1 = *(cur+1);
        cur += 2;
        num0 = num0<<8 | num1;
        sprintf(temp, "Type: %d", num0);
        row_tree = *(m_refTreeModel->append(childrow.children()));
        row_tree[treeColumns.str] = temp;

        num0 = *cur;
        num1 = *(cur+1);
        num0 = num0<<8 | num1;
        sprintf(temp, "Class: (0x%04x)", num0);
        row_tree = *(m_refTreeModel->append(childrow.children()));
        row_tree[treeColumns.str] = temp;
    }
}

