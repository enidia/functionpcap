//
// Created by malin on 2019/4/18.
//

#ifndef GTKPCAP_MODEL_H
#define GTKPCAP_MODEL_H

#include <gtkmm.h>

class ModelColumns : public Gtk::TreeModel::ColumnRecord
{
public:

    ModelColumns() {
        add(NO);
        add(Time);
        add(SrcIP);
        add(DstIP);
        add(Protocol);
    }

    Gtk::TreeModelColumn<unsigned int> NO;
    Gtk::TreeModelColumn<Glib::ustring> Time;
    Gtk::TreeModelColumn<Glib::ustring> SrcIP;
    Gtk::TreeModelColumn<Glib::ustring> DstIP;
    Gtk::TreeModelColumn<Glib::ustring> Protocol;
};

class treeColumns : public Gtk::TreeModel::ColumnRecord
{
public:

    treeColumns() {
        add(str);
    }
    Gtk::TreeModelColumn<Glib::ustring> str;
};

#endif //GTKPCAP_MODEL_H
