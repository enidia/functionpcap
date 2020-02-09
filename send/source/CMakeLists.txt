cmake_minimum_required(VERSION 3.13)
project(NetDeliver)

set(CMAKE_CXX_STANDARD 14)
set(SOURCE_FILES main.cpp protocol.h)
set(PCAP "C:/Program Files/Library/WpdPack")
set(INC ${PCAP}/Include)
set(LIB ${PCAP}/Lib/x64/wpcap.lib ${PCAP}/Lib/wpcap.lib)

add_executable(NetDeliver ${SOURCE_FILES})

include_directories(NetDeliver ${INC})

target_link_libraries(NetDeliver ws2_32)
target_link_libraries(NetDeliver netapi32)
target_link_libraries(NetDeliver ${LIB})
target_link_libraries(NetDeliver )

FIND_PACKAGE(PkgConfig REQUIRED)
PKG_CHECK_MODULES(GTK3 REQUIRED gtk+-3.0)

INCLUDE_DIRECTORIES(${GTK3_INCLUDE_DIRS})
LINK_DIRECTORIES(${GTK3_LIBRARY_DIRS})

TARGET_LINK_LIBRARIES(NetDeliver ${GTK3_LIBRARIES})
