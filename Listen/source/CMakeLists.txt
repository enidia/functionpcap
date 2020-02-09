cmake_minimum_required(VERSION 3.12)
project(gtkpcap)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mwindows")

set(PCAP_ROOT_DIR WpdPack)
set(PCAP_INCLUDE_DIR ${PCAP_ROOT_DIR}/Include)
set(PCAP_LIBRARY_DIR ${PCAP_ROOT_DIR}/Lib/x64 ${PCAP_ROOT_DIR}/Lib)

# Use the package PkgConfig to detect GTK+ headers/library files
find_package(PkgConfig REQUIRED)

pkg_check_modules(GTKMM REQUIRED gtkmm-3.0)

# Setup CMake to use GTK+, tell the compiler where to look for headers
# and to the linker where to look for libraries


link_directories(${GTKMM_LIBRARY_DIRS})
link_directories(${PCAP_LIBRARY_DIR})
include_directories(${GTKMM_INCLUDE_DIRS})
include_directories(${PROJECT_NAME} ${PCAP_INCLUDE_DIR})

add_executable(${PROJECT_NAME} packet.cpp packet.h protocol.h Model.h main.cpp)

# Link the target to the GTK+ libraries

target_link_libraries(${PROJECT_NAME} ${GTKMM_LIBRARIES})

target_link_libraries(${PROJECT_NAME} ws2_32)

target_link_libraries(${PROJECT_NAME} wpcap)
