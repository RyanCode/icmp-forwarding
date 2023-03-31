cmake_minimum_required(VERSION 2.8)

project(icmp-forwarding)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

include_directories(
    ${CMAKE_SOURCE_DIR}
)

set(${PROJECT_NAME}_SRCS
    icmp-forwarding.c
)
add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRCS})
target_link_libraries(${PROJECT_NAME} pcap pthread)