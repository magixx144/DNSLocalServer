cmake_minimum_required(VERSION 3.25)
project(DNSLocalServer C)

set(CMAKE_C_STANDARD 11)

add_executable(DNSLocalServer main.c DNSLocalServer.c DNSLocalServer.h)
