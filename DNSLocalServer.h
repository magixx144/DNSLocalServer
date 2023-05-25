//
// Created by minyu on 2023/5/21.
//

//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef DNSCLIENT_DNSCLIENT_H
#define DNSCLIENT_DNSCLIENT_H

#endif //DNSCLIENT_DNSCLIENT_H

#define TYPE_CNAME 0x05
#define TYPE_A 0x01
#define TYPE_MX 0x0f
#define CLASS_IN 0x01
#define MESSAGE_LEN 1024
#define DNS_SERVER_PORT 9946
#define DNS_SERVER_IP "8.8.8.8"
#define LOCAL_DNS_ADDRESS "127.0.0.1"
#define NAME_LEN 1024
#define IP_LEN 20
#define NET_IP_LEN 4

#define IN_ASCII 0x4E49
#define A_ASCII 0x41
#define MX_ASCII 0x584D
#define CNAME_ASCII 0x4E43



struct DNS_Header {
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};
struct DNS_Query{
    char name[NAME_LEN];
    unsigned short qtype;
    unsigned short qclass;
    int length;
};
struct DNS_RR {
    char name[NAME_LEN];
    unsigned short type;
    unsigned short rclass;
    unsigned int ttl;
    unsigned short data_len;
    char rdata[MESSAGE_LEN];
};



static void dns_parse_name(unsigned char* chunk, unsigned char *ptr, char *out, int *len);
static int is_pointer(int in);
char *DNS_request_parse(char *request);
unsigned short DNS_table_init(struct DNS_RR *answer,char *path,char *domain,unsigned short type,unsigned short *add);
int DNS_udp();
int DNS_build(struct DNS_Header *header,struct DNS_Query *query,struct DNS_RR *answer,char *response);
int DNS_query_create(struct DNS_Query *query,char *domain,unsigned short type);
int DNS_header_create(struct DNS_Header *header,char *domain,unsigned short type,unsigned short add);
char *response_build(struct DNS_Header *header,struct DNS_Query *query,struct DNS_RR *answer,char *response);
int get_answerNum(char *path,char *domain, unsigned short type);
