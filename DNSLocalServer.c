#include "DNSLocalServer.h"

static char *path = "LocalCacheA.txt";

static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len)
{
    int flag = 0, n = 0, alen = 0;
    // pos指向的内存用于存储解析得到的结果
    char *pos = out + (*len); // 传入的 *len = 0
    while (1)
    {
        flag = (int)ptr[0];
        if (flag == 0)
            break;
        // 如果为指针表明该Name重复出现过，这一字段只占2字节
        if (is_pointer(flag))
        {
            n = (int)ptr[1]; // 获取第一次Name出现的偏移
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;
        }
        else // Address情况下，所得len为ip地址的第一位{
            ptr++;
        memcpy(pos, ptr, flag);
        pos += flag;
        ptr += flag;

        *len += flag;
        if ((int)ptr[0] != 0)
        {
            memcpy(pos, ".", 1);
            pos += 1;
            (*len) += 1;
        }
    }
}

static int is_pointer(int in)
{
    // 0xC0 : 1100 0000
    return ((in & 0xC0) == 0xC0);
}

char *DNS_request_parse(char *request)
{
    if (request == NULL)
    {
        printf("No request\n");
        return -1;
    }
    char *ptr = request; // ptr指向request的开头
    // header
    struct DNS_Header header = {0};
    header.id = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.tag = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.queryNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.answerNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.authorNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.addNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;

    // query
    struct DNS_Query *query = calloc(header.queryNum, sizeof(struct DNS_Query)); // 先假定queryNum为1，后续完善
    int len_q = 0;
    //*query[0].name=malloc(NAME_LEN);
    dns_parse_name(request, ptr, &query[0].name, &len_q);
    ptr += (len_q + 2);
    query[0].qtype = htons(*(unsigned short *)ptr);
    ptr += 2;
    query[0].qclass = htons(*(unsigned short *)ptr);
    ptr += 2;
    // printf("query %s\n", &query[0].name);
    //  printf("%X\n",query[0].qtype);
    return &query[0].name;
}
int get_answerNum(char *path, char *domain, unsigned short type)
{
    char *buffer = malloc(MESSAGE_LEN);
    char *data_list[10]; // 存放buffer中读到的记录
    FILE *file = fopen(path, "ab+");
    unsigned short ascii_type = 0;

    int i = 0;
    unsigned short answerNum = 0;
    if (!file)
    {
        printf("No file!\n");
        return -1;
    }
    while (i < 10)
    {
        int query_state = 0;      // 表明查询状态，查到为1
        int query_name_state = 0; // 查name
        int query_type_state = 0; // 查对应type

        data_list[i] = (char *)malloc(sizeof(char) * 200);
        if (fgets(data_list[i], 1000, file) == NULL)
        { // 如果错误或者读到结束符，就返回NULL；
            // printf("%X num.\n",answerNum);
            break;
        }
        else
        {
            char *ret = strchr(data_list[i], '\n');
            *ret = '\0'; // 替换行末尾换行符
            char *p = strtok(data_list[i], " ");
            if (strcmp(p, domain) == 0) // 先匹配名字
            {
                // printf("Yes name.\n");   //查询到
                query_name_state = 1;
            }

            for (int j = 0; j < 3; j++)
            {
                p = strtok(NULL, " "); // 指向type
            }
            ascii_type = *(unsigned short *)p;
            if (type == TYPE_A)
            { // A对应A和CNAME
                if (ascii_type == A_ASCII)
                {
                    query_type_state = 1;
                }
                else if (ascii_type == CNAME_ASCII)
                {
                    query_type_state = 1;
                }
            }
            else if (type == TYPE_CNAME)
            { // CNAME对应CNAME
                if (ascii_type == CNAME_ASCII)
                {
                    query_type_state = 1;
                }
            }
            else if (type == TYPE_MX)
            { // MX对应A,CNAME,MX
                if (ascii_type == A_ASCII)
                {
                    query_type_state = 1;
                }
                else if (ascii_type == CNAME_ASCII)
                {
                    query_type_state = 1;
                }
                else if (ascii_type == MX_ASCII)
                {
                    query_type_state = 1;
                }
            }

            if (query_name_state && query_type_state)
                answerNum++;
        }
    }
    return answerNum;
}

int DNS_table_init(struct DNS_RR *answer, char *path, char *domain, unsigned short type, unsigned short *add)
{
    char *buffer = malloc(MESSAGE_LEN);
    char *data_list[10]; // 存放buffer中读到的记录
    FILE *file = fopen(path, "ab+");
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    int i = 0;
    unsigned short answerNum = 0;
    memset(rr, 0x00, sizeof(struct DNS_RR));
    int flag = 0; // 查询状态

    if (!file)
    {
        printf("No file!\n");
        return -1;
    }
    while (i < 10)
    {
        int query_state = 0;      // 表明查询状态，查到为1
        int query_name_state = 0; // 查name
        int query_type_state = 0; // 查type
        int query_type_A = 0;     // 查A返回address
        int query_type_CNAME = 0; // 查CNAME返回cname
        int query_type_MX = 0;    // 查MX返回cname
        data_list[i] = (char *)malloc(sizeof(char) * 200);
        if (fgets(data_list[i], 1000, file) == NULL)
        { // 如果错误或者读到结束符，就返回NULL；
            // printf("%X num.\n",answerNum);
            break;
        }
        else
        {
            char *ret = strchr(data_list[i], '\n');
            *ret = '\0'; // 替换行末尾换行符
            char *p = strtok(data_list[i], " ");
            strncpy(rr->name, p, MESSAGE_LEN);
            if (strcmp(rr->name, domain) == 0)
            {
                // printf("Yes name.\n");   //查询到
                // printf("init request%s\n",rr->name);
                query_name_state = 1;
                flag = 1;
            }

            p = strtok(NULL, " ");
            rr->ttl = atoi(p);
            // printf("%X\n",rr->ttl);

            p = strtok(NULL, " ");
            rr->rclass = *(unsigned short *)p;
            if (rr->rclass == IN_ASCII) // 0x4E49对应class IN
                rr->rclass = CLASS_IN;
            // printf("%X\n",rr->rclass);

            p = strtok(NULL, " ");
            rr->type = *(unsigned short *)p;
            if (rr->type == A_ASCII)
            { // 0x41对应type A
                rr->type = TYPE_A;
                query_type_A = 1;

                if (type == TYPE_MX && query_name_state == 1)
                {
                    (*add)++;
                    query_type_state = 1;
                }
            }
            else if (rr->type == MX_ASCII)
            { // 0x584D对应type MX
                rr->type = TYPE_MX;
                query_type_MX = 1;
            }
            else if (rr->type == CNAME_ASCII)
            { // cname只取前两位
                rr->type = TYPE_CNAME;
                query_type_CNAME = 1;
                query_type_state = 1;
            }
            if (rr->type == type)
            { // type是否对应
                // printf("Yes type.\n");
                // printf("%X\n",rr->type);
                query_type_state = 1;
            }
            rr->data_len = 4;

            p = strtok(NULL, " ");
            strncpy(rr->rdata, p, MESSAGE_LEN);
            // printf("%s\n",rr->rdata);

            if (query_name_state && query_type_state)
            { // 查询到，break
                // answer的name段
                char *ptr = &answer[answerNum].name; // ptr指向name,&不确定
                const char s[2] = ".";
                int offset = 0;
                char *rrname_dup = strdup(rr->name); // 用于分割
                char *token = strtok(rrname_dup, s);
                while (token != NULL)
                {
                    size_t len = strlen(token);
                    *(ptr + offset) = len;
                    offset++;
                    strncpy(ptr + offset, token, len + 1);
                    offset += len;
                    token = strtok(NULL, s);
                }
                *(ptr + offset) = '\0';
                free(rrname_dup);
                // type字段
                answer[answerNum].type = htons(rr->type);
                // class字段
                answer[answerNum].rclass = htons(rr->rclass);
                // ttl字段
                answer[answerNum].ttl = htons(rr->ttl);
                // data length字段

                if (rr->type == TYPE_A)
                {
                    answer[answerNum].data_len = htons((unsigned short)4);
                    // address字段
                    struct in_addr netip = {0};
                    inet_aton(rr->rdata, &netip);
                    memcpy(&answer[answerNum].rdata, (char *)&netip.s_addr, sizeof((char *)&netip.s_addr));
                    answerNum++;
                }
                else if (rr->type == TYPE_CNAME || rr->type == TYPE_MX)
                {
                    char *ptr = rr->rdata; // ptr指向name
                    const char s[2] = ".";
                    char *data_dup = strdup(rr->rdata); // 用于分割
                    char *token = strtok(data_dup, s);
                    while (token != NULL)
                    {
                        size_t len = strlen(token);
                        *ptr = len;
                        ptr++;
                        strncpy(ptr, token, len + 1);
                        ptr += len;
                        token = strtok(NULL, s);
                    }
                    free(data_dup);
                    answer[answerNum].data_len = htons((unsigned short)strlen(rr->rdata) + 1);
                    memcpy(&answer[answerNum].rdata, rr->rdata, strlen(rr->rdata));
                    answerNum++;
                }
            }
        }
    }
    fclose(file);
    return flag;
}

char *response_build(struct DNS_Header *header, struct DNS_Query *query, struct DNS_RR *answer, char *response)
{
    if (header == NULL || query == NULL || answer == NULL || response == NULL)
    {
        printf("Response build failed.\n");
        return -1;
    }
    char *ptr = response;
}

int DNS_header_create(struct DNS_Header *header, char *domain, unsigned short type, unsigned short add)
{
    if (header == NULL)
    {
        printf("Header wrong!\n");
        return -1;
    }

    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL)); // linux下
    header->id = random();
    // srand(time(NULL)); //windows下
    // header->id = rand();
    header->tag = htons(0x8100);
    header->queryNum = htons(0x0001); // 假定只有一条记录
    header->answerNum = htons(get_answerNum(path, domain, type) - add);
    header->authorNum = htons(0x0000);

    if (type == TYPE_MX)
    {
        header->addNum = htons(add);
    }
    else
    {
        header->addNum = htons(0x0000);
    }

    return 0;
}
int DNS_query_create(struct DNS_Query *query, char *domain, unsigned short type)
{
    if (query == NULL || domain == NULL)
    {
        printf("Fail to create query.\n");
        return -1;
    }
    memset(query, 0x00, sizeof(struct DNS_Query));
    // query->name=malloc(sizeof(domain)+2);
    query->length = strlen(domain) + 2;
    char *ptr = query->name; // ptr指向name
    const char s[2] = ".";
    char *domain_dup = strdup(domain); // 用于分割
    char *token = strtok(domain_dup, s);
    while (token != NULL)
    {
        size_t len = strlen(token);
        *ptr = len;
        ptr++;
        strncpy(ptr, token, len + 1);
        ptr += len;
        token = strtok(NULL, s);
    }
    free(domain_dup);
    query->qtype = htons(type);
    query->qclass = htons(0x0001);
    return strlen(domain);
}

int DNS_build(struct DNS_Header *header, struct DNS_Query *query, struct DNS_RR *answer, char *response)
{
    if (header == NULL || query == NULL || answer == NULL || response == NULL)
    {
        printf("DNS build failed.\n");
        return -1;
    }
    unsigned short prference = htons(0x05); // MX的preference字段
    int offset = 0;
    memset(response, 0x00, MESSAGE_LEN);

    memcpy(response + offset, header, sizeof(struct DNS_Header));
    offset += sizeof(struct DNS_Header);

    memcpy(response + offset, query->name, query->length);
    offset += query->length;

    memcpy(response + offset, &query->qtype, sizeof(query->qtype));
    offset += sizeof(query->qtype);
    memcpy(response + offset, &query->qclass, sizeof(query->qclass));
    offset += sizeof(query->qclass);

    int num = ntohs(header->answerNum + header->addNum);
    for (int i = 0; i < num; i++)
    {
        memcpy(response + offset, &answer[i].name, strlen(&answer[i].name) + 1);
        offset += (strlen(&answer[i].name) + 1);
        memcpy(response + offset, &answer[i].type, sizeof(answer[i].type));
        offset += sizeof(answer[i].type);
        memcpy(response + offset, &answer[i].rclass, sizeof(answer[i].rclass));
        offset += sizeof(answer[i].rclass);

        memcpy(response + offset, &answer[i].ttl, sizeof(answer[i].ttl));
        offset += sizeof(answer[i].ttl);

        if (ntohs(answer[i].type) == TYPE_MX)
        {
            unsigned short mx_len = htons(ntohs(answer[i].data_len) + 2);
            memcpy(response + offset, &mx_len, sizeof(answer[i].data_len));
            offset += sizeof(answer[i].data_len);
        }
        else
        {
            memcpy(response + offset, &answer[i].data_len, sizeof(answer[i].data_len));
            offset += sizeof(answer[i].data_len);
        }

        if (ntohs(answer[i].type) == TYPE_MX)
        {
            memcpy(response + offset, &prference, sizeof(prference));
            offset += sizeof(answer[i].data_len);
        }
        memcpy(response + offset, &answer[i].rdata, ntohs(answer[i].data_len));
        offset += ntohs(answer[i].data_len);
    }
    return offset;
}

int DNS_udp()
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("sockfd");
        return -1;
    }
    struct sockaddr_in ser, cli;
    ser.sin_family = AF_INET;
    ser.sin_port = htons(DNS_SERVER_PORT);
    ser.sin_addr.s_addr = inet_addr(LOCAL_DNS_ADDRESS);
    // ser.sin_addr.s_addr =htonl(INADDR_ANY);

    int ret = bind(sockfd, (struct sockaddr *)&ser, sizeof(ser));
    if (ret < 0)
    {
        perror("bind");
        return -1;
    }

    int n = sizeof(cli);

    while (1)
    {
        char request[MESSAGE_LEN] = {0};
        int m = recvfrom(sockfd, request, sizeof(request), 0, (struct sockaddr *)&cli, &n);
        printf("receive len = %d\n", m);
        char *domain = DNS_request_parse(request);

        // printf("%s\n",domain);
        unsigned short type = *(unsigned short *)(request + strlen(domain) + 14); // 12为头长,+2
        type = htons(type);
        int answerNum = get_answerNum(path, domain, type);
        unsigned short add = 0; // 记录add数目

        struct DNS_RR *answer = calloc(answerNum, sizeof(struct DNS_RR));
        int flag = DNS_table_init(answer, path, domain, type, &add);
        if (flag == 1)
        {
            struct DNS_Header header = {0};
            DNS_header_create(&header, domain, type, add);
            printf("add %d\n", add);

            struct DNS_Query *query = calloc(1, sizeof(struct DNS_Query));
            DNS_query_create(query, domain, type);
            // printf("id %X\n",header.id);
            char response[MESSAGE_LEN] = {0};
            int offset = DNS_build(&header, query, answer, response);

            sendto(sockfd, response, offset, 0, (struct sockaddr *)&cli, n);
        }
        else
        {
            int offset = 0;
            char root_response[MESSAGE_LEN] = {0};
            char ip[IP_LEN] = {0};
            char next_response[MESSAGE_LEN] = {0};
            DNS_tcp_root(domain, type, &offset, root_response, ip, next_response);
            int sendlen = ntohs(*(unsigned short *)next_response);                     // 解析了报文长度，即tcp的data length
            sendto(sockfd, next_response + 2, sendlen, 0, (struct sockaddr *)&cli, n); //+2，跳过data length(udp不需要)
        }
    }

    close(sockfd);

    return 0;
}
int tcp_socket_init(char *ip, char *request, int offset, char *response)
{ // 这里request向次级域名服务器发起查询，response为次级域名的回答
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_sockaddr; // 一般是储存地址和端口，用于信息的显示及存储作用
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(DNS_SERVER_PORT); // 将一个无符号短整型数值转换为网络字节序，即大端模式
    server_sockaddr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) < 0)
    {
        perror("connect");
        exit(1);
    }
    send(sockfd, request, offset, 0);
    printf("send to %s bytes:%d\n", ip, offset);
    int n = recv(sockfd, response, MESSAGE_LEN, 0);
    printf("receive bytes:%d\n", n);
    // 后续可加入缓存功能
    return 0;
}

char *DNS_tcp_root(char *domain, unsigned short type, int *offset, char *response, char *ip, char *next_response) // 返回的ip为需要去查询的ip地址
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); // 若成功则返回一个sockfd (套接字描述符)

    struct sockaddr_in server_sockaddr; // 一般是储存地址和端口，用于信息的显示及存储作用
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(DNS_SERVER_PORT); // 将一个无符号短整型数值转换为网络字节序，即大端模式
    server_sockaddr.sin_addr.s_addr = inet_addr(DNS_ROOT_ADDRESS);

    if (connect(sockfd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) < 0)
    {
        perror("connect");
        exit(1);
    }
    char request[MESSAGE_LEN] = {0};
    struct DNS_Header header = {0};
    struct DNS_Query *query = calloc(1, sizeof(struct DNS_Query));
    DNS_root_header_create(&header, domain);
    DNS_query_create(query, domain, type);
    *offset = DNS_root_build(&header, query, request);
    send(sockfd, request, *offset, 0);
    printf("send bytes:%d\n", *offset);

    int n = recv(sockfd, response, MESSAGE_LEN, 0);
    printf("receive bytes:%d\n", n);
    // 开始解析
    DNS_root_parse_response(response, ip);
    // 得到ip后，向该ip发起查询
    // char next_response[MESSAGE_LEN]={0};
    tcp_socket_init(ip, request, *offset, next_response); // 得到回应后，返回给client
    append_to_cache(next_response);
    return response;
}
int DNS_root_header_create(struct DNS_Header *header, char *domain) // 不止root,可适用于next-level
{
    if (header == NULL)
    {
        printf("Header wrong!\n");
        return -1;
    }

    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL)); // linux下
    header->id = random();
    // srand(time(NULL)); //windows下
    // header->id = rand();
    header->tag = htons(0x0100);
    header->queryNum = htons(0x0001); // 假定只有一条记录
    header->answerNum = htons(0x0000);
    header->authorNum = htons(0x0000);
    header->addNum = htons(0x0000);

    return 0;
}

int DNS_root_build(struct DNS_Header *header, struct DNS_Query *query, char *request) // 不止root,可适用于next-level
{
    if (header == NULL || query == NULL || request == NULL)
    {
        printf("DNS build failed.\n");
        return -1;
    }
    char *ptr = request;

    memset(request, 0x00, MESSAGE_LEN);
    int offset = 2;
    memcpy(request + offset, header, sizeof(struct DNS_Header));
    offset += sizeof(struct DNS_Header);

    memcpy(request + offset, query->name, query->length);
    offset += query->length;

    memcpy(request + offset, &query->qtype, sizeof(unsigned short));
    offset += sizeof(unsigned short);
    memcpy(request + offset, &query->qclass, sizeof(unsigned short));
    offset += sizeof(unsigned short);

    unsigned short data_len = htons((unsigned short)(offset - 2));

    memcpy(request, &data_len, 2);
    return offset;
}
int DNS_root_parse_response(char *response, char *ip)
{ // 这里返回的地址为应该查询的次级域名服务器
    if (response == NULL)
    {
        printf("no root response");
        return -1;
    }
    char *ptr = response + 2; // 跳过报文长
    // header
    struct DNS_Header header = {0};
    header.id = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.tag = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.queryNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.answerNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.authorNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.addNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;

    // query
    struct DNS_Query *query = calloc(header.queryNum, sizeof(struct DNS_Query));
    for (int i = 0; i < header.queryNum; i++)
    {
        int len_q = 0;
        dns_parse_name(response + 2, ptr, &query[i].name, &len_q);
        ptr += (len_q + 2);

        query[i].qtype = htons(*(unsigned short *)ptr);
        ptr += 2;
        query[i].qclass = htons(*(unsigned short *)ptr);
        ptr += 2;
    }

    // answer
    char cname[NAME_LEN], aname[NAME_LEN], net_ip[NET_IP_LEN];
    struct DNS_RR *answer = calloc(header.answerNum + header.addNum + header.authorNum, sizeof(struct DNS_RR));
    int len_r = 0;
    for (int i = 0; i < header.answerNum + header.addNum + header.authorNum; i++)
    {
        len_r = 0;
        dns_parse_name(response + 2, ptr, &answer[i].name, &len_r);
        ptr += (len_r + 2);
        answer[i].type = htons(*(unsigned short *)ptr);
        ptr += 2;
        answer[i].rclass = htons(*(unsigned short *)ptr);
        ptr += 2;
        answer[i].ttl = htons(*(unsigned int *)ptr);
        ptr += 4;
        answer[i].data_len = htons(*(unsigned short *)ptr);
        ptr += 2;
        len_r = 0;
        // bzero(ip, sizeof(ip));
        memcpy(net_ip, ptr, 4);
        dns_parse_name(response + 2, ptr, &answer[i].rdata, &len_r);
        ptr += answer[i].data_len;
        inet_ntop(AF_INET, net_ip, ip, sizeof(struct sockaddr));
        printf("%s has an address of %s\n", &answer[i].name, ip);
    }
}
void append_to_cache(char *response)
{ // 实现缓存功能
    if (response == NULL)
    {
        printf("No response");
        return -1;
    }
    char *ptr = response + 2;
    // header
    struct DNS_Header header = {0};
    header.id = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.tag = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.queryNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.answerNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.authorNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.addNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;

    // query
    struct DNS_Query *query = calloc(header.queryNum, sizeof(struct DNS_Query));
    for (int i = 0; i < header.queryNum; i++)
    {
        int len_q = 0;
        dns_parse_name(response, ptr, &query[i].name, &len_q);
        ptr += (len_q + 2);

        query[i].qtype = htons(*(unsigned short *)ptr);
        ptr += 2;
        query[i].qclass = htons(*(unsigned short *)ptr);
        ptr += 2;
    }

    // answer
    char cname[NAME_LEN], aname[NAME_LEN], ip[IP_LEN], net_ip[NET_IP_LEN];
    struct DNS_RR *answer = calloc(header.answerNum + header.addNum + header.authorNum, sizeof(struct DNS_RR));
    int len_r = 0;
    char split[] = " ";
    char *ttl_cache = "86400 ";
    char *class_cache = "IN ";
    for (int i = 0; i < header.answerNum + header.addNum + header.authorNum; i++)
    {
        len_r = 0;
        dns_parse_name(response, ptr, &answer[i].name, &len_r);
        ptr += (len_r + 2);
        answer[i].type = htons(*(unsigned short *)ptr);
        ptr += 2;
        answer[i].rclass = htons(*(unsigned short *)ptr);
        ptr += 2;
        answer[i].ttl = htons(*(unsigned int *)ptr);
        ptr += 4;
        answer[i].data_len = htons(*(unsigned short *)ptr);
        ptr += 2;
        len_r = 0;
        // 判断type
        if (answer[i].type == TYPE_CNAME)
        {
            FILE *file = fopen(path, "a+");
            dns_parse_name(response, ptr, &answer[i].rdata, &len_r);
            ptr += answer[i].data_len;
            printf("%s has a cname of %s\n", &answer[i].name, &answer[i].rdata);
            char *namedup = strdup(&answer[i].name);
            char *datadup = strdup(&answer[i].rdata);
            char *cache = strcat(namedup, split);
            cache = strcat(cache, ttl_cache);
            cache = strcat(cache, class_cache);
            cache = strcat(cache, "CNAME ");
            cache = strcat(cache, datadup);
            cache = strcat(cache, "\n");
            fputs(cache, file);
            fclose(file);
        }
        else if (answer[i].type == TYPE_A)
        {
            FILE *file = fopen(path, "a+");
            bzero(ip, sizeof(ip));
            memcpy(net_ip, ptr, 4);
            dns_parse_name(response, ptr, &answer[i].rdata, &len_r);
            ptr += answer[i].data_len;
            inet_ntop(AF_INET, net_ip, ip, sizeof(struct sockaddr));
            printf("%s has an address of %s\n", &answer[i].name, ip);
            char *namedup = strdup(&answer[i].name);
            char *ipdup=strdup(ip);
            // char *datadup=strdup(&answer[i].rdata);
            char *cache = strcat(namedup, split);
            cache = strcat(cache, ttl_cache);
            cache = strcat(cache, class_cache);
            cache = strcat(cache, "A ");
            cache = strcat(cache, ipdup);
            cache = strcat(cache, "\n");
            fputs(cache, file);
            fclose(file);
        }
        else if (answer[i].type == TYPE_MX)
        {
            ptr += 2; // 跳过preference
            dns_parse_name(response, ptr, &answer[i].rdata, &len_r);
            ptr += answer[i].data_len - 2;
            printf("%s has a mail exchange name of %s\n", &answer[i].name, &answer[i].rdata);
            char *namedup = strdup(&answer[i].name);
            char *datadup = strdup(&answer[i].rdata);
            char *cache = strcat(namedup, split);
            cache = strcat(cache, ttl_cache);
            cache = strcat(cache, class_cache);
            cache = strcat(cache, "MX ");
            cache = strcat(cache, datadup);
            cache = strcat(cache, "\n");
            FILE *tempFile = fopen("temp.txt", "w");
            FILE *file = fopen(path, "a+");
            char line[100];
            if (tempFile == NULL)
            {
                printf("cannot open temp file\n");
                exit(1);
            }
            // 写入要添加的行到临时文件中
            fputs(cache, tempFile);
            // 逐行将原始文件的内容写入临时文件中
            while (fgets(line, sizeof(line), file) != NULL)
            {
                fputs(line, tempFile);
            }
            fclose(tempFile);
            fclose(file);
            // 删除原始文件
            if (remove(path) != 0)
            {
                printf("cannot remove\n");
                exit(1);
            }
            // 重命名临时文件为原始文件名
            if (rename("temp.txt", path) != 0)
            {
                printf("无法重命名临时文件。\n");
                exit(1);
            }

            // fputs(cache,file);
        }
    }
}
