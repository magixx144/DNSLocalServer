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
            if (type == TYPE_A){ //A对应A和CNAME
                if (ascii_type == A_ASCII){
                    query_type_state = 1;
                }else if(ascii_type ==CNAME_ASCII){
                    query_type_state=1;
                }
            }else if(type==TYPE_CNAME){//CNAME对应CNAME
                if(ascii_type==CNAME_ASCII){
                    query_type_state=1;
                }
            }else if(type==TYPE_MX){//MX对应A,CNAME,MX
                if (ascii_type == A_ASCII){
                    query_type_state = 1;
                }else if(ascii_type ==CNAME_ASCII){
                    query_type_state=1;
                }else if(ascii_type==MX_ASCII){
                    query_type_state = 1;
                }
            }

            if (query_name_state&&query_type_state)
                answerNum++;
        }
    }
    return answerNum;
}

unsigned short DNS_table_init(struct DNS_RR *answer, char *path, char *domain, unsigned short type, unsigned short *add)
{
    char *buffer = malloc(MESSAGE_LEN);
    char *data_list[10]; // 存放buffer中读到的记录
    FILE *file = fopen(path, "ab+");
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    int i = 0;
    unsigned short answerNum = 0;
    memset(rr, 0x00, sizeof(struct DNS_RR));

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
    return answerNum;
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
    header->answerNum = htons(get_answerNum(path, domain,type) - add);
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
    ser.sin_port = htons(9945);
    ser.sin_addr.s_addr = inet_addr(LOCAL_DNS_ADDRESS);

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
        int answerNum = get_answerNum(path, domain,type);
        unsigned short add = 0; // 记录add数目

        struct DNS_RR *answer = calloc(answerNum, sizeof(struct DNS_RR));
        DNS_table_init(answer, path, domain, type, &add);
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

    close(sockfd);

    return 0;
}