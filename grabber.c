#include <gtk/gtk.h>
#include <stdio.h>
#include <pcap.h>
#include<time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<string.h>

typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;
eth_hdr *ethernet;

typedef struct ip_hdr
{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}ip_hdr;
ip_hdr *ip;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}tcp_hdr;
tcp_hdr *tcp;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
}udp_hdr;
udp_hdr *udp;


GtkWidget *window;
GtkWidget *filterText;
GtkWidget *bagNumText;
GtkWidget *intNameText;
GtkWidget *text_view;
GtkWidget *tablegrid;
GtkWidget *flowText;
GtkWidget *flowsText;
GtkTextBuffer *buffer;
GtkTextIter start,end;
int flows=0,flow;
char flowStr[30],flowsStr[30];

void pcap_callback(unsigned char * arg,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content){
    static int id=1;
    char info[1024];
    sprintf(info,"id=%d\n",id++);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    pcap_dump(arg,packet_header,packet_content);

    sprintf(info,"包长度 : %d\n",packet_header->len);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    sprintf(info,"字节数 : %d\n",packet_header->caplen);
    flow=packet_header->caplen;
    flows+=flow;
    sprintf(flowStr,"%d",flow);
    sprintf(flowsStr,"%d",flows);
    gtk_entry_set_text(flowText,flowStr);
    gtk_entry_set_text(flowsText,flowsStr);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    sprintf(info,"接收时间 : %s\n",ctime((const time_t*)&packet_header->ts.tv_sec));
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    int i;
    for(i=0;i<packet_header->caplen;i++){
        sprintf(info," %02x",packet_content[i]);
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        if((i+1)%16==0){
            sprintf(info,"\n");
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        }
    }
    sprintf(info,"\n\n");
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);

    u_int eth_len=sizeof(struct eth_hdr);
    u_int ip_len=sizeof(struct ip_hdr);
    u_int tcp_len=sizeof(struct tcp_hdr);
    u_int udp_len=sizeof(struct udp_hdr);

    sprintf(info,"信息分析:\n\n");
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);

    sprintf(info,"以太网头部信息:\n");
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    ethernet=(eth_hdr *)packet_content;
    sprintf(info,"来源mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    sprintf(info,"目的mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    sprintf(info,"以太网类型 : %u\n",ethernet->eth_type);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);

    if(ntohs(ethernet->eth_type)==0x0800){
        sprintf(info,"使用IPV4协议\n");
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        sprintf(info,"IPV4 头信息:\n");
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        ip=(ip_hdr*)(packet_content+eth_len);
        sprintf(info,"来源 ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        sprintf(info,"目标 ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        if(ip->protocol==6){
            sprintf(info,"使用TCP协议:\n");
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
            tcp=(tcp_hdr*)(packet_content+eth_len+ip_len);
            sprintf(info,"TCP 来源端口 : %u\n",tcp->sport);
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
            sprintf(info,"TCP 目的端口 : %u\n",tcp->dport);
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        }
        else if(ip->protocol==17){
            sprintf(info,"使用UDP协议:\n");
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
            udp=(udp_hdr*)(packet_content+eth_len+ip_len);
            sprintf(info,"UDP 来源端口 : %u\n",udp->sport);
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
            sprintf(info,"UDP 目标端口 : %u\n",udp->dport);
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        }
        else {
            sprintf(info,"使用其他协议\n");
            gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
        }
    }
    else {
        sprintf(info,"使用ipv6协议\n");
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    }

    sprintf(info,"------------------抓包完成，已保存-------------------\n");
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    sprintf(info,"\n\n");
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    while(gtk_events_pending()){ 

             gtk_main_iteration();         

    }         

    sleep(1); 
}


void grab(GtkObject *object, gpointer user_data)
{
    char *intName,*filters=NULL,*bagNumStr;
    char errbuf[1024];
    char *dev=intName;
    char info[1024];
    gtk_text_buffer_set_text(buffer,"",0); 
    intName=gtk_entry_get_text(intNameText);
    filters=gtk_entry_get_text(filterText);
    bagNumStr=gtk_entry_get_text(bagNumText);
    gtk_text_buffer_get_bounds(GTK_TEXT_BUFFER(buffer),&start,&end);
    dev=intName;
    if(dev==NULL){
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&start,"网络接口为空，请重新输入!",-1);
        return 0;
    }

    pcap_t *pcap_handle=pcap_open_live(dev,65535,1,0,errbuf);

    if(pcap_handle==NULL){
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&start,errbuf,-1);
        return 0;
    }

    struct in_addr addr;
    bpf_u_int32 ipaddress, ipmask;
    char *dev_ip,*dev_mask;

    if(pcap_lookupnet(dev,&ipaddress,&ipmask,errbuf)==-1){
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&start,errbuf,-1);
        return 0;
    }

    addr.s_addr=ipaddress;
    dev_ip=inet_ntoa(addr);
    sprintf(info,"ip 地址 : %s\n",dev_ip);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);

    addr.s_addr=ipmask;
    dev_mask=inet_ntoa(addr);
    sprintf(info,"掩码 : %s\n",dev_mask);
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);

    struct bpf_program filter;
    if(pcap_compile(pcap_handle,&filter,filters,1,0)<0){
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,"过滤规则错误!",-1);
        return 0;
    }
    if(pcap_setfilter(pcap_handle,&filter)<0){
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,"设置过滤规则失败!",-1);
        return 0;
    }


    sprintf(info,"---------开始抓包--------\n");
    gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,info,-1);
    int id=0;


    pcap_dumper_t* dumpfp=pcap_dump_open(pcap_handle,"./save1.pcap");

    if(pcap_loop(pcap_handle,atoi(bagNumStr),pcap_callback,(unsigned char *)dumpfp)<0){
        gtk_text_buffer_insert(GTK_TEXT_BUFFER(buffer),&end,"抓包失败!",-1);
        return 0;
    }

    pcap_dump_close(dumpfp);

    pcap_close(pcap_handle);

    return 0;
}
 
int main (int argc, char *argv[])
{
    GtkWidget *startBtn;  
    GtkWidget *window;
    gtk_init (&argc, &argv);
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    tablegrid=gtk_table_new(24,7,TRUE);
    GtkWidget *intLabel=gtk_label_new("网络接口");
    GtkWidget *bagNumLabel=gtk_label_new("抓包数量");
    GtkWidget *filterLabel=gtk_label_new("过滤规则");
    GtkWidget *flowLabel=gtk_label_new("当前流量");
    GtkWidget *flowsLabel=gtk_label_new("总流量");
    GtkWidget *scwindow=gtk_scrolled_window_new(NULL,NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scwindow),GTK_POLICY_AUTOMATIC,GTK_POLICY_ALWAYS);
    text_view=gtk_text_view_new();
    buffer=gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_container_add((GtkContainer*)scwindow,text_view);
    bagNumText = gtk_entry_new();
    filterText = gtk_entry_new();
    intNameText = gtk_entry_new();
    flowText=gtk_entry_new();;
    flowsText=gtk_entry_new();
    startBtn = gtk_button_new_with_label("开始抓包");
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), intLabel, 0, 1, 0, 1);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), intNameText, 1, 2, 0, 1);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), bagNumLabel, 2, 3, 0, 1);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), bagNumText, 3, 4, 0, 1);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), flowLabel, 4, 5, 0, 1);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), flowText, 5, 6, 0, 1);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), filterLabel, 0, 1, 1, 2);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), filterText, 1, 4, 1, 2);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), flowsLabel, 4, 5, 1, 2);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), flowsText, 5, 6, 1, 2);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), startBtn, 6, 7, 0, 2);
    gtk_table_attach_defaults(GTK_TABLE(tablegrid), scwindow, 0, 7, 2, 24);
    gtk_container_add(GTK_CONTAINER(window),tablegrid);
    g_signal_connect(startBtn, "pressed", G_CALLBACK(grab), "开始抓包");
    g_signal_connect (GTK_OBJECT(window), "destroy",G_CALLBACK (gtk_main_quit), NULL);
    gtk_widget_show_all ((GtkWidget*)window);
    gtk_main ();
    return 0;
}