#include<bits/stdc++.h>
#include<unistd.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <sys/wait.h>
#include<poll.h>
#include<sys/msg.h>
#include<csignal>
#include<sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
using namespace std;
int main()
{
    int sfd,nsfd;
    struct sockaddr_in s_add,c_add;
    int opt=1;
    if((sfd=socket(AF_INET,SOCK_STREAM,0))<0)
    {
        perror("socket failed");
        exit(0);
    }
    if(setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR|SO_REUSEPORT,&opt,sizeof(opt)))
    {
        perror("set socket option failed");
        exit(0);
    }
    s_add.sin_family=AF_INET;
    s_add.sin_addr.s_addr=inet_addr("172.20.207.29 "); 
    s_add.sin_port=htons(9500);
    if(bind(sfd,(struct sockaddr*)&s_add,sizeof(s_add))<0)
    {
        perror("binding failed");
        exit(0);
    }
    if(listen(sfd,3)<0)
    {
        perror("listining failed");
        exit(0);
    }
    socklen_t c_add_len=sizeof(c_add);
    if((nsfd=accept(sfd,(struct sockaddr*)&c_add,&c_add_len))<0)
    {
        perror("accpeting failed");
        exit(0);
    }
    char key[1000];
    int size=0;
    size=recv(nsfd,key,sizeof(key),0);
    key[size]='\0';
    cout<<"Key is "<<key<<endl;
    int fd=open("key.txt",O_WRONLY);
    write(fd,key,strlen(key));
    close(fd);
    close(nsfd);
    close(sfd);
    return 0;
}

