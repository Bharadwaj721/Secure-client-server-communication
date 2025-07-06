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

void send_msg()
{
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port= htons(9500);  
    add.sin_addr.s_addr =inet_addr("10.42.0.79");
    int reuse=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    system("openssl rand -hex 32 > key.txt");
    char key[10000];
    memset(key,0,sizeof(key));
    int fd2=open("key.txt",O_RDONLY);
    read(fd2,key,sizeof(key));
    cout<<"key="<<key<<endl;
    int c= connect(sfd,(struct sockaddr*)&add,sizeof(add));
    send(sfd,key,sizeof(key),0);
    cout<<"sent successfully"<<endl;
    close(sfd);
    close(fd2);
    return;
}

int main (int argc, char* argv[])
{ 
    send_msg();
    return 0;
}