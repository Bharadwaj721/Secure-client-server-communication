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
char message[1000];
void catch_message()
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
    s_add.sin_addr.s_addr=inet_addr("10.42.0.126"); 
    s_add.sin_port=htons(9503);
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
    int size=0;
    size=recv(nsfd,message,sizeof(message),0);
    message[size]='\0';
    cout<<"Message is "<<message<<endl;
    close(nsfd);
    close(sfd);
    return;
}
void send_msg()
{
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port= htons(9510);  
    add.sin_addr.s_addr =inet_addr("10.42.0.126");
    int reuse=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    
    
    if(bind(sfd,(struct sockaddr*)&add,sizeof(add))<0)
    {
        perror("binding failed");
        exit(0);
    }
    if(listen(sfd,3)<0)
    {
        perror("listining failed");
        exit(0);
    }
    socklen_t c_add_len=sizeof(add);
    
    cout<<"Sending message ..."<<endl;
    message[0]++;
    cout<<message<<endl;
    int nsfd;
    if((nsfd=accept(sfd,(struct sockaddr*)&add,&c_add_len))<0)
    {
        perror("accpeting failed");
        exit(0);
    }
    
    send(nsfd,message,sizeof(message),0);
    cout<<"sent successfully"<<endl;
    close(sfd);
    close(nsfd);
    return;
}
void send_hash()
{
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port= htons(8001);  
    add.sin_addr.s_addr =inet_addr("10.42.0.126");
    int reuse=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    
    system("openssl dgst -sha256 -hex message.txt > hash_value.txt");
    
    system("openssl enc -aes-128-ecb -e -in hash_value.txt -out cipherhash.txt -K $(cat key.txt)");
    
    char hash[10000];
    memset(hash,0,sizeof(hash));
    int fd2=open("cipherhash.txt",O_RDONLY);
    read(fd2,hash,sizeof(hash));
    cout<<"hash = "<<hash<<endl;
   
    if(bind(sfd,(struct sockaddr*)&add,sizeof(add))<0)
    {
        perror("binding failed");
        exit(0);
    }
    if(listen(sfd,3)<0)
    {
        perror("listining failed");
        exit(0);
    }
    socklen_t c_add_len=sizeof(add);
    int nsfd;
    if((nsfd=accept(sfd,(struct sockaddr*)&add,&c_add_len))<0)
    {
        perror("accpeting failed");
        exit(0);
    }
    send(nsfd,hash,sizeof(hash),0);
    cout<<"sent successfully"<<endl;
    close(sfd);
    close(nsfd);
    close(fd2);
    return;
}
void attack()
{
    send_msg();
    send_hash();
}
int main()
{
    catch_message();
    attack();
}

