#include<bits/stdc++.h>
#include<netinet/in.h>  
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h> 
#include<sys/types.h>
#include <arpa/inet.h>
#include<unistd.h>
#include<fcntl.h>
#include <stdio.h>
using namespace std;
void send_msg()
{
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port= htons(9501);  
    add.sin_addr.s_addr =inet_addr("172.20.207.29 ");
    int reuse=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    
    char plaintext[10000];
    memset(plaintext,0,sizeof(plaintext));
    int fd1=open("plaintext.txt",O_RDONLY);
    read(fd1,plaintext,sizeof(plaintext));
    cout<<"plaintext = "<<plaintext<<endl;
    
    system("openssl enc -aes-128-ecb -e -in plaintext.txt -out ciphertext.txt -K $(cat key.txt)");
    
    
    char ciphertext[10000];
    memset(ciphertext,0,sizeof(ciphertext));
    int fd2=open("ciphertext.txt",O_RDONLY);
    read(fd2,ciphertext,sizeof(ciphertext));
    cout<<"ciphertext = "<<ciphertext<<endl;
    cout<<strlen(ciphertext)<<endl;
   
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
    send(nsfd,ciphertext,sizeof(ciphertext),0);
    cout<<"sent successfully"<<endl;
    close(sfd);
    close(nsfd);
    close(fd1);
    close(fd2);
    return;
}
void send_hash()
{
    int sfd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add;
    add.sin_family = AF_INET;
    add.sin_port= htons(8000);  
    add.sin_addr.s_addr =inet_addr("172.20.207.29 ");
    int reuse=1;
    setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    
    system("openssl dgst -sha256 -hex plaintext.txt > hash_value.txt");
    
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
int main()
{
    string message="The sun set behind the mountains";
    int fd=open("hash_value.txt",O_RDONLY);
    write(fd,message.c_str(),message.size());
    close(fd);
    send_msg();
    send_hash();
    return 0;
}
