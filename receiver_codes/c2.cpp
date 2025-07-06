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
string s1,s2;
void recieving_hash()
{
    int sfd1=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add1;
    add1.sin_family = AF_INET;
    add1.sin_port= htons(8000);  
    add1.sin_addr.s_addr =inet_addr("10.42.0.79");
    int reuse=1;
    setsockopt(sfd1,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    int c= connect(sfd1,(struct sockaddr*)&add1,sizeof(add1));


    char cipher_hash1[1000];
    memset(cipher_hash1,0,sizeof(cipher_hash1));
    int size=0;
    size=recv(sfd1,cipher_hash1,sizeof(cipher_hash1),0);
    // cipher_hash[size]='\0';
    cout<<"hash1="<<cipher_hash1<<endl;
    int fd1=open("cipher_hash1.txt",O_WRONLY);
    write(fd1,cipher_hash1,strlen(cipher_hash1));
    system("openssl enc -aes-128-ecb -d -nopad -in cipher_hash1.txt -out decrypted_hash1.txt -K $(cat key.txt)");
    system("openssl dgst -sha256 -hex original_message1.txt > hash_computed1.txt");
    close(fd1);
    /*######################################################################################################*/

    int sfd2=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add2;
    add2.sin_family = AF_INET;
    add2.sin_port= htons(8001);  
    add2.sin_addr.s_addr =inet_addr("10.42.0.126");
    int reuse1=1;
    setsockopt(sfd2,SOL_SOCKET,SO_REUSEADDR,&reuse1,sizeof(reuse1));
    sleep(5);
    int c1= connect(sfd2,(struct sockaddr*)&add2,sizeof(add2));

    char cipher_hash2[1000];
    memset(cipher_hash2,0,sizeof(cipher_hash2));
    int size2=0;
    size2=recv(sfd2,cipher_hash2,sizeof(cipher_hash2),0);
    // cipher_hash[size]='\0';
    cout<<"hash2="<<cipher_hash2<<endl;
    int fd2=open("cipher_hash2.txt",O_WRONLY);
    write(fd2,cipher_hash2,strlen(cipher_hash2));
    system("openssl enc -aes-128-ecb -d -nopad -in cipher_hash2.txt -out decrypted_hash2.txt -K $(cat key.txt)");
    system("openssl dgst -sha256 -hex original_message2.txt > hash_computed2.txt");
    close(fd2);
    return;

}
int main()
{
    int sfd1=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add1;
    add1.sin_family = AF_INET;
    add1.sin_port= htons(9501);  
    add1.sin_addr.s_addr =inet_addr("10.42.0.79");
    int reuse=1;
    setsockopt(sfd1,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
    int c= connect(sfd1,(struct sockaddr*)&add1,sizeof(add1));


    char cipher_text1[1000];
    memset(cipher_text1,0,sizeof(cipher_text1));
    int size=0;
    size=recv(sfd1,cipher_text1,sizeof(cipher_text1),0);
    cipher_text1[size]='\0';
    cout<<"cipher_text1="<<cipher_text1<<endl;
    int fd1=open("cipher_text1.txt",O_WRONLY);
    write(fd1,cipher_text1,strlen(cipher_text1));
    cout.flush();
    sleep(3);
    system("openssl enc -aes-128-ecb -d -nopad -in cipher_text1.txt -out decrypted1.txt -K $(cat key.txt)");
    sleep(3);

    char msg1[32];
    memset(msg1,0,sizeof(msg1));
    int fd2=open("decrypted1.txt",O_RDONLY);
    read(fd2,msg1,sizeof(msg1));
    cout<<"message=";
    for(int i=0;i<32;i++)
    {
        s1.push_back({msg1[i]});
        cout<<msg1[i];
    }
    s1.push_back('\n');
    int fd10=open("original_message1.txt",O_WRONLY);
    write(fd10,s1.c_str(),s1.size());
    cout<<endl;
    close(sfd1);
    close(fd1);
    close(fd2);
    close(fd10);
    /*###################################################################################################*/
    int sfd2=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in add2;
    add2.sin_family = AF_INET;
    add2.sin_port= htons(9510);  
    add2.sin_addr.s_addr =inet_addr("10.42.0.126");
    int reuse1=1;
    setsockopt(sfd2,SOL_SOCKET,SO_REUSEADDR,&reuse1,sizeof(reuse1));
    sleep(5);
    int c1= connect(sfd2,(struct sockaddr*)&add2,sizeof(add2));


    char cipher_text2[1000];
    memset(cipher_text2,0,sizeof(cipher_text2));
    int size2=0;
    size2=recv(sfd2,cipher_text2,sizeof(cipher_text2),0);
    cipher_text2[size2]='\0';
    cout<<"cipher_text2="<<cipher_text2<<endl;
    int fd200=open("cipher_text2.txt",O_WRONLY);
    write(fd200,cipher_text2,strlen(cipher_text2));
    cout.flush();
    sleep(3);
    system("openssl enc -aes-128-ecb -d -nopad -in cipher_text2.txt -out decrypted2.txt -K $(cat key.txt)");

    sleep(3);

    char msg2[32];
    memset(msg2,0,sizeof(msg2));
    int fd22=open("decrypted2.txt",O_RDONLY);
    read(fd22,msg2,sizeof(msg2));
    cout<<"message=";
    for(int i=0;i<32;i++)
    {
        s2.push_back(msg2[i]);
        cout<<msg2[i];
    }
    s2.push_back('\n');
    cout<<endl;
    int fd11=open("original_message2.txt",O_WRONLY);
    write(fd11,s2.c_str(),s2.size());
    // cout<<msg;
    // cout.flush();
    close(sfd2);
    close(fd200);
    close(fd22);
    close(fd11);
    recieving_hash();
    return 0;
}

