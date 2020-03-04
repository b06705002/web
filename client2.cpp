#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iomanip>
#include <fstream>
#include <string>
using namespace std;

int main(int argc , char *argv[])
{

    //socket的建立
    int sockfd = 0;
    sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if (sockfd == -1){
        cout << "Fail to create a socket.";
        return 0;
    }

    //socket的連線

    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;

    //localhost test
    int port;
    char ip[100];
    cout << "Enter IP address" << "\n";
    cin >> ip;
    cout << "Enter Port" << "\n";
    cin >> port;
    info.sin_addr.s_addr = inet_addr(ip);
    info.sin_port = htons(port);


    int err = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(err == -1){
        cout << "Connection error";
        return 0;
    }


    //Send a message to server
    char receiveMessage[100] = {};
    recv(sockfd,receiveMessage,sizeof(receiveMessage),0);
    cout << "receiveMessage: " << receiveMessage << "\n";
    memset(receiveMessage, '\0', sizeof(receiveMessage));

    char imput[100] = {};
    char message[100] = {};
    char hostip[100] = {};
    bool suc_login = false;
    while(suc_login == false)
    {
        cout << "Enter 'r' To Register----Enter 'l' To Login" << "\n";
        cout << "------------------------------------------------------------" << "\n";
        memset(message, '\0', sizeof(message));
        memset(imput, '\0', sizeof(imput));
        memset(receiveMessage, '\0', sizeof(receiveMessage));
        string key;
        cin >> key;
        if (key == "r")
        {
            cout << "Enter Register Username: ";
            cin >> imput;
            strcpy(message, "REGISTER#");
            strcat(message, imput);
            strcat(message, "\n");
            send(sockfd, message, sizeof(message), 0);
            recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);
            cout << "Receivemessage: " << receiveMessage << "\n";
        }
        else if (key == "l")
        {
            cout << "Enter Login Username: ";
            cin >> imput;
            strcpy(hostip, imput);
            strcpy(message, imput);
            strcat(message, "#");
            memset(imput, '\0', sizeof(imput));
            cout << "Enter Portnumber: ";
            cin >> imput;
            strcat(message, imput);
            strcat(message, "\n");
            send(sockfd, message, sizeof(message), 0);
            recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);
            cout << "Receivemessage: " << receiveMessage << "\n";
            if (strstr(receiveMessage, "AUTH_FAIL") == NULL)
            {
                suc_login = true;
            }
        }
        else
        {
            cout << "Invalid Option!!!" << "\n";
            cout << "------------------------------------------------------------" << "\n";
        }
    }
    while(suc_login == true)
    {

        cout << "Enter 'ls' To List--Enter 'q' To Quit--Enter 'c' To Connect--Enter 'a' To Accept" << "\n";
        cout << "------------------------------------------------------------" << "\n";
        memset(message, '\0', sizeof(message));
        memset(receiveMessage, '\0', sizeof(receiveMessage));
        string key;
        cin >> key;
        if (key == "ls")
        {
            strcpy(message, "List");
            strcat(message, "\n");
            send(sockfd, message, sizeof(message), 0);
            recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);
            cout << "Receivemessage:" << "\n";
            cout << receiveMessage;
        }
        else if (key == "q")
        {
            strcpy(message, "Exit");
            strcat(message, "\n");
            send(sockfd, message, sizeof(message), 0);
            recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);
            cout << "Receivemessage: " << receiveMessage << "\n";
            if (strstr(receiveMessage, "Bye") != NULL)
            {
                suc_login = false;
            }
        }
        else if (key == "c")
        {
            int status;
            if (fork() == 0)
            {
                char connectuser[100] = {};
                strcpy(message, "RC#");
                cout << "Required User Name" << endl;
                cin >> connectuser;
                char cip[100] = {};
                char cport[100] ={};
                strcat(message, connectuser);
                strcat(message, "\n");
                send(sockfd, message, sizeof(message), 0);
                recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);
                // cout << "Receivemessage:" << "\n";
                // cout << receiveMessage;
                if (strstr(receiveMessage, "CON_FAIL") != NULL)
                {
                    cout << "User Does Not Exist" << endl;
                }
                else
                {
                    strcpy(cip, receiveMessage);
                    strtok(cip, "#");
                    strcpy(cport, strtok(NULL, "#"));
                    strcpy(cport, strtok(cport, "\n"));
                }
                // cout << "-----" << cip << "----" << cport << endl;
                int pNUM = 0;
                pNUM = atoi(cport);
                cout << "Enter Money:" << endl;
                int money = 0;
                cin >> money;

                int sockfd2 = 0;
                sockfd2 = socket(AF_INET, SOCK_STREAM, 0);

                if (sockfd2 == -1)
                {
                    cout << "Fail to create a socket.";
                    return 0;
                }

                struct sockaddr_in info2;
                bzero(&info,sizeof(info2));
                info2.sin_family = PF_INET;
                info2.sin_addr.s_addr = inet_addr(cip);
                info2.sin_port = htons(pNUM);

                int err2 = connect(sockfd2,(struct sockaddr *)&info2,sizeof(info2));
                if(err2 == -1){
                    cout << "Connection error";
                    return 0;
                }
                char enc[100] = {};
                char amount[100] = {};
                sprintf(amount, "%d", money);
                strcat(enc, hostip);
                strcat(enc, "#");
                strcat(enc, amount);
                strcat(enc, "#");
                strcat(enc, connectuser);
                strcat(enc, "\n");


                FILE *pri;
                RSA *privateRSA = nullptr;
                if ((pri = fopen("payer_pri.pem", "r")) == NULL)
                {
                    cout << "Payer Private Error" << endl;
                    exit(-1);
                }
                //initialize
                OpenSSL_add_all_algorithms();
                if ((privateRSA = PEM_read_RSAPrivateKey(pri, NULL, NULL, NULL)) == NULL)
                {
                    cout << "Fail to Read private" << endl;
                }
                fclose(pri);
                //size of key
                int rsa_len = RSA_size(privateRSA);
                const unsigned char* ptxt = (const unsigned char*)enc;
                unsigned char* stxt = (unsigned char*)malloc(rsa_len);
                //RSA_PKCS1_PADDING(-11)
                if (RSA_private_encrypt(rsa_len-11, ptxt, stxt, privateRSA, RSA_PKCS1_PADDING) < 0)
                {
                    cout << "Encode error" << endl;
                }
                cout << "stxt: " << stxt << endl;
                RSA_free(privateRSA);
                
                send(sockfd2, stxt, rsa_len, 0);
            }
            else
                wait(&status);
        }
        else if (key == "a")
        {
            int status;
            int fd[2];
            pipe(fd);
            char emessage[1000];
            if (fork() == 0)
            {
                int ppppp;
                cout << "Enter Port Again:" << "\n";
                cin >> ppppp;
                int socket_desc2, new_socket2, c2;
                struct sockaddr_in server2, client2;
                char ermessage[1000] = {};

                socket_desc2 = socket(AF_INET, SOCK_STREAM, 0);
                if (socket_desc2 == -1)
                {
                    cout << "Fail to create a socket.";
                    return 0;
                }

                server2.sin_family = AF_INET;
                server2.sin_addr.s_addr = INADDR_ANY; //任意地址
                server2.sin_port = htons(ppppp);

                if (bind(socket_desc2, (struct sockaddr*)&server2, sizeof(server2)) < 0)
                {
                    cout << "Fail to bind";
                    return 0;
                }
                cout << "Succeed to bind." << endl;
                listen(socket_desc2, 3);
                cout << "Waiting for connections..." << endl;
                c2 = sizeof(struct sockaddr_in);
                new_socket2 = accept(socket_desc2, (struct sockaddr*)&client2, (socklen_t*)&c2);
                if (new_socket2 < 0)
                {
                    cout << "Acception Failed" << endl;
                    return 0;
                }
                cout << "Assigned." << endl;
                recv(new_socket2, ermessage, sizeof(ermessage), 0);
                cout << "Receive message: " << ermessage << endl;


                FILE *payer;
                RSA *payerRSA = nullptr;
                if ((payer = fopen("payer_pub.pem", "r")) == NULL)
                {
                    cout << "Payer Public Error" << endl;
                    exit(-1);
                }
                //initialize
                OpenSSL_add_all_algorithms();
                if ((payerRSA = PEM_read_RSA_PUBKEY(payer, NULL, NULL, NULL)) == NULL)
                {
                    cout << "Fail to Read public" << endl;
                }
                fclose(payer);
                //size of key
                int rsa_len = RSA_size(payerRSA);
                const unsigned char* stxt = (const unsigned char*)ermessage;
                unsigned char* ptxt = (unsigned char*)malloc(rsa_len);
                //RSA_PKCS1_PADDING(-11)
                if (RSA_public_decrypt(rsa_len, stxt, ptxt, payerRSA, RSA_PKCS1_PADDING) < 0)
                {
                    cout << "Decode error" << endl;
                }
                cout << "ptxt: " << ptxt;
                RSA_free(payerRSA);




                FILE *pri;
                RSA *privateRSA = nullptr;
                if ((pri = fopen("payee_pri.pem", "r")) == NULL)
                {
                    cout << "Payee Private Error" << endl;
                    exit(-1);
                }
                //initialize
                OpenSSL_add_all_algorithms();
                if ((privateRSA = PEM_read_RSAPrivateKey(pri, NULL, NULL, NULL)) == NULL)
                {
                    cout << "Fail to Read private" << endl;
                }
                fclose(pri);
                //size of key
                int srsa_len = RSA_size(privateRSA);
                const unsigned char* pritxt = (const unsigned char*)ptxt;
                unsigned char* sectxt = (unsigned char*)malloc(srsa_len);
                //RSA_PKCS1_PADDING(-11)
                if (RSA_private_encrypt(srsa_len-11, pritxt, sectxt, privateRSA, RSA_PKCS1_PADDING) < 0)
                {
                    cout << "Encode error" << endl;
                }
                cout << "stxt: " << sectxt << endl;
                RSA_free(privateRSA);



                close(fd[0]);
                write(fd[1], sectxt, srsa_len);
                close(fd[1]);
                exit(0);
            }
            else
            {
                wait(&status);
                close(fd[1]);
                read(fd[0], emessage, sizeof(emessage));
                close(fd[0]);
            }

            cout << "Send message: " << emessage << endl;
            send(sockfd, emessage, sizeof(emessage), 0);
        }




        else
        {
            cout << "Invalid Option!!!" << "\n";
            cout << "------------------------------------------------------------" << "\n";
        }
    }
    cout << "Close Socket";
    close(sockfd);
    return 0;
}