#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
        cout << "Enter 'ls' To List----Enter 'q' To Quit" << "\n";
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