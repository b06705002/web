#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stack>
#include <cstdlib>
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iomanip>
#include <fstream>
#include <string>
#define R_MAX 100
#define ONLINE_MAX 5
using namespace std;

class R_account
{
	public:
		R_account() {}
		~R_account() {}
		R_account(char*, int);
		R_account(R_account&);
		char name[100];
		int value = 10000;
		int getv();
		void changev(int);
};

R_account::R_account(char* n, int v)
{
	strcpy(this->name, n);
	this->value = v;
}

int
R_account::getv()
{
	int x = this->value;
	return x;
}

void
R_account::changev(int x)
{
	this->value = x;
}

R_account::R_account(R_account& y)
{
	strcpy(this->name, y.name);
	this->value = y.value;
}

class O_account
{
public:
	O_account(){}
	~O_account(){}
	O_account(R_account&, char*, char*);
	O_account(O_account&);
	R_account user;
	char port[100];
	char ip[100];
};

O_account::O_account(R_account &u, char* p, char* i)
{
	this->user = u;
	strcpy(this->port, p);
	strcpy(this->ip, i);
}

R_account R[R_MAX];
O_account O[ONLINE_MAX];
int r = 0;
int o = 0;

O_account::O_account(O_account& x)
{
	R_account y(x.user);
	this->user = y;
	strcpy(this->port, x.port);
	strcpy(this->ip, x.ip);
}

void *connection_handler(void *);
char ipaddr[100] = {};

int main(int argc, char *argv[])
{
	int socket_desc, new_socket, c, *new_sock;
	struct sockaddr_in server, client;
	char message[100] = {};

	socket_desc = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_desc == -1)
	{
		cout << "Fail to create a socket.";
		return 0;
	}

	int port;
	cout << "Enter Port" << "\n";
	cin >> port;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY; //任意地址
	server.sin_port = htons(port);

	if (bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
	{
		cout << "Fail to bind";
		return 0;
	}
	cout << "Succeed to bind." << endl;

	listen(socket_desc, 5);

	cout << "Waiting for connections..." << endl;
	c = sizeof(struct sockaddr_in);
	while((new_socket = accept(socket_desc, (struct sockaddr*)&client, (socklen_t*)&c)))
	{
		memset(message, '\0', sizeof(message));
		cout << "Connection accepted!!!" << endl;
		strcpy(message, "Connection accept");
        strcat(message, "\n");
		write(new_socket, message, strlen(message));
		strcpy(ipaddr, (char*)inet_ntoa(client.sin_addr));
		pthread_t sniffer_thread;
		new_sock = (int*)malloc(1);
		*new_sock = new_socket;
		if (pthread_create(&sniffer_thread, NULL, connection_handler, (void*) new_sock) < 0)
		{
			cout << "Fail to create thread." << endl;
			return 0;
		}
		cout << "Handler assigned." << endl;
	}

	if (new_socket < 0)
	{
		cout << "Fail to accept." << endl;
		return 0;
	}
	return 0;
}

void *connection_handler(void *socket_desc)
{
	int sock = *(int*)socket_desc;
	int read_size;
	char ipad[100] = {};
	strcpy(ipad, ipaddr);
	strcpy(ipaddr, "'\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0''\0'");
	char message[100] = {};
	char recmessage[1000] = {};
	char username[100] = {};
	bool suc_lg = false;
	while((read_size = recv(sock, recmessage, sizeof(recmessage), 0)) > 0)
	{
		// cout << recmessage;
		if(suc_lg == false)
		{
			cout << recmessage;
			if(strstr(recmessage, "REGISTER#") != NULL)
			{
				bool con = true;
				// cout << recmessage;
				char k[100] = {};
				strcpy(k, recmessage);
				// cout << k;
				char key[100] = {};
				// cout << strlen(k) << endl;
				strtok(k, "#");
				strcpy(key, strtok(NULL, "#"));
				strcpy(key, strtok(key, "\n"));
				// cout << key << endl;
				for (int i = 0; i < r; ++i)
				{
					// cout << key << " " << R[i].name << endl;
					if (strstr(key, R[i].name) != NULL&& strstr(R[i].name, key) != NULL)
					{
						con = false;
					}
				}
				if (con == false || r == R_MAX)
				{
					strcpy(message, "210 FAIL");
	        		strcat(message, "\n");
					write(sock, message, strlen(message));
				}
				else
				{
					R_account NR(key, 10000);
					R[r] = NR;
					r = r + 1;
					strcpy(message, "100 OK");
	        		strcat(message, "\n");
					write(sock, message, strlen(message));
				}			
				memset(key, '\0', sizeof(key));
			}
			else if(strstr(recmessage, "#") != NULL)
			{
				// cout << " YOYOYO"<< recmessage;
				bool find = false;
				int num;
				char keyn[100] = {};
				char keyp[100] = {};
				strcpy(keyn, strtok(recmessage, "#"));
				strcpy(keyp, strtok(NULL, "#"));
				strcpy(keyp, strtok(keyp, "\n"));
				// cout << keyn << " " << keyp << " " << r << endl;
				for (int i = 0; i < r; ++i)
				{
					// cout << R[i].name << " " << keyn << endl;
					if (strstr(keyn, R[i].name) != NULL&& strstr(R[i].name, keyn) != NULL)
					{
						// cout << "get" << endl;
						find = true;
						num = i;
					}
				}
				if (find != true || o == ONLINE_MAX)
				{
					strcpy(message, "220 AUTH_FAIL");
	        		strcat(message, "\n");
					write(sock, message, strlen(message));
				}
				else
				{
					strcpy(username, keyn);
					O_account NO(R[num], keyp, ipad);
					O[o] = NO;
					int x = O[o].user.getv();
					o = o + 1;
					char v[100] = {};
					// cout << "YO" << x << endl;
					// sprintf(v, "%d", x);
					// strcpy(message, v);
	    //     		strcat(message, "\n");
	        		strcat(message, "number of accounts online: ");
	        		char onlinenum[100] = {};
					sprintf(onlinenum, "%d", o);
	        		strcat(message, onlinenum);
	        		strcat(message, "\n");
	        		for (int i = 0; i < o; ++i)
	        		{
	        			strcat(message, O[i].user.name);
	        			strcat(message, "#");
	        			strcat(message, O[i].ip);
	        			strcat(message, "#");
	        			strcat(message, O[i].port);
	        			strcat(message, "#");
	        			char ggg[100] = {};
	        			int g = 10000;
	        			for (int j = 0; j < r; ++j)
		        		{
		        			if (strstr(O[i].user.name, R[j].name) != NULL&& strstr(R[j].name, O[i].user.name) != NULL)
							{
								// cout << vvv << endl;
								g = R[j].value;
							}
		        		}
						sprintf(ggg, "%d", g);
	        			strcat(message, ggg);
	        			strcat(message, "\n");
	        		}	
					write(sock, message, strlen(message));
					memset(v, '\0', sizeof(v));
					suc_lg = true;
				}				
				memset(keyp, '\0', sizeof(keyp));
				memset(keyn, '\0', sizeof(keyn));
			}
			// else
			// 	cout << "invalid option" << endl;
			memset(message, '\0', sizeof(message));
	        memset(recmessage, '\0', sizeof(recmessage));
	        // read_size = recv(sock, recmessage, sizeof(recmessage), 0);
		}
		else
		{
			if (strstr(recmessage, "RC#") != NULL)
			{
				cout << recmessage;
				bool on = false;
				char k[100] = {};
				strcpy(k, recmessage);
				// cout << k;
				char key[100] = {};
				// cout << strlen(k) << endl;
				strtok(k, "#");
				strcpy(key, strtok(NULL, "#"));
				strcpy(key, strtok(key, "\n"));
				int find = -1;
				for (int i = 0; i < o; ++i)
				{
					// cout << key << " " << O[i].user.name << endl;
					if (strstr(key, O[i].user.name) != NULL && strstr(O[i].user.name, key) != NULL)
					{
						on = true;
						find = i;
					}
				}
				if (on == false)
				{
					strcpy(message, "CON_FAIL");
	        		strcat(message, "\n");
					write(sock, message, strlen(message));
					cout << "CON_FAIL"<< endl;
				}
				else
				{
					char ipnum[100] = {};
					strcpy(ipnum, O[find].ip);
					char portnum[100] = {};
					strcpy(portnum, O[find].port);
					strcpy(message, ipnum);
	        		strcat(message, "#");
	        		strcat(message, portnum);
	        		strcat(message, "\n");
	        		cout << "message:" << "\n";
            		cout << message;
					write(sock, message, strlen(message));
				}
				memset(key, '\0', sizeof(key));
				memset(k, '\0', sizeof(k));
			}



			else if(strstr(recmessage, "List") != NULL)
			{
				int num;
				for (int i = 0; i < o; ++i)
				{
					if (strstr(username, O[i].user.name) != NULL&& strstr(O[i].user.name, username) != NULL)
					{
						num = i;
					}
				}
				cout << recmessage;
				char v[100] = {};
				// int x = O[num].user.getv();
				// sprintf(v, "%d", x);
				// strcpy(message, v);
	   //     		strcat(message, "\n");
	       		strcat(message, "number of accounts online: ");
	       		char onlinenum[100] = {};
				sprintf(onlinenum, "%d", o);
        		strcat(message, onlinenum);
	       		strcat(message, "\n");
	       		for (int i = 0; i < o; ++i)
	       		{
	       			strcat(message, O[i].user.name);
        			strcat(message, "#");
	        		strcat(message, O[i].ip);
	        		strcat(message, "#");
	        		strcat(message, O[i].port);
	        		strcat(message, "#");
	        		char ggg[100] = {};
	        		int g = 10000;
	        		for (int j = 0; j < r; ++j)
	        		{
	        			if (strstr(O[i].user.name, R[j].name) != NULL && strstr(R[j].name, O[i].user.name) != NULL)
						{
							// cout << vvv << endl;
							g = R[j].value;
						}
	        		}
					sprintf(ggg, "%d", g);
	       			strcat(message, ggg);
	       			strcat(message, "\n");
	       		}	
				write(sock, message, strlen(message));
				memset(v, '\0', sizeof(v));
			}
			else if(strstr(recmessage, "Exit") != NULL)
			{
				for (int i = 0; i < o; ++i)
				{
					if (strstr(username, O[i].user.name) != NULL&& strstr(O[i].user.name, username) != NULL)
					{
						for (int j = i; j < o; ++j)
						{
							O[j] = O[j+1];
						}
					}
				}
				o = o - 1;
				cout << recmessage;
				cout << "Enter response: Bye" << endl;
				strcpy(message, "Bye");
	        	strcat(message, "\n");
				write(sock, message, strlen(message));
				memset(username, '\0', sizeof(username));
				suc_lg = false;			
			}
			else
			{
				FILE *payee;
                RSA *payeeRSA = nullptr;
                if ((payee = fopen("payee_pub.pem", "r")) == NULL)
                {
                    cout << "Payee Public Error" << endl;
                    exit(-1);
                }
                //initialize
                OpenSSL_add_all_algorithms();
                if ((payeeRSA = PEM_read_RSA_PUBKEY(payee, NULL, NULL, NULL)) == NULL)
                {
                    cout << "Fail to Read public" << endl;
                }
                fclose(payee);
                //size of key
                int rsa_len = RSA_size(payeeRSA);
                const unsigned char* stxt = (const unsigned char*)recmessage;
                unsigned char* ptxt = (unsigned char*)malloc(rsa_len);
                //RSA_PKCS1_PADDING(-11)
                if (RSA_public_decrypt(rsa_len, stxt, ptxt, payeeRSA, RSA_PKCS1_PADDING) < 0)
                {
                    cout << "Decode error" << endl;
                }
                cout << "ptxt: " << ptxt;
                RSA_free(payeeRSA);

                char ppp[100] = {};
                strcpy(ppp, (const char*)ptxt);
                // cout << ppp;
                char keym[100] = {};
				char keype[100] = {};
				strtok(ppp, "#");
				strcpy(keym, strtok(NULL, "#"));
				strcpy(keype, strtok(NULL, "#"));
				strcpy(keype, strtok(keype, "\n"));
				// cout << ppp << "--" << keym << "--" << keype << "--" << endl;
				// cout << "rec: "<<recmessage <<endl;
				int vvv;
				vvv = atoi(keym);
				for (int i = 0; i < r; ++i)
				{
					// cout << ppp << " " << R[i].name << endl;
					if (strstr(ppp, R[i].name) != NULL&& strstr(R[i].name, ppp) != NULL)
					{
						// cout << R[i].getv() << endl;
						// cout << vvv << endl;
						int xxx = R[i].getv();
						// cout << xxx << endl;
						// cout << R[i].value << endl;
						R[i].changev(xxx - vvv);
						// cout << R[i].value << endl;
					}
				}

				for (int i = 0; i < r; ++i)
				{
					// cout << ppp << " " << R[i].name << endl;
					if (strstr(keype, R[i].name) != NULL&& strstr(R[i].name, keype) != NULL)
					{
						// cout << vvv << endl;
						int xxx = R[i].getv();
						R[i].changev(xxx + vvv);
						// cout << R[i].value << endl;
					}
				}


				memset(ppp, '\0', sizeof(ppp));
				memset(keym, '\0', sizeof(keym));
				memset(keype, '\0', sizeof(keype));
			}
			// 	cout << "invalid option" << endl;
			memset(message, '\0', sizeof(message));
	        memset(recmessage, '\0', sizeof(recmessage));
	        // read_size = recv(sock, recmessage, sizeof(recmessage), 0);
		}
	}
	// cout << "YOYOYO";
	if (read_size == 0)
	{
		cout << "Client disconnected" << endl;
		fflush(stdout);
	}
	else if(read_size == -1)
	{
		cout << "Fail to receive." << endl;
	}
	free(socket_desc);
	return 0;
}