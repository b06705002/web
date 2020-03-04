all:
		g++ client2.cpp -L /home/chired/桌面/network/b06705002_part3/openssl-1.1.1d -lssl -lcrypto -o client2.out
		g++ server2.cpp -L /home/chired/桌面/network/b06705002_part3/openssl-1.1.1d -lssl -lcrypto -o server2.out -lpthread
clean:
		rm -f client2.out
		rm -f server2.out	