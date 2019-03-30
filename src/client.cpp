#include <bits/stdc++.h>
#include <string>   //strlen 
#include <errno.h> 
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <thread>
#include <atomic>
#include "dhaes.hpp"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>
#include <crypto++/hex.h>
atomic<int> flag{0};

Deffie_Hellman* dff;
string output;
void reader(int socket_id)
{
    char buffer[4096];
    while(flag)
    {
        int read_val = recv(socket_id, buffer, 4096, 0);
        buffer[read_val] = '\0';
        string lawl(buffer);
        SecByteBlock pubO((const byte*)lawl.data(), lawl.size());
        dff->AgreeFunc(pubO);
        Integer a;
        a.Decode(dff->getaesKey().BytePtr(), dff->getaesKey().SizeInBytes());
        cout << hex << a << endl;
        bzero(buffer, 4096);
    
        int r = recv(socket_id, buffer, 4096, 0);
        buffer[r] = '\0';
        string h(buffer);
        cout << "h : " << h << endl;
        if(h == output) {
            cout << "Verified key. Starting session...";
        }
        // string s = buffer;
        // if(s.compare("buffer full") == 0)
        //     exit(1);

    }
}


void writer(int socket_id)
{
    string input;
    int count = 0;
    while(flag)
    {
        cin >> input;
        if(input.compare("exit") == 0)
        {
            cout << "Exiting " << endl;
            close(socket_id);
            exit(1);
        }
        else
        {
            stringstream ss;
            stringstream sss;
            if(count == 0)
            {

                Integer prime = dff->getPrime();
                cout << "P :" << dff->getPrime() << endl;
                ss << hex << prime;
                string s2 = ss.str();

                int val = send(socket_id, s2.c_str(), s2.length(), 0 );
                if(val  < 0)
                    cout << "send eroor" << endl;
                count = 1;
            }
            else if(count == 1)
            {
                Integer prime = dff->getGenerator();
                sss << hex << prime;
                string s2 = sss.str();
                cout << s2 << endl;

                int val = send(socket_id, s2.c_str(), s2.length(), 0 );
                if(val  < 0)
                    cout << "send eroor" << endl;
                count = 2;
            }
            else if(count == 2)
            {
                SecByteBlock pub = dff->getpubKey();

                string  s2((const char*)pub.data(),pub.size());
                int val = send(socket_id, s2.c_str(), s2.length(), 0 );
                if(val  < 0)
                    cout << "send eroor" << endl;
                count = 3;
            }
            else if(count == 3) {
                byte digest[ CryptoPP::Weak::MD5::DIGESTSIZE ];
                CryptoPP::Weak::MD5 hash;
                hash.CalculateDigest( digest, dff->getaesKey(), sizeof(SecByteBlock));
                HexEncoder encoder;

                encoder.Attach( new CryptoPP::StringSink( output ) );
                encoder.Put( digest, sizeof(digest) );
                encoder.MessageEnd();
                std::cout << "hash" << output << std::endl;
                int val = send(socket_id, output.c_str(), output.length(), 0 );
                if(val  < 0)
                    cout << "send eroor" << endl;
                    count = 4;
            }
        }
    }
    
}

int main()
{
    dff = new Deffie_Hellman;
    cout << "OM : " << dff->getPrime() << endl;
    char buffer[1024] = {0};
    int read_val;
    flag  = 1;
    string input;
    struct sockaddr_in client_address;
    struct sockaddr_in server_addr;
    int socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id  == 0)
    {
        printf("Socket Error\n");
    }

    int result = inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    if(result < 0)
        printf("error for inet_pton");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(3542);

    int connection = connect(socket_id, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if(connection < 0)
        printf("Connection error\n");

    thread readerth(reader, socket_id);
    thread writerth(writer, socket_id);

    readerth.join();
    writerth.join();

   
    return 0;

}
