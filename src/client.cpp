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
#include "utils.hpp"
atomic<int> flag{0};

Deffie_Hellman* dff;
bool agreed = false;
bool prime = false;
bool gen = false;
int tcp_port;
void reader(int socket_id)
{
    char buffer[4096];
    int r;
    while(flag)
    {
        r = recv(socket_id, buffer, 4096, 0);
        buffer[r] = '\0';
        string p(buffer);
        if(p == "prime")
        {
            prime = true;
        }

        r = recv(socket_id, buffer, 4096, 0);
        buffer[r] = '\0';
        string g(buffer);
        if(g == "gen")
        {
            gen = true;
        }

        int read_val = recv(socket_id, buffer, 4096, 0);
        buffer[read_val] = '\0';
        string lawl(buffer);
        SecByteBlock pubO = utils::stringToSecByte(lawl);
        dff->AgreeFunc(pubO);
        agreed = true;
        cout << "Deffie-Hellman completed AES key generated " << endl; 

        r = recv(socket_id, buffer, 4096, 0);
        buffer[r] = '\0';
        string h(buffer);
        string output = utils::findMD5(dff->getaesKey());
        if(h == output) {
            cout << "Verified key. Starting session..." << endl;
        }
        else
        {
            cout << "Handshake failed " << endl;
            exit(2);
        }

        r = recv(socket_id, buffer, 4096, 0);
        buffer[r] = '\0';
        string po(buffer);
        tcp_port = stoi(po);
        cout << "New port " << tcp_port << endl;
        flag = false;
        

    }
}


void writer(int socket_id)
{
    string input;
    int count = 0;
    cout << "Starting Handshake Protcol..." << endl;
    while(flag)
    {
        if(count == 0)
        {
            cout << "Using Deffie-Hellman for aes Key generation...\n";
            string s2 = utils::IntegerTohexString(dff->getPrime());
            int val = send(socket_id, s2.c_str(), s2.length(), 0 );
            if(val  < 0)
                cout << "Prime send error" << endl;
            count = 1;
        }
        else if(count == 1 && prime)
        {
            string s2 = utils::IntegerTohexString(dff->getGenerator());
            int val = send(socket_id, s2.c_str(), s2.length(), 0 );
            if(val  < 0)
                cout << "generator send eroor" << endl;
            count = 2;
        }
        else if(count == 2 && gen)
        {
            string  s2 = utils::SecByteToString(dff->getpubKey());
            int val = send(socket_id, s2.c_str(), s2.length(), 0 );
            if(val  < 0)
                cout << "send eroor" << endl;
            count = 3;
        }
        else if(count == 3 && agreed) {
            
            cout << "Starting AES key conformation " <<endl;
            string output = utils::findMD5(dff->getaesKey());
            int val = send(socket_id, output.c_str(), output.length(), 0);
            if(val  < 0)
                cout << "send eroor" << endl;
            count = 4;
        }
        else if(count == 4)
        {
            char s[] = "om and shubham";
            int length = (int)strlen(s)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), s, length);
            int val = send(socket_id, s, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;
            count = 5;
        }
    }
    
}

int main()
{
    dff = new Deffie_Hellman;
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

    socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id  == 0)
    {
        printf("Socket Error\n");
    }

    result = inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    if(result < 0)
        printf("error for inet_pton");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcp_port);

    connection = connect(socket_id, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if(connection < 0)
        printf("Connection error\n");

    string iinput;
    while(true)
    {
        cin >> input;
        cout << "Sending : " << input << endl;
        int len = input.length();
        char message[len + 1];
        strcpy(message, input.c_str());
        int length = (int)strlen(message)+ 1;
        utils::aesEncryption(dff->getaesShaKey(), message, length);
        int val = send(socket_id, message, length, 0 );
        if(val  < 0)
            cout << "send eroor" << endl;

    }


   
    return 0;

}
