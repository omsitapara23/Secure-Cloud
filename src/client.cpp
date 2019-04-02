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
#include <sys/stat.h>
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

string create_user()
{
    string username;
    cout << "Enter user name(a-z0-9A-Z) : ";
    cin >> username;
    string  password;
    cout << "Enter password(a-z0-9A-Z) : ";
    cin >> password;
    int length = password.length();
    while(length < 8)
    {
        cout << "Enter a password with length 8 or more : ";
        cin >> password;
        length = password.length();
    }

    string to = "CREATE|" + username + "|" + password + "|"; 
    return to;
}
string user_login() {
    string username;
    string password;
    cout << "Please Enter your user name : ";
    cin >> username;
    cout << "Please Enter your password : ";
    cin >> password;
    string to = "LOGIN|" + username + "|" + password + "|"; 
    return to;
}
string user_upload() {
    string file_path;
    cout << "Enter the relative path or absolute path of the file you want to upload : ";
    cin >> file_path;
    return file_path;
}
int main()
{
    dff = new Deffie_Hellman;
    char buffer[4096] = {0};
    int read_val;
    flag  = 1;
    struct sockaddr_in client_address, client_address1;
    struct sockaddr_in server_addr, server_addr1;
    int socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id  == 0)
    {
        printf("Socket Error\n");
    }

    int result = inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    if(result < 0)
        printf("error for inet_pton");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(3425);

    int connection = connect(socket_id, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if(connection < 0)
        printf("Connection error aa\n");

    thread readerth(reader, socket_id);
    thread writerth(writer, socket_id);
    
    readerth.join();
    writerth.join();
    close(socket_id);
    int socket_id1 = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id1  == 0)
    {
        printf("Socket Error\n");
    }

    result = inet_pton(AF_INET, "127.0.0.1", &server_addr1.sin_addr);
    if(result < 0)
        printf("error for inet_pton");
    server_addr1.sin_family = AF_INET;
    server_addr1.sin_port = htons(tcp_port);

    connection = connect(socket_id1, (struct sockaddr *)&server_addr1, sizeof(server_addr1));
    if(connection < 0)
        printf("Connection error\n");

    int input;
    while(true)
    {
        cin >> input;
        if(input == 1)
        {
            string to_send = create_user();
            cout << "Sending : " << to_send << endl;
            int len = to_send.length();
            char message[len + 1];
            strcpy(message, to_send.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl; 
            int byteRec = recv(socket_id1, buffer, 4096, 0);
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec);
            string recv_msg(buffer);
            cout << recv_msg << endl;  

        }
        if(input == 2) {
            char buffer[4096] = {0};
            string to_send = user_login();
            cout << "Sending : " << to_send << endl;
            int len = to_send.length();
            char message[len + 1];
            strcpy(message, to_send.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;   
            int byteRec = recv(socket_id1, buffer, 4096, 0);
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec);
            string recv_msg(buffer);
            cout << recv_msg << endl;
        }
        if(input == 3) {
            string file_to_upload = user_upload();
            string file_name;
            bool loc_flag = false;
            // Finding the file name from the file path
            for(int i = file_to_upload.length()-1; i >=0; i--) {
                if(file_to_upload[i] == '/') {
                    file_name = file_to_upload.substr(i+1, file_to_upload.length() - i);
                    loc_flag = true;
                }
            }
            if(loc_flag == false)
                file_name = file_to_upload;
            char buffer[10000] = {0};
            struct stat FS;
            int rc = stat(file_to_upload.c_str(), &FS); 
            long long fs;
            fs = FS.st_size;
            string to = "UPLOAD|" + file_name + "|" + to_string(fs) + "|"; 
            cout << "Sending : " << to << endl;
            int len = to.length();
            char message[len + 1];
            strcpy(message, to.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;   
            int byteRec = recv(socket_id1, buffer, 10000, 0);
            string recv_msg(buffer);
            cout << "enc : " << recv_msg << endl;
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec);
            recv_msg = string(buffer);
            cout << recv_msg << endl;
            if(recv_msg == "UPLOAD OK") {
                ifstream in;
                in.open(file_to_upload, ios::binary | ios::in);
                int curPoint = 0;                
                while(!in.eof()) {
                    bzero(buffer, sizeof(buffer));
                    in.read(buffer, 10000);
                    curPoint += 10000;
                    if(curPoint < fs) {
                        int length = (int)strlen(buffer)+ 1;
                        utils::aesEncryption(dff->getaesShaKey(), buffer, length);
                        int s = send(socket_id1, buffer, 10000, 0);
                        cout << "sent : " << 10000 << endl;
                    } else {
                        int length = (int)strlen(buffer)+ 1;
                        utils::aesEncryption(dff->getaesShaKey(), buffer, length);
                        int s = send(socket_id1, buffer, fs + 10000 - curPoint, 0);
                        cout << "sent : " << fs + 10000 - curPoint << endl;
                        curPoint = fs;
                    }
                }
                in.close();
            }
        }
        if (input == -1)
        {
            close(socket_id1);
            return 100;
        }

    }


   
    return 0;

}
