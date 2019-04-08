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

inline bool file_exist(const std::string& name)
{
    ifstream file(name);
    if(!file)            // If the file was not found, then file is 0, i.e. !file=1 or true.
        return false;    // The file was not found.
    else                 // If the file was found, then file is non-0.
        return true;     // The file was found.
}
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

string user_download() {
    string file_path;
    cout << "Enter the filename on server to download from server: ";
    cin >> file_path;
    return file_path;
}

string user_delete() {
    string file_path;
    cout << "Enter the filename on server to delete from server: ";
    cin >> file_path;
    return file_path;
}

string user_share() {
    string file_path,user;
    cout << "Enter the filename on server to share: ";
    cin >> file_path;
    cout << "Enter the user with whom you want to share: ";
    cin >> user;
    return file_path + "|" + user + "|";
}
int main()
{
    string server_ip;
    cout << "Enter Ip of ther server : ";
    cin >> server_ip; 
    dff = new Deffie_Hellman;
    char buffer[10000] = {0};
    int read_val;
    flag  = 1;
    struct sockaddr_in client_address, client_address1;
    struct sockaddr_in server_addr, server_addr1;
    int socket_id = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_id  == 0)
    {
        printf("Socket Error\n");
    }

    int result = inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);
    if(result < 0)
        printf("error for inet_pton");
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(3542);

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
    usleep(5000000);
    result = inet_pton(AF_INET, server_ip.c_str(), &server_addr1.sin_addr);
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
            bool exist = false;
            string file_to_upload; 
            while(!exist)
            {
                file_to_upload = user_upload();
                exist = file_exist(file_to_upload);
                if(!exist)
                {
                    cout << "Enter a valid file path" << endl;
                }

            }
            string file_name;
            bool loc_flag = false;
            // Finding the file name from the file path
            for(int i = file_to_upload.length()-1; i >=0; i--) {
                if(file_to_upload[i] == '/') {
                    file_name = file_to_upload.substr(i+1, file_to_upload.length() - i);
                    loc_flag = true;
                    break;
                }
            }
            if(loc_flag == false)
                file_name = file_to_upload;
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
            buffer[byteRec] = '\0';
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
                    memset(buffer, 0, sizeof(buffer));
                    in.read(buffer, 10000);
                    curPoint += 10000;
                    if(curPoint < fs) {
                        int length = (int)strlen(buffer)+ 1;
                        utils::aesEncryption(dff->getaesShaKey(), buffer, 10000);
                        int s = send(socket_id1, buffer, 10000, 0);
                        cout << "sent : " << length << endl;
                    } else {
                        int length = (int)strlen(buffer)+ 1;
                        utils::aesEncryption(dff->getaesShaKey(), buffer, fs + 10000 - curPoint+1);
                        int s = send(socket_id1, buffer, fs + 10000 - curPoint, 0);
                        cout << "sent : " << fs + 10000 - curPoint << endl;
                        curPoint = fs;
                    }
                }
                byteRec = recv(socket_id1, buffer, 10000, 0);
                buffer[byteRec] = '\0';
                recv_msg = string(buffer);
                cout << "enc : " << recv_msg << endl;
                utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec);
                recv_msg = string(buffer);
                cout << recv_msg << endl;
                in.close();

            }
        }
        if(input == 4)
        {
            string file_to_downlolad = user_download();
            string to = "DOWNLOAD|" + file_to_downlolad + "|";
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
            buffer[byteRec] = '\0';
            string recv_msg(buffer);
            cout << "enc : " << recv_msg << endl;
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec);
            recv_msg = string(buffer);
            cout << recv_msg << endl;
            string size, type;
            int count = 0;
            type = recv_msg.substr(0,recv_msg.find(':'));
            cout << type << endl;
            size = recv_msg.substr(recv_msg.find(':') + 1, recv_msg.length() - type.length() - 1);
            cout  << size << endl;
            if(type == "DOWNLOAD OK")
            {
                string ready = "0";
                int val = send(socket_id1, ready.c_str(), ready.length(), 0 );
                if(val  < 0)
                    cout << "send eroor" << endl;   
                long long file_s = stoll(size);
                fstream out;
                out.open(file_to_downlolad, ios::binary | ios::out);
                long long numBytes = 0;
                int byteRecieved;
                char buffer_sec[10000];
                long long count = 0;
                int last_size = file_s%10000;
                int sec_count = 0;
                int packets = ceil((double)file_s/10000);
                int packets_rec = 0;
                cout << "LAst size " << last_size << " no of packets : " << packets << endl;
                while(numBytes < file_s) {
                    memset(buffer, 0, 10000);
                    byteRecieved = recv(socket_id1, buffer, sizeof(buffer), 0);
                    cout << "rec: " << byteRecieved << endl;
                    // utils::aesDecryption(client->dh2->getaesShaKey(), buffer, byteRecieved+1);
                    numBytes += byteRecieved;
                    // for(int k = 0; k < byteRecieved; k++)
                    // {
                    //     out << buffer[k];
                    // }        // of << client->hashuname << endl;
                // of << client->total_mem_consumed << endl;
                    count += byteRecieved;
                    cout << "numBytes: " << numBytes << endl;
                    for (int j = 0; j < byteRecieved; j++)
                    {
                        buffer_sec[sec_count] = buffer[j];
                        sec_count++;
                        if(sec_count == 10000)
                        {
                            cout << "Decryption of packet " << packets_rec << endl;
                            utils::aesDecryption(dff->getaesShaKey(), buffer_sec, 10001);
                            for(int k = 0; k < 10000; k++)
                            {
                                cout << buffer[k];
                                out << buffer_sec[k];
                            }
                            cout << endl;
                            sec_count = 0;
                            packets_rec++;
                            memset(buffer_sec, 0, 10000);
                        }
                        else if(packets - packets_rec == 1 && sec_count == last_size)
                        {
                            cout << "LAst packet " << endl;
                            utils::aesDecryption(dff->getaesShaKey(), buffer_sec, last_size+1);
                            for(int k = 0; k < last_size; k++)
                            {
                                out << buffer_sec[k];
                            }
                        }

                    }
                }
                cout << "Download complete.." << endl;

            }
            
        }
        if(input == 5)
        {
            string file_to_delete = user_delete();
            string to = "DELETE|" + file_to_delete + "|";
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
            buffer[byteRec] = '\0';
            string recv_msg(buffer);
            cout << "enc : " << recv_msg << endl;
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec);
            recv_msg = string(buffer);
            cout << recv_msg << endl;

        }
        if(input == 6) {
            char buffer1[10000] = {0};
            string to = "LS|";
            int len = to.length();
            char message[len + 1];
            strcpy(message, to.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;
            int l = recv(socket_id1, buffer1, 10000, 0);
            utils::aesDecryption(dff->getaesShaKey(), buffer1, l);
            string msg(buffer1);
            cout << msg << endl;
            if(msg == "LS OK") {
                int byteRec1 = recv(socket_id1, buffer1, 10000, 0);
                utils::aesDecryption(dff->getaesShaKey(), buffer1, byteRec1);
                string file_num(buffer1);
                cout << file_num << endl;
                int fn = stoi(file_num);
                cout << fn << endl;
                int count = 0;
                while(count < fn){
                    bzero(buffer1, 10000);
                    int byteRec = recv(socket_id1, buffer1, 10000, 0);
                    if(count == fn) {
                        count++;
                        continue;
                    }
                    utils::aesDecryption(dff->getaesShaKey(), buffer1, byteRec);
                    string recv_msg(buffer1);
                    cout << recv_msg << endl;
                    count++;
                }
            }
        }
        if(input == 7) {
            string to = "DELETEUSER|";
            int len = to.length();
            char message[len + 1];
            strcpy(message, to.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;
            int byteRec1 = recv(socket_id1, buffer, 10000, 0);
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec1);
            string msg(buffer);
            cout << msg << endl;
        }
        if(input == 8)
        {
            string to  = "SHARE|" + user_share();
            int len = to.length();
            char message[len + 1];
            strcpy(message, to.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;
            int byteRec1 = recv(socket_id1, buffer, 10000, 0);
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec1);
            string msg(buffer);
            cout << msg << endl;
        }

        if(input == 9) {
            string to = "LOGOUT|";
            int len = to.length();
            char message[len + 1];
            strcpy(message, to.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(dff->getaesShaKey(), message, length);
            int val = send(socket_id1, message, length, 0 );
            if(val  < 0)
                cout << "send eroor" << endl;
            int byteRec1 = recv(socket_id1, buffer, 10000, 0);
            utils::aesDecryption(dff->getaesShaKey(), buffer, byteRec1);
            string msg(buffer);
            cout << msg << endl;
        }
        if (input == -1)
        {
            close(socket_id1);
            return 100;
        }

    }


   
    return 0;

}
