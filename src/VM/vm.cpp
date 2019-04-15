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
#include <cstdio>
#include <sys/stat.h>
using namespace std;
struct sockaddr_in addrport;
vector<thread> th;
vector<int> acc;
atomic<int> job{0};
void execute_func(int sock) {
    int job_loc = job++;
    string dir_make = "VM_data/" + job_loc;
    mkdir(dir_make.c_str(), 0777);
    char buffer[10000];
    send(sock, "Connection Established", strlen("Connection Established"), 0);
    recv(sock, buffer, 10000, 0);
    int i = 0;
    string request(buffer);
    string fname, file_size, com_cmd, run_cmd;
    long long fs;
    while(request[i] != '|')
    {
        fname += request[i];
        i++;
    }
    i++;
    while(request[i] != '|')
    {
        file_size += request[i];
        i++;
    }
    i++;
    while(request[i] != '|')
    {
        com_cmd += request[i];
        i++;
    }
    i++;
    while(request[i] != '|')
    {
        run_cmd += request[i];
        i++;
    }
    i++;
    fs = stoll(file_size);
    fstream code;
    code.open(fname.c_str(), ios::binary | ios::out);
    long long numBytes = 0;
    int byteRecieved;
    send(sock, "SEND FILE", strlen("SEND FILE"), 0);
    while(numBytes < fs) {
        memset(buffer, 0, 10000);
        byteRecieved = recv(sock, buffer, sizeof(buffer), 0);
        cout << "rec: " << byteRecieved << endl;
        numBytes += byteRecieved;
        for(int j = 0; j < byteRecieved; j++) {
            code << buffer[j];
        }
    }
    code.close();
    cout << "Recieved Source code." << endl;
    cout << "Compiling the source code..." << endl;
    string com = com_cmd + " >" + dir_make +"/out.txt 2>&1";
    if(system(com.c_str()) != 0) {
        string exec_s, out_file;
        out_file = dir_make + "/out.txt";
        fstream in;
        in.open(out_file, ios::binary|ios::in);
        struct stat FS;
        int rc = stat(out_file.c_str(), &FS);
        long long fs;
        fs = FS.st_size;
        exec_s = to_string(fs);
        bzero(buffer, 10000);
        send(sock, exec_s.c_str(), exec_s.length(), 0);
        recv(sock, buffer, 10000, 0); 
        cout << string(buffer) << endl;
        long long curPoint = 0;
        while(!in.eof()) {
            bzero(buffer, sizeof(buffer));
            in.read(buffer, 10000);
            curPoint += 10000;
            if(curPoint < fs) {
                int s = send(sock, buffer, 10000, 0);
                cout << "sent : " << 10000 << endl;
            } else {
                int s = send(sock, buffer, fs + 10000 - curPoint , 0);
                cout << "sent : " << fs + 10000 - curPoint << endl;
                curPoint = fs;
            }
        }
        in.close();
    }
    else {
        string run = run_cmd + " >" + dir_make +"/out.txt 2>&1";
        system(run.c_str());
        string exec_s, out_file;
        out_file = dir_make + "/out.txt";        
        fstream in;
        in.open(out_file, ios::binary|ios::in);
        struct stat FS;
        int rc = stat(out_file.c_str(), &FS);
        long long fs;
        fs = FS.st_size;
        exec_s = to_string(fs);
        bzero(buffer, 10000);
        send(sock, exec_s.c_str(), exec_s.length(), 0);
        recv(sock, buffer, 10000, 0); 
        cout << string(buffer) << endl;
        long long curPoint = 0;
        while(!in.eof()) {
            bzero(buffer, sizeof(buffer));
            in.read(buffer, 10000);
            curPoint += 10000;
            if(curPoint < fs) {
                int s = send(sock, buffer, 10000, 0);
                cout << "sent : " << 10000 << endl;
            } else {
                int s = send(sock, buffer, fs + 10000 - curPoint , 0);
                cout << "sent : " << fs + 10000 - curPoint << endl;
                curPoint = fs;
            }
        }
        in.close();
    }
    // string del = "rm -rf " + dir_make;
    // system(del.c_str());
}
void accept_thread(int sockid, int servSize) {
    int i = 0;
    while(1) {
        acc.push_back(accept(sockid, (struct sockaddr *) &addrport, (socklen_t *) &servSize));        
        th.push_back(thread(execute_func,acc[i]));
        th[i].detach();
        i++;
    }
}
int main() {
    int sockid = socket(AF_INET, SOCK_STREAM, 0);
    int t = 1;
    setsockopt(sockid,SOL_SOCKET,SO_REUSEADDR,&t,sizeof(int));
    addrport.sin_family = AF_INET;
    addrport.sin_port = htons(8000);
    addrport.sin_addr.s_addr  = htons(INADDR_ANY);
    if(bind(sockid, (struct sockaddr *) &addrport, sizeof(addrport)) < 0) {
        close(sockid);
        printf("bind failed");
    }
    int status = listen(sockid, 100);

    if(status == -1)
    {
        close(sockid);
        printf("status error ");
    }
    int servSize = sizeof(addrport);
    thread acct = thread(accept_thread, sockid, servSize);
    acct.join();
    close(sockid);
}