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
#include <sys/stat.h> 
using namespace std;
long long MAXMEMORY = 1000000;
atomic<int> total_Conn{0};
atomic<int> port;
mutex mtx;
fstream f;
fstream of;
fstream shaf;
map<string, string> uname_pass;                // mapping of user name to MD5 hash of its password
map<string, long long> uname_mem;              // mapping of user name to memory consumed
map<string, string> fname_shasum;              // mapping of file path to its SHA256 digest

inline bool file_exist(const std::string& name)
{
    ifstream file(name);
    if(!file)            // If the file was not found, then file is 0, i.e. !file=1 or true.
        return false;    // The file was not found.
    else                 // If the file was found, then file is non-0.
        return true;     // The file was found.
}
struct client_soc
{
    int fd;
    int count;
    Integer prime;
    Integer generator;
    SecByteBlock pub0;
    Deffie_Hellman * dh2;
    string dir;
    bool logged_in;
    long long total_mem_consumed;
    string hashuname;
    client_soc()
    {
        count = 0;
        fd = 0;
        dir = "";
        logged_in = false;
        total_mem_consumed = 0;
    }
};
void parser_request(string request, int client_socket, client_soc * client)
{
    char buffer[10000] = {0};
    string type = "";
    int i = 0;
    while(request[i] != '|')
    {
        type += request[i];
        i++;
    }
    i++;
    cout << "Request : " << type << endl;
    if(type == "CREATE")
    {
        string uname = "";
        while(request[i] != '|')
        {
            uname += request[i];
            i++;
        }
        i++;
        cout << "Uname : " << uname << endl;
        string password = "";
        while(request[i] != '|')
        {
            password += request[i];
            i++;
        }
        cout << "pass : " << password << endl;
        string hashuname = utils::findMD5(uname);
        string hashpass = utils::findMD5(password);
        string dir_make = "server_data/" + hashuname;
        if (mkdir(dir_make.c_str(), 0777) == -1) 
        {
            cerr << "Error :  " << " user already exists" << endl; 
            string err = "Error : user already exists";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        else
        {
            cout << "Directory created";    
            string err = "User Created";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            uname_pass[hashuname] = hashpass;
            f << hashuname << endl;
            f << hashpass << endl;
            of << hashuname << endl;
            of << client->total_mem_consumed << endl;
            client->hashuname = hashuname;
            uname_mem[client->hashuname] = 0;
            return;
        }
    }
    else if(type == "LOGIN") {
        if(client->logged_in == true) {
            string err = "LOGIN Error : You are already logged in. Please LOGOUT before logging in to a different account.";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        string uname = "";
        while(request[i] != '|')
        {
            uname += request[i];
            i++;
        }
        i++;
        cout << "Uname : " << uname << endl;
        string password = "";
        while(request[i] != '|')
        {
            password += request[i];
            i++;
        }
        string hashuname = utils::findMD5(uname);
        string hashpass = utils::findMD5(password);
        if(uname_pass.find(hashuname) == uname_pass.end()) {
            string err = "LOGIN Failed : Error : User " + uname + " does not exist.";
            cout << err << endl;
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            client->logged_in = false;
            return;
        }
        if(uname_pass[hashuname] != hashpass) {
            string err = "LOGIN Failed : Error : wrong password for User : " + uname;
            cout << err << endl;
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            client->logged_in = false;
            return;
        } else {
            string str = "LOGIN Successful : Further requests can be served.";
            cout << str << endl;
            int len = str.length();
            char message[len + 1];
            strcpy(message, str.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            client->hashuname = hashuname;
            client->logged_in = true;
            client->dir = "server_data/" + hashuname;
            client->total_mem_consumed = uname_mem[client->hashuname];
            return;
        }
    }
    else if(type == "UPLOAD") {
        if(client->logged_in == false) {
            string err = "LOGIN Error : You need to be logged in to UPLOAD a file. Please LOGIN with your account or CREATE an account if you dont have one.";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        string file_name = "";
        while(request[i] != '|')
        {
            file_name += request[i];
            i++;
        }
        i++;
        cout << "file name : " << file_name << endl;
        string file_size = "";
        while(request[i] != '|')
        {
            file_size += request[i];
            i++;
        }
        long long file_s;
        file_s = stoll(file_size);
        string hashfilename = utils::findMD5(file_name);
        if(client->total_mem_consumed + file_s > MAXMEMORY) {
            string err = "UPLOAD Error : Insufficient space, please delete a file or upload a smaller file. Available Memory " + to_string(MAXMEMORY - client->total_mem_consumed) + " request UPLOAD has size " + to_string(file_s);
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        cout << client->dir << endl;
        string file_path_out = client->dir + "/" + file_name;
        if(file_exist(file_path_out) == true) {
            cout << "already exist" << endl;
            string err = "UPLOAD Error : file " + file_name +" already exists.";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            cout << "exiting ex" << endl;
            return;
        }
        string s = "UPLOAD OK";
        int len = s.length();
        char message[len + 1];
        strcpy(message, s.c_str());
        int length = (int)strlen(message)+ 1;
        utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
        int val = send(client_socket, message, length, 0 );
        fstream out;
        out.open(file_path_out, ios::binary | ios::out);
        long long numBytes = 0;
        int byteRecieved;
        while(numBytes < file_s) {
            memset(buffer, 0, 10000);
            byteRecieved = recv(client_socket, buffer, sizeof(buffer), 0);
            cout << "rec: " << byteRecieved << endl;
            utils::aesDecryption(client->dh2->getaesShaKey(), buffer, byteRecieved);
            numBytes += byteRecieved;
            cout << "numBytes: " << numBytes << endl;
            for (int i = 0; i < byteRecieved; i++)
            {
                out << buffer[i];
            }
        }
        client->total_mem_consumed += file_s;
        uname_mem[client->hashuname] += file_s;
        of << client->hashuname << endl;
        of << client->total_mem_consumed << endl;
        out.close();
        cout << "File successfully uploaded.." << endl;
        string err = "File successfully uploaded.";
        len = err.length();
        message[len + 1];
        strcpy(message, err.c_str());
        length = (int)strlen(message)+ 1;
        utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
        val = send(client_socket, message, length, 0 );
        return;
    }
    else if(type == "DOWNLOAD")
    {
        if(client->logged_in == false) {
            string err = "LOGIN Error : You need to be logged in to UPLOAD a file. Please LOGIN with your account or CREATE an account if you dont have one.";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        string file_name = "";
        while(request[i] != '|')
        {
            file_name += request[i];
            i++;
        }
        i++;
        cout << "file name : " << file_name << endl;
        string path = client->dir + "/" + file_name;
        if(file_exist(path) == false)
        {
            string err = "Download Error: File does not exist on server";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        else
        {
            string err = "DOWNLOAD OK";
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            fstream in;
            in.open(path, ios::binary|ios::in);
            struct stat FS;
            int rc = stat(path.c_str(), &FS);
            long long fs;
            fs = FS.st_size;
            string size = to_string(fs);
            len = size.length();
            char message1[len + 1];
            strcpy(message1, size.c_str());
            length = (int)strlen(message1)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message1, length);
            val = send(client_socket, message1, length, 0 );
            int curPoint = 0;
            while(!in.eof()) {
                bzero(buffer, sizeof(buffer));
                in.read(buffer, 10000);
                curPoint += 10000;
                if(curPoint < fs) {
                    int length = (int)strlen(buffer)+ 1;
                    utils::aesEncryption(client->dh2->getaesShaKey(), buffer, 10000);
                    int s = send(client_socket, buffer, 10000, 0);
                    cout << "sent : " << 10000 << endl;
                } else {
                    int length = (int)strlen(buffer)+ 1;
                    utils::aesEncryption(client->dh2->getaesShaKey(), buffer, fs + 10000 - curPoint);
                    int s = send(client_socket, buffer, fs + 10000 - curPoint, 0);
                    cout << "sent : " << fs + 10000 - curPoint << endl;
                    curPoint = fs;
                }
            }


            in.close();

        }
    }
    else if(type == "DELETE")
    {
        string file_to_delete = "";
        while(request[i] != '|')
        {
            file_to_delete += request[i];
            i++;
        }
        string path = client->dir + "/" + file_to_delete;
        cout << "Path : " << path << endl;
        if(!file_exist(path))
        {
            cout << "File does not exist on server" << endl;
            string err = "File does not exist on server" ;
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
        else
        {
            string command = "rm " + path;
            system(command.c_str());
            cout << "File Deleted" << endl;
            string err = "File Deleted" ;
            int len = err.length();
            char message[len + 1];
            strcpy(message, err.c_str());
            int length = (int)strlen(message)+ 1;
            utils::aesEncryption(client->dh2->getaesShaKey(), message, length);
            int val = send(client_socket, message, length, 0 );
            return;
        }
    }
}

void client_runner_th(client_soc client)
{
    int string_length;
    char buffer[4096];
    int server_socket;
    int option = 1;
    struct sockaddr_in sever_address;
    int addrlen = sizeof(sever_address); 
    int client_socket;
    if( (server_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)  
    {  
        perror("socket creation failed");  
        exit(EXIT_FAILURE);  
    } 

    if( setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&option, 
          sizeof(option)) < 0 )  
    {  
        perror("setsockopt failed");  
        exit(EXIT_FAILURE);  
    }  

    //data structure for the server
    sever_address.sin_family = AF_INET;  
    sever_address.sin_addr.s_addr = INADDR_ANY;  
    mtx.lock();
    sever_address.sin_port = htons( port );  
    string s = to_string(port);
    int val = send(client.fd, s.c_str(), s.length(), 0 );
    if(val  < 0)
        cout << "send eroor" << endl;
    port = port + 1;
    mtx.unlock();
    //binding the server to listen to respective port
    if (bind(server_socket, (struct sockaddr *)&sever_address, sizeof(sever_address))<0)  
    {  
        perror("bind for socket failed");  
        exit(EXIT_FAILURE);  
    }  

    //lsiten to that socket and 5 is the waiting queue of clients
    if (listen(server_socket, 2) < 0)  
    {  
        perror("listen");  
        exit(EXIT_FAILURE);  
    }

    if ((client_socket = accept(server_socket, (struct sockaddr *)&sever_address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    }   
    bool flag = 1;
    while(flag)
    {
        //checking if some one disconnected
        if ((string_length = read( client_socket, buffer, 4096)) <= 0)  
        { 
            cout << "Client disconnected " << endl;
            close(client_socket);  
            flag = 0;
        }  
        else
        {
            cout << "rec : " << string_length << endl;
            buffer[string_length] = '\0';
            cout << "e : " << buffer << "------";
            utils::aesDecryption(client.dh2->getaesShaKey(), buffer, string_length);
            cout << "d : " << buffer << endl;
            string request(buffer);
            parser_request(request, client_socket, &client);
        }
    }


}
int main()
{
    port = 4000;
    int n;
    cout << "Enter max clients : ";
    cin >> n;
    int server_socket;
    int option = 1;
    client_soc client_socket[n];
    int max_clients = n;
    int activity, i , string_length , curr_soc;
    int sever_address_length , new_socket, max_sd;
    int sender, receiver;
    int channels = 0;
    int marker = 0;
    string u,p;
    f.open("server_data/uname_pass.txt", ios::in);
    while(!f.eof()) {
        f >> u;
        f >> p;
        uname_pass[u] = p;
    }
    f.close();
    long long allcMem;
    of.open("server_data/uname_mem.txt", ios::in);
    while(!of.eof()) {
        of >> u;
        of >> allcMem;
        uname_mem[u] = allcMem;
    }
    of.close();
    shaf.open("server_data/fname_shasum.txt", ios::in);
    while(!shaf.eof()) {
        shaf >> u;
        shaf >> p;
        fname_shasum[u] = p;
    }
    shaf.close();
    f.open("server_data/uname_pass.txt", ios::out | ios::app);
    of.open("server_data/uname_mem.txt", ios::out | ios::app);
    shaf.open("server_data/fname_shasum.txt", ios::out | ios::app);
    struct sockaddr_in sever_address;
    char buffer[4096];

    fd_set scoket_descriptor;

    string message;

    // for (i = 0; i < max_clients; i++)  
    // {  
    //     client_socket[i].fd = 0; 
    // } 

    //creating the server socket
    if( (server_socket = socket(AF_INET , SOCK_STREAM , 0)) == 0)  
    {  
        perror("socket creation failed");  
        exit(EXIT_FAILURE);  
    } 


    // making the server
    if( setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&option, 
          sizeof(option)) < 0 )  
    {  
        perror("setsockopt failed");  
        exit(EXIT_FAILURE);  
    }  

    //data structure for the server
    sever_address.sin_family = AF_INET;  
    sever_address.sin_addr.s_addr = INADDR_ANY;  
    sever_address.sin_port = htons( 3425 );  

    //binding the server to listen to respective port
    if (bind(server_socket, (struct sockaddr *)&sever_address, sizeof(sever_address))<0)  
    {  
        perror("bind for socket failed");  
        exit(EXIT_FAILURE);  
    }  

    cout << "here" << endl;
    //lsiten to that socket and 5 is the waiting queue of clients
    if (listen(server_socket, n + 1) < 0)  
    {  
        perror("listen");  
        exit(EXIT_FAILURE);  
    }  

    sever_address_length = sizeof(sever_address); 
    int flag = 1;
    total_Conn = 10;
    //run server loop
    while(total_Conn || flag )  
    {  

        //clearing the socket 
        FD_ZERO(&scoket_descriptor);  
    
        //setting the server socket
        FD_SET(server_socket, &scoket_descriptor);  
        max_sd = server_socket;  
            
        //for loop for the client connected
        for ( i = 0 ; i < max_clients ; i++)  
        {  
            //socket for each client
            curr_soc = client_socket[i].fd;  
                
            //if the scoket is readable than add to read list
            if(curr_soc > 0)  
                FD_SET( curr_soc , &scoket_descriptor);  
                
            //we need highest number of fd for select function
            if(curr_soc > max_sd)  
                max_sd = curr_soc;  
        }  
    
        /*
        waiting for activity on the socket,
        here the timeout is set to null so it waits infinetly
        The purpose of this method is to wake up the server if 
        something happens to its socket
        */
        activity = select( max_sd + 1 , &scoket_descriptor , NULL , NULL , NULL);  
        
      
        if ((activity < 0) && (errno!=EINTR))  
        {  
            printf("select error");  
        }  
            
        //checking new connection
        if (FD_ISSET(server_socket, &scoket_descriptor))  
        {  
            if ((new_socket = accept(server_socket, (struct sockaddr *)&sever_address, (socklen_t*)&sever_address_length))<0)  
            {  
                perror("accept");  
                exit(EXIT_FAILURE);  
            }  
            
            
            int isget = 0;
            //adding new connection
            for (i = 0; i < max_clients; i++)  
            {  
                //adding to first non-empty position
                if( client_socket[i].fd == 0 )  
                {  
                    cout << "New Client starting handshake.. " << endl;
                    client_socket[i].fd = new_socket;   
                    total_Conn++;  
                    isget = 1 ;
                    break;  
                }  
            } 
            if(isget == 0)
            {
                string s = "server capacity reached";
                send(new_socket, s.c_str(), s.length(), 0);
            } 
        }  
            
        //checking each client for IO
        for (i = 0; i < max_clients; i++)  
        {                          // for(int i = 0; i < conns.size(); i++)
                        //     channels[i] = 0;
            curr_soc = client_socket[i].fd;  
                
            if (FD_ISSET( curr_soc , &scoket_descriptor))  
            { 
                //checking if some one disconnected
                if (client_socket[i].count != -1 && (string_length = read( curr_soc , buffer, 4096)) == 0)  
                {  
                    cout << "Client " << i << " switching to new connection " << endl;
                    client_socket[i].count = -1;
                }  
                    
                //receviving the message came in
                else
                {  
                    if(client_socket[i].count == 0)
                    {
                        client_socket[i].count = 1;
                        cout << "Starting Deffie-Hellman for AES key generation.." << endl;
                        buffer[string_length] = '\0';
                        string l(buffer);
                        client_socket[i].prime = utils::stringHexToInteger(l);
                        string s = "prime";
                        int val = send(client_socket[i].fd, s.c_str(), s.length(), 0 );
                        if(val  < 0)
                            cout << "send eroor" << endl;
                    }
                    else if (client_socket[i].count == 1)
                    {
                        client_socket[i].count = 2;
                        buffer[string_length] = '\0';
                        client_socket[i].generator = utils::stringHexToInteger(buffer);
                        string s = "gen";
                        int val = send(client_socket[i].fd, s.c_str(), s.length(), 0 );
                        if(val  < 0)
                            cout << "send eroor" << endl;

                    }
                    else if(client_socket[i].count == 2)
                    {
                        client_socket[i].count = 3;
                        buffer[string_length] = '\0';
                        string lawl(buffer);
                        SecByteBlock pubO = utils::stringToSecByte(lawl);
                        client_socket[i].dh2 = new Deffie_Hellman(client_socket[i].prime, client_socket[i].generator);

                        bool result = client_socket[i].dh2->AgreeFunc(pubO);
                        if(!result)
                        {
                            cout << "Agreeemnet failed " << endl;
                        }
                        cout << "AES key generated .. " << endl;
                        Integer a;
                        a.Decode(client_socket[i].dh2->getaesKey().BytePtr(), client_socket[i].dh2->getaesKey().SizeInBytes());
                        SecByteBlock pub = client_socket[i].dh2->getpubKey();

                        string  s2 = utils::SecByteToString(pub);
                        int val = send(client_socket[i].fd, s2.c_str(), s2.length(), 0 );
                        if(val  < 0)
                            cout << "pub send eroor" << endl;
                    
                    }
                    else if(client_socket[i].count == 3) {
                        client_socket[i].count = 4;
                        cout << "Starting AES key verification.." << endl;
                        buffer[string_length] = '\0';
                        string h(buffer);
                        string output = utils::findMD5(client_socket[i].dh2->getaesKey());
                        if(h == output) {
                            cout << "verified Secret Key. Starting Session..." << endl;
                        }
                        else
                        {
                            cout << "Verification failed" << endl;
                        }
                        
                        int val = send(client_socket[i].fd, output.c_str(), output.length(), 0 );
                        if(val  < 0)
                            cout << "send eroor" << endl;
                    }
                    else if(client_socket[i].count == 4)
                    {
                        buffer[string_length] = '\0';
                        utils::aesDecryption(client_socket[i].dh2->getaesShaKey(), buffer, string_length);
                        cout << "d : " << buffer << endl;
                        thread new_client = thread(client_runner_th, client_socket[i]);
                        new_client.detach();
                    }
                    
                }  
            }  
        }  
    } 

    //closing the server
    close(server_socket);

}
