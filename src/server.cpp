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

atomic<int> total_Conn{0};
atomic<int> port;
mutex mtx;
fstream f;
map<string, string> uname_pass;

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
    client_soc()
    {
        count = 0;
        fd = 0;
        dir = "";
        logged_in = false;
    }
};

void parser_request(string request, int client_socket, client_soc * client)
{
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
            cerr << "Error :  " << " user already exists" << endl; 
        else
        {
            cout << "Directory created";    
            uname_pass[hashuname] = hashpass;
            f << hashuname << endl;
            f << hashpass << endl;
        }

    }
    else if(type == "LOGIN") {
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
            send(client_socket, err.c_str(), err.length(), 0);
            client->logged_in = false;
            return;
        }
        if(uname_pass[hashuname] != hashpass) {
            string err = "LOGIN Failed : Error : wrong password for User : " + uname;
            cout << err << endl;
            send(client_socket, err.c_str(), err.length(), 0);
            client->logged_in = false;
            return;
        } else {
            string str = "LOGIN Successful : Further requests can be served.";
            cout << str << endl;
            send(client_socket, str.c_str(), str.length(), 0);
            client->logged_in = true;
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
    f.open("server_data/uname_pass.txt", ios::out | ios::app);
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
