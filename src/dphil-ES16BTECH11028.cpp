#include<bits/stdc++.h>
#include<fstream>
#include<chrono>
#include<thread>
#include<sys/time.h>
#include<ctime>
#include<mutex>
#include<condition_variable>
using namespace std;
int n = 5,k = 10;
float lambda1 = 1, lambda2 = 2;
mutex m;
condition_variable * self;
string *state;
float *wait;
float *wait_worst;
double give_exp_dist(float lam)
{
    default_random_engine gen;
    exponential_distribution <double> distribution(1.0/lam);
    return distribution(gen);
}
void test(int i) {
    if ((state[(i + 4) % 5] != "EATING") &&
        (state[i] == "HUNGRY") &&
        (state[(i + 1) % n] != "EATING")) {
        state[i] = "EATING";
        self[i].notify_all();
    }
}
void philosopher(int id, mutex * m) {
    for(int i = 0; i < k; i++) {
        auto clock_start = chrono::steady_clock::now();
        time_t time_be = time(0);
        tm *ltm = localtime(&time_be);
        printf("%d th eat request by Philosopher Thread %d at %d:%d\n",i, id, ltm->tm_min, ltm->tm_sec); 
        unique_lock<std::mutex> lck (*m);
        state[id] = "HUNGRY";
        test(id);
        if(state[id] != "EATING")
            self[id].wait(lck);
        time_be = time(0);
        ltm = localtime(&time_be);
        printf("%d th eat entry by Philosopher Thread %d at %d:%d\n",i, id, ltm->tm_min, ltm->tm_sec);
        auto clock_end = chrono::steady_clock::now();
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(clock_end - clock_start);
        auto ms = milliseconds.count(); 
        wait[id] += ms;
        if(wait_worst[id] < ms)
            wait_worst[id] = ms;
        this_thread::sleep_for(std::chrono::seconds((int)(give_exp_dist(lambda1))));
        time_be = time(0);
        ltm = localtime(&time_be);
        printf("%d th eat exit by Philosopher Thread %d at %d:%d\n",i, id, ltm->tm_min, ltm->tm_sec);
        state[id] = "THINKING";
        test((id + 4) % n);
        test((id + 1) % n);
        this_thread::sleep_for(std::chrono::seconds((int)(give_exp_dist(lambda2))));
    }
}
int main() {
    state = new string[n];
    self = new condition_variable[n];
    mutex m[n];
    wait = new float[n];
    thread th[n];
    wait_worst  = new float[n];
    for (int i = 0; i < n; i++){
        state[i] = "THINKING";
    }
    for (int i = 0; i < n; i++){
        wait[i] = 0;
        wait_worst[i] = -1;
    }
    for(int i = 0; i < n; i++) {
        th[i] = thread(philosopher, i, m + i);
    }
    for(int i = 0; i < n; i++) {
        th[i].join();
    }
    float sum = 0,w = -1;
    for(int i = 0; i < n; i++) {
        sum = sum + wait[i];
        if(w < wait_worst[i])
            w = wait_worst[i];
    }
    cout << "Average time : " << sum / (float)(n*k) << endl;
    cout << "Worst case time : " << w << endl;
    return 0;
}
