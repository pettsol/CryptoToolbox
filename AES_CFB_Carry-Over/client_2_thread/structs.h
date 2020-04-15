#ifndef _STRUCTS_H
#define _STRUCTS_H

#include <mutex>
#include <queue>
#include <string>
#include <chrono>
#include <condition_variable>

#define QUEUE_SIZE 1
#define LOAD_SIZE 0


struct data_struct {

	int is_broken;

	float data;

	double load[LOAD_SIZE];

	std::chrono::system_clock::time_point time_stamp;
};

struct data_queue {
	std::queue<data_struct> queue;
	std::mutex lock;
	std::condition_variable cond_var;
};

struct string_queue {
	std::queue<std::string> queue;
	std::mutex lock;
};

#endif
