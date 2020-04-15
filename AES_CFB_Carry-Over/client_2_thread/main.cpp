/* CLIENT FILE FOR THE ENCRYPTION LABORATORY SETUP */
/* WRITTEN BY PETTER SOLNØR JANUARY 2020           */

#include <iostream>
#include <thread>
#include <mutex>

#include "network.h"
#include "structs.h"

#include <unistd.h>

int main()
{

	//Server address: 10.53.0.10
	//Client address: 10.53.0.20

	std::string server_address = "10.53.0.10";
	int server_port = 4322;
	int client_port = 4321;

	#ifdef MAC
	std::cout << "MESSAGE AUTHENTICATION ENABLED" << std::endl;
	#else
	std::cout << "MESSAGE AUTHENTICATION IS NOT ENABLED" << std::endl;
	#endif

	std::thread tx{tx_thread, server_address, server_port};
	std::thread rx{rx_thread, client_port};
	
	tx.join();
	rx.join();
}
