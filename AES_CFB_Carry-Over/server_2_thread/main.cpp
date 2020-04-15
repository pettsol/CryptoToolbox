/* SERVER SIDE OF THE ENCRYPTION LABORATORY SETUP */

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

	//Set destination IP address and port
	std::string client_address = "10.53.0.20";
	int server_port = 4322;
	int client_port = 4321;

	#ifdef MAC
	std::cout << "MESSAGE AUTHENTICATION ENABLED" << std::endl;
	#else
	std::cout << "MESSAGE AUTHENTICATION IS NOT ENABLED" << std::endl;
	#endif

	// Queue from Decryption module to Encryption module
	data_queue Q;


	std::thread rx{rx_thread, server_port, std::ref(Q)};
	std::thread tx{tx_thread, client_address, client_port, std::ref(Q)};

	rx.join();
	tx.join();
}
