#ifndef _NETWORK_H
#define _NETWORK_H

#include "structs.h"

void tx_thread(std::string server_address, int server_port, data_queue &Q);
void rx_thread(int client_port, data_queue &Q);

#endif
