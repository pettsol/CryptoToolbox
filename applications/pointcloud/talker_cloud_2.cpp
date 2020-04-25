//ROS libraries
#include "ros/ros.h"
#include "std_msgs/String.h"

//point cloud
#include <sensor_msgs/PointCloud2.h>

//IO etc
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <chrono>
#include <string.h>
#include <stdio.h>
#include <thread>

//crypto
#include "/home/oysteinvolden/catkin_ws_crypto/src/beginner_tutorials/include/beginner_tutorials/aes_cfb.h"


#define BLOCKSIZE 16

std::string filepath_log = "/home/oysteinvolden/catkin_ws_crypto/src/beginner_tutorials/src/";

std::chrono::time_point<std::chrono::system_clock> start, end;

// Create a container for the data received from rosbag
sensor_msgs::PointCloud2 cloud_msg;

// Create a container for the data received from listener
sensor_msgs::PointCloud2 cloud_msg_list;


void string2hexString(char* output, const unsigned char* input, int size)
{
	int loop;
	int i;

	i = 0;
	loop = 0;

	while(loop != size)
	{
		sprintf((char*)(output+i), "%02X", input[loop]);
		loop+=1;
		i+=2;
	}
	output[i++] = '\0';
}

// callback for rosbag
void lidarCallback(const sensor_msgs::PointCloud2ConstPtr& msg){

  cloud_msg = *msg;

  return;
}

// callback for listener node
void lidarCallback2(const sensor_msgs::PointCloud2ConstPtr& msg){

  cloud_msg_list = *msg;

  return;
}



int main(int argc, char **argv)
{
  
  ros::init(argc, argv, "talker");

  ros::NodeHandle n;


  // point cloud publisher
  ros::Publisher lidar_pub = n.advertise<sensor_msgs::PointCloud2>("/points", 1000);

  ros::Publisher lidar_recovered = n.advertise<sensor_msgs::PointCloud2>("/recovered_points", 1000);

  // point cloud subscriber - from rosbag
  ros::Subscriber sub = n.subscribe<sensor_msgs::PointCloud2> ("/os1_cloud_node/points", 1000, lidarCallback); 

  // point cloud subscriber - from listener
  ros::Subscriber sub_list = n.subscribe<sensor_msgs::PointCloud2> ("/points2", 1000, lidarCallback2); 

  // start time
  start = std::chrono::system_clock::now();

  while (ros::ok())
  {
      // ** PART 1: listen for ROS messages from rosbag, then encrypt and send to talker node

      // log files
      std::string path_log_plaintext1 = filepath_log + "log_plaintext_1.txt";
      std::ofstream log_plaintext_1(path_log_plaintext1);
      std::string path_log_ciphertext_1= filepath_log + "log_ciphertext_1.txt";
      std::ofstream log_ciphertext_1(path_log_ciphertext_1);

      // define data field 
      int size_cloud = cloud_msg.row_step * cloud_msg.height;
      u8* data_cloud = new u8[size_cloud];

      // print original plaintext values received from (copy of) rosbag
      for(int i = 0; i < size_cloud; i++){
        data_cloud[i] = cloud_msg.data[i];
        char hex[3];
        string2hexString(hex, &data_cloud[i], 2);
        std::string printableHex(hex, 2);
        if(i < 200){
          log_plaintext_1 << printableHex << " ";
        }
      }

      log_plaintext_1.close();

      u8* out_buff = new u8[size_cloud];
      memcpy(out_buff, data_cloud, size_cloud);
      delete[] data_cloud;

  
      // ** ENCRYPTION **
      u8* ciphertext = new u8[size_cloud];
    
      u8 key[BLOCKSIZE] = {0};
	    u32 iv[BLOCKSIZE/4] = {0};
      cipher_state e_cs;
	    cfb_initialize_cipher(&e_cs, key, iv);
      cfb_process_packet(&e_cs, out_buff, ciphertext, size_cloud, ENCRYPT);

      delete[] out_buff;

      u8* cipher_copy = new u8[size_cloud];
      memcpy(cipher_copy, ciphertext, size_cloud);
    
      // copy original message and overwrite data field with encrypted data
      sensor_msgs::PointCloud2 cloud_msg_copy;
      cloud_msg_copy = cloud_msg;
      for(int i = 0; i < size_cloud; i++){
        cloud_msg_copy.data[i] = cipher_copy[i];
      }
    
      // publish encrypted point cloud
      lidar_pub.publish(cloud_msg_copy);

    
      // print encrypted point cloud  
      for(int i = 0; i < size_cloud; i++){
        char hex[3];
        string2hexString(hex, &cipher_copy[i], 2);
        std::string printableHex(hex, 2);
        if(i < 200){
          log_ciphertext_1 << printableHex << " ";
        }
      }

      log_ciphertext_1.close();
      

      delete[] cipher_copy;
      delete[] ciphertext;  




      // ** PART3: listen for received ROS messages from listener node, then decrypt and publish recovered point cloud **

      // log files
      std::string path_log_ciphertext_4 = filepath_log + "log_ciphertext_4.txt";
      std::ofstream log_ciphertext_4(path_log_ciphertext_4);
      std::string path_log_recovered_3= filepath_log + "log_recovered_3.txt";
      std::ofstream log_recovered_3(path_log_recovered_3);

      // define data field
      int size_cloud2 = cloud_msg_list.row_step * cloud_msg_list.height;
      u8* ciphertext_2 = new u8[size_cloud2];
      
      for(int i = 0; i < size_cloud2; i++){
        ciphertext_2[i] = cloud_msg_list.data[i];
        char hex[3];
        string2hexString(hex, &ciphertext_2[i], 2);
        std::string printableHex(hex, 2);
        if(i < 200){
          log_ciphertext_4 << printableHex << " ";
        }
      }
      

      log_ciphertext_4.close();

      u8* ciphertext_3 = new u8[size_cloud2];    
      memcpy(ciphertext_3, ciphertext_2, size_cloud2);

      delete[] ciphertext_2;

        
      // RECOVER 
      cipher_state d_cs;
	    cfb_initialize_cipher(&d_cs, key, iv);

      u8* deciphered_3 = new u8[size_cloud2];

	    cfb_process_packet(&d_cs, ciphertext_3, deciphered_3, size_cloud2, DECRYPT);

      u8* deciphered_4 = new u8[size_cloud2];    
      memcpy(deciphered_4, deciphered_3, size_cloud2);

      delete[] ciphertext_3;    
    
      for(int i = 0; i < size_cloud2; i++){
        char hex[3];
        string2hexString(hex, &deciphered_3[i], 2);
        std::string printableHex(hex, 2);
        if(i < 200){
          log_recovered_3 << printableHex << " ";
        }  
      }
        
      
      log_recovered_3.close();

      delete[] deciphered_3;

      // make a copy of ROS message from listener node and overwrite datafield with recovered data        
      sensor_msgs::PointCloud2 cloud_msg_copy3;
      cloud_msg_copy3 = cloud_msg_list;
      for(int i = 0; i < size_cloud2; i++){
        cloud_msg_copy3.data[i] = deciphered_4[i];
      }

      // publish recovered data
      lidar_recovered.publish(cloud_msg_copy3);

      // measure elapsed time (RTT when rosbag, listener and talker node is running at the same time)
      end = std::chrono::system_clock::now();
      std::chrono::duration<double> elapsed_seconds = end - start;
      std::cout << "RTT: " << elapsed_seconds.count() << std::endl;

      delete[] deciphered_4;

      
      // calls callback functions for each spinOnce();
      ros::spinOnce();

    
  }
  


  return 0;
}