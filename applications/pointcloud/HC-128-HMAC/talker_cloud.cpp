//ROS libraries
#include "ros/ros.h"
#include "std_msgs/String.h"


//point cloud
#include <sensor_msgs/PointCloud2.h>  // to construct Pointcloud2 object
#include <sensor_msgs/point_cloud2_iterator.h> // to resize Pointcloud2 object

//general
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <chrono>
#include <string.h>
#include <stdio.h>
#include <thread>

//crypto
//#include "/home/oysteinvolden/catkin_ws_crypto/src/beginner_tutorials/include/beginner_tutorials/hc128.h"
//#include "/home/oysteinvolden/catkin_ws_crypto/src/beginner_tutorials/include/beginner_tutorials/encoder.h"
#include "hc128.h"
#include "encoder.h"
#include "hmac.h"
#include "aes_cfb.h"


// We will use the standard 128-bit HMAC-tag.
#define TAGSIZE 16

// measure RTT
std::chrono::time_point<std::chrono::system_clock> start, end;

// Create a container for the data received from rosbag and listener
sensor_msgs::PointCloud2 cloud_msg; 
sensor_msgs::PointCloud2 cloud_msg_list;


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


  // point cloud publisher - from talker
  ros::Publisher lidar_pub = n.advertise<sensor_msgs::PointCloud2>("/encrypted_points_from_talker", 1000);

  // point cloud publisher - recovered
  ros::Publisher lidar_recovered = n.advertise<sensor_msgs::PointCloud2>("/recovered_points_talker", 1000);

  // point cloud subscriber - from rosbag
  ros::Subscriber sub = n.subscribe<sensor_msgs::PointCloud2> ("/os1_cloud_node/points", 1000, lidarCallback); 

  // point cloud subscriber - from listener
  ros::Subscriber sub_list = n.subscribe<sensor_msgs::PointCloud2> ("/encrypted_points_from_listener", 1000, lidarCallback2); 


  // start time
  start = std::chrono::system_clock::now();

  while (ros::ok())
  {
    
    // ** PART 1: listen for ROS messages from rosbag, then encrypt and send to talker node

    // define data size
    u64 size_cloud = (cloud_msg.row_step * cloud_msg.height); 
    int total_size = (HC128_IV_SIZE) + (cloud_msg.row_step * cloud_msg.height) + (TAGSIZE);

    // if incomming messages
    if(size_cloud > 0){

      // ** ENCRYPTION **

      // copy and then extend data field
      sensor_msgs::PointCloud2 cloud_msg_copy;
      cloud_msg_copy = cloud_msg;
      cloud_msg_copy.data.resize(total_size);


      u8 a_key[HMAC_KEYLENGTH] = {0};
      u8 e_key[AES_BLOCKSIZE] = {0};
      u32 iv[AES_BLOCKSIZE/4] = {0};

      // Instantiate and initialize a HMAC struct
	    hmac_state a_cs;
	    hmac_load_key(&a_cs, a_key, HMAC_KEYLENGTH);

      hc128_state e_cs;
      hc128_initialize(&e_cs, (u32*)e_key, iv);

      // Load the IV
      std::memcpy(&cloud_msg_copy.data[0], iv, HC128_IV_SIZE);

      //encrypt
      hc128_process_packet(&e_cs, &cloud_msg_copy.data[HC128_IV_SIZE], &cloud_msg.data[0], size_cloud);

      // Compute the tag and append. NB! Tag is computed over IV || Ciphertext
      tag_generation(&a_cs, &cloud_msg_copy.data[HC128_IV_SIZE+size_cloud], &cloud_msg_copy.data[0], HC128_IV_SIZE+size_cloud, TAGSIZE);
       
      // publish decrypted point cloud with tag and iv
      lidar_pub.publish(cloud_msg_copy);
      
    
    }


    // ** PART3: listen for received ROS messages from listener node, then decrypt and publish recovered point cloud **

    // define data size
    u64 size_cloud2 = cloud_msg_list.data.size() - TAGSIZE - HC128_IV_SIZE;
      
    // RECOVER 
    u8 a_key2[HMAC_KEYLENGTH] = {0};
    u8 e_key2[AES_BLOCKSIZE] = {0};

    // Instantiate and initialize a HMAC struct
    hmac_state a_cs2;
    hmac_load_key(&a_cs2, a_key2, HMAC_KEYLENGTH);    

    if(size_cloud2 == 6291456){

      // Validate the tag over the IV and the ciphertext. If the(IV || Ciphertext, Tag)-pair is
	    // not valid, the ciphertext is NOT decrypted.
	    if ( !(tag_validation(&a_cs2, &cloud_msg_list.data[HC128_IV_SIZE+size_cloud2], &cloud_msg_list.data[0], HC128_IV_SIZE+size_cloud2, TAGSIZE)) ) {
		    std::cout << "Invalid tag!" << std::endl;;
	    }
      else
      {
        // Else, tag is valid. Proceed to initialize the cipher and decrypt.
	      std::cout << "Valid tag!\n" << std::endl;
      }

      // Create decryption object
	    hc128_state d_cs2;

      // copy incomming message and resize to original size without tag and iv
      sensor_msgs::PointCloud2 cloud_msg_list_copy;
      cloud_msg_list_copy = cloud_msg_list;
      cloud_msg_list_copy.data.resize(size_cloud2);
     
      // Initialize cipher with new IV. The IV sits at the front of the msg2.
	    hc128_initialize(&d_cs2, (u32*)e_key2, (u32*)&cloud_msg_list.data[0]);

	    // Decrypt. The ciphertext sits after the IV in msg2.
      hc128_process_packet(&d_cs2, &cloud_msg_list_copy.data[0], &cloud_msg_list.data[HC128_IV_SIZE], size_cloud2);
 
      // publish recovered point cloud
      lidar_recovered.publish(cloud_msg_list_copy);  

    }

    // measure elapsed time (RTT when rosbag, listener and talker node is running at the same time)
    end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::cout << "RTT: " << elapsed_seconds.count() << std::endl;

    ros::spinOnce();
  }
  


  return 0;
}