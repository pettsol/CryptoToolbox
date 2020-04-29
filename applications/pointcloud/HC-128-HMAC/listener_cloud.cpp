// ROS libraries
#include "ros/ros.h"
#include "std_msgs/String.h"

// point cloud
#include <sensor_msgs/PointCloud2.h> // to construct Pointcloud2 object
#include <sensor_msgs/point_cloud2_iterator.h> // to resize Pointcloud2 object

// general
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <chrono>
#include <string.h>
#include <stdio.h>
#include <thread>
#include <vector>

//crypto
//#include "/home/oysteinvolden/catkin_ws_crypto/src/beginner_tutorials/include/beginner_tutorials/hc128.h"
//#include "/home/oysteinvolden/catkin_ws_crypto/src/beginner_tutorials/include/beginner_tutorials/encoder.h"
#include "hc128.h"
#include "encoder.h"
#include "hmac.h"
#include "aes_cfb.h"



// We will use the standard 128-bit HMAC-tag.
#define TAGSIZE 16


// Create a container for the data received from talker
sensor_msgs::PointCloud2 cloud_msg2;


void lidarCallback2(const sensor_msgs::PointCloud2ConstPtr& msg2){

  cloud_msg2 = *msg2;

}




int main(int argc, char **argv)
{

  ros::init(argc, argv, "listener");

  ros::NodeHandle n;

  // point cloud publisher - from listener
  ros::Publisher lidar_pub2 = n.advertise<sensor_msgs::PointCloud2>("/encrypted_points_from_listener", 1000);

  // point cloud publisher - from listener
  ros::Publisher lidar_pub3 = n.advertise<sensor_msgs::PointCloud2>("/recovered_points_listener", 1000);

  // point cloud subscriber - from talker
  ros::Subscriber encryptedPointCloud = n.subscribe("/encrypted_points_from_talker", 1000, lidarCallback2);




  while (ros::ok()){


    // ** PART 2: listen for received ROS messages from talker node, then decrypt and encrypt before sending back to talker

    //define data size
    u64 size_cloud = cloud_msg2.data.size() - TAGSIZE - HC128_IV_SIZE;
 
    // RECOVER
    u8 a_key[HMAC_KEYLENGTH] = {0};
    u8 e_key[AES_BLOCKSIZE] = {0};

    // Instantiate and initialize a HMAC struct
    hmac_state a_cs;
    hmac_load_key(&a_cs, a_key, HMAC_KEYLENGTH);


    // if incomming messages arrives
    if(size_cloud == 6291456){

      // Validate the tag over the IV and the ciphertext. If the(IV || Ciphertext, Tag)-pair is
	    // not valid, the ciphertext is NOT decrypted.
	    if ( !(tag_validation(&a_cs, &cloud_msg2.data[HC128_IV_SIZE+size_cloud], &cloud_msg2.data[0], HC128_IV_SIZE+size_cloud, TAGSIZE)) ) {
		    std::cout << "Invalid tag!" << std::endl;;
	    }
      else
      {
        // Else, tag is valid. Proceed to initialize the cipher and decrypt.
	      std::cout << "Valid tag!\n" << std::endl;
      }
      
	          
      // Create decryption object
	    hc128_state d_cs;

      // copy incomming message and resize to original size without tag and iv
      sensor_msgs::PointCloud2 cloud_msg2_copy;
      cloud_msg2_copy = cloud_msg2;
      cloud_msg2_copy.data.resize(size_cloud);
     
      // Initialize cipher with new IV. The IV sits at the front of the msg2.
	    hc128_initialize(&d_cs, (u32*)e_key, (u32*)&cloud_msg2.data[0]);

	    // Decrypt. The ciphertext sits after the IV in msg2.
      hc128_process_packet(&d_cs, &cloud_msg2_copy.data[0], &cloud_msg2.data[HC128_IV_SIZE], size_cloud);
  
      // publish recovered point cloud
      lidar_pub3.publish(cloud_msg2_copy);  




      // ** ENCRYPTION ** 

      //define data size
      u64 size_cloud2 = cloud_msg2_copy.data.size();

      // copy and then extend data field
      sensor_msgs::PointCloud2 cloud_msg2_copy2;
      cloud_msg2_copy2 = cloud_msg2_copy;
      cloud_msg2_copy2.data.resize(size_cloud2 + TAGSIZE + HC128_IV_SIZE);

      u8 a_key2[HMAC_KEYLENGTH] = {0};
      u8 e_key2[AES_BLOCKSIZE] = {0};
      u32 iv[AES_BLOCKSIZE/4] = {0};

      // Instantiate and initialize a HMAC struct
	    hmac_state a_cs2;
	    hmac_load_key(&a_cs2, a_key2, HMAC_KEYLENGTH);

      hc128_state e_cs2;
      hc128_initialize(&e_cs2, (u32*)e_key2, iv);

      // Load the IV
      std::memcpy(&cloud_msg2_copy.data[0], iv, HC128_IV_SIZE);

      // encrypt
      hc128_process_packet(&e_cs2, &cloud_msg2_copy2.data[HC128_IV_SIZE], &cloud_msg2_copy.data[0], size_cloud2);

      // Compute the tag and append. NB! Tag is computed over IV || Ciphertext
      tag_generation(&a_cs2, &cloud_msg2_copy2.data[HC128_IV_SIZE+size_cloud2], &cloud_msg2_copy2.data[0], HC128_IV_SIZE+size_cloud2, TAGSIZE);

      std::cout << "size 2: " << cloud_msg2_copy2.data.size() << std::endl;
 
      // publish decrypted point cloud with tag and iv
      lidar_pub2.publish(cloud_msg2_copy2);

    }
      

    ros::spinOnce();
    
  }

  return 0;
}