//ROS libraries
#include "ros/ros.h"
#include "std_msgs/String.h"

//point cloud
#include <sensor_msgs/PointCloud2.h>

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


//#define BLOCKSIZE 16


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

  //std::cout << "test2" << std::endl;

  cloud_msg_list = *msg;

  return;
}



int main(int argc, char **argv)
{
  
  ros::init(argc, argv, "talker");

  ros::NodeHandle n;


  // point cloud publisher - from talker
  ros::Publisher lidar_pub = n.advertise<sensor_msgs::PointCloud2>("/encrypted_points_from_talker", 1000);

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
    u64 size_cloud = cloud_msg.row_step * cloud_msg.height; // move outside while loop?

    std::cout << size_cloud << std::endl;
   
    // ** ENCRYPTION **
    sensor_msgs::PointCloud2 cloud_msg_copy;
    cloud_msg_copy = cloud_msg;

    std::string hexkey = "0F62B5085BAE0154A7FA4DA0F34699EC";
	  std::string hexIv = "288FF65DC42B92F960C72E95FC63CA31";    


    u32 key[4];
    hex2stringString((u8*)key, hexkey.data(), 32);

    u32 iv[4];
    hex2stringString((u8*)iv, hexIv.data(), 32);

    hc128_state e_cs;
	  hc128_initialize(&e_cs, key, iv);
    if(size_cloud > 0){
      hc128_process_packet(&e_cs, &cloud_msg_copy.data[0], &cloud_msg.data[0], size_cloud);
      lidar_pub.publish(cloud_msg_copy);
    }
	  


    // ** PART3: listen for received ROS messages from listener node, then decrypt and publish recovered point cloud **

    // define data size
    int size_cloud2 = cloud_msg_list.row_step * cloud_msg_list.height;
      
    // RECOVER 
    sensor_msgs::PointCloud2 cloud_msg_copy4;
    cloud_msg_copy4 = cloud_msg_list;

    hc128_state d_cs;
	  hc128_initialize(&d_cs, key, iv);
    if(size_cloud2 > 0){
      hc128_process_packet(&d_cs, &cloud_msg_copy4.data[0], &cloud_msg_list.data[0], size_cloud2);
      lidar_recovered.publish(cloud_msg_copy4);
    }



    // measure elapsed time (RTT when rosbag, listener and talker node is running at the same time)
    end = std::chrono::system_clock::now();
    std::chrono::duration<double> elapsed_seconds = end - start;
    std::cout << "RTT: " << elapsed_seconds.count() << std::endl;

    hexkey += "1";

    ros::spinOnce();
  }
  


  return 0;
}