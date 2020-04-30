//ROS libraries
#include "ros/ros.h"
#include "std_msgs/String.h"
#include <image_transport/image_transport.h>
#include <sensor_msgs/image_encodings.h>
#include <sensor_msgs/Image.h>
#include <cv_bridge/cv_bridge.h>

//openCV
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc/imgproc.hpp>
#include <opencv2/opencv.hpp>



//general
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <chrono>
#include <string.h>
#include <stdio.h>


//crypto
#include "aes_cfb.h"


#define BLOCKSIZE 16


void serialize(u8 *out, cv::Mat *in, int size)
{
	for (int h = 0; h < in->rows; h++)
	{
		for (int w = 0; w < in->cols; w++)
		{
			*out = (*in).at<u8>(h,w); out++;
		}
	}
}

void deserialize(cv::Mat *out, u8 *in, int size)
{
	for (int h = 0; h < out->rows; h++)
	{
		for (int w = 0; w < out->cols; w++)
		{
			(*out).at<u8>(h,w) = *in; in++;
		}
	}
}

//define captured frame and current frame in use
cv::Mat cap_frame, cur_frame;

void cameraCallback(const sensor_msgs::ImageConstPtr& msg)
  {
  cv_bridge::CvImagePtr cv_ptr;

  try {
    ROS_INFO("Callback Called");
    cv_ptr = cv_bridge::toCvCopy(msg, sensor_msgs::image_encodings::MONO8);
    cap_frame = cv_ptr->image.clone();

  } catch (cv_bridge::Exception& e) {
    ROS_ERROR("cv_bridge exception: %s", e.what());
    return;
  }
  return;
}




int main(int argc, char **argv)
{

  ros::init(argc, argv, "listener");

  ros::NodeHandle n;

  // subscribe for encrypted stream from talker
  ros::Subscriber encryptedImageSubscriber = n.subscribe("/encrypted_stream_from_talker", 1000, cameraCallback);

  // encrypted image publisher
  ros::Publisher encryptedImagePublisher2 = n.advertise<sensor_msgs::Image>("/encrypted_stream_from_listener", 1000);

  u8 key[BLOCKSIZE] = {0};
  u32 iv[BLOCKSIZE/4] = {0};

  while (ros::ok()){

      cur_frame = cap_frame.clone();

      if(!cur_frame.empty() && cur_frame.isContinuous()){

        int size = cur_frame.total() * cur_frame.elemSize();

        u8 ciphertext[size];
        serialize(ciphertext, &cur_frame, size);

        // RECOVER
	      cipher_state d_cs;
	      cfb_initialize_cipher(&d_cs, key, iv);

        u8 deciphered[size];

	      cfb_process_packet(&d_cs, ciphertext, deciphered, size, DECRYPT);

        cv::Mat decrypted = cv::Mat::zeros(cv::Size(cur_frame.cols, cur_frame.rows), CV_8UC1);

	      deserialize(&decrypted, deciphered, size);

	      //cv::imshow( "Recovered image", decrypted );
	      //cv::waitKey(500);

        //encrypt again and send back
        cipher_state e_cs;
	      cfb_initialize_cipher(&e_cs, key, iv);

        u8 plaintext[size];
        if (decrypted.isContinuous())
            serialize(plaintext, &decrypted, size);
        
        cv::Mat deserialized = cv::Mat::zeros(cv::Size(decrypted.cols, decrypted.rows), CV_8U);
	      deserialize(&deserialized, plaintext, size);

        //u8 ciphertext[size];

	      cv::Mat encrypted = cv::Mat::zeros(cv::Size(decrypted.cols, decrypted.rows), CV_8U);

        cfb_process_packet(&e_cs, plaintext, ciphertext, size, ENCRYPT);
	
	      deserialize(&encrypted, ciphertext, size);

        // publish encrypted image via ROS
        sensor_msgs::ImagePtr msg = cv_bridge::CvImage(std_msgs::Header(), "mono8", encrypted).toImageMsg();
        encryptedImagePublisher2.publish(msg);
 
    }
 
    ros::spinOnce();
  }

 

  return 0;
}