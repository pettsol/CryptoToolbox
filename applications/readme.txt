///////////////////////////////////////////

Application folder

This folder contains source code and instructions to interface C++ implemetations of cryptological algorithms for different sensor data such as images / video stream, point cloud and control signals.
By following the instructions, you should be able to create a pipeline to transfer different types of sensor data securely across machines. I.e, sensor data is encrypted during transfer and only decrypted at end-points. Authentication algorithms from the toolbox is also included to ensure that data is not changed during transfer. 

We use Robot Operating System (ROS) as a software platform to handle sensor interfacing and low-level communication between nodes (either locally on one single machine or across multiple machines). This simplfies the task of applying the cryptological toolbox of algorithms for different sensor data significantly. 
 

//////////////////////////////////////////
