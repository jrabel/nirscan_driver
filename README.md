# nirscan_driver
A ROS driver for the Texas Instruments NIRScan spectrometer

## Getting Started
This ROS driver makes use of the library libssh (https://www.libssh.org/) to create a simple client - server interface between the host machine and the TI NIRScan system. 

### Prerequisites
1. Install libssh

### Installing
Clone this repository inside a new or pre-existing catkin workspace and simply run the catkin_make command at the workspace level to build.

### Running
1. You can run the ROS service server using rosrun with the package name as follows:

  ```source devel/setup.bash```

  ```rosrun nirscan_driver nirscan_spec_server```

2. After running the server as described above, a ROS parameter called "/nirscan_ssh_login" is created with a default value of "root@192.168.0.10". You should alter this parameter to match the ssh username and IP address that corresponds to your NIRScan device. An example is shown below:

  ```rosparam set /nirscan_ssh_login "root@192.168.1.30"```

3. Finally, you can make a call to the ROS service as follows:

    Run Calibration Scan: ```rosservice call /nirscan_spec_calibration_scan```
  
    Run Reflectance Scan: ```rosservice call /nirscan_spec_reflection_scan```
