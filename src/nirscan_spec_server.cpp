#include "ros/ros.h"
#include <string>

extern "C" {
    #include "spec_libssh.h"
}
#include "nirscan_driver/NIRScan.h"


bool calibration_scan_callback(nirscan_driver::NIRScan::Request &req,
                               nirscan_driver::NIRScan::Response &res) {
    ROS_INFO("Performing a calibration scan...");

    // get nirscan_ssh_login param
    ros::NodeHandle n;
    std::string ssh_login;
    n.param<std::string>("nirscan_ssh_login", ssh_login, "root@192.168.0.10");

    int string_len = ssh_login.length();
    char ssh_login_cstr[string_len+1];

    strcpy(ssh_login_cstr, ssh_login.c_str());
    run_calibration_scan(ssh_login_cstr);

    return true;
}

bool reflectance_scan_callback(nirscan_driver::NIRScan::Request &req,
                               nirscan_driver::NIRScan::Response &res) {
    ROS_INFO("Performing a reflectance scan...");

    // get nirscan_ssh_login param
    ros::NodeHandle n;
    std::string ssh_login;
    n.param<std::string>("nirscan_ssh_login", ssh_login, "root@192.168.0.10");

    int string_len = ssh_login.length();
    char ssh_login_cstr[string_len+1];

    strcpy(ssh_login_cstr, ssh_login.c_str());
    run_reflectance_scan(ssh_login_cstr);
    return true;
}

int main(int argc, char **argv) {

    ros::init(argc, argv, "nirscan_spec_server");
    ros::NodeHandle n;

    ros::ServiceServer calibration_service = n.advertiseService("nirscan_spec_calibration_scan", calibration_scan_callback);
    ros::ServiceServer reflectance_service = n.advertiseService("nirscan_spec_reflectance_scan", reflectance_scan_callback);
    
    // set nirscan_ssh_login param
    n.setParam("nirscan_ssh_login", "root@192.168.0.10");

    ROS_INFO("NIRScan_server ready to perform scans...");
    ROS_INFO("\tIt is recommended to first run a calibration scan.");
    ros::spin();
    
    return 0;

}
