cmake_minimum_required(VERSION 2.8.3)
project(nirscan_driver)

set(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_C_FLAGS "-lssh")
set(CMAKE_CXX_FLAGS "-fpermissive")

find_package(catkin REQUIRED COMPONENTS
  roscpp
  rospy
  std_msgs
  genmsg
  message_generation
)


## Generate services in the 'srv' folder
add_service_files(
  FILES
  NIRScan.srv
)

generate_messages(
  DEPENDENCIES
)

catkin_package(
#  INCLUDE_DIRS include
#  LIBRARIES nirscan_driver
#  CATKIN_DEPENDS roscpp rospy std_msgs
#  DEPENDS system_lib
)

###########
## Build ##
###########

include_directories(
    src
    ~/libssh-0.7.5/include
    ${catkin_INCLUDE_DIRS}
)

add_executable(nirscan_spec_server src/nirscan_spec_server.cpp src/spec_libssh.c)

add_dependencies(nirscan_spec_server nirscan_driver_generate_messages_cpp)

target_link_libraries(nirscan_spec_server /usr/lib/libssh.so ${catkin_LIBRARIES} )
