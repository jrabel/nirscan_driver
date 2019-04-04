#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <time.h>


int verify_knownhost(ssh_session session);

int scp_receive_calib(ssh_session session, ssh_scp scp);

int scp_read_calib(ssh_session session);

int scp_receive_refl(ssh_session session, ssh_scp scp);

int scp_read_refl(ssh_session session);

int create_directory(ssh_session session, char* dir_name);

int delete_directory(ssh_session session, char* dir_name);

int remote_command(ssh_session session, char* cmd, int read);

// example ssh_login: "root@192.168.0.10"
int run_calibration_scan(char* ssh_login);

int run_reflectance_scan(char* ssh_login);