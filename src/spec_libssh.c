#include "spec_libssh.h"

int verify_knownhost(ssh_session session)
{
  int state, hlen;
  unsigned char *hash = NULL;
  char *hexa;
  char buf[10];
  state = ssh_is_server_known(session);
  hlen = ssh_get_pubkey_hash(session, &hash);
  if (hlen < 0)
    return -1;
  switch (state)
  {
    case SSH_SERVER_KNOWN_OK:
      break; /* ok */
    case SSH_SERVER_KNOWN_CHANGED:
      fprintf(stderr, "Host key for server changed: it is now:\n");
      ssh_print_hexa("Public key hash", hash, hlen);
      fprintf(stderr, "For security reasons, connection will be stopped\n");
      free(hash);
      return -1;
    case SSH_SERVER_FOUND_OTHER:
      fprintf(stderr, "The host key for this server was not found but an other"
        "type of key exists.\n");
      fprintf(stderr, "An attacker might change the default server key to"
        "confuse your client into thinking the key does not exist\n");
      free(hash);
      return -1;
    case SSH_SERVER_FILE_NOT_FOUND:
      fprintf(stderr, "Could not find known host file.\n");
      fprintf(stderr, "If you accept the host key here, the file will be"
       "automatically created.\n");
      /* fallback to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_SERVER_NOT_KNOWN:
      hexa = ssh_get_hexa(hash, hlen);
      fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
      fprintf(stderr, "Public key hash: %s\n", hexa);
      free(hexa);
      if (fgets(buf, sizeof(buf), stdin) == NULL)
      {
        free(hash);
        return -1;
      }
      if (strncasecmp(buf, "yes", 3) != 0)
      {
        free(hash);
        return -1;
      }
      if (ssh_write_knownhost(session) < 0)
      {
        fprintf(stderr, "Error %s\n", strerror(errno));
        free(hash);
        return -1;
      }
      break;
    case SSH_SERVER_ERROR:
      fprintf(stderr, "Error %s", ssh_get_error(session));
      free(hash);
      return -1;
  }
  free(hash);
  return 0;
}


int scp_receive_calib(ssh_session session, ssh_scp scp) {
    int rc;
    int size, mode;
    char *filename, *buffer, *newfile;
    char timebuf [43];
    time_t rawtime;
    struct tm *timeinfo;

    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_NEWFILE) {
        fprintf(stderr, "Error receiving information about file: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    size = ssh_scp_request_get_size(scp);
    filename = strdup(ssh_scp_request_get_filename(scp));
    mode = ssh_scp_request_get_permissions(scp);
    printf("Receiving file %s, size %d, permisssions 0%o\n",
           filename, size, mode);
    free(filename);
    buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return SSH_ERROR;
    }
    ssh_scp_accept_request(scp);
    rc = ssh_scp_read(scp, buffer, size);
    if (rc == SSH_ERROR) {
        fprintf(stderr, "Error receiving file data: %s\n",
        ssh_get_error(session));
        free(buffer);
        return rc;
    }
    
    time (&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timebuf, sizeof(timebuf), "./nirscan_output_data/calibration_data/calibration_data_%m-%d_%H:%M:%S.txt", timeinfo);
    
    write(1, timebuf, sizeof(timebuf));
    FILE *f = fopen(timebuf, "w");
    if (f == NULL) {
        printf("Error opening local file!\n");
        exit(1);
    }

    //write(1, buffer, size); // write data to cmd line
    fprintf(stderr, "\n");
    fprintf(f, buffer); // write data to file 
    free(buffer);
    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_EOF) {
        fprintf(f, "Unexpected request: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }

    return SSH_OK;
}


int scp_read_calib(ssh_session session) {
    ssh_scp scp;
    int rc;
    scp = ssh_scp_new(session, SSH_SCP_READ, "/usr/share/SNR-test/avg_readings.txt");
    if (scp == NULL) {
        fprintf(stderr, "Error allocating scp session: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
    fprintf(stderr, "Error initializing scp session: %s\n",
            ssh_get_error(session));
    ssh_scp_free(scp);
    return rc;
    }
    
    scp_receive_calib(session, scp);

    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;
}


int scp_receive_refl(ssh_session session, ssh_scp scp) {
    int rc;
    int size, mode;
    char *filename, *buffer, *newfile;
    char timebuf [43];
    time_t rawtime;
    struct tm *timeinfo;

    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_NEWFILE) {
        fprintf(stderr, "Error receiving information about file: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    size = ssh_scp_request_get_size(scp);
    filename = strdup(ssh_scp_request_get_filename(scp));
    mode = ssh_scp_request_get_permissions(scp);
    printf("Receiving file %s, size %d, permisssions 0%o\n",
           filename, size, mode);
    free(filename);
    buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return SSH_ERROR;
    }
    ssh_scp_accept_request(scp);
    rc = ssh_scp_read(scp, buffer, size);
    if (rc == SSH_ERROR) {
        fprintf(stderr, "Error receiving file data: %s\n",
        ssh_get_error(session));
        free(buffer);
        return rc;
    }
    
    time (&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timebuf, sizeof(timebuf), "./nirscan_output_data/sample_data/sample_data_%m-%d_%H:%M:%S.txt", timeinfo);
    
    write(1, timebuf, sizeof(timebuf));
    FILE *f = fopen(timebuf, "w");
    if (f == NULL) {
        printf("Error opening local file!\n");
        exit(1);
    }

    //write(1, buffer, size); // write data to cmd line
    fprintf(stderr, "\n");
    fprintf(f, buffer); // write data to file 
    free(buffer);
    rc = ssh_scp_pull_request(scp);
    if (rc != SSH_SCP_REQUEST_EOF) {
        fprintf(f, "Unexpected request: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }

    return SSH_OK;
}


int scp_read_refl(ssh_session session) {
    ssh_scp scp;
    int rc;
    scp = ssh_scp_new(session, SSH_SCP_READ, "/usr/share/SNR-test/avg_readings.txt");
    if (scp == NULL) {
        fprintf(stderr, "Error allocating scp session: %s\n",
        ssh_get_error(session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK) {
    fprintf(stderr, "Error initializing scp session: %s\n",
            ssh_get_error(session));
    ssh_scp_free(scp);
    return rc;
    }
    
    scp_receive_refl(session, scp);

    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;
}

int create_directory(ssh_session session, char* dir_name){
    sftp_session sftp;
    int rc;

    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", 
                ssh_get_error(session));
        return SSH_ERROR;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", 
                sftp_get_error(sftp));
        sftp_free(sftp);
        return rc; 
    }
 
    rc = sftp_mkdir(sftp, dir_name, S_IRWXU);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't create directory: %s\n", 
                ssh_get_error(session));
        return rc;
    }

    sftp_free(sftp);
    return SSH_OK;
}

int delete_directory(ssh_session session, char* dir_name){
    sftp_session sftp;
    int rc;

    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error allocating SFTP session: %s\n",
                ssh_get_error(session));
        return SSH_ERROR;
    }

    rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n",
                sftp_get_error(sftp));
        sftp_free(sftp);
        return rc;
    }

    rc = sftp_rmdir(sftp, dir_name);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't create directory: %s\n",
                ssh_get_error(session));
        return rc;
    }

    sftp_free(sftp);
    return SSH_OK;
}


int remote_command(ssh_session session, char* cmd, int read) {
    
    ssh_channel channel;
    int rc; 
    
    channel = ssh_channel_new(session);
    if (channel == NULL) return SSH_ERROR;
   
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "error opening channel\n");
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_exec(channel, cmd);
    if (rc != SSH_OK) {
        fprintf(stderr, "Can't execute command: %s\n", 
                "cd /usr/share");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc; 
    }
    
    if (read) {
        char buffer[256];
        int nbytes;
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        while (nbytes > 0) {
            if (fwrite(buffer, 1, nbytes, stdout) != nbytes) {
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return SSH_ERROR;
            }
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        }

        if (nbytes < 0) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);        

    return SSH_OK;
}


int run_calibration_scan(char* ssh_login) {
    ssh_session my_ssh_session;
    int verbosity = SSH_LOG_PROTOCOL;
    int rc;    
    char *password;

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ssh_login);
    //ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, SSH_LOG_NOLOG);

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n", 
                ssh_get_error(my_ssh_session));
        exit(-1);
    }
 
    // Verify the server's identity
    if (verify_knownhost(my_ssh_session) < 0) {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }       
    
    // Authenticate ourselves
    //password = getpass("Password: ");
    password = "";
    rc = ssh_userauth_password(my_ssh_session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
   
    // **delete SNR-test directory (not needed in some cases) 
    //remote_command(my_ssh_session, "rm -r /usr/share/SNR-test",0);    
    // **create SNR-test directory in /usr/share
    //create_directory(my_ssh_session, "/usr/share/SNR-test");
    // **create patterns directory in /usr/share/SNR-test
    //create_directory(my_ssh_session, "/usr/share/SNR-test/patterns");
    // Calibration Scan command list 
    //remote_command(my_ssh_session, "cd /usr/share/SNR-test ; dlp_nirscan -A51 -Z1723 -N200 ; cd patterns ; dlp_nirscan -Pscan.sdf ; dlp_nirscan -l9 ; cd .. ; dlp_nirscan -S200 -E1400 -fcalib_scan.txt -L5 ; ls", 1);
    remote_command(my_ssh_session, "cd /usr/share/SNR-test ; dlp_nirscan -S200 -E1400 -fcalib_scan.txt -L5", 1);

    scp_read_calib(my_ssh_session);
    /* HOW TO COPY MANUALLY FROM TERMINAL
    sudo scp -r 192.168.0.10:/usr/share/SNR-test /home/justin/Documents/c\ code
    */
    
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
}

int run_reflectance_scan(char* ssh_login) {
  ssh_session my_ssh_session;
    int verbosity = SSH_LOG_PROTOCOL;
    int rc;    
    char *password;

    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ssh_login);
    //ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, SSH_LOG_NOLOG);

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n", 
                ssh_get_error(my_ssh_session));
        exit(-1);
    }
 
    // Verify the server's identity
    if (verify_knownhost(my_ssh_session) < 0) {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }       
    
    // Authenticate ourselves
    //password = getpass("Password: ");
    password = "";
    rc = ssh_userauth_password(my_ssh_session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
   
    // **delete SNR-test directory (not needed in some cases) 
    //remote_command(my_ssh_session, "rm -r /usr/share/SNR-test",0);    
    // **create SNR-test directory in /usr/share
    //create_directory(my_ssh_session, "/usr/share/SNR-test");
    // **create patterns directory in /usr/share/SNR-test
    //create_directory(my_ssh_session, "/usr/share/SNR-test/patterns");
    // Calibration Scan command list 
    //remote_command(my_ssh_session, "cd /usr/share/SNR-test ; dlp_nirscan -A51 -Z1723 -N200 ; cd patterns ; dlp_nirscan -Pscan.sdf ; dlp_nirscan -l9 ; cd .. ; dlp_nirscan -S200 -E1400 -fcalib_scan.txt -L5 ; ls", 1);
    remote_command(my_ssh_session, "cd /usr/share/SNR-test ; dlp_nirscan -S200 -E1400 -fsample_scan.txt -L5", 1);

    scp_read_refl(my_ssh_session);
    /* HOW TO COPY MANUALLY FROM TERMINAL
    sudo scp -r 192.168.0.10:/usr/share/SNR-test /home/justin/Documents/c\ code
    */
    
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
}
