#pragma once

#include <string>

#ifdef __cplusplus
extern "C"
{
#endif

struct dist_fs_rpc {
    std::string method_name;
};

/**
 * Open a file in distributed file system and return file descriptor
*/
int DOCA_dist_fs_open(const std::string &filename, dist_fs_rpc action = {}, bool dpu_offload = false);

/**
 * Close the distributed file descriptor
*/
int DOCA_dist_fs_close(int fd, bool dpu_offload = false);

// TODO (yiakwy) : read, write, seek, ...

#ifdef __cplusplus
}
#endif