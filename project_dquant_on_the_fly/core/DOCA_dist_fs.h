#pragma once

#include <string>

namespace doca_dist_fs {
    int open(const std::string &filename, dist_fs_rpc action = {}, bool dpu_offload = false) {
        return DOCA_dist_fs_open(filename, action, dpu_offload);
    }

    int close(int fd, bool dpu_offload = false) {
        return DOCA_dist_fs_close(fd, dpu_offload);
    }
} // namespace doca_dist_fs

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

// TODO (yiakwy) : impl read, write, seek, open_async, close_async, read_async, write_async, seek_async...

#ifdef __cplusplus
}
#endif