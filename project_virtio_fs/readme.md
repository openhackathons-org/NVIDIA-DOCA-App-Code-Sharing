This is a project about combine JuiceFS to BuleField2 or BlueField3 DPU, for host to use remote object storage like ceph or others.It is need BF card's snap function to emeluate virtio-fs device which is not export yet. Maybe in doca3 or newer snap version will offer it. And it is also need DPFS to connect juiceFS through a NFS interface. For more detail about DPFS, please visit https://github.com/IBM/DPFS. For JuiceFS, You can got it from https://juicefs.com. It is a system like this:

![image](https://github.com/gongcheng9/NVIDIA-DOCA-App-Code-Sharing/assets/153048235/16f28e5a-0bb4-4a6d-aba8-2035f51a2b0c)

There are two important point to finish this job:
DPFS: It connect JuiceFS with DPFS-NFS-Client to offer backend of object storage like ceph or others. It is a importand fuction of DPFS.
Virtio-FS: It is in SNAP fuction of Bluefield2 or Bluefield3, but not expose yet. It connect host or VMs's FUSE and DPU through a hardware of PCIe. 
Here is the architecture of DPFS compared to a host NFS client from <<DPFS: DPU-Powered File System Virtualization>> on https://github.com/IBM/DPFS.

![image](https://github.com/gongcheng9/NVIDIA-DOCA-App-Code-Sharing/assets/153048235/43dec295-22cf-40b2-9b12-00833d787c77)

In this project, Host or VMs can use share POSIX file system through BlueField with no DFS client. It just like local vfs. with users don't need manager this storage on host, BlueFlied can handle all of these complex things, and save the cpus for important applications on host or VMs. It is also perform much better than traditional way.
AI is the most important application in data center now, and for model,samples and checkpoints in AI train fuctions, These data must be sharing for many hosts or GPUs cards. The nvme or virtio-block emulate in DOCA and SNAP can not handle the sharing needs. So this project will be an especial way to offer the file system for nvidia GPUs to run AI applications, and we will pay an insistent working emotion on this job.
