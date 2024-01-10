这是一个将 JuiceFS 与 BuleField2/BlueField3 DPU结合的工程，能够将远端的共享POSIX存储服务（存储后端采用ceph等对象存储）像本地磁盘一样挂载到主机或虚拟机上，用户在使用这些磁盘的时候不会觉察到使用的是远端的存储。这需要BuleField的SNAP服务中的virtio-fs模拟功能（该功能暂未释出，英伟达在未来的DOCA3和更新的SNAP版本服务中也许会释放）。与此同时，我们还需要 DPFS通过NFS接口连接开源的JuiceFS文件系统。有关DPFS的更多详细信息，请访问https://github.com/IBM/DPFS。关于JuiceFS，你可以从 https://juicefs.com 获取。整套系统大概是下面这个样子：

![image](https://github.com/gongcheng9/NVIDIA-DOCA-App-Code-Sharing/assets/153048235/16f28e5a-0bb4-4a6d-aba8-2035f51a2b0c)

完成这项工作有两个重点：
第一是DPFS：它将 JuiceFS与DPFS-NFS-Client连接起来，为用户提供ceph等对象存储的后端服务，它也同样是DPFS的重要功能。
另一个则是virtio-fs：这个模块处于 Bluefield2 或 Bluefield3 的 SNAP 功能中，目前暂未开放。它通过硬件的PCIe接口将主机或VM的FUSE与DPU进行连接。
以下是https://github.com/IBM/DPFS中<<DPFS：DPU 驱动的文件系统虚拟化>>上关于主机NFS客户端与DPU上的NFS客户端的比较。

![image](https://github.com/gongcheng9/NVIDIA-DOCA-App-Code-Sharing/assets/153048235/43dec295-22cf-40b2-9b12-00833d787c77)

在这个项目中，主机或虚拟机可以通过BlueField使用共享的POSIX文件系统，并不需要部署和管理DFS客户端，就像本地使用vfs 一样。BlueFlied处理了和存储相关的复杂工作，用户不再需要在主机上管理和维护复杂的存储工作，同时还为主机或虚拟机上的重要应用程序节省 了CPU等资源。它的性能也比host上部署nfs客户端的传统方式好高得多。

鉴于AI是目前数据中心最重要的应用，对于AI训练功能中的模型、样本和checkpoints等，这类“大数据”必须共享给许多主机或GPU卡。DOCA和SNAP目前提供的nvme或 virtio-block的存储模拟方案无法满足大数据数据共享的需求。本项目采用的特殊的工作方式，能够为nvidia GPUs提供支持POSIX语义的共享文件系统，在目前AI的大环境下显得尤为重要，我们将会持续的投入到在这项工作中。



This is a project about combine JuiceFS to BuleField2 or BlueField3 DPU, for host to use remote object storage like ceph or others.It is need BF card's snap function to emeluate virtio-fs device which is not export yet. Maybe in doca3 or newer snap version will offer it. And it is also need DPFS to connect juiceFS through a NFS interface. For more detail about DPFS, please visit https://github.com/IBM/DPFS. For JuiceFS, You can got it from https://juicefs.com. It is a system like this:

![image](https://github.com/gongcheng9/NVIDIA-DOCA-App-Code-Sharing/assets/153048235/16f28e5a-0bb4-4a6d-aba8-2035f51a2b0c)

There are two important point to finish this job:
DPFS: It connect JuiceFS with DPFS-NFS-Client to offer backend of object storage like ceph or others. It is a importand fuction of DPFS.
Virtio-FS: It is in SNAP fuction of Bluefield2 or Bluefield3, but not expose yet. It connect host or VMs's FUSE and DPU through a hardware of PCIe. 
Here is the architecture of DPFS compared to a host NFS client from <<DPFS: DPU-Powered File System Virtualization>> on https://github.com/IBM/DPFS.

![image](https://github.com/gongcheng9/NVIDIA-DOCA-App-Code-Sharing/assets/153048235/43dec295-22cf-40b2-9b12-00833d787c77)

In this project, Host or VMs can use share POSIX file system through BlueField with no DFS client. It just like local vfs. with users don't need manager this storage on host, BlueFlied can handle all of these complex things, and save the cpus for important applications on host or VMs. It is also perform much better than traditional way.
AI is the most important application in data center now, and for model,samples and checkpoints in AI train fuctions, These data must be sharing for many hosts or GPUs cards. The nvme or virtio-block emulate in DOCA and SNAP can not handle the sharing needs. So this project will be an especial way to offer the file system for nvidia GPUs to run AI applications, and we will pay an insistent working emotion on this job.
