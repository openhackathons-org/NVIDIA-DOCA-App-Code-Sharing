<!Event Name>
# Unified storage management system based on DPU


<!Event Introduction>
## project description

> In scenarios such as data centers, local storage devices are no longer necessary due to virtualization of storage resources. In the actual deployment practice of cloud vendors, remote storage resources have gradually changed from supplementing local storage resources to dominating them. Cloud data centers pay attention to costs, efficient utilization of storage resources, and flexible deployment, reducing both device costs and operating costs per unit of storage capacity.

> NVIDIA BuleField SNAP is a storage virtualization technology. BuleField SNAP can virtualize a local NVMe SSD drive and connect it to the back-end storage system over a network. The actual data is dumped into the back-end storage cluster. The host operating system uses storage devices through standard storage drivers, and does not need to care whether it is using a real physical storage device or a storage device emitated using the NVMe SNAP framework. The SNAP framework sends all I/O requests or data over the network to the back-end storage system.

> Compared with the traditional method of connecting remote storage resources by deploying storage clients on the host operating system, BuleField SNAP can effectively save host cpu resources, uninstall host operations on the network, and improve deployment flexibility.

> The purpose of this project is to build a storage management system to manage the bulefield3 DPU in the network, the host where the DPU is installed, and the storage cluster in a unified way. SNAP in the bulefield3 DPU is used to simulate nvme storage devices for the host, and SNAP uses rbd interfaces to interconnect with the ceph cluster.


##  Project planning content

> 1. Automatically deploy snap applications on the DPU.

> 2. Deploy a proxy program on the DPU to parse snap configurations through the rpc interface. The DPU status is collected through the agent program and reported to the management node. The agent and the management node communicate using tcp sockets, and the communication messages are in json format.

> 3. Deploy an agent on the ceph management node to operate the ceph cluster from the command line. The agent and the management node communicate using tcp sockets, and the communication messages are in json format.

> 4. The storage management system is deployed on an independent device and the DPU is managed using tcp sockets. The device status collected from the DPU is also displayed.


  
