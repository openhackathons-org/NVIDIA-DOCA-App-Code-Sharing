# TC-htb-dpu

作者：胡凌翔

GitHub ID：CHRIS123540

doca 版本: 1.4.0079

source code FINAL_l2fwd/l2fwd.c

前期工作：[链接至文章](https://juejin.cn/post/7158639124994326541)

## 简介

Linux流量控制（Traffic Control, TC）是一个强大的工具，用于控制和管理Linux内核中的网络流量。它提供了一套丰富的功能来分类、排队和安排网络数据包，从而使网络管理员能够控制网络服务的质量（QoS）。TC的核心组件包括分类器（classifiers）、行为（actions）、策略（policies）和qdiscs（排队规则）。

在现代网络环境中，数据传输量和速度都在不断增加，尤其是在数据中心和大规模网络基础设施中。在这些情景下，Linux的流量控制（TC）功能是关键组件，用于确保网络质量和性能。然而，随着数据流量的增加，TC在处理大量网络流量时可能面临一些挑战：

- **处理能力：** 随着网络流量的增加，传统的TC可能会遇到处理能力的瓶颈，尤其是在高峰时期。
- **CPU资源消耗：** TC的运算通常由主机的CPU执行，处理大量的网络流量可能会消耗大量的CPU资源，从而影响其他应用程序的性能。
- **延迟和吞吐量：** 在高负载条件下，传统的TC可能无法保证低延迟和高吞吐量，尤其是对于实时性要求较高的应用程序。

随着数据处理单元（DPU, Data Processing Unit）的出现，这一现状得到了改变。DPU通常包括ARM核心和网络硬件加速器，以及可编程的网络交换芯片（例如eSwitch）。通过这些硬件和软件资源，我们可以将TC的功能卸载到DPU上，实现以下好处：

- **处理能力提升：** 利用DPU的硬件加速和高效的ARM核心，可以显著提高TC的处理能力，以应对大量的网络流量。
- **减轻主机CPU负担：** 通过卸载TC功能到DPU，可以减轻主机CPU的负担，释放CPU资源用于其他应用程序。
- **延迟和吞吐量优化：** 借助DPU的硬件加速功能，可以实现低延迟和高吞吐量的流量控制，提高网络的服务质量（QoS）。
- **灵活部署和扩展：** 利用ARM的计算能力，可以根据需要实现调度算法。

本应用基于多叉树结构，利用加权轮询算法，通过将TC htb卸载到DPU上，这样我们不仅可以改善网络的性能和服务质量，还可以为未来网络流量的增长和新应用的部署提供可扩展和灵活的解决方案。该项目提供一个小型的框架。

该应用以主机上有3个class为例，3个class共享65Gbps的链路带宽，3者之间需要满足不同的优先级、带宽限制以及层次结构。为了演示效果，该应用展示了3个class的公平队列。测试结果如图。

## 使用方法

以下是应用的使用方法（只在doca1.4下测试过），具体运行代码如下：

**主机部分：**

```bash
# 创建2个vf，模拟服务器承载的虚拟化业务
echo 0 > /sys/class/net/enp1s0f1np1/device/sriov_numvfs
echo 4 > /sys/class/net/enp1s0f1np1/device/sriov_numvfs
ifconfig enp1s0f1np1 192.168.201.1 up
ifconfig enp1s0f1v0 192.168.201.3 up
ifconfig enp1s0f1v1 192.168.201.5 up
```
**DPU部分：**
```bash
# 删除DPU上所有的sf，此处设备号需要手动查询删除，以下是我环境中的例子。
/opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.1/294944 state inactive
/opt/mellanox/iproute2/sbin/mlxdevm port show
/opt/mellanox/iproute2/sbin/mlxdevm port del pci/0000:03:00.1/294944

cd FINAL_l2fwd
./A201
```

# TC-HTB-DPU

**Author**: Lingxiang Hu

**GitHub ID**: CHRIS123540

**Doca Version**: 1.4.0079

**Preliminary Work**: [Link to the article](https://juejin.cn/post/7158639124994326541)

## Introduction

Linux Traffic Control (TC) is a powerful tool for controlling and managing network traffic within the Linux kernel. It offers an extensive set of features for classifying, queuing, and scheduling network packets, enabling network administrators to maintain quality of service (QoS). Key components of TC include classifiers, actions, policies, and qdiscs (queuing disciplines).

In today's network landscape, both data volumes and speeds are ever-increasing, particularly in data centers and large-scale network infrastructures. In these scenarios, Linux TC functions play a pivotal role in ensuring network quality and performance. However, with the surge in data traffic, traditional TC may face challenges in handling massive network flows:

- **Processing Capacity:** With the growth in network traffic, traditional TC may encounter bottlenecks, especially during peak periods.
- **CPU Resource Consumption:** TC computations are typically performed by the host's CPU. Processing vast amounts of network traffic can consume significant CPU resources, impacting the performance of other applications.
- **Latency and Throughput:** Under high-load conditions, traditional TC might not guarantee low latency and high throughput, particularly for applications with high real-time requirements.

With the advent of the Data Processing Unit (DPU), this paradigm is shifting. A DPU typically incorporates ARM cores and network hardware accelerators, as well as programmable network switch chips (like eSwitch). By leveraging these hardware and software assets, we can offload TC functionalities onto the DPU, achieving the following benefits:

- **Enhanced Processing Capacity:** Using the DPU's hardware acceleration and efficient ARM cores, TC processing capacity can be substantially improved to handle massive network flows.
- **Reduced CPU Load on the Host:** By offloading TC functionalities to the DPU, the load on the host's CPU can be minimized, freeing up CPU resources for other applications.
- **Optimized Latency and Throughput:** With the DPU's hardware acceleration, low latency and high throughput traffic control can be realized, enhancing network QoS.
- **Flexible Deployment and Scalability:** Leveraging ARM computational capabilities, scheduling algorithms can be implemented as needed.

This application is based on a multi-branch tree structure, employing a weighted round-robin algorithm. By offloading TC htb onto the DPU, not only can we enhance network performance and QoS but also offer a scalable and flexible solution for the anticipated growth in network traffic and deployment of new applications. This project offers a compact framework.

For demonstration purposes, the application assumes three classes on the host, sharing a 65Gbps link bandwidth. These three classes need to satisfy different priorities, bandwidth limits, and hierarchical structures. To showcase the capabilities, this application presents a fair queue of these three classes. Test results are illustrated in the included graph.

## Usage

Here's how to use the application (tested only with doca 1.4), with the specific run code detailed below:

### Host Part:

```bash
# Create 2 VFs to simulate the virtualized business the server carries
echo 0 > /sys/class/net/enp1s0f1np1/device/sriov_numvfs
echo 4 > /sys/class/net/enp1s0f1np1/device/sriov_numvfs
ifconfig enp1s0f1np1 192.168.201.1 up
ifconfig enp1s0f1v0 192.168.201.3 up
ifconfig enp1s0f1v1 192.168.201.5 up
```
### DPU Part:

```bash
# Delete all sfs on the DPU, the device number here needs to be manually queried and deleted, the following is an example in my environment.
/opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.1/294944 state inactive
/opt/mellanox/iproute2/sbin/mlxdevm port show
/opt/mellanox/iproute2/sbin/mlxdevm port del pci/0000:03:00.1/294944

cd FINAL_l2fwd
./A201
```



运行仪表盘如下图所示

The operation of the dashboard is as shown in the following image.

![image](https://github.com/CHRIS123540/TC-htb-dpu/assets/64949823/b367a45e-f21c-473d-aed4-386c1a8cc108)



利用iperf对3个class进行测试，画图所示，可以看出对流量控制效果较好

By testing the three classes using iperf, as illustrated in the graph, it can be observed that the traffic control effect is quite satisfactory.

![image](https://github.com/CHRIS123540/TC-htb-dpu/assets/64949823/1fbec7b6-5bf8-4ad0-a40e-df1763c1936b)



