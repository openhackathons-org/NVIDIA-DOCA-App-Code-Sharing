<!Event Name>
# 基于DPU的统一存储管理系统

<!Event Introduction>
## 项目说明

> 在数据中心等场景下，存储资源的虚拟化使得本地存储设备不再是必需品。在云厂商的实际部署实践中远端存储资源从本地存储的补充逐渐转变为主导。云数据中心重视成本，高效的存储资源利用、灵活的部署，使得单位存储能力设备成本和运营成本双双降低。

> NVIDIA BuleField SNAP 是一种存储虚拟化技术。 BuleField SNAP 可以虚拟出本地NVMe SSD 驱动器，通过网络连接到后端存储系统，实际的数据落盘在后端存储集群中。 主机操作系统通过标准存储驱动程序使用存储设备，不需要关心使用的是真实的物理存储设备，还是使用 NVMe SNAP 框架模拟的存储设备。SNAP 框架会将所有的I/O请求或者数据通过网络发送到后端的存储系统。

> 相比于传统的在主机操作系统部署存储客户端的方式接入远端存储资源，使用 BuleField SNAP 接入远端存储资源可以有效的节省主机的cpu资源，卸载主机对网络的操作，同时提高部署的灵活性。

> 本项目旨在构建一套存储管理系统，对网络中的bulefield3 DPU、安装DPU的主机和存储集群进行统一管理。利用bulefield3 DPU中的SNAP为主机模拟nvme存储设备，使用SNAP 的 rbd 接口对接ceph集群。


##  项目规划内容：
> 1，实现在DPU上自动部署snap应用。
> 2，在DPU 上部署一个代理程序，通过rpc接口对snap 应用解析配置。同时通过代理程序采集DPU状态并上报到管理节点。代理程序和管理节点采用tcp socket 进行通讯，通讯消息采用json格式。
> 3，在ceph管理节点部署代理程序，通过命令行操作ceph集群。代理程序和管理节点采用tcp socket 进行通讯，通讯消息采用json格式。
> 4，在一台独立的设备上部署存储管理系统，通过tcp socket 管理DPU。同时展示从DPU上采集到的设备状态。


  