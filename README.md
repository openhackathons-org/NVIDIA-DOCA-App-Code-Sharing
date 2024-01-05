<!Event Name>
# NVIDIA DOCA - Dquant

<!Event Introduction>
## 背景

大规模机器学习系统采用 4D parallel，通常瓶颈在节点间通讯。 由于节点间带宽限制，Tensor Parallel \(TP\) 通常被限制在一个 8 卡节点（Node）内。

8-ranks 卡间通讯依赖 Infiniband (IB) 高速互联，但是 Node 之间仍然需要走以太网。对于训练来说，由于普遍的数据中心架构采用分布式文件系统 + 虚机，实际上导致整个数据集文件的处理吞吐，受限于网卡。

GPU/IPU 等高性能计算设备将计算 offload 到这些协处理器成为数据中心的支柱，而支持 RoCE 的网卡成为数据中心大规模并行 HPC 突破性能上限解决方案的另一个底层支柱。

对于分布式文件系统，由于磁盘读写 IO (fio) 实际上走网卡，这一点可以通过 sar 命令和 iotop 来交叉验证，这意味着数据网卡传输期间就可以做一些处理：

> 对于机器学习中文数据集大概有 500 GB 数据按 INT32 在分布式文件系统存储，不考虑本地磁盘缓存，一般离线处理程序涉及多个数据集的配比，转化，通常会在数据发包（此时磁盘读写实际首先网络）通过PCIe读入到内存后, 在 CPU cache 创建cache line（64B），并读入CPU进行处理，并再次通过 PCIe 写回 CPU 内存。

对于一款可编程的网卡 [**NVIDIA BlueField DPU**](https://www.nvidia.cn/networking/products/data-processing-unit/) ，一种可能是在网卡内做一些处理，这样数据流通的负载可以有效降低：相关需要处理的数据，可以 绕过 CPU，不再走 PCIe 进驻 CPU 内存，直接和目标协处理器设备通信。

如果这种处理能力 [**NVIDIA® DOCA™ 软件框架**](https://developer.nvidia.cn/zh-cn/networking/doca) 逐渐变多、变强，就可以形成在 DPU 上的一个 preprocess_pipeline，数据通过 DMA 直接和目标设备通信，无需再走两遍 PCIe 的数据路径。这种处理方式绕过CPU (by-pass CPU), 可以比较高效的利用 DMA 能力。

## Background

Large scale machine learning system employ 4D parallel，is bounded by inter-node communication bandwidth. TP parallel is limited to a single node of 8 cards due to this limitatin .

8-ranks inter-card communication bandwidth can be accelerated by Infiniband high speed network, however inter-node communication still go though eithernet. When we talk about trainning, since they typically employ distributed file system and virtual machines, the whole filesystem is bouned by net-card.

RoCE plays an important role in the future solution of by-pass CPU in the large scale distributed network, while GPU/IPU plays another great role in computation offloading.

We can verify that in a distributed file system that IO operations (fio) go through net cards instead of local disk IO via sar and iotop commands. This means we can do something during transportion period of data : 

> For a more than 500 GB dataset stored in a distritued filesystem, if they are store in INT32 format, and we don't consider caching of local disk system, some offline operations such as dataset blending, transformation, can be done after they are sent to  CPU as packets and go though PCIe to CPU nearest memory for further processing by reloading from CPU nearest memory by walking though PCIe again.

Hence for a progrmmable network card [**NVIDIA BlueField DPU**](https://www.nvidia.cn/networking/products/data-processing-unit/), one of many possiblities is such pending preprocess pipeline can be done inside network card to PCIe travels, such that data can be sent to target devices via DMA directly. Such by-pass CPU can make high utilizaiton of DMA ability.


<!Pull Requests>
## 开发环境

- 硬件环境：NVIDIA BlueField-2 DPU 或 NVIDIA BlueField-3 DPU
- 软件环境：NVIDIA DOCA 1.5.1 及以上版本
- 开发级别：采用更高级别抽象的 DOCA 库，如 DOCA Flow

赞助：

- 丽台（上海）信息科技有限公司 doca@leadtek.com
- 上海信泓智能科技有限公司 doca@zentek.com.cn

## 安装

TBD

## 应用测试和案例

TBD
