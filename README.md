## HOST Memory Access Framework (HMAF)

### Introduction
* HMAF: An efficient framework for DPU accessing Host memory, specifically designed for DPUs, support that DPU's process directly access remote memory in HOST host processes. It enables automatic remote memory registration and management including remote memory map. Transparent to upper-layer developers, allowing developers to read and write Host memory on DPU just like on the Host. The framework intelligently manages and maps memory resources. It utilizes DOCA Comm Channel and DOCA DMA, where DOCA Comm Channel is only used during initialization to construct the initial communication channel for DOCA DMA. Subsequently, DOCA DMA is used for communication and memory operations, with performance metrics matching performance of DOCA DMA, introducing minuscule additional overhead.
* Usage Scenario: Ideal for scenarios where some of services within the same process are offloaded from the HOST to the DPU. This framework is responsible for remote memory access in DPU.

### File Structure
* include: Stores SDK header files, providing interface definitions for the framework's functionality.

* comm_chann: This folder contains encapsulated code for DOCA Comm Channel, used during initialization to construct the DOCA DMA communication channel, only uses it in the initialization phase.

* memory: Includes encapsulation files for DMA operations and DOCA DMA communication, encapsulating the implementation of DOCA DMA.

* proxy_func: This folder encapsulates memory management and memory mapping management, providing implementations of SDK interfaces that developers can directly invoke.



## HOST Memory Access Framework (HMAF)

### Introduction

* 一款高效的 DPU 访问 Host 内存框架，专为 DPU 设计，支持 DPU 对 HOST 主机进程内存的自动访问。支持内存自动注册以及内存自动管理。对上层开发者透明，开发者可以像在 Host 一样在  DPU 上对 Host 内存进行读写操作。该框架能够智能地管理和映射内存资源。它使用了 DOCA Comm Channel 和 DOCA DMA，其中 DOCA Comm Channel 仅在初始化阶段使用，通过它构建 DOCA DMA 的初始通信信道，此后就一直使用 DOCA DMA 进行通信以及操作内存，其性能指标完成与 DOCA DMA 的性能相同，几乎没有引入额外的开销。
* 使用场景：可以使用在 HOST 卸载同进程的服务到 DPU 上时，本框架可以负责内存的同步工作。

### File strcution

* include : 存放 SDK 的头文件，提供对框架功能的接口定义。
* comm_chann : 该文件夹包含了 DOCA Comm Channel 的封装代码，在初始化时用于构建 DOCA DMA 通信信道，仅在初始化阶段使用。
* memory : 包含进行 DMA 操作和 DOCA DMA 通信的封装文件，对DOCA DMA 实现的封装。
* proxy_func : 该文件夹封装了内存管理以及内存映射管理，提供了对 SDK 的开发调用接口的实现，开发者可以直接调用的实现。

