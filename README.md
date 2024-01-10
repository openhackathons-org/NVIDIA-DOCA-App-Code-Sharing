

## HOST memory access framework
### Introduction
* HMAF: An efficient memory management and automatic memory registration framework designed specifically for DPUs, supporting access to HOST host process memory. This framework intelligently manages and maps memory resources. Communication is facilitated through the use of the Common Channel and doca_dma, where the common channel is responsible for initializing the communication channel of doca_dma during the initialization phase. doca_dma serves as the primary means for memory access and communication in this framework, achieving performance close to the theoretical limits of DMA communication.

### File Structure
* comm_chann: This folder contains the code used to construct the DMA communication channel during framework initialization, only utilized in the initialization phase.

* include: This directory stores SDK header files, providing interface definitions for the framework's functionality.

* memory: Includes encapsulation files for DMA operations and communication, providing convenient interfaces for implementing memory operations.

* proxy_func: This folder encapsulates address mapping and memory access models, offering developers a direct interface for SDK development.



## HOST memory access framework

### Introduction

* HMAF: 一款高效的内存管理和自动内存注册框架，专为 DPU 设计，支持对 HOST 主机进程内存的自动访问。该框架能够智能地管理和映射内存资源。通过使用 Common Channel 和 doca_dma 进行通信，其中 common channel 在初始化阶段负责对 doca dma 通信信道进行初始化。doca dma 在此框架中充当主要的内存访问和通信手段，其性能可达到 DMA 通信的理论极限。

### File strcution

* comm_chann : 该文件夹包含了框架初始化时用于构建 DMA 通信信道的代码，仅在初始化阶段使用。
* include : 存放 SDK 的头文件，提供对框架功能的接口定义。
* memory : 包含进行 DMA 操作和 DMA 通信的封装文件，为实现内存操作提供了便捷的接口。
* proxy_func : 该文件夹封装了地址映射和访存模型，提供了对 SDK 的开发接口，开发者可以直接调用的实现。

