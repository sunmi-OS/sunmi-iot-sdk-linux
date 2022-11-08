# sunmi-iot-sdk-linux
## IoT SDK架构介绍
IoT SDK架构设计说明：https://developer.sunmi.com/docs/zh-CN/crxfqeghjk513/zzmeghjk546

## 编译环境
### 开发环境要求
编译主机建议使用Ubuntu 16.04、18.04或20.04版本，并安装automake、libtool、cmake、sed等工具。
可执行以下命令安装相关工具：
```
sudo apt install automake libtool cmake sed
```
### 交叉工具链配置
修改根目录下的config.mk文件，设置TOOLCHAIN_PATH为你所使用的交叉工具链路径，设置CROSS_COMPILE_PRIFIX为你所使用的交叉工具链前缀。
```
#交叉工具链路径
TOOLCHAIN_PATH := ../../mips-gcc472-glibc216/bin

#交叉工具链前缀
CROSS_COMPILE_PRIFIX := mips-linux-gnu-
```
## 编译命令
1. make  
完整编译SDK。编译最终产物位于output目录。  

2. make clean  
清除SDK编译中间文件和最终产物。  

3. make package_name  
其中package_name为单个软件包名称，如make demo_adapter可增量编译demo_adapter这个软件包，不需要重复编译整个工程。各软件包存在依赖，需要先进行一次完整编译，再进行增量编译调试。  

# Linux IoT SDK编译
## IoT SDK
### 目录说明
build_dir：临时编译目录，package中的源码会拷贝到该目录进行编译；  
output：编译产物目录，该目录下有bin和lib两个子目录，分别放置应用程序和运行时需要的动态库文件；  
package：软件包源码目录；  
staging_dir：临时目录，用于编译头文件引用和库链接。  

### 编译产物说明  
bin目录存放应用程序。  
（1）demo_adapter：adapter示例程序，注册adapter服务和处理业务消息；  
（2）mqtt_client：用于连接mqtt云服务器；  
（3）thing_service：管理thing_adapter组件，负责云端消息分发；  
（4）ubus：调试命令工具；  
（5）ubusd：进程间通讯服务。  

lib目录存放程序运行所需要的动态库。  
output目录下的应用程序和动态库文件都需要拷贝到目标开发板上。  

## 运行SDK服务
运行程序
将所有目标应用程序和动态库拷贝到开发板上后，顺序执行以下服务：
```
ubusd &
mqtt_client &
thing_service &
demo_adapter &
```
其中ubusd、mqtt_client和thing_service进程是基础服务进程，adapter进程是用户开发的业务adapter进程。
