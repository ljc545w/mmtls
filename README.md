### Description
参考[gommtls](https://github.com/duo/gommtls)实现的C++版本微信mmtls握手协议。  
支持Linux和Windows，在**AMD64**架构下编译通过，x86和ARM未做测试。

### Build
#### Windows
在开始构建之前，需要安装OpenSSL 1.1.x版本，然后使用**Visual Studio**进行构建，注意修改**包含目录**和**库目录**。  
#### Linux
使用cmake进行构建：
```shell
cd linux
mkdir build
cd bulid
cmake ..
make
```
### Disclaimer
代码仅作学习交流使用，请勿用于非法用途。