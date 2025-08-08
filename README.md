# Delphi&FPC 跨平台 Zip 压缩解压缩库

作者: WiNDDRiVER(soulawing@gmail.com)

### [English](README.en.md)

<br>

这个库参考了 [CnVcl](https://github.com/cnpack/cnvcl) 组件库中的 CnZip.pas, 以及 Delphi RTL 中的 System.zip.pas
并引用了部分 [CnCrypto](https://gitee.com/cnpack/cncrypto) 组件库中的单元

感谢 [CnPack](https://www.cnpack.org/) 组织对开源社区的贡献



## 主要特性

- 支持 delphi + fpc, 跨平台
- 支持 aes
- 支持 zip64
- 动态加密/解密, 处理超大文件也只需要很小的内存, 没有多余的内存复制, 极大提升性能
- 读取数据的同时进行 crc32 计算, 极大提升性能



## 不足

- 虽然与Delphi内置的System.Zip以及AbZip相比速度已经快了非常多,  但是与成熟的压缩解压缩软件相比速度还有较大差距, 比如 WinRAR / 7Zip 等, 希望有更多高手参与进来共同改进



## 更新记录

#### 2025.08.08
- 首次提交