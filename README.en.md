# Delphi&FPC Cross Platform Zip Compress&Decompress Library

Author: WiNDDRiVER(soulawing@gmail.com)

### [中文](README.md)

<br>

This library refers to CnZip.pas in the [CnVcl](https://github.com/cnpack/cnvcl) component library, and System.zip.pas in Delphi RTL
And references some units in the component library [CnCrypto](https://gitee.com/cnpack/cncrypto)
Thanks to [CnPack](https://www.cnpack.org/) for the organization's contribution to the open source community



## Features

- Support delphi + fpc, cross-platform
- Support aes
- Support zip64
- Dynamic encryption/decryption, only requires a small amount of memory to process large files, without redundant memory copying, greatly improving performance
- Crc32 calculation while reading data, greatly improving performance



## Insufficient

- Although the speed is much faster than the built-in System.Zip and AbZip of Delphi, it is still a big gap in speed compared to mature compression and decompression software, such as WinRAR / 7Zip, etc. I hope more experts will participate in the improvement together.



## Update list

#### 2025.08.08
- First Submit