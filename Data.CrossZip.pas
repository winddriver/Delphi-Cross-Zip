{******************************************************************************}
{                                                                              }
{       Delphi&FPC cross platform zip library                                  }
{                                                                              }
{       Copyright (c) 2025 WiNDDRiVER(soulawing@gmail.com)                     }
{                                                                              }
{       Homepage: https://github.com/winddriver/Delphi-Cross-Zip               }
{                                                                              }
{******************************************************************************}
unit Data.CrossZip;

{$I zLib.inc}

//{$IFDEF FPC}
//  {$MODE DELPHI}
//  {$MODESWITCH UNICODESTRINGS}
//{$ENDIF}

{$DEFINE SUPPORT_ZLIB_WINDOWBITS}

// 密钥相关计算需要设置这两个编译开关, 否则会出现越界异常
{$R-}
{$Q-}

{$IFNDEF SUPPORT_ZLIB_WINDOWBITS}
// {$MESSAGE WARN 'NOT Compatable with WinZip/WinRAR etc.'}
{$ENDIF}

// 这个库参考了 CnVcl 组件库中的 CnZip.pas, 以及 Delphi RTL 中的 System.zip.pas
//
// 主要特性:
//  1. 支持 delphi + fpc, 跨平台
//  2. 支持 aes
//  3. 支持 zip64
//  4. 动态加密/解密, 处理超大文件也只需要很小的内存, 没有多余的内存复制, 极大提升性能
//  5. 读取数据的同时进行 crc32 计算, 极大提升性能

interface

uses
  SysUtils,
  Classes,
  Math,
  Generics.Collections,
  DateUtils,
  //ZLib,
  {$IFDEF DELPHI}
  ZLib,
  {$ELSE}
  DTF.StaticZLib,
  {$ENDIF}

  CnAES,
  CnNative,

  Utils.Hash,
  Utils.PBKDF2,
  Utils.AES.CTR,
  Utils.CryptRandom,
  Utils.DateTime;

const
  SIZE_LOCAL_HEADER    = 26; // 本地文件头大小
  SIZE_CENTRAL_HEADER  = 42; // 中心目录文件头大小
  SIZE_END_HEADER      = 18; // 结束文件头大小
  SIZE_ZIP_CRYPT_HEAD  = 12; // 加密头大小

  // 通用标志位(TZipHeader.Flag)
  FLAG_PASSWORD        = $0001;  // 加密
  FLAG_DATA_DESCRIPTOR = $0008;  // 1 shl 3  使用数据描述符
  FLAG_UTF8            = $0800;  // 1 shl 11 文件名使用 UTF-8 编码

  EXID_ZIP64           = $0001; // ZIP64 扩展字段标志
  EXID_NTFS            = $000A; // NTFS 扩展时间戳字段标志
  EXID_UNIX            = $000D; // Unix 扩展字段标志
  EXID_TIMESTAMP       = $5455; // 扩展时间戳字段标志 (Extended Timestamp)
  EXID_UNICODE_COMMENT = $6375; // Info-ZIP Unicode 注释扩展字段
  EXID_UNICODE_PATH    = $7075; // Info-ZIP Unicode 路径扩展字段
  EXID_AES             = $9901; // AES 扩展字段标志
  PBKDF2_ITERATIONS    = 1000;  // WinZip AES 标准固定 1000 次迭代（PKWARE AES 规范）
  
  // Unix 时间戳基准时间 (1970-01-01 00:00:00)
  UnixDateDelta        = 25569;  // Days between 1899-12-30 and 1970-01-01

  MAX_UINT16           = High(UInt16);
  MAX_UINT32           = High(UInt32);
  MAX_COMMENT_SIZE     = $FFFF;        // 最大注释大小

  BUF_SIZE = 64 * 1024; // 缓存大小

type
  /// <summary>
  ///   Zip 相关异常
  /// </summary>
  EZipException = class(Exception);

  /// <summary>
  ///   Zip 压缩方法编号. 普通条目表示真实压缩方法; WinZip AES 条目使用 99 作为 AES 标记,
  ///   真实压缩方法保存在 AES 扩展字段中
  /// </summary>
  TZipCompressionMethod = (
    zcStored = 0,
    zcShrunk,
    zcReduce1,
    zcReduce2,
    zcReduce3,
    zcReduce4,
    zcImplode,
    zcTokenize,
    zcDeflate,
    zcDeflate64,
    zcPKImplode,
    zcReserved11,
    zcBZIP2,
    zcReserved13,
    zcLZMA,
    zcReserved15,
    zcReserved16,
    zcReserved17,
    zcTERSE,
    zcLZ77,
    zcWavePack = 97,
    zcPPMdI1   = 98,
    zcAES      = 99
  );

  /// <summary>
  ///   Zip 文件头结构(中心目录文件头和本地文件头合一)
  /// </summary>
  TZipHeader = packed record
    MadeByVersion:      UInt16;     // **中心目录文件头开始
    RequiredVersion:    UInt16;     // **本地文件头开始
    Flag:               UInt16;     // 通用标志位
    CompressionMethod:  UInt16;     // 压缩方法编号或 WinZip AES 标记
                                    // 0  无压缩
                                    // 8  Deflate最常用的压缩方法, 使用 LZ77 和 Huffman 编码进行压缩, 平衡了压缩率和速度.
                                    // 99 WinZip AES 标记, 真实压缩方法保存在 AES 扩展字段中
                                    // 传统 ZipCrypto 加密由 Flag 的加密位表示, 本字段仍保存真实压缩方法
    ModifiedDateTime:   UInt32;
    CRC32:              UInt32;
    _CompressedSize:    UInt32;
    _UncompressedSize:  UInt32;
    FileNameLength:     UInt16;
    ExtraFieldLength:   UInt16;     // **本地文件头结束(从 RequiredVersion 到 ExtraFieldLength 共 26 字节)
    FileCommentLength:  UInt16;
    DiskNumberStart:    UInt16;
    InternalAttributes: UInt16;
    ExternalAttributes: UInt32;
    _LocalHeaderOffset: UInt32;     // **中心目录文件头结束(从 MadeByVersion 到 LocalHeaderOffset 共 42 字节)

    FileName:           TBytes;
    ExtraField:         TBytes;
    FileComment:        TBytes;

    function HasPassword: Boolean;
    function HasDataDescriptor: Boolean;
    function IsUtf8FileName: Boolean;
    function IsDirectory: Boolean;

    function GetCompressedSize64: UInt64;
    function GetLocalHeaderOffset64: UInt64;
    function GetUncompressedSize64: UInt64;
    function GetExtendedModTime: TDateTime;

    procedure SetCompressedSize64(const AValue: UInt64);
    procedure SetLocalHeaderOffset64(const AValue: UInt64);
    procedure SetUncompressedSize64(const AValue: UInt64);
    procedure SetExtendedModTime(const AValue: TDateTime);

    property CompressedSize: UInt64 read GetCompressedSize64 write SetCompressedSize64;
    property UncompressedSize: UInt64 read GetUncompressedSize64 write SetUncompressedSize64;
    property LocalHeaderOffset: UInt64 read GetLocalHeaderOffset64 write SetLocalHeaderOffset64;
    property ExtendedModTime: TDateTime read GetExtendedModTime write SetExtendedModTime;
  end;
  PZipHeader = ^TZipHeader;

  /// <summary>
  ///   Zip 中心目录结束头
  /// </summary>
  TZipEndOfCentralHeader = packed record
    DiskNumber:          UInt16; // 当前磁盘编号
    CentralDirStartDisk: UInt16; // 中心目录起始所在的磁盘编号
    NumEntriesThisDisk:  UInt16; // 当前磁盘上的中心目录条目数
    CentralDirEntries:   UInt16; // 中心目录的总条目数(包括所有磁盘)
    CentralDirSize:      UInt32; // 中心目录的大小(以字节为单位)
    CentralDirOffset:    UInt32; // 中心目录相对于文件开头的偏移量
    CommentLength:       UInt16; // 注释字段的长度(以字节为单位), 如果为 0, 则表示没有附加注释
    {Comment: RawByteString}
  end;

  /// <summary>
  ///   ZIP64 中心目录扩展头部
  /// </summary>
  TZip64Header = packed record
    Signature:           UInt32; // ZIP64 结束中心目录标志(固定为 $06064B50)
    HeaderSize:          Int64;  // HeaderSize 表示从记录的 HeaderSize 字段之后到记录结束的字节数(不包括 Signature 和 HeaderSize 字段本身)
    MadeByVersion:       UInt16; // 创建 ZIP 文件的版本号
    RequiredVersion:     UInt16; // 解压此 ZIP 文件所需的最低版本号
    NumberOfDisks:       UInt32; // 当前磁盘的编号
    CentralDirStartDisk: UInt32; // 中心目录起始所在磁盘的编号
    NumEntriesThisDisk:  UInt64; // 当前磁盘上的中心目录条目总数
    CentralDirEntries:   UInt64; // 中心目录的总条目数(包括所有磁盘)
    CentralDirSize:      UInt64; // 中心目录的大小(以字节为单位)
    CentralDirOffset:    UInt64; // 中心目录起始相对于起始磁盘编号的偏移量
  //zip64 extensible data sector
  end;

  /// <summary>
  ///   ZIP64 中心目录定位器
  /// </summary>
  TZip64EndOfCentralHeader = packed record
    Signature:             UInt32; // ZIP64 中心目录定位器标志(固定为 $07064B50)
    CentralDirStartDisk:   UInt32; // 中心目录所在磁盘的编号
    Zip64CentralDirOffset: UInt64; // ZIP64 中心目录记录相对于文件开头的偏移量
    TotalNumberOfDisks:    UInt32; // ZIP 文件中的磁盘总数
  end;

  /// <summary>
  ///   扩展字段结构
  /// </summary>
  TZipExtraField = packed record
    FieldId: Word;
    FieldLen: Word;
  // Data: Array[FieldLen] of Byte
  end;

  /// <summary>
  ///   ZIP64 扩展字段结构(FieldId = $0001)
  /// </summary>
  TZip64ExtraHeader = packed record
    UncompressedSize:  UInt64; // 未压缩数据的大小(单位:字节), 如果原始字段的值为 $FFFFFFFF, 则此字段有效
    CompressedSize:    UInt64; // 压缩数据的大小(可选, 单位:字节), 如果原始字段的值为 $FFFFFFFF, 则此字段有效
    LocalHeaderOffset: UInt64; // 本地文件头的偏移量(可选, 相对于文件开头), 如果原始字段的值为 $FFFFFFFF, 则此字段有效
    DiskNumberStart:   UInt32; // 起始磁盘编号(可选), 如果原始字段的值为 $FFFFFFFF, 则此字段有效
  end;

  /// <summary>
  ///   AES 加密扩展字段结构(FieldId = $9901), 用于保存 AES 参数和加密前的真实压缩方法
  /// </summary>
  TAESExtraField = packed record
    Version:  UInt16; // AES 加密版本号, 一般为 $0001
    Vendor:   UInt16; // AES 加密的供应商标识, 一般为"AE"(ASCII 编码, $4541)
    EncryptionStrength: UInt8;  // AES 密钥长度($01 表示 128 位, $02 表示 192 位, $03 表示 256 位)
    CompressionMethod:  UInt16; // AES 加密前的真实压缩方法, 如 0 表示 Stored, 8 表示 Deflate
  end;

  /// <summary>
  ///   扩展时间戳字段结构(FieldId = $5455)
  ///   Extended Timestamp Extra Field
  ///   支持 Unix 时间戳格式, 可以表示 1970-2038 年(32位)或更远(64位)
  /// </summary>
  TExtTimestampExtraField = packed record
    Flags:        UInt8;  // 标志位: bit 0=修改时间, bit 1=访问时间, bit 2=创建时间
    ModTime:      Int32;  // 修改时间 (Unix 时间戳, 秒)
    // 可选字段:
    // AcTime:    Int32;  // 访问时间 (Unix 时间戳, 秒) - 仅当 Flags bit 1 = 1
    // CrTime:    Int32;  // 创建时间 (Unix 时间戳, 秒) - 仅当 Flags bit 2 = 1
  end;

  /// <summary>
  ///   Zip 文件打开方式
  /// </summary>
  TZipMode = (zmRead, zmReadWrite, zmCreate);

  /// <summary>
  ///   Zip 操作类
  /// </summary>
  TCrossZip = class
  private const
    SIGNATURE_END_HEADER:           UInt32 = $06054B50; // 中心目录结束标志
    SIGNATURE_CENTRAL_HEADER:       UInt32 = $02014B50; // 中心目录文件头标志
    SIGNATURE_LOCAL_HEADER:         UInt32 = $04034B50; // 本地文件头标志
    SIGNATURE_ZIP64_END_HEADER:     UInt32 = $07064B50; // ZIP64 结束中心目录标志
    SIGNATURE_ZIP64_CENTRAL_HEADER: UInt32 = $06064B50; // ZIP64 中心目录定位器标志
    SIGNATURE_DESCRIPTOR:           UInt32 = $08074B50; // 数据描述符标志
  protected class threadvar
    FBuffer: array [0..BUF_SIZE-1] of Byte;
  private
    FUtf8: Boolean;
    FFileList: TList<PZipHeader>;
    FComment: TBytes;
    FPassword: TBytes;
    FZipFileName: string;
    FZipStream: TStream;
    FOpenMode: TZipMode;
    FOwnedStream, FChanged: Boolean;
    FRemovePath: Boolean;

    function GetComment: string;
    function GetFileComment(Index: Integer): string;
    function GetFileCount: Integer;
    function GetFileInfo(Index: Integer): PZipHeader;
    function GetFileName(Index: Integer): string;

    procedure SetComment(const Value: string);
    procedure SetFileComment(Index: Integer; const Value: string);
    procedure SetUtf8(const Value: Boolean);

    procedure SetupHeaderFlags(const AHeader: PZipHeader);

    // 读取中心目录
    procedure ReadCentralHeader;

    // 定位中心目录结束头
    function LocateEndOfCentralHeader(const AStream: TStream;
      var AZipEndHeader: TZipEndOfCentralHeader): Boolean;

    // 添加数据流
    function AddStream(const AData: TStream; const ALocalHeader: PZipHeader;
      const ACompressLevel: Integer = Z_DEFAULT_COMPRESSION;
      const AStrategy: Integer = Z_DEFAULT_STRATEGY): Boolean;

    procedure FreeOwnedStream;
    procedure OpenStream(const AZipFileStream: TStream;
      const AOpenMode: TZipMode; const AOwned, AFreeOwnedOnError: Boolean);
    // 保存 Zip 文件
    procedure Save;
    function GetUtf8: Boolean;
  private
    class procedure NewHeader(var AHeader: PZipHeader); static;
    class procedure FreeHeader(const AHeader: PZipHeader); static;
  protected
    FStartFileData: Int64;
    FEndFileData: Int64;

    procedure ClearFiles;
    function RawToString(const ARaw: TBytes): string; overload;
    function RawToString(const ARaw: TBytes; const AIsUtf8: Boolean): string; overload;
    function FileCommentToString(const AHeader: PZipHeader): string;
    function FileNameToString(const AHeader: PZipHeader): string;
    function StringToRaw(const AStr: string): TBytes;

    function GetHasPassword: Boolean; virtual;
    function GetPassword: string;
    procedure SetPassword(const Value: string); virtual;
  public
    constructor Create; virtual;
    destructor Destroy; override;

    /// <summary>
    ///   打开 Zip 文件
    /// </summary>
    /// <param name="AZipFileName">
    ///   zip文件名
    /// </param>
    /// <param name="AOpenMode">
    ///   打开方式
    /// </param>
    procedure Open(const AZipFileName: string; const AOpenMode: TZipMode); overload;

    /// <summary>
    ///   打开 Zip 流
    /// </summary>
    /// <param name="AZipFileStream">
    ///   zip文件数据流
    /// </param>
    /// <param name="AOpenMode">
    ///   打开方式
    /// </param>
    /// <param name="AOwned">
    ///   是否由 Zip 对象持有流. AOwned=True 时, Close 不释放该流, 下次 Open 或析构时释放
    /// </param>
    procedure Open(const AZipFileStream: TStream; const AOpenMode: TZipMode; const AOwned: Boolean); overload;

    /// <summary>
    ///   关闭 Zip 文件, 同时会自动保存并清空条目列表. 文件名 Open 创建的内部文件流会在 Close 中释放.
    ///   流 Open 传入且 AOwned=True 的流也会在 Close 中释放
    /// </summary>
    procedure Close;

    /// <summary>
    ///   解压指定序号的单个文件至流
    /// </summary>
    /// <param name="AArchiveIndex">
    ///   文件序号
    /// </param>
    /// <param name="ADstStream">
    ///   用于保存数据的流
    /// </param>
    function ExtractToStream(const AArchiveIndex: Integer; const ADstStream: TStream): Boolean; overload;

    /// <summary>
    ///   解压指定名称的单个文件至流
    /// </summary>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    /// <param name="ADstStream">
    ///   用于保存数据的流
    /// </param>
    function ExtractToStream(const AArchiveName: string; const ADstStream: TStream): Boolean; overload;

    /// <summary>
    ///   解压指定序号的单个文件至文件
    /// </summary>
    /// <param name="AArchiveIndex">
    ///   文件序号
    /// </param>
    /// <param name="ADstStream">
    ///   用于保存数据的流
    /// </param>
    function ExtractToFile(const AArchiveIndex: Integer; const ADstFileName: string): Boolean; overload;

    /// <summary>
    ///   解压指定名称的单个文件至文件
    /// </summary>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    /// <param name="ADstStream">
    ///   用于保存数据的流
    /// </param>
    function ExtractToFile(const AArchiveName: string; const ADstFileName: string): Boolean; overload;

    /// <summary>
    ///   解压指定序号的单个文件至指定目录
    /// </summary>
    /// <param name="AArchiveIndex">
    ///   文件序号
    /// </param>
    /// <param name="ADstPath">
    ///   用于保存数据的目录
    /// </param>
    /// <param name="ACreateSubdirs">
    ///   是否创建子目录
    /// </param>
    function ExtractToPath(const AArchiveIndex: Integer; const ADstPath: string; const ACreateSubdirs: Boolean = True): Boolean; overload;

    /// <summary>
    ///   解压指定名称的单个文件至指定目录
    /// </summary>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    /// <param name="ADstPath">
    ///   用于保存数据的目录
    /// </param>
    /// <param name="ACreateSubdirs">
    ///   是否创建子目录
    /// </param>
    function ExtractToPath(const AArchiveName: string; const ADstPath: string; const ACreateSubdirs: Boolean = True): Boolean; overload;

    /// <summary>
    ///   将打开的 Zip 文件全部解压至指定目录
    /// </summary>
    /// <param name="ADstPath">
    ///   用于保存数据的目录
    /// </param>
    procedure ExtractAllToPath(const ADstPath: string);

    /// <summary>
    ///   向 Zip 中添加文件数据
    /// </summary>
    /// <param name="AFileStream">
    ///   文件数据流
    /// </param>
    /// <param name="AFileDateTime">
    ///   文件修改时间
    /// </param>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    /// <param name="ACompression">
    ///   压缩方法
    /// </param>
    /// <param name="ACompressLevel">
    ///   压缩级别(Deflate: 1-9, -1使用默认级别)
    /// </param>
    function AddFromStream(const AFileStream: TStream;
      const AFileDateTime: TDateTime; const AArchiveName: string;
      const ACompression: TZipCompressionMethod = zcDeflate;
      const ACompressLevel: Integer = Z_DEFAULT_COMPRESSION;
      const AStrategy: Integer = Z_DEFAULT_STRATEGY): Boolean; overload;

    /// <summary>
    ///   向 Zip 中添加文件数据
    /// </summary>
    /// <param name="AFileStream">
    ///   文件数据流
    /// </param>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    /// <param name="ACompression">
    ///   压缩方法
    /// </param>
    /// <param name="ACompressLevel">
    ///   压缩级别(Deflate: 1-9, -1使用默认级别)
    /// </param>
    function AddFromStream(const AFileStream: TStream;
      const AArchiveName: string;
      const ACompression: TZipCompressionMethod = zcDeflate;
      const ACompressLevel: Integer = Z_DEFAULT_COMPRESSION;
      const AStrategy: Integer = Z_DEFAULT_STRATEGY): Boolean; overload;

    /// <summary>
    ///   向 Zip 中添加文件数据
    /// </summary>
    /// <param name="AFileName">
    ///   文件名
    /// </param>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    /// <param name="ACompression">
    ///   压缩方法
    /// </param>
    /// <param name="ACompressLevel">
    ///   压缩级别(Deflate: 1-9, -1使用默认级别)
    /// </param>
    function AddFromFile(const AFileName: string;
      const AArchiveName: string = '';
      const ACompression: TZipCompressionMethod = zcDeflate;
      const ACompressLevel: Integer = Z_DEFAULT_COMPRESSION;
      const AStrategy: Integer = Z_DEFAULT_STRATEGY): Boolean; overload;

    /// <summary>
    ///   向 Zip 中添加空目录
    /// </summary>
    /// <param name="ADirName">
    ///   目录名
    /// </param>
    function AddEmptyDir(const ADirName: string): Boolean;

    /// <summary>
    ///   从 Zip 文件内删除一个指定序号的文件
    /// </summary>
    /// <param name="AArchiveIndex">
    ///   文件序号
    /// </param>
    function Delete(const AArchiveIndex: Integer): Boolean; overload;

    /// <summary>
    ///   从 Zip 文件内删除一个指定文件
    /// </summary>
    /// <param name="AArchiveName">
    ///   zip内部文件名
    /// </param>
    function Delete(const AArchiveName: string): Boolean; overload;

    /// <summary>
    ///   在该 Zip 文件中查找指定文件名, 返回其顺序索引
    /// </summary>
    function IndexOf(const AArchiveName: string): Integer; overload;
    function IndexOf(const AArchiveName: string; const ACaseSensitive: Boolean): Integer; overload;

    /// <summary>
    ///   该 Zip 文件包含的文件个数
    /// </summary>
    property FileCount: Integer read GetFileCount;

    /// <summary>
    ///   该 Zip 文件包含的文件名
    /// </summary>
    property FileName[Index: Integer]: string read GetFileName;

    /// <summary>
    ///   该 Zip 文件包含的文件信息, 从中央目录读出的
    /// </summary>
    property FileInfo[Index: Integer]: PZipHeader read GetFileInfo;

    /// <summary>
    ///   该 Zip 文件包含的文件注释
    /// </summary>
    property FileComment[Index: Integer]: string read GetFileComment write SetFileComment;

    /// <summary>
    ///   该 Zip 文件包含的注释
    /// </summary>
    property Comment: string read GetComment write SetComment;

    /// <summary>
    ///   该 Zip 文件是否支持 Utf8
    /// </summary>
    property Utf8: Boolean read GetUtf8 write SetUtf8;

    /// <summary>
    ///   该 Zip 文件的密码
    /// </summary>
    property Password: string read GetPassword write SetPassword;

    /// <summary>
    ///   该 Zip 文件是否有密码
    /// </summary>
    property HasPassword: Boolean read GetHasPassword;

    /// <summary>
    ///   是否去除每个文件的路径信息只留文件名信息
    ///   只在 AddFromFile 中 ArchiveFileName 为空的情况下有效
    /// </summary>
    property RemovePath: Boolean read FRemovePath write FRemovePath;
  end;

  /// <summary>
  ///   压缩类型的实现基类
  /// </summary>
  TZipCompressionHandlerBase = class abstract
  public
    class function CanHandleCompressionMethod(
      const AMethod: TZipCompressionMethod): Boolean; virtual; abstract;

    class function CreateCompressionStream(
      const AMethod: TZipCompressionMethod; const AOutStream: TStream;
      const AZipHeader: PZipHeader; const APassword: TBytes;
      const ACompressLevel, AStrategy: Integer): TStream; virtual; abstract;

    class function CreateDecompressionStream(
      const AMethod: TZipCompressionMethod; const AInStream: TStream;
      const AZipHeader: PZipHeader; const APassword: TBytes): TStream; virtual; abstract;
  end;

  TZipCompressionHandlerClass = class of TZipCompressionHandlerBase;

// 供外界提供对新的压缩方式的支持
procedure RegisterZipCompressionHandler(const AClass: TZipCompressionHandlerClass);

// 判断 Zip 文件是否合法
function ZipFileIsValid(const AFileName: string): Boolean;

// 将指定 Zip 文件解压缩到指定目录
function ZipExtractTo(const AFileName: string; const ADstDir: string;
  const APassword: string = ''): Boolean;

implementation

uses
  Utils.IOUtils;

resourcestring
  SZipErrorRead = 'Error Reading Zip File';
  SZipErrorWrite = 'Error Writing Zip File';
  SZipInvalidZip = 'Invalid Zip File';
  SZipInvalidMode = 'Invalid Zip Mode';
  SZipInvalidLocalHeader = 'Invalid Zip Local Header';
  SZipInvalidCentralHeader = 'Invalid Zip Central Header';
  SFileNotFound = 'Error Finding File';
  SZipNoWrite = 'File must be open for writing';
  SZipNotSupport = 'Zip Compression Method NOT Support';
  SZipInvalidPassword = 'Invalid Password';
  SZipNotImplemented = 'Feature NOT Implemented';
  SZipUtf8NotSupport = 'UTF8 NOT Support';
  SZipInvalideModeSetProp = 'Only zmReadWrite and zmCreate mode can set prop';
  SZipInvalidExtraField = 'Invalid extra field';
  SZipInvalidAESExtraField = 'Invalid AES extra field';
  SZipDeflateCompressError = 'Deflate compress error: %d';
  SZipDeflateDecompressError = 'Deflate decompress error: %d';
  SZipCrcError = 'Zip crc error';
  SZipInvalidExtractPath = 'Invalid zip extract path';
  SZipCryptRandomError = 'Error generating crypt random bytes';

type
  TZipCompressionHandlerList = TList<TZipCompressionHandlerClass>;

var
  FZipCompressionHandlers: TZipCompressionHandlerList = nil;

type
  IZipFinishable = interface
    ['{B1C2E3F4-A5B6-7890-CDEF-1234567890AB}']
    procedure Finish;
  end;

  // 默认压缩处理类
  // 支持情况:
  //   压缩方式: Stored, Deflate
  //   加密方式: 传统加密(ZipCrypto), AES
  TZipDefaultCompressionHandler = class(TZipCompressionHandlerBase)
  public
    // 是否支持特定的压缩方法
    class function CanHandleCompressionMethod(
      const AMethod: TZipCompressionMethod): Boolean; override;

    // 创建针对特定输入流的压缩流. 压缩流的概念是, 压缩流有个输出流, 当朝压缩流写入数据时,
    // 将自动把压缩后的数据写入输出流. 所以压缩流要实现 Write 方法写明文, 内部压缩加密后写输出流}
    class function CreateCompressionStream(
      const AMethod: TZipCompressionMethod; const AOutStream: TStream;
      const AZipHeader: PZipHeader; const APassword: TBytes;
      const ACompressLevel, AStrategy: Integer): TStream; override;

    // 创建针对特定输入流的解压缩流. 解压缩流的概念是, 解压缩流有个输入流, 当从解压缩流读数据时,
    // 将自动把解压缩后的数据提供出来到 Buffer. 所以解压缩流要实现 Read 方法返回明文, 内部从输入流读并解压缩解密之类的
    class function CreateDecompressionStream(
      const AMethod: TZipCompressionMethod; const AInStream: TStream;
      const AZipHeader: PZipHeader; const APassword: TBytes): TStream; override;
  end;

  // 存储方式(不压缩)的压缩流与解压缩流
  TStoredStream = class(TStream, IZipFinishable)
  private
    FOwner: Boolean;
    FStream: TStream;
  public
    constructor Create(const AStream: TStream; const AOwner: Boolean);
    destructor Destroy; override;

    procedure Finish;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;

    // IInterface
    function QueryInterface({$IFDEF FPC}constref{$ELSE}const{$ENDIF} IID: TGUID; out Obj): HResult; {$IF defined(FPC) and defined(POSIX)}cdecl{$ELSE}stdcall{$ENDIF};
    function _AddRef: LongInt; {$IF defined(FPC) and defined(POSIX)}cdecl{$ELSE}stdcall{$ENDIF};
    function _Release: LongInt; {$IF defined(FPC) and defined(POSIX)}cdecl{$ELSE}stdcall{$ENDIF};
  end;

  // Deflate压缩/解压流基础类
  TCustomDeflateStream = class(TStream)
  private
    FOwner: Boolean;
    FStream: TStream;
    FStreamStartPos: Int64;
    FStreamPos: Int64;
    FZStream: TZStreamRec;
    FZInitialized: Boolean;
  protected class threadvar
    FBuffer: array [0..BUF_SIZE-1] of Byte;
  public
    constructor Create(const AStream: TStream; const AOwner: Boolean);
    destructor Destroy; override;
  end;

  // Deflate压缩流
  TDeflateCompressStream = class(TCustomDeflateStream)
  public
    constructor Create(const AStream: TStream; const AOwner: Boolean;
      const ACompressLevel: Integer = Z_DEFAULT_COMPRESSION;
      const AWindowBits: Integer = -15;
      const AMemLevel: Integer = 8;
      const AStrategy: Integer = Z_DEFAULT_STRATEGY);
    destructor Destroy; override;

    procedure Flush;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

  // Deflate解压流
  TDeflateDecompressStream = class(TCustomDeflateStream, IZipFinishable)
  public
    constructor Create(const AStream: TStream; const AOwner: Boolean);
    destructor Destroy; override;

    procedure Finish;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;

    // IInterface
    function QueryInterface({$IFDEF FPC}constref{$ELSE}const{$ENDIF} IID: TGUID; out Obj): HResult; {$IF defined(FPC) and defined(POSIX)}cdecl{$ELSE}stdcall{$ENDIF};
    function _AddRef: LongInt; {$IF defined(FPC) and defined(POSIX)}cdecl{$ELSE}stdcall{$ENDIF};
    function _Release: LongInt; {$IF defined(FPC) and defined(POSIX)}cdecl{$ELSE}stdcall{$ENDIF};
  end;

  // zip传统加密类
  TZipCrypto = class
  private const
    // zip传统加密方式要用到的几个密钥
    KEY0_INIT: UInt32  = 305419896;
    KEY1_INIT: UInt32  = 591751049;
    KEY2_INIT: UInt32  = 878082192;
    KEY_UPDATE: UInt32 = 134775813;
  private
    FKey0, FKey1, FKey2: UInt32;
  protected
    function CalcDecryptByte: UInt8; inline;
  public
    procedure InitKeys(const APassword: TBytes);
    procedure UpdateKeys(const C: UInt8); inline;

    procedure DecryptByte(var Value: UInt8); inline;
    procedure EncryptByte(var Value: UInt8); inline;

    procedure Decrypt(AData: PByte; ASize: Integer);
    procedure Encrypt(AData: PByte; ASize: Integer);
  end;

  // 传统方式解密流(动态解密)
  TZipCryptoDecryptStream = class(TStream)
  private
    FZipStream: TStream;
    FZipCrypto: TZipCrypto;
    FPosStart, FSize: Int64;
  public
    constructor Create(const AInStream: TStream; const APassword: TBytes;
      const AZipHeader: PZipHeader);
    destructor Destroy; override;

    function Read(var Buffer; Count: Integer): Integer; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
    function Write(const Buffer; Count: Integer): Integer; override; // 可无需实现
  end;

  // 传统方式加密流(动态加密)
  TZipCryptoEncryptStream = class(TStream)
  private
    FZipStream: TStream;
    FZipCrypto: TZipCrypto;
  public
    constructor Create(const AOutStream: TStream; const APassword: TBytes;
      const AZipHeader: PZipHeader);
    destructor Destroy; override;

    function Read(var Buffer; Count: Integer): Integer; override; // 可无需实现
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override; // 可无需实现
    function Write(const Buffer; Count: Integer): Integer; override;
  end;

  // aes解密流(动态解密)
  TZipAESDecryptStream = class(TStream)
  private
    FZipStream: TStream;
    FPosStart, FSize: Int64;

    FCryptNonce: TCnAESBuffer;
    FAESCTREncryptor: TAESCTREncryptor;
    FSha1Hmac: THashBase;
    FAuthChecked: Boolean;

    procedure CheckHmac;
  public
    constructor Create(const AInStream: TStream; const APassword: TBytes;
      const AZipHeader: PZipHeader; const AAESExtraField: TAESExtraField);
    destructor Destroy; override;

    procedure Finish;
    function Read(var Buffer; Count: Integer): Integer; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
    function Write(const Buffer; Count: Integer): Integer; override; // 可无需实现
  end;

  // aes加密流(动态加密)
  TZipAESEncryptStream = class(TStream)
  private
    FZipStream: TStream;

    FCryptNonce: TCnAESBuffer;
    FAESCTREncryptor: TAESCTREncryptor;
    FSha1Hmac: THashBase;

    procedure WriteHmac;
  public
    constructor Create(const AOutStream: TStream; const APassword: TBytes;
      const AZipHeader: PZipHeader; const AAESExtraField: TAESExtraField);
    destructor Destroy; override;

    function Read(var Buffer; Count: Integer): Integer; override; // 可无需实现
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override; // 可无需实现
    function Write(const Buffer; Count: Integer): Integer; override;
  end;

// 计算 CRC32 值
function CRC32Calc(const AOrgCRC32: UInt32; const AData; const ADataSize: UInt32): UInt32; inline;
begin
  Result := crc32(AOrgCRC32, @AData, ADataSize);
end;

procedure FillCryptRandomBytes(var ABuf; const ASize: Integer);
begin
  if not TryFillCryptRandomBytes(ABuf, ASize) then
    raise EZipException.CreateRes(@SZipCryptRandomError);
end;

function CalcCRC32Byte(const AOrgCRC32: UInt32; const B: UInt8): UInt32; inline;
begin
  Result := not crc32(not AOrgCRC32, @B, 1);
end;

function NormalizeZipArchivePath(const APath: string): string;
begin
  Result := StringReplace(APath, '\', '/', [rfReplaceAll]);
end;

function NormalizeRootlessZipArchivePath(const APath: string): string;
begin
  Result := NormalizeZipArchivePath(APath);

  if (Length(Result) >= 2) and (Result[2] = ':') then
    Delete(Result, 1, 2);

  while (Result <> '') and (Result[1] = '/') do
    Delete(Result, 1, 1);
end;

// 获取指定ID的扩展字段
function GetExtraField(const AExtraData: TBytes; AFieldId, AFieldLen: Word; AExtra: Pointer): Integer;
var
  LOffset: Integer;
  LField: TZipExtraField;
  LCount: Integer;
  LDataOffset: Integer;
begin
  LOffset := 0;
  LCount := Length(AExtraData);
  while LOffset + SizeOf(TZipExtraField) <= LCount do
  begin
    Move(AExtraData[LOffset], LField, SizeOf(LField));
    LDataOffset := LOffset + SizeOf(TZipExtraField);
    if (LField.FieldLen > LCount - LDataOffset) then
      raise EZipException.CreateRes(@SZipInvalidExtraField);

    if LField.FieldId = AFieldId then
    begin
      Result := LField.FieldLen;
      if AExtra <> nil then
      begin
        if Result < AFieldLen then
          AFieldLen := Result;
        Move(AExtraData[LDataOffset], AExtra^, AFieldLen);
      end;
      Exit;
    end;
    Inc(LOffset, SizeOf(TZipExtraField) + LField.FieldLen);
  end;
  Result := 0;
end;

// 定位指定ID的扩展字段数据
function GetExtraFieldData(const AExtraData: TBytes; const AFieldId: Word;
  out ADataOffset, AFieldLen: Integer): Boolean;
var
  LOffset: Integer;
  LField: TZipExtraField;
  LCount: Integer;
  LDataOffset: Integer;
begin
  LOffset := 0;
  LCount := Length(AExtraData);
  while LOffset + SizeOf(TZipExtraField) <= LCount do
  begin
    Move(AExtraData[LOffset], LField, SizeOf(LField));
    LDataOffset := LOffset + SizeOf(TZipExtraField);
    if (LField.FieldLen > LCount - LDataOffset) then
      raise EZipException.CreateRes(@SZipInvalidExtraField);

    if LField.FieldId = AFieldId then
    begin
      ADataOffset := LDataOffset;
      AFieldLen := LField.FieldLen;
      Exit(True);
    end;
    Inc(LOffset, SizeOf(TZipExtraField) + LField.FieldLen);
  end;

  ADataOffset := 0;
  AFieldLen := 0;
  Result := False;
end;

function TryGetUnicodeExtraFieldText(const AExtraData, ARawData: TBytes;
  const AFieldId: Word; out AText: string): Boolean;
var
  LDataOffset: Integer;
  LFieldLen: Integer;
  LTextBytes: TBytes;
  LTextCrc32: UInt32;
  LRawCrc32: UInt32;
  LTextLen: Integer;
begin
  Result := False;
  AText := '';

  if not GetExtraFieldData(AExtraData, AFieldId, LDataOffset, LFieldLen)
    or (LFieldLen <= SizeOf(UInt8) + SizeOf(UInt32))
    or (AExtraData[LDataOffset] <> 1) then Exit;

  Move(AExtraData[LDataOffset + SizeOf(UInt8)], LTextCrc32, SizeOf(LTextCrc32));

  if Length(ARawData) > 0 then
    LRawCrc32 := CRC32Calc(0, ARawData[0], Length(ARawData))
  else
    LRawCrc32 := 0;

  if LTextCrc32 <> LRawCrc32 then Exit;

  LTextLen := LFieldLen - SizeOf(UInt8) - SizeOf(UInt32);
  SetLength(LTextBytes, LTextLen);
  Move(AExtraData[LDataOffset + SizeOf(UInt8) + SizeOf(UInt32)],
    LTextBytes[0], LTextLen);
  AText := TEncoding.UTF8.GetString(LTextBytes);
  Result := True;
end;

// 删除指定ID的扩展字段
procedure DelExtraField(var AExtraData: TBytes; AFieldId: Word);
var
  LOffset: Integer;
  LField: TZipExtraField;
  LCount: Integer;
  LDataOffset: Integer;
begin
  LOffset := 0;
  LCount := Length(AExtraData);
  while LOffset + SizeOf(TZipExtraField) <= LCount do
  begin
    Move(AExtraData[LOffset], LField, SizeOf(LField));
    LDataOffset := LOffset + SizeOf(TZipExtraField);
    if (LField.FieldLen > LCount - LDataOffset) then
      raise EZipException.CreateRes(@SZipInvalidExtraField);

    if LField.FieldId = AFieldId then
    begin
      Delete(AExtraData, LOffset, SizeOf(TZipExtraField) + LField.FieldLen);
      Exit;
    end;
    Inc(LOffset, SizeOf(TZipExtraField) + LField.FieldLen);
  end;
end;

// 设置指定ID的扩展字段
procedure SetExtraField(var AExtraData: TBytes; AFieldId, AFieldLen: Word; AExtra: Pointer);
var
  LOffset: Integer;
  LField: ^TZipExtraField;
  LFieldHeader: TZipExtraField;
  LCount: Integer;
  LLen: Integer;
  LDataOffset: Integer;
begin
  if AFieldLen = 0 then
  begin
    DelExtraField(AExtraData, AFieldId);
    Exit;
  end;
  LOffset := 0;
  LCount := Length(AExtraData);
  while LOffset + SizeOf(TZipExtraField) <= LCount do
  begin
    Move(AExtraData[LOffset], LFieldHeader, SizeOf(LFieldHeader));
    LDataOffset := LOffset + SizeOf(TZipExtraField);
    if (LFieldHeader.FieldLen > LCount - LDataOffset) then
      raise EZipException.CreateRes(@SZipInvalidExtraField);

    LField := @AExtraData[LOffset];
    LLen := SizeOf(TZipExtraField) + LFieldHeader.FieldLen;
    if LFieldHeader.FieldId = AFieldId then
    begin
      Inc(LOffset, SizeOf(TZipExtraField));
      LLen := Integer(AFieldLen) - LFieldHeader.FieldLen;
      if LLen < 0 then
      begin
        LField.FieldLen := AFieldLen;
        Delete(AExtraData, LOffset, -LLen);
      end else
      if LLen > 0 then
      begin
        LField.FieldLen := AFieldLen;
        SetLength(AExtraData, Length(AExtraData) + LLen);
        Move(AExtraData[LOffset], AExtraData[LOffset + LLen], Length(AExtraData) - LOffset - LLen);
      end;
      Move(AExtra^, AExtraData[LOffset], AFieldLen);
      Exit;
    end;
    Inc(LOffset, LLen);
  end;
  LCount := Length(AExtraData);
  SetLength(AExtraData, LCount + SizeOf(TZipExtraField) + AFieldLen);
  LField := @AExtraData[LCount];
  LField.FieldId := AFieldId;
  LField.FieldLen := AFieldLen;
  Inc(LCount, SizeOf(TZipExtraField));
  Move(AExtra^, AExtraData[LCount], AFieldLen);
end;

function IsZip64EndOfCentralHeader(const AEndHeader: TZipEndOfCentralHeader): Boolean;
begin
  Result := (AEndHeader.DiskNumber = MAX_UINT16) or
     (AEndHeader.CentralDirStartDisk = MAX_UINT16) or
     (AEndHeader.NumEntriesThisDisk = MAX_UINT16) or
     (AEndHeader.CentralDirEntries = MAX_UINT16) or
     (AEndHeader.CentralDirSize = MAX_UINT32) or
     (AEndHeader.CentralDirOffset = MAX_UINT32);
end;

procedure RegisterZipCompressionHandler(const AClass: TZipCompressionHandlerClass);
begin
  if (FZipCompressionHandlers.IndexOf(AClass) < 0) then
    FZipCompressionHandlers.Add(AClass);
end;

// 查找能处理指定压缩方式的 Handler
function FindHandlerForMethod(const AMethod: TZipCompressionMethod): TZipCompressionHandlerClass;
var
  I: Integer;
begin
  for I := 0 to FZipCompressionHandlers.Count - 1 do
  begin
    Result := TZipCompressionHandlerClass(FZipCompressionHandlers[I]);
    if (Result <> nil) and Result.CanHandleCompressionMethod(AMethod) then
      Exit;
  end;
  Result := nil;
end;

// 是否支持指定的压缩方式
function SupportCompressionMethod(const AMethod: TZipCompressionMethod): Boolean;
begin
  Result := FindHandlerForMethod(AMethod) <> nil;
end;

function CreateCompressStreamFromHandler(const AMethod: TZipCompressionMethod;
  AOutStream: TStream; const AZipHeader: PZipHeader; const APassword: TBytes;
  const ACompressLevel, AStrategy: Integer): TStream;
var
  LHandler: TZipCompressionHandlerClass;
begin
  Result := nil;
  LHandler := FindHandlerForMethod(AMethod);
  if LHandler <> nil then
    Result := LHandler.CreateCompressionStream(
      AMethod, AOutStream, AZipHeader, APassword, ACompressLevel, AStrategy);
end;

function CreateDecompressStreamFromHandler(const AMethod: TZipCompressionMethod;
  const AInStream: TStream; const AZipHeader: PZipHeader; const APassword: TBytes): TStream;
var
  LHandler: TZipCompressionHandlerClass;
begin
  Result := nil;
  LHandler := FindHandlerForMethod(AMethod);
  if LHandler <> nil then
    Result := LHandler.CreateDecompressionStream(AMethod, AInStream, AZipHeader, APassword);
end;

function ZipFileIsValid(const AFileName: string): Boolean;
var
  LZipHeader: TCrossZip;
  LZipStream: TStream;
  LZipEndHeader: TZipEndOfCentralHeader;
begin
  Result := False;
  try
    try
      LZipHeader := TCrossZip.Create;
      LZipStream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
      Result := LZipHeader.LocateEndOfCentralHeader(LZipStream, LZipEndHeader);
    finally
      FreeAndNil(LZipStream);
      FreeAndNil(LZipHeader);
    end;
  except
    on E: EZipException do ;
  end;
end;

function ZipExtractTo(const AFileName, ADstDir, APassword: string): Boolean;
var
  LZip: TCrossZip;
begin
  Result := False;
  if not FileExists(AFileName) then Exit;

  LZip := TCrossZip.Create;
  try
    LZip.Open(AFileName, zmRead);
    LZip.Password := APassword;
    LZip.ExtractAllToPath(ADstDir);
    Result := True;
  finally
    FreeAndNil(LZip);
  end;
end;

procedure VerifyRead(AStream: TStream; var ABuffer; ACount: Integer);
begin
  if (AStream.Read(ABuffer, ACount) <> ACount) then
    raise EZipException.CreateRes(@SZipErrorRead);
end;

procedure VerifyWrite(AStream: TStream; const ABuffer; ACount: Integer);
begin
  if (AStream.Write(ABuffer, ACount) <> ACount) then
    raise EZipException.CreateRes(@SZipErrorWrite);
end;

function BuildSafeExtractPath(const ADstPath, AArchiveName: string;
  const ACreateSubdirs: Boolean; out ADstFileName: string): Boolean;
var
  LArchiveName: string;
begin
  Result := False;
  ADstFileName := '';

  LArchiveName := AArchiveName;

  if not ACreateSubdirs then
    LArchiveName := TPathUtils.GetFileName(LArchiveName);
  if (LArchiveName = '') then Exit;

  Result := TPathUtils.TryResolveLocalPath(ADstPath, LArchiveName, ADstFileName);
end;

procedure MoveUp(AStream: TStream; AFromOffset, AToOffset, AMoveCount: Int64);
var
  LBuffer: TBytes;
  LCount: Integer;
begin
  if (AMoveCount <= 0) then Exit;

  Assert(AFromOffset > AToOffset);
  if (AMoveCount > BUF_SIZE) then
    LCount := BUF_SIZE
  else
    LCount := AMoveCount;

  SetLength(LBuffer, LCount);
  while (LCount > 0) do
  begin
    AStream.Position := AFromOffset;
    AStream.ReadData(LBuffer, LCount);
    AStream.Position := AToOffset;
    AStream.WriteData(LBuffer, LCount);
    Inc(AFromOffset, LCount);
    Inc(AToOffset, LCount);
    Dec(AMoveCount, LCount);
    if AMoveCount < LCount then
      LCount := AMoveCount;
  end;
end;

{ TZipHeader }

procedure SetZip64Field(AHeader: PZipHeader; const AValue: UInt64;
  var AZip64Extra: TZip64ExtraHeader; var ARawField: UInt32;
  const AFieldIndex: Integer); forward;

function TZipHeader.GetCompressedSize64: UInt64;
var
  LZip64Extra: TZip64ExtraHeader;
begin
  if (GetExtraField(
    ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @LZip64Extra) >= SizeOf(UInt64) * 2) then
    Result := LZip64Extra.CompressedSize
  else
    Result := _CompressedSize;
end;

function TZipHeader.GetLocalHeaderOffset64: UInt64;
var
  LZip64Extra: TZip64ExtraHeader;
begin
  if (GetExtraField(
    ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @LZip64Extra) >= SizeOf(UInt64) * 3) then
    Result := LZip64Extra.LocalHeaderOffset
  else
    Result := _LocalHeaderOffset;
end;

function TZipHeader.GetUncompressedSize64: UInt64;
var
  LZip64Extra: TZip64ExtraHeader;
begin
  if (GetExtraField(
    ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @LZip64Extra) >= SizeOf(UInt64)) then
    Result := LZip64Extra.UncompressedSize
  else
    Result := _UncompressedSize;
end;

function TZipHeader.GetExtendedModTime: TDateTime;
var
  LExtTimestamp: TExtTimestampExtraField;
  LUnixTime: Int32;
  LUtcTime: TDateTime;
begin
  if (GetExtraField(
    ExtraField,
    EXID_TIMESTAMP,
    SizeOf(TExtTimestampExtraField),
    @LExtTimestamp) >= SizeOf(UInt8) + SizeOf(Int32))
    and ((LExtTimestamp.Flags and $01) <> 0) then
  begin
    LUnixTime := LExtTimestamp.ModTime;
    // Unix 时间戳是 UTC 时间，转换为本地时间
    LUtcTime := UnixDateDelta + (LUnixTime / SecsPerDay);
    Result := LUtcTime.ToLocalTime;
  end else
    Result := 0;
end;

function TZipHeader.HasDataDescriptor: Boolean;
begin
  Result := (Flag and FLAG_DATA_DESCRIPTOR <> 0);
end;

function TZipHeader.HasPassword: Boolean;
begin
  Result := (Flag and FLAG_PASSWORD <> 0);
end;

function TZipHeader.IsDirectory: Boolean;
begin
  Result := (ExternalAttributes and faDirectory <> 0)
    or ((Length(FileName) > 0) and (FileName[High(FileName)] in [Ord('\'), Ord('/')]));
end;

function TZipHeader.IsUtf8FileName: Boolean;
begin
  Result := (Flag and FLAG_UTF8 <> 0);
end;

procedure TZipHeader.SetCompressedSize64(const AValue: UInt64);
var
  LZip64Extra: TZip64ExtraHeader;
begin
  SetZip64Field(@Self, AValue, LZip64Extra, _CompressedSize, 2);
end;

procedure TZipHeader.SetLocalHeaderOffset64(const AValue: UInt64);
var
  LZip64Extra: TZip64ExtraHeader;
begin
  SetZip64Field(@Self, AValue, LZip64Extra, _LocalHeaderOffset, 3);
end;

procedure TZipHeader.SetUncompressedSize64(const AValue: UInt64);
var
  LZip64Extra: TZip64ExtraHeader;
begin
  SetZip64Field(@Self, AValue, LZip64Extra, _UncompressedSize, 1);
end;

procedure TZipHeader.SetExtendedModTime(const AValue: TDateTime);
var
  LExtTimestamp: TExtTimestampExtraField;
  LUnixTime: Int64;
  LUtcTime: TDateTime;
begin
  // 将本地时间转换为 UTC 时间
  LUtcTime := AValue.ToUniversalTime;
  
  // 转换为 Unix 时间戳
  LUnixTime := Round((LUtcTime - UnixDateDelta) * SecsPerDay);
  
  if (LUnixTime < Low(Int32)) or (LUnixTime > High(Int32)) then
    Exit;
  
  LExtTimestamp.Flags := $01;
  LExtTimestamp.ModTime := Int32(LUnixTime);
  
  SetExtraField(ExtraField, EXID_TIMESTAMP, SizeOf(UInt8) + SizeOf(Int32), @LExtTimestamp);
  ExtraFieldLength := Length(ExtraField);
end;

procedure SetZip64Field(AHeader: PZipHeader; const AValue: UInt64;
  var AZip64Extra: TZip64ExtraHeader; var ARawField: UInt32;
  const AFieldIndex: Integer);
var
  LExSize: Integer;
begin
  LExSize := GetExtraField(
    AHeader^.ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @AZip64Extra);

  if (AValue >= MAX_UINT32) or (LExSize >= SizeOf(UInt64)) then
  begin
    if (AHeader^.MadeByVersion < 45) then
      AHeader^.MadeByVersion := 45;
    AHeader^.RequiredVersion := 45;

    ARawField := MAX_UINT32;

    case AFieldIndex of
      1: AZip64Extra.UncompressedSize := AValue;
      2: AZip64Extra.CompressedSize := AValue;
      3: AZip64Extra.LocalHeaderOffset := AValue;
    end;

    // 补齐前面缺失的 ZIP64 字段
    if (AFieldIndex > 1) and (LExSize < 1 * SizeOf(UInt64)) then
    begin
      AZip64Extra.UncompressedSize := AHeader^._UncompressedSize;
      AHeader^._UncompressedSize := MAX_UINT32;
    end;
    if (AFieldIndex > 2) and (LExSize < 2 * SizeOf(UInt64)) then
    begin
      AZip64Extra.CompressedSize := AHeader^._CompressedSize;
      AHeader^._CompressedSize := MAX_UINT32;
    end;

    if LExSize < AFieldIndex * SizeOf(UInt64) then
      LExSize := AFieldIndex * SizeOf(UInt64);
  end else
  begin
    if LExSize < SizeOf(UInt64) then
      AHeader^.RequiredVersion := 20;
    ARawField := UInt32(AValue);
  end;

  if (LExSize >= SizeOf(UInt64)) then
  begin
    SetExtraField(AHeader^.ExtraField, EXID_ZIP64, LExSize, @AZip64Extra);
    AHeader^.ExtraFieldLength := Length(AHeader^.ExtraField);
  end;
end;

{ TCrossZip }

function TCrossZip.AddEmptyDir(const ADirName: string): Boolean;
var
  LExistsIndex: Integer;
  LLocalHeader: PZipHeader;
  LNow: TDateTime;
  LDirName: string;
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipNoWrite);

  LDirName := NormalizeZipArchivePath(ADirName);

  LExistsIndex := IndexOf(LDirName);
  if (LExistsIndex >= 0) then
    Delete(LExistsIndex);

  NewHeader(LLocalHeader);

  SetupHeaderFlags(LLocalHeader);

  LNow := Now;

  LLocalHeader^.CompressionMethod := UInt16(zcStored);
  LLocalHeader^.ModifiedDateTime := LNow.ToDosDateTime; // zip文件中的时间戳保存的是msdos格式
  LLocalHeader^.InternalAttributes := 0;
  LLocalHeader^.ExternalAttributes := faDirectory;
  LLocalHeader^.FileName := StringToRaw(LDirName);
  LLocalHeader^.FileNameLength := Length(LLocalHeader^.FileName);
  LLocalHeader^.ExtraFieldLength := 0;
  
  // 写入扩展时间戳字段
  LLocalHeader^.ExtendedModTime := LNow;

  Result := AddStream(nil, LLocalHeader);

  FChanged := True;
end;

function TCrossZip.AddFromFile(const AFileName, AArchiveName: string;
  const ACompression: TZipCompressionMethod; const ACompressLevel, AStrategy: Integer): Boolean;

  function GetFileDateTime(const AFileName: string): TDateTime;
  var
    LDateTimeRec: TDateTimeInfoRec;
  begin
    FileGetDateTimeInfo(AFileName, LDateTimeRec);
    Result := LDateTimeRec.TimeStamp;
  end;

var
  LInStream: TStream;
  LArchive: string;
begin
  if not FileExists(AFileName) then Exit(False);

  if (AArchiveName <> '') then
    LArchive := NormalizeZipArchivePath(AArchiveName)
  else if FRemovePath then
    LArchive := NormalizeZipArchivePath(ExtractFileName(AFileName))
  else
    LArchive := NormalizeRootlessZipArchivePath(AFileName);

  LInStream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := AddFromStream(
      LInStream,
      GetFileDateTime(AFileName),
      LArchive, ACompression,
      ACompressLevel,
      AStrategy);
  finally
    FreeAndNil(LInStream);
  end;
end;

function TCrossZip.AddFromStream(const AFileStream: TStream;
  const AFileDateTime: TDateTime; const AArchiveName: string;
  const ACompression: TZipCompressionMethod;
  const ACompressLevel, AStrategy: Integer): Boolean;
var
  LExistsIndex: Integer;
  LLocalHeader: PZipHeader;
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipNoWrite);

  if not SupportCompressionMethod(ACompression) then
    raise EZipException.CreateRes(@SZipNotSupport);

  LExistsIndex := IndexOf(AArchiveName);
  if (LExistsIndex >= 0) then
    Delete(LExistsIndex);

  NewHeader(LLocalHeader);

  SetupHeaderFlags(LLocalHeader);

  LLocalHeader^.CompressionMethod := UInt16(ACompression);
  LLocalHeader^.ModifiedDateTime := AFileDateTime.ToDosDateTime;
  LLocalHeader^.InternalAttributes := 0;
  LLocalHeader^.ExternalAttributes := 0;
  LLocalHeader^.FileName := StringToRaw(AArchiveName);
  LLocalHeader^.FileNameLength := Length(LLocalHeader^.FileName);
  LLocalHeader^.ExtraFieldLength := 0;
  
  // 写入扩展时间戳字段, 提供更精确的时间信息, 支持超过 2107 年的时间
  LLocalHeader^.ExtendedModTime := AFileDateTime;

  Result := AddStream(AFileStream, LLocalHeader, ACompressLevel, AStrategy);

  FChanged := True;
end;

function TCrossZip.AddFromStream(const AFileStream: TStream;
  const AArchiveName: string; const ACompression: TZipCompressionMethod;
  const ACompressLevel, AStrategy: Integer): Boolean;
begin
  Result := AddFromStream(
    AFileStream,
    Now,
    AArchiveName,
    ACompression,
    ACompressLevel,
    AStrategy);
end;

function TCrossZip.AddStream(const AData: TStream;
  const ALocalHeader: PZipHeader; const ACompressLevel, AStrategy: Integer): Boolean;

  procedure WriteLocalHeaderToStream;
  begin
    VerifyWrite(FZipStream, ALocalHeader^.RequiredVersion, SIZE_LOCAL_HEADER);
    if ALocalHeader^.FileNameLength > 0 then
      VerifyWrite(FZipStream, ALocalHeader^.FileName[0], ALocalHeader^.FileNameLength);
    if ALocalHeader^.ExtraFieldLength > 0 then
      VerifyWrite(FZipStream, ALocalHeader^.ExtraField[0], ALocalHeader^.ExtraFieldLength);
  end;

var
  LAESExtraField: TAESExtraField;
  LCompressStream: TStream;
  LSignature: UInt32;
  LDataSize, LStartPos, LRemained: Int64;
  LCompressedSize, LUncompressedSize: UInt64;
  LBlockSize: Integer;
begin
  FZipStream.Position := FEndFileData;

  if (ALocalHeader^.MadeByVersion < 20) then
    ALocalHeader^.MadeByVersion := 20;
  if (ALocalHeader^.RequiredVersion < 20) then
    ALocalHeader^.RequiredVersion := 20;

  if (TZipCompressionMethod(ALocalHeader.CompressionMethod) = zcAES) then
  begin
    // WinZip AES 条目的本地头和中心目录头 CompressionMethod 写 99,
    // 加密前的真实压缩方法写入 AES 扩展字段
    // Version: 1 表示 AE-1, 需要校验 CRC32; 2 表示 AE-2, CRC32 通常置 0 并依赖 AES 认证码
    LAESExtraField.Version := 1;
    // Vendor: WinZip AES 固定为 "AE" 的小端序编码 $4541
    LAESExtraField.Vendor := $4541;
    // EncryptionStrength: 1=AES128, 2=AES192, 3=AES256
    LAESExtraField.EncryptionStrength := 3;
    LAESExtraField.CompressionMethod := Ord(zcDeflate);
    SetExtraField(ALocalHeader^.ExtraField, EXID_AES, SizeOf(LAESExtraField), @LAESExtraField);
  end;

  ALocalHeader^.FileNameLength   := Length(ALocalHeader^.FileName);
  ALocalHeader^.ExtraFieldLength := Length(ALocalHeader^.ExtraField);

  LSignature := SIGNATURE_LOCAL_HEADER;
  // 写入本地头标志
  VerifyWrite(FZipStream, LSignature, SizeOf(LSignature));

  if (AData <> nil) then
    LDataSize := AData.Size - AData.Position
  else
    LDataSize := 0;

  // 在写入 ExtraField 之前先写入尺寸相关的几个字段
  // 如果文件大小超过 MAX_UINT32, 则会自动生成 zip64 相关的 ExtraField 数据
  ALocalHeader^.UncompressedSize := LDataSize;      // 压缩前的数据大小
  ALocalHeader^.CompressedSize := 0;                // 压缩后的数据大小(先写0占位)
  ALocalHeader^.LocalHeaderOffset := FEndFileData - FStartFileData;  // 该条数据在整个zip中的偏移量
  ALocalHeader^.CRC32 := 0;

  // 写入本地文件头, 有部分属性还需要等数据压缩后重新计算
  // 由于本地文件头是在 TZipHeader.RequiredVersion 开始连续的 SIZE_LOCAL_HEADER 个字节
  // 所以可以一条命令全部写入, 不需要每个属性单独写一次
  WriteLocalHeaderToStream;

  // 根据实际数据计算压缩后大小、未压缩大小、CRC32
  // 记录压缩数据流当前位置, 方便压缩数据写入后计算压缩大小
  LStartPos := FZipStream.Position;

  LCompressStream := CreateCompressStreamFromHandler(
    TZipCompressionMethod(ALocalHeader^.CompressionMethod),
    FZipStream, ALocalHeader, FPassword, ACompressLevel, AStrategy);
  try
    if (LDataSize > 0) then
    begin
      LRemained := LDataSize;
      while (LRemained > 0) do
      begin
        // 读取一块数据
        LBlockSize := AData.Read(FBuffer[0], Min(Length(FBuffer), LRemained));
        if (LBlockSize <= 0) then Break;

        // 计算原始的 CRC32 值
        ALocalHeader^.CRC32 := CRC32Calc(ALocalHeader^.CRC32, FBuffer[0], LBlockSize);

        // 写入压缩数据流
        LCompressStream.Write(FBuffer[0], LBlockSize);

        Dec(LRemained, LBlockSize);
      end;
    end;

    if LCompressStream is TDeflateCompressStream then
      TDeflateCompressStream(LCompressStream).Flush;
  finally
    FreeAndNil(LCompressStream);
  end;

  // 压缩后的数据大小
  ALocalHeader^.CompressedSize := FZipStream.Position - LStartPos;

  // 写入数据描述符
  //   -- 数据描述符标志($08074B50)
  //   -- CRC32(4字节)
  //   -- 压缩大小(4字节或8字节)
  //   -- 为压缩大小(4字节或8字节)
  if ALocalHeader.HasDataDescriptor then
  begin
    LCompressedSize := ALocalHeader.CompressedSize;
    LUncompressedSize := ALocalHeader.UncompressedSize;

    if (LCompressedSize >= MAX_UINT32) or (LUncompressedSize >= MAX_UINT32) then
      LBlockSize := SizeOf(UInt64)
    else
      LBlockSize := SizeOf(UInt32);

    VerifyWrite(FZipStream, SIGNATURE_DESCRIPTOR, SizeOf(SIGNATURE_DESCRIPTOR));
    VerifyWrite(FZipStream, ALocalHeader.CRC32, SizeOf(ALocalHeader.CRC32));
    VerifyWrite(FZipStream, LCompressedSize, LBlockSize);
    VerifyWrite(FZipStream, LUncompressedSize, LBlockSize);
  end;

  // 记录当前结束位置
  FEndFileData := FZipStream.Position;

  // 重新定位到本地头位置
  // LocalHeaderOffset实际是定位在本地头标志的位置
  // 所以需要定位到标志后面开始写本地头内容
  FZipStream.Position := FStartFileData + Int64(ALocalHeader^.LocalHeaderOffset) + SizeOf(UInt32){本地头标志大小};

  // 重新写入计算后的属性
  // 由于zip64的相关属性在 ExtraField 中, 所以也需要重新写入
  // 由于 ExtraField 保存在 FileName 之后, 所以要先写入 FileName
  WriteLocalHeaderToStream;

  FFileList.Add(ALocalHeader);

  Result := True;
end;

procedure TCrossZip.ClearFiles;
var
  I: Integer;
begin
  for I := FileCount - 1 downto 0 do
    FreeHeader(FFileList[I]);
  FFileList.Clear;
end;

procedure TCrossZip.Close;
begin
  if (FZipStream = nil) then Exit;
  
  Save;
  ClearFiles;

  // 文件名 Open 创建的内部文件流在 Close 中释放,
  // 防止外部代码在 Zip 对象释放前重新打开同一文件时被占用.
  if (FZipFileName <> '') then
  begin
    FZipFileName := '';
    if (FZipStream <> nil) then
      FreeAndNil(FZipStream);
  end;

  // 流 Open 传入且 AOwned=True 的流在 Close 中释放
  FreeOwnedStream;

  // 安全擦除密码
  if (FPassword <> nil) then
  begin
    FillChar(FPassword[0], Length(FPassword), 0);
    FPassword := nil;
  end;
end;

constructor TCrossZip.Create;
begin
  inherited;

  FFileList := TList<PZipHeader>.Create;
end;

function TCrossZip.Delete(const AArchiveIndex: Integer): Boolean;
var
  LZipHeader: PZipHeader;
  LTargetOffset: Int64;
  LSourceOffset: Int64;
  LFileIndex: Integer;
  LDeltaOffset: Int64;
  LFileOffset: UInt64;
begin
  Result := False;
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipNoWrite);

  if (AArchiveIndex < 0) or (AArchiveIndex >= FileCount) then Exit;

  LTargetOffset := FileInfo[AArchiveIndex].LocalHeaderOffset;

  LZipHeader := PZipHeader(FFileList[AArchiveIndex]);
  FFileList.Delete(AArchiveIndex);
  FreeHeader(LZipHeader);

  // 4.4.1.3  The entries in the central directory MAY NOT necessarily
  //      be in the same order that files appear in the .ZIP file.
  LSourceOffset := FEndFileData - FStartFileData;
  for LFileIndex := 0 to FileCount - 1 do
  begin
    LFileOffset := FileInfo[LFileIndex].LocalHeaderOffset;
    if (LFileOffset > LTargetOffset) and (LFileOffset < LSourceOffset) then
      LSourceOffset := LFileOffset;
  end;

  if (LSourceOffset < FEndFileData - FStartFileData) then
  begin
    // [....][LTargetOffset...][LSourceOffset....][...........][FEndFileData...]
    //       <----------------[.............................]
    MoveUp(FZipStream, FStartFileData + LSourceOffset, FStartFileData + LTargetOffset,
      FEndFileData - FStartFileData - LSourceOffset);
    LDeltaOffset := LSourceOffset - LTargetOffset;
    Dec(FEndFileData, LDeltaOffset);
    // Update LocalHeaderOffsets
    for LFileIndex := 0 to FileCount - 1 do
    begin
      LFileOffset := FileInfo[LFileIndex].LocalHeaderOffset;
      if LFileOffset > LTargetOffset then
      begin
        LFileOffset := LFileOffset - UInt64(LDeltaOffset);
        FileInfo[LFileIndex].LocalHeaderOffset := LFileOffset;
      end;
    end;
  end else
  begin
    // it was the last entry, just truncate FEndFileData
    FEndFileData := FStartFileData + LTargetOffset;
  end;

  FChanged := True;
  Result := True;
end;

function TCrossZip.Delete(const AArchiveName: string): Boolean;
begin
  Result := Delete(IndexOf(AArchiveName));
end;

destructor TCrossZip.Destroy;
begin
  Close;
  FreeAndNil(FFileList);

  inherited;
end;

procedure FinishAESIfNeeded(const AStream: TStream); forward;

function TCrossZip.ExtractToStream(const AArchiveIndex: Integer;
  const ADstStream: TStream): Boolean;
var
  LZipHeader: TZipHeader;
  LCentralHeader: PZipHeader;
  LSignature: UInt32;
  LDecompressStream: TStream;
  LRemained: Int64;
  LBlockSize: Integer;
  LCrc32: UInt32;
  LNeedCheckCrc32: Boolean;
  LFinishable: IZipFinishable;
begin
  Result := False;
  if (AArchiveIndex < 0)
    or (AArchiveIndex >= FileCount)
    or (ADstStream = nil) then Exit;

  LCentralHeader := FileInfo[AArchiveIndex];

  LZipHeader := Default(TZipHeader);

  // 定位到本地文件头
  FZipStream.Position := FStartFileData + Int64(LCentralHeader.LocalHeaderOffset);

  // 读取本地文件头标志
  VerifyRead(FZipStream, LSignature, Sizeof(LSignature));

  // 检查本地文件头标志
  if LSignature <> SIGNATURE_LOCAL_HEADER then
    raise EZipException.CreateRes(@SZipInvalidLocalHeader);

  // 读本地文件头
  VerifyRead(FZipStream, LZipHeader.RequiredVersion, SIZE_LOCAL_HEADER);

  // 读取文件名
  if (LZipHeader.FileNameLength > 0) then
  begin
    SetLength(LZipHeader.FileName, LZipHeader.FileNameLength);
    VerifyRead(FZipStream, LZipHeader.FileName[0], LZipHeader.FileNameLength);
  end;

  // 读取扩展信息
  if LZipHeader.ExtraFieldLength > 0 then
  begin
    SetLength(LZipHeader.ExtraField, LZipHeader.ExtraFieldLength);
    VerifyRead(FZipStream, LZipHeader.ExtraField[0], LZipHeader.ExtraFieldLength);
  end;

  // 如果启用了数据描述符
  // 本地文件头中的 CRC32,_CompressedSize,_UncompressedSize 可能会是 0
  // 需要从中心文件头中读取
  if LZipHeader.HasDataDescriptor then
  begin
    LZipHeader.CRC32 := LCentralHeader.CRC32;
    // 由于 zip64 的压缩大小和未压缩大小保存在扩展字段中,
    // 在调用 CompressedSize/UncompressedSize 属性读取大小时会自动从扩展字段中获取,
    // 无须在这里重新读取, 这里只需要重新读取32位的大小就行了
    LZipHeader._CompressedSize := LCentralHeader._CompressedSize;
    LZipHeader._UncompressedSize := LCentralHeader._UncompressedSize;
  end;

  if LZipHeader.IsDirectory then
  begin
    Result := True;
    Exit;
  end;

  // 创建解压数据流
  LDecompressStream := CreateDecompressStreamFromHandler(
    TZipCompressionMethod(LZipHeader.CompressionMethod),
    FZipStream, @LZipHeader, FPassword);

  if (LDecompressStream = nil) then
    raise EZipException.CreateRes(@SZipNotSupport);

  try
    if (ADstStream = nil)
      or LZipHeader.IsDirectory then Exit;

    // 7zip 生成的 aes zip 文件 crc32 部分是 0, 这种就没必要校验 crc32 了
    // 这也说得过去, 毕竟 aes zip 在数据结束部分有10字节的认证码, 可以进行数据完整性校验
    LNeedCheckCrc32 := (LZipHeader.CRC32 <> 0);
    LRemained := LZipHeader.UncompressedSize;

    LCrc32 := 0;
    while (LRemained > 0) do
    begin
      // 读取一块数据(读取的同时自动解压)
      LBlockSize := LDecompressStream.Read(FBuffer[0], Min(Length(FBuffer), LRemained));
      if (LBlockSize <= 0) then Break;

      // 计算原始的 CRC32 值
      if LNeedCheckCrc32 then
        LCrc32 := CRC32Calc(LCrc32, FBuffer[0], LBlockSize);

      // 写入解压后的数据
      ADstStream.Write(FBuffer[0], LBlockSize);

      Dec(LRemained, LBlockSize);
    end;

    if (LRemained <> 0) then
      raise EZipException.CreateRes(@SZipErrorRead);

    if LNeedCheckCrc32 and (LCrc32 <> LZipHeader.CRC32) then
      raise EZipException.CreateRes(@SZipCrcError);

    if Supports(LDecompressStream, IZipFinishable, LFinishable) then
      LFinishable.Finish;
  finally
    FreeAndNil(LDecompressStream);
  end;

  Result := True;
end;

function TCrossZip.ExtractToStream(const AArchiveName: string;
  const ADstStream: TStream): Boolean;
begin
  Result := ExtractToStream(IndexOf(AArchiveName), ADstStream);
end;

class procedure TCrossZip.FreeHeader(const AHeader: PZipHeader);
begin
  SetLength(AHeader^.FileName, 0);
  SetLength(AHeader^.ExtraField, 0);
  SetLength(AHeader^.FileComment, 0);
  System.Dispose(AHeader);
end;

procedure TCrossZip.FreeOwnedStream;
begin
  if FOwnedStream and (FZipStream <> nil) then
    FreeAndNil(FZipStream);
end;

procedure TCrossZip.ExtractAllToPath(const ADstPath: string);
var
  I: Integer;
begin
  for I := 0 to FileCount - 1 do
    ExtractToPath(I, ADstPath);
end;

function TCrossZip.ExtractToFile(const AArchiveIndex: Integer;
  const ADstFileName: string): Boolean;
var
  LOutStream: TStream;
  LOutputCreated: Boolean;

  procedure DeleteOutputFile;
  begin
    if LOutputCreated and FileExists(ADstFileName) then
      DeleteFile(ADstFileName);
  end;

begin
  Result := False;
  if (AArchiveIndex < 0) or (AArchiveIndex >= FileCount) then Exit;
  if FileInfo[AArchiveIndex].IsDirectory then Exit(True);

  LOutputCreated := False;
  try
    LOutStream := TFileStream.Create(ADstFileName, fmCreate);
    LOutputCreated := True;
    try
      Result := ExtractToStream(AArchiveIndex, LOutStream);
    finally
      FreeAndNil(LOutStream);
    end;
  except
    DeleteOutputFile;
    raise;
  end;

  if not Result then
    DeleteOutputFile;
end;

function TCrossZip.ExtractToFile(const AArchiveName, ADstFileName: string): Boolean;
begin
  Result := ExtractToFile(IndexOf(AArchiveName), ADstFileName);
end;

function TCrossZip.ExtractToPath(const AArchiveName, ADstPath: string;
  const ACreateSubdirs: Boolean): Boolean;
begin
  Result := ExtractToPath(IndexOf(AArchiveName), ADstPath, ACreateSubdirs);
end;

function TCrossZip.ExtractToPath(const AArchiveIndex: Integer;
  const ADstPath: string; const ACreateSubdirs: Boolean): Boolean;
var
  LZipHeader: PZipHeader;
  LIsDirectory: Boolean;
  LDir, LFileName, LDstFileName: string;
begin
  Result := False;
  if (AArchiveIndex < 0) or (AArchiveIndex >= FileCount) then Exit;

  LZipHeader := FileInfo[AArchiveIndex];
  LIsDirectory := LZipHeader.IsDirectory;

  // 如果这条数据是个目录, 并且参数传了不要创建子目录, 那什么都不用做了
  if LIsDirectory and not ACreateSubdirs then Exit(True);

  LFileName := FileNameToString(LZipHeader);
  if (LFileName = '') then Exit;

  if not BuildSafeExtractPath(ADstPath, LFileName, ACreateSubdirs, LDstFileName) then
    raise EZipException.CreateRes(@SZipInvalidExtractPath);

  LDir := ExtractFileDir(LDstFileName);
  if (LDir <> '') then
    ForceDirectories(LDir);

  // 如果这是个目录, 创建完目录之后就可以返回了
  // 因为目录本身没有文件数据
  if LIsDirectory then Exit(True);

  Result := ExtractToFile(AArchiveIndex, LDstFileName);
end;

function TCrossZip.GetComment: string;
begin
  Result := RawToString(FComment);
end;

function TCrossZip.GetFileComment(Index: Integer): string;
begin
  Result := FileCommentToString(FileInfo[Index]);
end;

function TCrossZip.GetFileCount: Integer;
begin
  Result := FFileList.Count;
end;

function TCrossZip.GetFileInfo(Index: Integer): PZipHeader;
begin
  Result := PZipHeader(FFileList[Index]);
end;

function TCrossZip.GetFileName(Index: Integer): string;
begin
  Result := FileNameToString(FileInfo[Index]);
end;

function TCrossZip.GetHasPassword: Boolean;
var
  I: Integer;
begin
  if (FPassword <> nil) then Exit(True);  

  for I := 0 to GetFileCount - 1 do
  begin
    if FileInfo[I]^.HasPassword then
      Exit(True);
  end;

  Result := False;
end;

function TCrossZip.GetPassword: string;
begin
  if (FPassword <> nil) then
    Result := TEncoding.UTF8.GetString(FPassword)
  else
    Result := '';
end;

function TCrossZip.GetUtf8: Boolean;
var
  I: Integer;
begin
  if FUtf8 then Exit(True);

  for I := 0 to GetFileCount - 1 do
  begin
    if FileInfo[I]^.IsUtf8FileName then
      Exit(True);
  end;

  Result := False;
end;

function TCrossZip.IndexOf(const AArchiveName: string): Integer;
begin
  Result := IndexOf(AArchiveName, False);
end;

function TCrossZip.IndexOf(const AArchiveName: string; const ACaseSensitive: Boolean): Integer;
var
  I: Integer;
  LFileName: string;
begin
  for I := 0 to FileCount - 1 do
  begin
    LFileName := FileNameToString(FileInfo[I]);
    if ACaseSensitive then
    begin
      if LFileName = AArchiveName then
        Exit(I);
    end else
    if SameText(LFileName, AArchiveName) then
      Exit(I);
  end;

  Result := -1;
end;

class procedure TCrossZip.NewHeader(var AHeader: PZipHeader);
begin
  System.New(AHeader);
  FillChar(AHeader^, SizeOf(AHeader^), 0);
end;

procedure TCrossZip.Open(const AZipFileStream: TStream;
  const AOpenMode: TZipMode; const AOwned: Boolean);
begin
  OpenStream(AZipFileStream, AOpenMode, AOwned, True);
end;

procedure TCrossZip.OpenStream(const AZipFileStream: TStream;
  const AOpenMode: TZipMode; const AOwned, AFreeOwnedOnError: Boolean);
begin
  // 先保存并关闭老的数据
  Close;

  FZipStream := AZipFileStream;
  FOpenMode := AOpenMode;
  FOwnedStream := AOwned;
  FChanged := False;

  FStartFileData := FZipStream.Position;
  FEndFileData := FStartFileData;
  if AOpenMode in [zmRead, zmReadWrite] then
  try
    // 读取中心目录文件头, 确定是不是有效的zip文件
    ReadCentralHeader;
  except
    ClearFiles;
    FChanged := False;
    FOpenMode := zmRead;
    FStartFileData := 0;
    FEndFileData := 0;
    if AOwned and AFreeOwnedOnError and (FZipStream <> nil) then
      FreeAndNil(FZipStream)
    else
      FZipStream := nil;
    FOwnedStream := False;
    raise;
  end;
end;

procedure TCrossZip.Open(const AZipFileName: string;
  const AOpenMode: TZipMode);
var
  LMode: LongInt;
  LFileStream: TFileStream;
begin
  case AOpenMode of
    zmRead:      LMode := fmOpenRead or fmShareDenyWrite;
    zmReadWrite: LMode := fmOpenReadWrite or fmShareDenyWrite;
    zmCreate:    LMode := fmCreate or fmShareDenyWrite;
  else
    raise EZipException.CreateRes(@SZipInvalidMode);
  end;

  LFileStream := TFileStream.Create(AZipFileName, LMode);
  try
    OpenStream(LFileStream, AOpenMode, True, False);
    LFileStream := nil;
    FZipFileName := AZipFileName;
  except
    FreeAndNil(LFileStream);
    raise;
  end;
end;

function TCrossZip.FileCommentToString(const AHeader: PZipHeader): string;
var
  LComment: string;
begin
  if (AHeader <> nil)
    and not AHeader^.IsUtf8FileName
    and TryGetUnicodeExtraFieldText(
      AHeader^.ExtraField,
      AHeader^.FileComment,
      EXID_UNICODE_COMMENT,
      LComment) then Exit(LComment);

  if AHeader <> nil then
    Result := RawToString(AHeader^.FileComment, AHeader^.IsUtf8FileName)
  else
    Result := '';
end;

function TCrossZip.FileNameToString(const AHeader: PZipHeader): string;
var
  LName: string;
begin
  if (AHeader <> nil)
    and not AHeader^.IsUtf8FileName
    and TryGetUnicodeExtraFieldText(
      AHeader^.ExtraField,
      AHeader^.FileName,
      EXID_UNICODE_PATH,
      LName) then Exit(LName);

  if AHeader <> nil then
    Result := RawToString(AHeader^.FileName, AHeader^.IsUtf8FileName)
  else
    Result := '';
end;

function TCrossZip.RawToString(const ARaw: TBytes): string;
begin
  Result := RawToString(ARaw, Utf8);
end;

function TCrossZip.RawToString(const ARaw: TBytes; const AIsUtf8: Boolean): string;
begin
  if AIsUtf8 then
    Result := TEncoding.UTF8.GetString(ARaw)
  else
    Result := TEncoding.Default.GetString(ARaw);
end;

procedure TCrossZip.SetupHeaderFlags(const AHeader: PZipHeader);
begin
  AHeader^.Flag := 0;
  if Utf8 then
    AHeader^.Flag := AHeader^.Flag or FLAG_UTF8;
  if HasPassword then
  begin
    AHeader^.Flag := AHeader^.Flag or FLAG_PASSWORD;

    // 设置 FLAG_DATA_DESCRIPTOR 标志让加密头不需要使用 CRC32 做校验码
    // 这样可以方便一边读取数据一边计算 CRC32, 提高性能
    AHeader^.Flag := AHeader^.Flag or FLAG_DATA_DESCRIPTOR;
  end;
end;

procedure TCrossZip.ReadCentralHeader;
var
  I: UInt64;
  LSignature: UInt32;
  LEndHeader: TZipEndOfCentralHeader;
  LEndHeader64: TZip64EndOfCentralHeader;
  LHeader64: TZip64Header;
  LCentralDirEntries: UInt64;
  LHeader: PZipHeader;
begin
  ClearFiles;
  if FZipStream.Size = 0 then Exit;

  // 搜索结束文件头
  if not LocateEndOfCentralHeader(FZipStream, LEndHeader) then
    raise EZipException.CreateRes(@SZipInvalidZip);

  // 检查是不是ZIP64文件
  if IsZip64EndOfCentralHeader(LEndHeader) then
  begin
    VerifyRead(FZipStream, LEndHeader64.Signature, SizeOf(LEndHeader64));
    if (LEndHeader64.Signature <> SIGNATURE_ZIP64_END_HEADER) then
      raise EZipException.CreateRes(@SZipInvalidZip);
    FZipStream.Position := FStartFileData + Int64(LEndHeader64.Zip64CentralDirOffset);
    VerifyRead(FZipStream, LHeader64.Signature, SizeOf(TZip64Header));
    if (LHeader64.Signature <> SIGNATURE_ZIP64_CENTRAL_HEADER) then
      raise EZipException.CreateRes(@SZipInvalidZip);

    // 结束文件头中包含了中心文件头偏移
    // 根据该属性定位到中心文件头
    FZipStream.Position := FStartFileData + Int64(LHeader64.CentralDirOffset);
    FEndFileData := FStartFileData + Int64(LHeader64.CentralDirOffset);
    LCentralDirEntries := LHeader64.CentralDirEntries;
  end else begin
    // 结束文件头中包含了中心文件头偏移
    // 根据该属性定位到中心文件头
    FZipStream.Position := FStartFileData + Int64(LEndHeader.CentralDirOffset);
    FEndFileData := FStartFileData + Int64(LEndHeader.CentralDirOffset);
    LCentralDirEntries := LEndHeader.CentralDirEntries;
  end;

  for I := 0 to LCentralDirEntries - 1 do
  begin
    VerifyRead(FZipStream, LSignature, Sizeof(LSignature));
    // 检查中心目录文件头标志
    if (LSignature <> SIGNATURE_CENTRAL_HEADER) then
      raise EZipException.CreateRes(@SZipInvalidCentralHeader);

    NewHeader(LHeader);
    try
      // 读中心目录文件头
      VerifyRead(FZipStream, LHeader^.MadeByVersion, SIZE_CENTRAL_HEADER);

      // 读文件名
      if (LHeader^.FileNameLength > 0) then
      begin
        SetLength(LHeader^.FileName, LHeader^.FileNameLength);
        VerifyRead(FZipStream, LHeader^.FileName[0], LHeader^.FileNameLength);
      end;

      // 读扩展信息
      if (LHeader^.ExtraFieldLength > 0) then
      begin
        SetLength(LHeader^.ExtraField, LHeader^.ExtraFieldLength);
        VerifyRead(FZipStream, LHeader^.ExtraField[0], LHeader^.ExtraFieldLength);
      end;

      // 读文件注释
      if (LHeader^.FileCommentLength > 0) then
      begin
        SetLength(LHeader^.FileComment, LHeader^.FileCommentLength);
        VerifyRead(FZipStream, LHeader^.FileComment[0], LHeader^.FileCommentLength);
      end;

    except
      FreeHeader(LHeader);
      raise;
    end;
    FFileList.Add(LHeader);
  end;
end;

procedure TCrossZip.Save;
var
  LHeader: PZipHeader;
  LEndOfHeader: TZipEndOfCentralHeader;
  LHeader64: TZip64Header;
  LEndHeader64: TZip64EndOfCentralHeader;
  I: Integer;
  LSignature: UInt32;
  LCentralDirOffset: UInt64;
  LCentralDirSize: UInt64;
  LNeedZip64: Boolean;
begin
  if not FChanged
    or not (FOpenMode in [zmReadWrite, zmCreate])
    or (FZipStream = nil) then Exit;

  FZipStream.Position := FEndFileData;
  LSignature := SIGNATURE_CENTRAL_HEADER;

  // 写入中心目录文件头
  for I := 0 to FileCount - 1 do
  begin
    LHeader := FileInfo[I];

    // 写入中心目录文件头标志
    VerifyWrite(FZipStream, LSignature, SizeOf(LSignature));

    // 由于中心目录文件头是在 TZipHeader.MadeByVersion 开始连续的 SIZE_CENTRAL_HEADER 个字节
    // 所以可以一条命令全部写入, 不需要每个属性单独写一次
    VerifyWrite(FZipStream, LHeader^.MadeByVersion, SIZE_CENTRAL_HEADER);

    // 写入文件名
    if (LHeader^.FileNameLength > 0) then
      VerifyWrite(FZipStream, LHeader^.FileName[0], LHeader^.FileNameLength);

    // 写入扩展信息
    if (LHeader^.ExtraFieldLength > 0) then
      VerifyWrite(FZipStream, LHeader^.ExtraField[0], LHeader^.ExtraFieldLength);

    // 写入注释
    if (LHeader^.FileCommentLength > 0) then
      VerifyWrite(FZipStream, LHeader^.FileComment[0], LHeader^.FileCommentLength);
  end;

  // 生成中心目录结束头
  FillChar(LEndOfHeader, Sizeof(LEndOfHeader), 0);
  LCentralDirOffset := FEndFileData - FStartFileData;
  LCentralDirSize := FZipStream.Position - FEndFileData;
  LNeedZip64 := (FileCount >= MAX_UINT16)
    or (LCentralDirSize >= MAX_UINT32)
    or (LCentralDirOffset >= MAX_UINT32);

  if not LNeedZip64 then
  begin
    for I := 0 to FileCount - 1 do
    begin
      LNeedZip64 := GetExtraField(FileInfo[I]^.ExtraField, EXID_ZIP64, 0, nil) > 0;
      if LNeedZip64 then Break;
    end;
  end;

  // 如果是 zip64 则需要写入相关的扩展信息
  if LNeedZip64 then
  begin
    LHeader64.Signature := SIGNATURE_ZIP64_CENTRAL_HEADER;
    LHeader64.HeaderSize := 44;
    LHeader64.MadeByVersion := 45;
    LHeader64.RequiredVersion := 45;
    LHeader64.NumberOfDisks := 0;
    LHeader64.CentralDirStartDisk := 0;
    LHeader64.NumEntriesThisDisk := FileCount;
    LHeader64.CentralDirEntries := FileCount;
    LHeader64.CentralDirSize := LCentralDirSize;
    LHeader64.CentralDirOffset := LCentralDirOffset;

    LEndHeader64.Signature := SIGNATURE_ZIP64_END_HEADER;
    LEndHeader64.CentralDirStartDisk := 0;
    LEndHeader64.Zip64CentralDirOffset := FZipStream.Position - FStartFileData;
    LEndHeader64.TotalNumberOfDisks := 1;

    VerifyWrite(FZipStream, LHeader64, SizeOf(LHeader64));
    VerifyWrite(FZipStream, LEndHeader64, SizeOf(LEndHeader64));

    if (FileCount >= MAX_UINT16) then
    begin
      LEndOfHeader.CentralDirEntries := MAX_UINT16;
      LEndOfHeader.NumEntriesThisDisk := MAX_UINT16;
    end else
    begin
      LEndOfHeader.CentralDirEntries := FileCount;
      LEndOfHeader.NumEntriesThisDisk := FileCount;
    end;
    if (LCentralDirSize >= MAX_UINT32) then
      LEndOfHeader.CentralDirSize := MAX_UINT32
    else
      LEndOfHeader.CentralDirSize := UInt32(LCentralDirSize);
    if (LCentralDirOffset >= MAX_UINT32) then
      LEndOfHeader.CentralDirOffset := MAX_UINT32
    else
      LEndOfHeader.CentralDirOffset := UInt32(LCentralDirOffset);
  end else begin
    LEndOfHeader.CentralDirEntries := FileCount;
    LEndOfHeader.NumEntriesThisDisk := FileCount;
    LEndOfHeader.CentralDirSize := UInt32(LCentralDirSize);
    LEndOfHeader.CentralDirOffset := UInt32(LCentralDirOffset);
  end;

  // 注释最大 65535 字节
  if (Length(FComment) > MAX_COMMENT_SIZE) then
    SetLength(FComment, MAX_COMMENT_SIZE);
  LEndOfHeader.CommentLength := Length(FComment);

  LSignature := SIGNATURE_END_HEADER;
  // 写入中心目录结束标志
  VerifyWrite(FZipStream, LSignature, SizeOf(LSignature));

  // 写入中心目录结束头
  VerifyWrite(FZipStream, LEndOfHeader.DiskNumber, SIZE_END_HEADER);

  // 写入注释
  if (LEndOfHeader.CommentLength > 0) then
    VerifyWrite(FZipStream, FComment[0], LEndOfHeader.CommentLength);

  // 修正数据流大小
  // 因为如果执行了Delete操作, zip数据流后面会出现一段多余的数据
  // 需要在保存的时候将数据流的大小调整为实际数据大小
  FZipStream.Size := FZipStream.Position;

  FChanged := False;
end;

function TCrossZip.LocateEndOfCentralHeader(const AStream: TStream;
  var AZipEndHeader: TZipEndOfCentralHeader): Boolean;
var
  LEndHeaderAndSignatureSize, LBackRead, LMaxBack, LReadSize, I: Integer;
  LBackBuf: TBytes;
begin
  Result := False;

  // 中心目录结束标志 + Zip 中心目录结束头
  LEndHeaderAndSignatureSize := SizeOf(SIGNATURE_END_HEADER) + SizeOf(TZipEndOfCentralHeader);

  // 从文件尾部最多往回找(注释 + 中心目录结束头 + 中心目录结束标志)个字节
  LMaxBack := MAX_COMMENT_SIZE + LEndHeaderAndSignatureSize;
  if (LMaxBack > AStream.Size) then
    LMaxBack := AStream.Size;

  // 如果能读取的部分比结束头加结束标志还小, 说明这是个无效的zip文件
  if (LMaxBack < LEndHeaderAndSignatureSize) then Exit;

  // 每次最多读取50倍(中心目录结束头 + 中心目录结束标志)个字节
  // 多读一点减少磁盘操作, 提升性能
  SetLength(LBackBuf, 50 * LEndHeaderAndSignatureSize);
  LBackRead := SizeOf(SIGNATURE_END_HEADER);
  while (LBackRead < LMaxBack) do
  begin
    // 下一块数据与上一块数据重叠 LEndHeaderAndSignatureSize 个字节
    // 这样可以保证不会漏掉标志
    Inc(LBackRead, Length(LBackBuf) - LEndHeaderAndSignatureSize);
    if (LBackRead > LMaxBack) then
      LBackRead := LMaxBack;

    AStream.Position := AStream.Size - LBackRead;

    // 计算可以读取的数据块大小
    LReadSize := AStream.Size - AStream.Position;
    if (LReadSize > Length(LBackBuf)) then
      LReadSize := Length(LBackBuf);

    // 读数据块
    VerifyRead(AStream, LBackBuf[0], LReadSize);

    // 查找结束标志
    for I := LReadSize - LEndHeaderAndSignatureSize downto 0 do
    begin
      // 检查结束文件头标志
      if (PCardinal(@LBackBuf[I])^ = SIGNATURE_END_HEADER) then
      begin
        // 复制结束文件头
        // 结束文件头中不包含结束标志, 所以在标志处要往后偏移 SizeOf(SIGNATURE_END_HEADER)
        Move(LBackBuf[I + SizeOf(SIGNATURE_END_HEADER)], AZipEndHeader, SIZE_END_HEADER);

        // 读取zip注释
        if (AZipEndHeader.CommentLength > 0) then
        begin
          AStream.Position := AStream.Size - LBackRead + I + LEndHeaderAndSignatureSize;
          if (AStream.Size - AStream.Position < AZipEndHeader.CommentLength) then Exit;
          SetLength(FComment, AZipEndHeader.CommentLength);
          VerifyRead(AStream, FComment[0], AZipEndHeader.CommentLength);
        end else
          SetLength(FComment, 0);

        // 检查是不是ZIP64文件
        if IsZip64EndOfCentralHeader(AZipEndHeader) then
        begin
          // AStream.Size - LBackRead 是当前这块数据的偏移位置
          // 再 +I, 就是 SIGNATURE_END_HEADER 所在的位置
          // 再 - SizeOf(TZip64EndOfCentralHeader), 就是 ZIP64 中心目录定位器所在的位置了
          AStream.Position := AStream.Size - LBackRead + I - SizeOf(TZip64EndOfCentralHeader);
        end;

        Exit(True);
      end;
    end;
  end;
end;

procedure TCrossZip.SetComment(const Value: string);
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipInvalideModeSetProp);

  FComment := StringToRaw(Value);
  FChanged := True;
end;

procedure TCrossZip.SetFileComment(Index: Integer; const Value: string);
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipInvalideModeSetProp);

  FileInfo[Index]^.FileComment := StringToRaw(Value);
  FileInfo[Index]^.FileCommentLength := Length(FileInfo[Index]^.FileComment);
  FChanged := True;
end;

procedure TCrossZip.SetPassword(const Value: string);
begin
  FPassword := TEncoding.UTF8.GetBytes(Value);
end;

procedure TCrossZip.SetUtf8(const Value: Boolean);
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipInvalideModeSetProp);

  if (FUtf8 = Value) then Exit;
  FUtf8 := Value;
  FChanged := True;
end;

function TCrossZip.StringToRaw(const AStr: string): TBytes;
begin
  if FUtf8 then
    Result := TEncoding.UTF8.GetBytes(AStr)
  else
    Result := TEncoding.Default.GetBytes(AStr);
end;

{ TZipDefaultCompressionHandler }

class function TZipDefaultCompressionHandler.CanHandleCompressionMethod(
  const AMethod: TZipCompressionMethod): Boolean;
begin
  Result := AMethod in [zcStored, zcDeflate, zcAES];
end;

class function TZipDefaultCompressionHandler.CreateCompressionStream(
  const AMethod: TZipCompressionMethod; const AOutStream: TStream;
  const AZipHeader: PZipHeader; const APassword: TBytes;
  const ACompressLevel, AStrategy: Integer): TStream;
const
  KB = 1024;
  MB = 1024*1024;

  procedure GetOptimalDeflateParams(const AFileSize: Int64;
    out AWindowBits, AMemLevel: Integer);
  begin
    case AFileSize of
      0..64*KB:         // < 64KB
      begin
        AWindowBits := -12;  // 4KB窗口
        AMemLevel := 1;      // 2KB内存
      end;

      64*KB+1..512*KB:  // 64KB - 512KB
      begin
        AWindowBits := -13;  // 8KB窗口
        AMemLevel := 6;      // 64KB内存
      end;

      512*KB+1..10*MB:  // 512KB - 10MB
      begin
        AWindowBits := -14; // 16KB窗口
        AMemLevel := 8;     // 256KB内存
      end;

    else  // > 10MB
      AWindowBits := -15;   // 32KB窗口
      AMemLevel := 9;       // 512KB内存
    end;
  end;

var
  LOutStream: TStream;
  LWindowBits, LMemLevel: Integer;
  LAESExtraField: TAESExtraField;
begin
  Result := nil;

  // 根据压缩方法确定使用什么方式压缩
  case AMethod of
    zcStored:
      begin
        if AZipHeader^.HasPassword then
          LOutStream := TZipCryptoEncryptStream.Create(AOutStream, APassword, AZipHeader)
        else
          LOutStream := AOutStream;

        Result := TStoredStream.Create(LOutStream, (LOutStream <> AOutStream));
      end;

    zcDeflate:
      begin
        if AZipHeader^.HasPassword then
          LOutStream := TZipCryptoEncryptStream.Create(AOutStream, APassword, AZipHeader)
        else
          LOutStream := AOutStream;

        GetOptimalDeflateParams(AZipHeader.UncompressedSize, LWindowBits, LMemLevel);
        Result := TDeflateCompressStream.Create(
          LOutStream,
          (LOutStream <> AOutStream),
          ACompressLevel,
          LWindowBits,
          LMemLevel,
          AStrategy);
      end;

    zcAES:
      begin
        // 从扩展字段中提取 AES 扩展信息
        // Header 中的 CompressionMethod=99 仅表示 WinZip AES, 真实压缩方法保存在 AES 扩展字段
        if (GetExtraField(
          AZipHeader.ExtraField,
          EXID_AES,
          SizeOf(TAESExtraField),
          @LAESExtraField) <> SizeOf(TAESExtraField)) then
          raise EZipException.CreateRes(@SZipInvalidAESExtraField);

        // 根据 AES 扩展信息中的压缩方法确定使用什么方式压缩
        case TZipCompressionMethod(LAESExtraField.CompressionMethod) of
          zcStored:
            begin
              // AES 加密数据流
              LOutStream := TZipAESEncryptStream.Create(AOutStream, APassword, AZipHeader, LAESExtraField);
              Result := TStoredStream.Create(LOutStream, (LOutStream <> AOutStream));
            end;

          zcDeflate:
            begin
              // AES 加密数据流
              LOutStream := TZipAESEncryptStream.Create(AOutStream, APassword, AZipHeader, LAESExtraField);
              GetOptimalDeflateParams(AZipHeader.UncompressedSize, LWindowBits, LMemLevel);
              Result := TDeflateCompressStream.Create(
                LOutStream,
                (LOutStream <> AOutStream),
                ACompressLevel,
                LWindowBits,
                LMemLevel,
                AStrategy);
            end;
        end;
      end;
  end;
end;

class function TZipDefaultCompressionHandler.CreateDecompressionStream(
  const AMethod: TZipCompressionMethod; const AInStream: TStream;
  const AZipHeader: PZipHeader; const APassword: TBytes): TStream;
var
  LInStream: TStream;
  LAESExtraField: TAESExtraField;
begin
  Result := nil;

  // 根据压缩方法确定使用什么方式解压
  case AMethod of
    zcStored:
      begin
        if AZipHeader^.HasPassword then
          LInStream := TZipCryptoDecryptStream.Create(AInStream, APassword, AZipHeader)
        else
          LInStream := AInStream;

        Result := TStoredStream.Create(LInStream, (LInStream <> AInStream));
      end;

    zcDeflate:
      begin
        if AZipHeader^.HasPassword then
          LInStream := TZipCryptoDecryptStream.Create(AInStream, APassword, AZipHeader)
        else
          LInStream := AInStream;

        Result := TDeflateDecompressStream.Create(LInStream, (LInStream <> AInStream));
      end;

    zcAES:
      begin
        // 从扩展字段中提取 AES 扩展信息
        // Header 中的 CompressionMethod=99 仅表示 WinZip AES, 真实压缩方法保存在 AES 扩展字段
        if (GetExtraField(
          AZipHeader.ExtraField,
          EXID_AES,
          SizeOf(TAESExtraField),
          @LAESExtraField) <> SizeOf(TAESExtraField)) then
          raise EZipException.CreateRes(@SZipInvalidAESExtraField);

        // 根据 AES 扩展信息中的压缩方法确定使用什么方式解压
        case TZipCompressionMethod(LAESExtraField.CompressionMethod) of
          zcStored:
            begin
              // AES 解密数据流
              LInStream := TZipAESDecryptStream.Create(AInStream, APassword, AZipHeader, LAESExtraField);
              Result := TStoredStream.Create(LInStream, (LInStream <> AInStream));
            end;

          zcDeflate:
            begin
              // AES 解密数据流
              LInStream := TZipAESDecryptStream.Create(AInStream, APassword, AZipHeader, LAESExtraField);
              Result := TDeflateDecompressStream.Create(LInStream, (LInStream <> AInStream));
            end;
        end;
      end;
  end;
end;

{ TStoredStream }

constructor TStoredStream.Create(const AStream: TStream;
  const AOwner: Boolean);
begin
  inherited Create;

  FOwner := AOwner;
  FStream := AStream;
end;

destructor TStoredStream.Destroy;
begin
  if FOwner then
    FreeAndNil(FStream);

  inherited;
end;

procedure FinishAESIfNeeded(const AStream: TStream);
begin
  if AStream is TZipAESDecryptStream then
    TZipAESDecryptStream(AStream).Finish;
end;

procedure TStoredStream.Finish;
begin
  FinishAESIfNeeded(FStream);
end;

function TStoredStream.QueryInterface({$IFDEF FPC}constref{$ELSE}const{$ENDIF} IID: TGUID; out Obj): HResult;
begin
  if GetInterface(IID, Obj) then
    Result := S_OK
  else
    Result := E_NOINTERFACE;
end;

function TStoredStream._AddRef: LongInt;
begin
  Result := -1;
end;

function TStoredStream._Release: LongInt;
begin
  Result := -1;
end;

function TStoredStream.Read(var Buffer; Count: Integer): Longint;
begin
  Result := FStream.Read(Buffer, Count);
end;

function TStoredStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  Result := FStream.Seek(Offset, Origin);
end;

function TStoredStream.Write(const Buffer; Count: Integer): Longint;
begin
  Result := FStream.Write(Buffer, Count);
end;

{ TCustomDeflateStream }

constructor TCustomDeflateStream.Create(const AStream: TStream;
  const AOwner: Boolean);
begin
  inherited Create;

  FOwner := AOwner;
  FStream := AStream;
  FStreamStartPos := AStream.Position;
  FStreamPos := FStreamStartPos;
end;

destructor TCustomDeflateStream.Destroy;
begin
  if FOwner then
    FreeAndNil(FStream);
  inherited;
end;

{ TDeflateCompressStream }

constructor TDeflateCompressStream.Create(const AStream: TStream;
  const AOwner: Boolean; const ACompressLevel, AWindowBits, AMemLevel, AStrategy: Integer);
var
  LZResult: Integer;
begin
  inherited Create(AStream, AOwner);

  FZStream.next_out := @FBuffer[0];
  FZStream.avail_out := Length(FBuffer);

(*
  *** deflateInit2参数说明 ***

int level
  作用：压缩级别, 控制压缩速度与压缩率的权衡。

  取值范围：
  Z_NO_COMPRESSION (0)：不压缩, 仅复制数据。
  Z_BEST_SPEED (1)：最快压缩, 但压缩率最低。
  Z_BEST_COMPRESSION (9)：最高压缩率, 但速度最慢。
  Z_DEFAULT_COMPRESSION (-1)：默认平衡(通常等价于6)。

  典型场景：
  实时传输：使用低级别(1-3)。
  存储归档：使用高级别(7-9)。


int method
  作用：指定压缩算法。
  唯一有效值：Z_DEFLATED (8), 对应 DEFLATE 算法(基于LZ77和哈夫曼编码)。
  其他值：理论上允许扩展其他方法, 但 zlib 仅支持 Z_DEFLATED。


int windowBits
  作用：设置滑动窗口大小(以2为底的对数值), 影响压缩率和内存占用。

  取值范围：
  常规模式：8 到 15(窗口大小为2^windowBits字节)。
  例如, windowBits=15 表示窗口大小 32KB(2^15=32768)。

  gzip 模式：在常规值基础上加 16(如 15+16=31), 生成 gzip 格式的头部和尾部。
  原始模式：取负值(如 -15), 禁用 zlib 头部校验, 生成纯 DEFLATE 数据流。

  内存影响：
  每增加1, 窗口大小翻倍, 内存占用也近似翻倍。
  默认值 15(常规模式)或 31(gzip 模式)。


int memLevel
  作用：控制内部压缩状态的内存使用量(以2为底的对数值)。

  取值范围：1 到 9(内存为2^memLevelKB)。
  默认值 8(256KB)。
  值越大, 压缩速度可能越快(更多内存用于哈希表), 但内存消耗增加。

  典型建议：
  内存受限环境：使用 1(2KB)或 8(256KB)。
  高性能场景：使用 9(512KB)。


int strategy
  作用：调整压缩算法策略, 优化特定类型数据。

  可选值：
  Z_DEFAULT_STRATEGY (0)：通用数据(默认)。
  Z_FILTERED (1)：过滤后的数据(如文本中存在大量重复字符)。
  Z_HUFFMAN_ONLY (2)：仅使用哈夫曼编码, 禁用LZ77匹配(适用于不可压缩数据)。
  Z_RLE (3)：游程编码优化(适用于包含连续重复字节的数据, 如简单图像)。
  Z_FIXED (4)：使用固定哈夫曼表(减少动态表开销, 适合小数据或低熵数据)。

  应用示例：
  文本日志：Z_FILTERED 或 Z_DEFAULT_STRATEGY。
  PNG图像：Z_RLE 可能更高效。
*)
  LZResult := deflateInit2(
    FZStream,
    ACompressLevel,
    Z_DEFLATED,
    AWindowBits,
    AMemLevel,
    AStrategy
  );
  if (LZResult <> Z_OK) then
    raise EZipException.CreateResFmt(@SZipDeflateCompressError, [LZResult]);
  FZInitialized := True;
end;

destructor TDeflateCompressStream.Destroy;
begin
  try
    if FZInitialized then
    begin
      deflateEnd(FZStream);
      FZInitialized := False;
    end;
  finally
    inherited;
  end;
end;

procedure TDeflateCompressStream.Flush;
var
  LZResult: Integer;
  LOutSize: Integer;
begin
  if not FZInitialized then Exit;

  FZStream.next_in := nil;
  FZStream.avail_in := 0;

  try
    if (FStream.Position <> FStreamPos) then
      FStream.Position := FStreamPos;

    repeat
      LZResult := deflate(FZStream, Z_FINISH);
      if (LZResult <> Z_OK) and (LZResult <> Z_STREAM_END) then
        raise EZipException.CreateResFmt(@SZipDeflateCompressError, [LZResult]);

      LOutSize := Length(FBuffer) - Integer(FZStream.avail_out);
      if (LOutSize > 0) then
        FStream.WriteBuffer(FBuffer, LOutSize);

      FZStream.next_out := @FBuffer[0];
      FZStream.avail_out := Length(FBuffer);
    until (LZResult = Z_STREAM_END);
  finally
    deflateEnd(FZStream);
    FZInitialized := False;
  end;
end;

function TDeflateCompressStream.Read(var Buffer; Count: Longint): Longint;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

function TDeflateCompressStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

function TDeflateCompressStream.Write(const Buffer; Count: Longint): Longint;
var
  LZResult: Integer;
begin
  FZStream.next_in := @Buffer;
  FZStream.avail_in := Count;

  while (FZStream.avail_in > 0) do
  begin
    LZResult := deflate(FZStream, Z_NO_FLUSH);
    if (LZResult < 0) then
      raise EZipException.CreateResFmt(@SZipDeflateCompressError, [LZResult]);

    if (FZStream.avail_out = 0) then
    begin
      if (FStream.Position <> FStreamPos) then
        FStream.Position := FStreamPos;
      FStream.WriteBuffer(FBuffer, Length(FBuffer));
      Inc(FStreamPos, Length(FBuffer));

      FZStream.next_out := @FBuffer[0];
      FZStream.avail_out := Length(FBuffer);
    end;
  end;

  Result := Count;
end;

{ TDeflateDecompressStream }

constructor TDeflateDecompressStream.Create(const AStream: TStream;
  const AOwner: Boolean);
var
  LZResult: Integer;
begin
  inherited Create(AStream, AOwner);

  FZStream.next_in := @FBuffer[0];
  FZStream.avail_in := 0;

  LZResult := inflateInit2(
    FZStream,
    -15);
  if (LZResult <> Z_OK) then
    raise EZipException.CreateResFmt(@SZipDeflateDecompressError, [LZResult]);
  FZInitialized := True;
end;

destructor TDeflateDecompressStream.Destroy;
begin
  try
    if FZInitialized then
    begin
      inflateEnd(FZStream);
      FZInitialized := False;
    end;
    FStream.Position := FStreamPos - FZStream.avail_in;
  finally
    inherited;
  end;
end;

procedure TDeflateDecompressStream.Finish;
begin
  FinishAESIfNeeded(FStream);
end;

function TDeflateDecompressStream.QueryInterface({$IFDEF FPC}constref{$ELSE}const{$ENDIF} IID: TGUID; out Obj): HResult;
begin
  if GetInterface(IID, Obj) then
    Result := S_OK
  else
    Result := E_NOINTERFACE;
end;

function TDeflateDecompressStream._AddRef: LongInt;
begin
  Result := -1;
end;

function TDeflateDecompressStream._Release: LongInt;
begin
  Result := -1;
end;

function TDeflateDecompressStream.Read(var Buffer; Count: Longint): Longint;
var
  LZResult: Integer;
begin
  FZStream.next_out := @Buffer;
  FZStream.avail_out := Count;

  LZResult := Z_OK;

  while (FZStream.avail_out > 0)
    and (LZResult <> Z_STREAM_END)
    and (LZResult <> Z_BUF_ERROR) do
  begin
    if (FZStream.avail_in = 0) then
    begin
      if (FStream.Position <> FStreamPos) then
        FStream.Position := FStreamPos;
      FZStream.avail_in := FStream.Read(FBuffer, Length(FBuffer));
      Inc(FStreamPos, FZStream.avail_in);

      FZStream.next_in := @FBuffer[0];
    end;

    LZResult := inflate(FZStream, Z_NO_FLUSH);
    if (LZResult < 0) then
      raise EZipException.CreateResFmt(@SZipDeflateDecompressError, [LZResult]);
  end;

  if (LZResult = Z_STREAM_END) and (FZStream.avail_in > 0) then
  begin
    Dec(FStreamPos, FZStream.avail_in);

    FZStream.avail_in := 0;
  end;

  Result := NativeUInt(Count) - FZStream.avail_out;
end;

function TDeflateDecompressStream.Seek(const Offset: Int64;
  Origin: TSeekOrigin): Int64;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

function TDeflateDecompressStream.Write(const Buffer; Count: Longint): Longint;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

{ TZipCrypto }

function TZipCrypto.CalcDecryptByte: UInt8;
var
  T: UInt16;
begin
  T := FKey2 or 2;
  Result := UInt16(T * (T xor 1)) shr 8;
end;

procedure TZipCrypto.Decrypt(AData: PByte; ASize: Integer);
var
  I: Integer;
begin
  for I := 0 to ASize - 1 do
    DecryptByte(AData[I]);
end;

procedure TZipCrypto.DecryptByte(var Value: UInt8);
begin
  Value := Value xor CalcDecryptByte;
  UpdateKeys(Value);
end;

procedure TZipCrypto.Encrypt(AData: PByte; ASize: Integer);
var
  I: Integer;
begin
  for I := 0 to ASize - 1 do
    EncryptByte(AData[I]);
end;

procedure TZipCrypto.EncryptByte(var Value: UInt8);
var
  T: UInt8;
begin
  T := CalcDecryptByte;
  UpdateKeys(Value);
  Value := Value xor T;
end;

procedure TZipCrypto.InitKeys(const APassword: TBytes);
var
  I: Integer;
begin
  FKey0 := KEY0_INIT;
  FKey1 := KEY1_INIT;
  FKey2 := KEY2_INIT;

  for I := 0 to High(APassword) do
    UpdateKeys(APassword[I]);
end;

procedure TZipCrypto.UpdateKeys(const C: UInt8);
begin
  FKey0 := CalcCRC32Byte(FKey0, C);
  FKey1 := FKey1 + (FKey0 and $FF);
  FKey1 := FKey1 * KEY_UPDATE + 1;
  FKey2 := CalcCRC32Byte(FKey2, FKey1 shr 24);
end;

{ TZipCryptoDecryptStream }

constructor TZipCryptoDecryptStream.Create(const AInStream: TStream;
  const APassword: TBytes; const AZipHeader: PZipHeader);
var
  I: Integer;
  LZipClassicCryptHeader: array [0..SIZE_ZIP_CRYPT_HEAD - 1] of UInt8;
  LVerifyOK: Boolean;
begin
  inherited Create;

  FZipStream := AInStream;
  FZipCrypto := TZipCrypto.Create;
  FZipCrypto.InitKeys(APassword);

  // 读 12 字节加密头
  VerifyRead(FZipStream, LZipClassicCryptHeader, Sizeof(LZipClassicCryptHeader));

  // 对加密头进行解密
  for I := 0 to SIZE_ZIP_CRYPT_HEAD - 1 do
    FZipCrypto.DecryptByte(LZipClassicCryptHeader[I]);

  // 检查验证码以判断密码是否正确
  if AZipHeader.HasDataDescriptor then
    // 有DataDescriptor, 加密头结构: 10字节盐值 + 2字节验证码(修改时间低2字节)
    LVerifyOK := (PWord(@LZipClassicCryptHeader[SIZE_ZIP_CRYPT_HEAD - 2])^ = (AZipHeader.ModifiedDateTime and $FFFF))
  else
    // 无DataDescriptor, 加密头结构: 11字节盐值 + 1字节验证码(crc32最高字节)
    LVerifyOK := (LZipClassicCryptHeader[SIZE_ZIP_CRYPT_HEAD - 1] = AZipHeader.CRC32 shr 24);

  if not LVerifyOK then
    raise EZipException.CreateRes(@SZipInvalidPassword);

  if AZipHeader^.CompressedSize < SIZE_ZIP_CRYPT_HEAD then
    raise EZipException.CreateRes(@SZipInvalidZip);

  FSize := AZipHeader^.CompressedSize - UInt64(SIZE_ZIP_CRYPT_HEAD);
  FPosStart := FZipStream.Position;
end;

destructor TZipCryptoDecryptStream.Destroy;
begin
  FreeAndNil(FZipCrypto);

  inherited;
end;

function TZipCryptoDecryptStream.Read(var Buffer; Count: Integer): Integer;
var
  LCount: Integer;
  P: PByte;
begin
  LCount := Min(Count, FSize - Position);
  // 读取已加密的数据
  Result := FZipStream.Read(Buffer, LCount);
  if (Result <= 0) then Exit;

  P := @Buffer;
  // 解密数据
  FZipCrypto.Decrypt(P, Result);
end;

function TZipCryptoDecryptStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
var
  LPosition, LOrgPos: Int64;
begin
  LPosition := FZipStream.Position;
  LOrgPos := LPosition;

  case Origin of
    soBeginning: LPosition := FPosStart + Offset;
    soCurrent: Inc(LPosition, Offset);
    soEnd: LPosition := FSize + FPosStart + Offset;
  end;

  Result := LPosition - FPosStart;

  if (LPosition <> LOrgPos) then
    FZipStream.Position := LPosition;
end;

function TZipCryptoDecryptStream.Write(const Buffer; Count: Integer): Integer;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

{ TZipCryptoEncryptStream }

constructor TZipCryptoEncryptStream.Create(const AOutStream: TStream;
  const APassword: TBytes; const AZipHeader: PZipHeader);
var
  LZipClassicCryptHeader: array[0..SIZE_ZIP_CRYPT_HEAD - 1] of UInt8;
  I: Integer;
begin
  inherited Create;

  FZipStream := AOutStream;

  FZipCrypto := TZipCrypto.Create;
  FZipCrypto.InitKeys(APassword);

  // 加密头结构(分2种情况):
  //   1. 有DataDescriptor, 10字节盐值 + 2字节验证码(修改时间低2字节)
  //   2. 无DataDescriptor, 11字节盐值 + 1字节验证码(crc32最高字节)
  // 随机生成盐值
  FillCryptRandomBytes(LZipClassicCryptHeader, SizeOf(LZipClassicCryptHeader));

  // 当有数据描述符的时候
  // 加密头最后两个字节保存修改时间(只要时间部分, 所以取低2字节)
  if AZipHeader.HasDataDescriptor then
    PWord(@LZipClassicCryptHeader[SIZE_ZIP_CRYPT_HEAD - 2])^ := (AZipHeader^.ModifiedDateTime and $FFFF)
  else
    // 这种模式必须事先计算好 CRC32, 不利于性能优化, 不建议使用
    LZipClassicCryptHeader[SIZE_ZIP_CRYPT_HEAD - 1] := (AZipHeader^.CRC32 shr 24);

  // 对加密头进行加密
  for I := 0 to SIZE_ZIP_CRYPT_HEAD - 1 do
    FZipCrypto.EncryptByte(LZipClassicCryptHeader[I]);

  // 写入加密头
  FZipStream.Write(LZipClassicCryptHeader, Sizeof(LZipClassicCryptHeader));
end;

destructor TZipCryptoEncryptStream.Destroy;
begin
  FreeAndNil(FZipCrypto);

  inherited;
end;

function TZipCryptoEncryptStream.Read(var Buffer; Count: Integer): Integer;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

function TZipCryptoEncryptStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  Result := FZipStream.Seek(Offset, Origin);
end;

function TZipCryptoEncryptStream.Write(const Buffer; Count: Integer): Integer;
var
  P: PByte;
{$IFNDEF CONST_BUFFER_WRITABLE}
  LLocalBuf: TBytes;
{$ENDIF}
begin
{$IFDEF CONST_BUFFER_WRITABLE}
  // 原地加密, 避免内存复制 (x86/x64 平台 const 参数可写)
  P := @Buffer;
  FZipCrypto.Encrypt(P, Count);
  Result := FZipStream.Write(P^, Count);
{$ELSE}
  // 非 x86/x64 平台, const 参数可能在只读段, 复制到局部变量再加密
  SetLength(LLocalBuf, Count);
  Move(Buffer, LLocalBuf[0], Count);
  P := @LLocalBuf[0];
  FZipCrypto.Encrypt(P, Count);
  Result := FZipStream.Write(P^, Count);
{$ENDIF}
end;

{ TZipAESDecryptStream }

procedure TZipAESDecryptStream.CheckHmac;
var
  LAuthData: array [0..9] of Byte;
  LHmacData: TBytes;
begin
  // AES加密数据后面跟着10个字节的认证码
  VerifyRead(FZipStream, LAuthData[0], 10);

  // 由实际数据计算出的认证码
  LHmacData := FSha1Hmac.HMACFinish;

  // 校验认证码
  if not CompareMem(@LAuthData[0], @LHmacData[0], 10) then
    raise EZipException.CreateRes(@SZipCrcError);
end;

constructor TZipAESDecryptStream.Create(const AInStream: TStream;
  const APassword: TBytes; const AZipHeader: PZipHeader;
  const AAESExtraField: TAESExtraField);
var
  LSaltSize, LKeySize: Integer;
  LSalt, LKeyBuf, LHMACKey: TBytes;
  LVerifyCode: Word;
  LAESKey128: TCnAESKey128;
  LAESKey192: TCnAESKey192;
  LAESKey256: TCnAESKey256;
begin
  inherited Create;

  FZipStream := AInStream;

  // 根据加密强度计算盐值大小
  case AAESExtraField.EncryptionStrength of
    1{AES128}: LSaltSize := 8;
    2{AES192}: LSaltSize := 12;
    3{AES256}: LSaltSize := 16;
  else
    raise EZipException.CreateRes(@SZipInvalidAESExtraField);
  end;

  // AES 密钥大小是盐值的两倍
  LKeySize := LSaltSize * 2;

  SetLength(LSalt, LSaltSize);
  // 读取AES加密头盐值
  VerifyRead(FZipStream, LSalt[0], LSaltSize);
  // 读取AES加密头密码校验值
  VerifyRead(FZipStream, LVerifyCode, SizeOf(LVerifyCode));

  // 根据盐值和密码生成密钥
  // 密钥结构: AES密钥+HMAC密钥+密码校验值
  // WinZip AES 规范固定 1000 次迭代
  LKeyBuf := PBKDF2ToBytes(LSalt, APassword, PBKDF2_ITERATIONS, LKeySize * 2 + 2);
  if (LVerifyCode <> PWord(@LKeyBuf[LKeySize * 2])^) then
    raise EZipException.CreateRes(@SZipInvalidPassword);

  // 加密数据结构:
  // 盐值 + 2字节密码校验值 + AES加密数据 + 10字节认证码
  if AZipHeader^.CompressedSize < UInt64(LSaltSize + 2{密码校验值} + 10{认证码(HMAC)}) then
    raise EZipException.CreateRes(@SZipInvalidZip);

  FSize := AZipHeader^.CompressedSize - UInt64(LSaltSize + 2{密码校验值} + 10{认证码(HMAC)});
  FPosStart := FZipStream.Position;

  // aes zip ctr 初始盐值所有元素为0
  FillChar(FCryptNonce, SizeOf(FCryptNonce), 0);
  case AAESExtraField.EncryptionStrength of
    1{AES128}:
      begin
        Move(LKeyBuf[0], LAESKey128, SizeOf(LAESKey128));
        FAESCTREncryptor := TAESCTREncryptor.Create(LAESKey128, FCryptNonce);
      end;

    2{AES192}:
      begin
        Move(LKeyBuf[0], LAESKey192, SizeOf(LAESKey192));
        FAESCTREncryptor := TAESCTREncryptor.Create(LAESKey192, FCryptNonce);
      end;

    3{AES256}:
      begin
        Move(LKeyBuf[0], LAESKey256, SizeOf(LAESKey256));
        FAESCTREncryptor := TAESCTREncryptor.Create(LAESKey256, FCryptNonce);
      end;
  end;

  // 提取HMAC密钥
  LHMACKey := Copy(LKeyBuf, LKeySize, LKeySize);
  FSha1Hmac := THashSHA1.Create;
  FSha1Hmac.HMACStart(LHMACKey);

  // 安全擦除密钥缓冲区
  FillChar(LSalt[0], Length(LSalt), 0);
  FillChar(LKeyBuf[0], Length(LKeyBuf), 0);
  FillChar(LHMACKey[0], Length(LHMACKey), 0);
end;

destructor TZipAESDecryptStream.Destroy;
begin
  try
    if not FAuthChecked then
    try
      Finish;
    except
      // 忽略析构函数中的异常, 避免资源泄漏
    end;
  finally
    FreeAndNil(FAESCTREncryptor);
    FreeAndNil(FSha1Hmac);
    inherited Destroy;
  end;
end;

procedure TZipAESDecryptStream.Finish;
begin
  if FAuthChecked then Exit;

  CheckHmac;
  FAuthChecked := True;
end;

function TZipAESDecryptStream.Read(var Buffer; Count: Integer): Integer;
var
  LCount: Integer;
begin
  LCount := Min(Count, FSize - Position);
  // 读取已加密的数据
  Result := FZipStream.Read(Buffer, LCount);
  if (Result <= 0) then Exit;

  // 更新认证码
  FSha1Hmac.Update(@Buffer, LCount);

  // 解密数据
  FAESCTREncryptor.Execute(@Buffer, LCount);
end;

function TZipAESDecryptStream.Seek(const Offset: Int64;
  Origin: TSeekOrigin): Int64;
var
  LPosition, LOrgPos: Int64;
begin
  LPosition := FZipStream.Position;
  LOrgPos := LPosition;

  case Origin of
    soBeginning: LPosition := FPosStart + Offset;
    soCurrent: Inc(LPosition, Offset);
    soEnd: LPosition := FSize + FPosStart + Offset;
  end;

  Result := LPosition - FPosStart;

  if (LPosition <> LOrgPos) then
    FZipStream.Position := LPosition;
end;

function TZipAESDecryptStream.Write(const Buffer; Count: Integer): Integer;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

{ TZipAESEncryptStream }

constructor TZipAESEncryptStream.Create(const AOutStream: TStream;
  const APassword: TBytes; const AZipHeader: PZipHeader;
  const AAESExtraField: TAESExtraField);
var
  LSaltSize, LKeySize: Integer;
  LSalt, LKeyBuf, LHMACKey: TBytes;
  LVerifyCode: Word;
  LAESKey128: TCnAESKey128;
  LAESKey192: TCnAESKey192;
  LAESKey256: TCnAESKey256;
begin
  inherited Create;

  // aes zip 结构:
  // 盐值(根据加密强度确定长度) + 2字节校验码(PBKDF2生成) + 加密数据(aes ctr加密) + 10字节验证码
  FZipStream := AOutStream;

  // 根据加密强度计算盐值大小
  case AAESExtraField.EncryptionStrength of
    1{AES128}: LSaltSize := 8;
    2{AES192}: LSaltSize := 12;
    3{AES256}: LSaltSize := 16;
  else
    raise EZipException.CreateRes(@SZipInvalidAESExtraField);
  end;

  // AES 密钥大小是盐值的两倍
  LKeySize := LSaltSize * 2;

  // 生成随机盐值
  SetLength(LSalt, LSaltSize);
  FillCryptRandomBytes(LSalt[0], LSaltSize);

  // 根据盐值和密码生成密钥
  // 密钥结构: AES密钥(LKeySize字节) + HMAC密钥(LKeySize字节) + 密码校验值(2字节)
  LKeyBuf := PBKDF2ToBytes(LSalt, APassword, PBKDF2_ITERATIONS, LKeySize * 2 + 2);
  // WinZip AES 规范固定 1000 次迭代

  // 密码校验值
  LVerifyCode := PWord(@LKeyBuf[LKeySize * 2])^;

  // 写入AES加密头盐值
  VerifyWrite(FZipStream, LSalt[0], LSaltSize);
  // 写入AES加密头密码校验值
  VerifyWrite(FZipStream, LVerifyCode, SizeOf(LVerifyCode));

  // aes zip ctr 初始盐值所有元素为0
  FillChar(FCryptNonce, SizeOf(FCryptNonce), 0);
  case AAESExtraField.EncryptionStrength of
    1{AES128}:
      begin
        Move(LKeyBuf[0], LAESKey128, SizeOf(LAESKey128));
        FAESCTREncryptor := TAESCTREncryptor.Create(LAESKey128, FCryptNonce);
      end;

    2{AES192}:
      begin
        Move(LKeyBuf[0], LAESKey192, SizeOf(LAESKey192));
        FAESCTREncryptor := TAESCTREncryptor.Create(LAESKey192, FCryptNonce);
      end;

    3{AES256}:
      begin
        Move(LKeyBuf[0], LAESKey256, SizeOf(LAESKey256));
        FAESCTREncryptor := TAESCTREncryptor.Create(LAESKey256, FCryptNonce);
      end;
  end;

  // 提取HMAC密钥
  LHMACKey := Copy(LKeyBuf, LKeySize, LKeySize);
  FSha1Hmac := THashSHA1.Create;
  FSha1Hmac.HMACStart(LHMACKey);

  // 安全擦除密钥缓冲区
  FillChar(LSalt[0], Length(LSalt), 0);
  FillChar(LKeyBuf[0], Length(LKeyBuf), 0);
  FillChar(LHMACKey[0], Length(LHMACKey), 0);
end;

destructor TZipAESEncryptStream.Destroy;
begin
  try
    WriteHmac;
  finally
    FreeAndNil(FAESCTREncryptor);
    FreeAndNil(FSha1Hmac);
    inherited Destroy;
  end;
end;

function TZipAESEncryptStream.Read(var Buffer; Count: Integer): Integer;
begin
  raise EZipException.CreateRes(@SZipNotImplemented);
end;

function TZipAESEncryptStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  Result := FZipStream.Seek(Offset, Origin);
end;

function TZipAESEncryptStream.Write(const Buffer; Count: Integer): Integer;
var
  P: PByte;
{$IFNDEF CONST_BUFFER_WRITABLE}
  LLocalBuf: TBytes;
{$ENDIF}
begin
{$IFDEF CONST_BUFFER_WRITABLE}
  // 原地加密, 避免内存复制 (x86/x64 平台 const 参数可写)
  P := @Buffer;
  FAESCTREncryptor.Execute(P, Count);
  FSha1Hmac.Update(P, Count);
  Result := FZipStream.Write(P^, Count);
{$ELSE}
  // 非 x86/x64 平台, const 参数可能在只读段, 复制到局部变量再加密
  SetLength(LLocalBuf, Count);
  Move(Buffer, LLocalBuf[0], Count);
  P := @LLocalBuf[0];
  FAESCTREncryptor.Execute(P, Count);
  FSha1Hmac.Update(P, Count);
  Result := FZipStream.Write(LLocalBuf[0], Count);
{$ENDIF}
end;

procedure TZipAESEncryptStream.WriteHmac;
var
  LHmacData: TBytes;
begin
  // 由实际数据计算出的认证码
  LHmacData := FSha1Hmac.HMACFinish;

  // AES加密数据后面跟着10个字节的认证码
  VerifyWrite(FZipStream, LHmacData[0], 10);
end;

initialization
  FZipCompressionHandlers := TZipCompressionHandlerList.Create;
  RegisterZipCompressionHandler(TZipDefaultCompressionHandler);

finalization
  FreeAndNil(FZipCompressionHandlers);

end.
