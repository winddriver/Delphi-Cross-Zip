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
  ZLib,

  CnAES,
  CnNative,

  Utils.Hash,
  Utils.PBKDF2,
  Utils.AES.CTR;

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
  EXID_AES             = $9901; // AES 扩展字段标志
  PBKDF2_ITERATIONS    = 1000;  // AES 密钥迭代次数

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
  ///   Zip 压缩类型
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
    CompressionMethod:  UInt16;     // 压缩方法
                                    // 0  无压缩
                                    // 8  Deflate最常用的压缩方法, 使用 LZ77 和 Huffman 编码进行压缩, 平衡了压缩率和速度.
                                    // 99 AES加密
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
    procedure SetCompressedSize64(const AValue: UInt64);
    procedure SetLocalHeaderOffset64(const AValue: UInt64);
    procedure SetUncompressedSize64(const AValue: UInt64);

    property CompressedSize: UInt64 read GetCompressedSize64 write SetCompressedSize64;
    property UncompressedSize: UInt64 read GetUncompressedSize64 write SetUncompressedSize64;
    property LocalHeaderOffset: UInt64 read GetLocalHeaderOffset64 write SetLocalHeaderOffset64;
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
  ///   AES 加密扩展字段结构(FieldId = $9901)
  /// </summary>
  TAESExtraField = packed record
    Version:  UInt16; // AES 加密版本号, 一般为 $0001
    Vendor:   UInt16; // AES 加密的供应商标识, 一般为"AE"(ASCII 编码, $4541)
    EncryptionStrength: UInt8;  // AES 密钥长度($01 表示 128 位, $02 表示 192 位, $03 表示 256 位)
    CompressionMethod:  UInt16; // 原始文件使用的压缩方法. 这一字段用于标明文件在加密前采用的压缩方法, 如 8 表示 Deflate
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
    function RawToString(const ARaw: TBytes): string;
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
    /// <param name="AZipFileStream">
    ///   zip文件数据流
    /// </param>
    /// <param name="AOpenMode">
    ///   打开方式
    /// </param>
    procedure Open(const AZipFileName: string; const AOpenMode: TZipMode); overload;

    /// <summary>
    ///   打开 Zip 文件
    /// </summary>
    /// <param name="AZipFileName">
    ///   zip文件名
    /// </param>
    /// <param name="AOpenMode">
    ///   打开方式
    /// </param>
    procedure Open(const AZipFileStream: TStream; const AOpenMode: TZipMode; const AOwned: Boolean); overload;

    /// <summary>
    ///   关闭 Zip 文件(同时会自动保存)
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
    function IndexOf(const AArchiveName: string): Integer;

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
  SZipInvalidAESExtraField = 'Invalid AES extra field';
  SZipDeflateCompressError = 'Deflate compress error: %d';
  SZipDeflateDecompressError = 'Deflate decompress error: %d';
  SZipCrcError = 'Zip crc error';

type
  TZipCompressionHandlerList = TList<TZipCompressionHandlerClass>;

var
  FZipCompressionHandlers: TZipCompressionHandlerList = nil;

type
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
  TStoredStream = class(TStream)
  private
    FOwner: Boolean;
    FStream: TStream;
  public
    constructor Create(const AStream: TStream; const AOwner: Boolean);
    destructor Destroy; override;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

  // Deflate压缩/解压流基础类
  TCustomDeflateStream = class(TStream)
  private
    FOwner: Boolean;
    FStream: TStream;
    FStreamStartPos: Int64;
    FStreamPos: Int64;
    FZStream: TZStreamRec;
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

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

  // Deflate解压流
  TDeflateDecompressStream = class(TCustomDeflateStream)
  public
    constructor Create(const AStream: TStream; const AOwner: Boolean);
    destructor Destroy; override;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
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

    procedure CheckHmac;
  public
    constructor Create(const AInStream: TStream; const APassword: TBytes;
      const AZipHeader: PZipHeader; const AAESExtraField: TAESExtraField);
    destructor Destroy; override;

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
  Result := ZLib.crc32(AOrgCRC32, @AData, ADataSize);
end;

function CalcCRC32Byte(const AOrgCRC32: UInt32; const B: UInt8): UInt32; inline;
begin
  Result := not ZLib.crc32(not AOrgCRC32, @B, 1);
end;

// 获取指定ID的扩展字段
function GetExtraField(const AExtraData: TBytes; AFieldId, AFieldLen: Word; AExtra: Pointer): Integer;
var
  LOffset: Integer;
  LField: ^TZipExtraField;
  LCount: Integer;
begin
  LOffset := 0;
  LCount := Length(AExtraData);
  while LOffset + SizeOf(TZipExtraField) <= LCount do
  begin
    LField := @AExtraData[LOffset];
    if LField.FieldId = AFieldId then
    begin
      Result := LField.FieldLen;
      if AExtra <> nil then
      begin
        if Result < AFieldLen then
          AFieldLen := Result;
        Move(AExtraData[LOffset + SizeOf(TZipExtraField)], AExtra^, AFieldLen);
      end;
      Exit;
    end;
    Inc(LOffset, SizeOf(TZipExtraField) + LField.FieldLen);
  end;
  Result := 0;
end;

// 删除指定ID的扩展字段
procedure DelExtraField(var AExtraData: TBytes; AFieldId: Word);
var
  LOffset: Integer;
  LField: ^TZipExtraField;
  LCount: Integer;
begin
  LOffset := 0;
  LCount := Length(AExtraData);
  while LOffset + SizeOf(TZipExtraField) <= LCount do
  begin
    LField := @AExtraData[LOffset];
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
  LCount: Integer;
  LLen: Integer;
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
    LField := @AExtraData[LOffset];
    LLen := SizeOf(TZipExtraField) + LField.FieldLen;
    if LOffset + LLen > LCount then
      Exit;
    if LField.FieldId = AFieldId then
    begin
      Inc(LOffset, SizeOf(TZipExtraField));
      LLen := Integer(AFieldLen) - LField.FieldLen;
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

procedure RegisterZipCompressionHandler(const AClass: TZipCompressionHandlerClass);
begin
  if (FZipCompressionHandlers.IndexOf(AClass) < 0) then
    FZipCompressionHandlers.Add(AClass);
end;

// 是否支持指定的压缩方式
function SupportCompressionMethod(const AMethod: TZipCompressionMethod): Boolean;
var
  I: Integer;
  AComp: TZipCompressionHandlerClass;
begin
  Result := False;
  for I := 0 to FZipCompressionHandlers.Count - 1 do
  begin
    AComp := TZipCompressionHandlerClass(FZipCompressionHandlers[I]);
    if AComp <> nil then
    begin
      if AComp.CanHandleCompressionMethod(AMethod) then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
end;

function CreateCompressStreamFromHandler(const AMethod: TZipCompressionMethod;
  AOutStream: TStream; const AZipHeader: PZipHeader; const APassword: TBytes;
  const ACompressLevel, AStrategy: Integer): TStream;
var
  I: Integer;
  LComp: TZipCompressionHandlerClass;
begin
  Result := nil;
  for I := 0 to FZipCompressionHandlers.Count - 1 do
  begin
    LComp := TZipCompressionHandlerClass(FZipCompressionHandlers[I]);
    if LComp <> nil then
    begin
      if LComp.CanHandleCompressionMethod(AMethod) then
      begin
        Result := LComp.CreateCompressionStream(
          AMethod,
          AOutStream,
          AZipHeader,
          APassword,
          ACompressLevel,
          AStrategy);

        Exit;
      end;
    end;
  end;
end;

function CreateDecompressStreamFromHandler(const AMethod: TZipCompressionMethod;
  const AInStream: TStream; const AZipHeader: PZipHeader; const APassword: TBytes): TStream;
var
  I: Integer;
  LComp: TZipCompressionHandlerClass;
begin
  Result := nil;
  for I := 0 to FZipCompressionHandlers.Count - 1 do
  begin
    LComp := TZipCompressionHandlerClass(FZipCompressionHandlers[I]);
    if LComp <> nil then
    begin
      if LComp.CanHandleCompressionMethod(AMethod) then
      begin
        Result := LComp.CreateDecompressionStream(
          AMethod,
          AInStream,
          AZipHeader,
          APassword);

        Exit;
      end;
    end;
  end;
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
  except on E: EStreamError do
    ;
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
    or ((Length(FileName) > 0) and (FileName[Length(FileName) - 1] in [Ord('\'), Ord('/')]));
end;

function TZipHeader.IsUtf8FileName: Boolean;
begin
  Result := (Flag and FLAG_UTF8 <> 0);
end;

procedure TZipHeader.SetCompressedSize64(const AValue: UInt64);
var
  LZip64Extra: TZip64ExtraHeader;
  LExSize: Integer;
begin
  LExSize := GetExtraField(
    ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @LZip64Extra);

  if (AValue >= MAX_UINT32) or (LExSize >= SizeOf(UInt64)) then
  begin
    // 要支持 ZIP64, 需要解压库支持 45 版本及以上
    RequiredVersion := 45;
    LZip64Extra.CompressedSize := AValue;
    _CompressedSize := MAX_UINT32;

    // 由于 LZip64Extra.CompressedSize 是第 2 个成员,
    // 如果此时还未写入 LZip64Extra.UncompressedSize
    // 应该将其补上
    if (LExSize < 1 * SizeOf(UInt64)) then
    begin
      LZip64Extra.UncompressedSize := _UncompressedSize;
      _UncompressedSize := MAX_UINT32;
    end;

    // ZIP64 扩展字段中只有第一个成员 UncompressedSize 是必须的
    // 其它成员只有实际用到才需要写入
    // CompressedSize 是其中的第1个成员, 所以如果要写入 CompressedSize
    // 则扩展字段的尺寸至少应该是 2 * SizeOf(UInt64)
    if (LExSize < 2 * SizeOf(UInt64)) then
      LExSize := 2 * SizeOf(UInt64);
  end else
  begin
    RequiredVersion := 20;
    _CompressedSize := AValue;
  end;

  if (LExSize >= SizeOf(UInt64)) then
  begin
    SetExtraField(ExtraField, EXID_ZIP64, LExSize, @LZip64Extra);
    ExtraFieldLength := Length(ExtraField);
  end;
end;

procedure TZipHeader.SetLocalHeaderOffset64(const AValue: UInt64);
var
  LZip64Extra: TZip64ExtraHeader;
  LExSize: Integer;
begin
  LExSize := GetExtraField(
    ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @LZip64Extra);

  if (AValue >= MAX_UINT32) or (LExSize >= SizeOf(UInt64)) then
  begin
    // 要支持 ZIP64, 需要解压库支持 45 版本及以上
    RequiredVersion := 45;
    LZip64Extra.LocalHeaderOffset := AValue;
    _LocalHeaderOffset := MAX_UINT32;

    // 由于 LZip64Extra.LocalHeaderOffset 是第 3 个成员,
    // 如果此时还未写入 LZip64Extra.UncompressedSize
    // 应该将其补上
    if (LExSize < 1 * SizeOf(UInt64)) then
    begin
      LZip64Extra.UncompressedSize := _UncompressedSize;
      _UncompressedSize := MAX_UINT32;
    end;

    // 由于 LZip64Extra.LocalHeaderOffset 是第 3 个成员,
    // 如果此时还未写入 LZip64Extra.CompressedSize
    // 应该将其补上
    if (LExSize < 2 * SizeOf(UInt64)) then
    begin
      LZip64Extra.CompressedSize := _CompressedSize;
      _CompressedSize := MAX_UINT32;
    end;

    // ZIP64 扩展字段中只有第一个成员 UncompressedSize 是必须的
    // 其它成员只有实际用到才需要写入
    // LocalHeaderOffset 是其中的第3个成员, 所以如果要写入 LocalHeaderOffset
    // 则扩展字段的尺寸至少应该是 3 * SizeOf(UInt64)
    if (LExSize < 3 * SizeOf(UInt64)) then
      LExSize := 3 * SizeOf(UInt64);
  end else
  begin
    RequiredVersion := 20;
    _LocalHeaderOffset := AValue;
  end;

  if (LExSize >= SizeOf(UInt64)) then
  begin
    SetExtraField(ExtraField, EXID_ZIP64, LExSize, @LZip64Extra);
    ExtraFieldLength := Length(ExtraField);
  end;
end;

procedure TZipHeader.SetUncompressedSize64(const AValue: UInt64);
var
  LZip64Extra: TZip64ExtraHeader;
  LExSize: Integer;
begin
  LExSize := GetExtraField(
    ExtraField,
    EXID_ZIP64,
    SizeOf(TZip64ExtraHeader),
    @LZip64Extra);

  if (AValue >= MAX_UINT32) or (LExSize >= SizeOf(UInt64)) then
  begin
    // 要支持 ZIP64, 需要解压库支持 45 版本及以上
    RequiredVersion := 45;
    LZip64Extra.UncompressedSize := AValue;
    _UncompressedSize := MAX_UINT32;

    // ZIP64 扩展字段中只有第一个成员 UncompressedSize 是必须的
    // 其它成员只有实际用到才需要写入
    // UncompressedSize 是其中的第1个成员, 所以如果要写入 UncompressedSize
    // 则扩展字段的尺寸至少应该是 1 * SizeOf(UInt64)
    if (LExSize < 1 * SizeOf(UInt64)) then
      LExSize := 1 * SizeOf(UInt64);
  end else
  begin
    RequiredVersion := 20;
    _UncompressedSize := AValue;
  end;

  if (LExSize >= SizeOf(UInt64)) then
  begin
    SetExtraField(ExtraField, EXID_ZIP64, LExSize, @LZip64Extra);
    ExtraFieldLength := Length(ExtraField);
  end;
end;

{ TCrossZip }

function TCrossZip.AddEmptyDir(const ADirName: string): Boolean;
var
  LExistsIndex: Integer;
  LLocalHeader: PZipHeader;
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipNoWrite);

  LExistsIndex := IndexOf(ADirName);
  if (LExistsIndex >= 0) then
    Delete(LExistsIndex);

  NewHeader(LLocalHeader);
  FillChar(LLocalHeader^, SizeOf(LLocalHeader^), 0);

  LLocalHeader^.Flag := 0;
  if Utf8 then
    LLocalHeader^.Flag := LLocalHeader^.Flag or FLAG_UTF8;
  if HasPassword then
  begin
    LLocalHeader^.Flag := LLocalHeader^.Flag or FLAG_PASSWORD;

    // 设置 FLAG_DATA_DESCRIPTOR 标志让加密头不需要使用 CRC32 做校验码
    // 这样可以方便一边读取数据一边计算 CRC32, 提高性能
    LLocalHeader^.Flag := LLocalHeader^.Flag or FLAG_DATA_DESCRIPTOR;
  end;

  LLocalHeader^.CompressionMethod := UInt16(zcStored);
  LLocalHeader^.ModifiedDateTime := DateTimeToFileDate(Now);
  LLocalHeader^.InternalAttributes := 0;
  LLocalHeader^.ExternalAttributes := faDirectory;
  LLocalHeader^.FileName := StringToRaw(ADirName);
  LLocalHeader^.FileNameLength := Length(LLocalHeader^.FileName);
  LLocalHeader^.ExtraFieldLength := 0;

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
    LArchive := AArchiveName
  else if FRemovePath then
    LArchive := ExtractFileName(AFileName)
  else
    LArchive := AFileName;

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
  FillChar(LLocalHeader^, SizeOf(LLocalHeader^), 0);

  LLocalHeader^.Flag := 0;
  if Utf8 then
    LLocalHeader^.Flag := LLocalHeader^.Flag or FLAG_UTF8;
  if HasPassword then
  begin
    LLocalHeader^.Flag := LLocalHeader^.Flag or FLAG_PASSWORD;

    // 设置 FLAG_DATA_DESCRIPTOR 标志让加密头不需要使用 CRC32 做校验码
    // 这样可以方便一边读取数据一边计算 CRC32, 提高性能
    LLocalHeader^.Flag := LLocalHeader^.Flag or FLAG_DATA_DESCRIPTOR;
  end;

  LLocalHeader^.CompressionMethod := UInt16(ACompression);
  LLocalHeader^.ModifiedDateTime := DateTimeToFileDate(AFileDateTime);
  LLocalHeader^.InternalAttributes := 0;
  LLocalHeader^.ExternalAttributes := 0;
  LLocalHeader^.FileName := StringToRaw(AArchiveName);
  LLocalHeader^.FileNameLength := Length(LLocalHeader^.FileName);
  LLocalHeader^.ExtraFieldLength := 0;

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
    LAESExtraField.Version := 1;
    LAESExtraField.Vendor := $4541; // AE
    LAESExtraField.EncryptionStrength := 3; // AES256
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
  ALocalHeader^.LocalHeaderOffset := FEndFileData;  // 该条数据在整个zip中的偏移量
  ALocalHeader^.CRC32 := 0;

  // 写入本地文件头, 有部分属性还需要等数据压缩后重新计算
  // 由于本地文件头是在 TZipHeader.RequiredVersion 开始连续的 SIZE_LOCAL_HEADER 个字节
  // 所以可以一条命令全部写入, 不需要每个属性单独写一次
  VerifyWrite(FZipStream, ALocalHeader^.RequiredVersion, SIZE_LOCAL_HEADER);
  if ALocalHeader^.FileNameLength > 0 then
    VerifyWrite(FZipStream, ALocalHeader^.FileName[0], ALocalHeader^.FileNameLength);
  if ALocalHeader^.ExtraFieldLength > 0 then
    VerifyWrite(FZipStream, ALocalHeader^.ExtraField[0], ALocalHeader^.ExtraFieldLength);

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
  FZipStream.Position := ALocalHeader^.LocalHeaderOffset + SizeOf(UInt32){本地头标志大小};

  // 重新写入计算后的属性
  // 由于zip64的相关属性在 ExtraField 中, 所以也需要重新写入
  // 由于 ExtraField 保存在 FileName 之后, 所以要先写入 FileName
  VerifyWrite(FZipStream, ALocalHeader^.RequiredVersion, SIZE_LOCAL_HEADER);
  if ALocalHeader^.FileNameLength > 0 then
    VerifyWrite(FZipStream, ALocalHeader^.FileName[0], ALocalHeader^.FileNameLength);
  if ALocalHeader^.ExtraFieldLength > 0 then
    VerifyWrite(FZipStream, ALocalHeader^.ExtraField[0], ALocalHeader^.ExtraFieldLength);

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

  // 如果是打开的文件, 在关闭的时候释放文件流,
  // 是为了防止外部代码在Zip对象Close之后, 释放之前打开文件出现占用异常;
  // 之所以不在这里直接调用FreeOwnedStream,
  // 是为了允许外部代码在Zip对象Close之后, 释放之前继续访问文件流
  if (FZipFileName <> '') then
  begin
    FZipFileName := '';
    if (FZipStream <> nil) then
      FreeAndNil(FZipStream);
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
  LSourceOffset := FEndFileData;
  for LFileIndex := 0 to FileCount - 1 do
  begin
    LFileOffset := FileInfo[LFileIndex].LocalHeaderOffset;
    if (LFileOffset > LTargetOffset) and (LFileOffset < LSourceOffset) then
      LSourceOffset := LFileOffset;
  end;

  if (LSourceOffset < FEndFileData) then
  begin
    // [....][LTargetOffset...][LSourceOffset....][...........][FEndFileData...]
    //       <----------------[.............................]
    MoveUp(FZipStream, LSourceOffset, LTargetOffset, FEndFileData - LSourceOffset);
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
    FEndFileData := LTargetOffset;
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
  FreeOwnedStream;

  inherited;
end;

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
begin
  Result := False;
  if (AArchiveIndex < 0)
    or (AArchiveIndex >= FileCount)
    or (ADstStream = nil) then Exit;

  LCentralHeader := FileInfo[AArchiveIndex];

  FillChar(LZipHeader, SizeOf(TZipHeader), 0);

  // 定位到本地文件头
  FZipStream.Position := LCentralHeader.LocalHeaderOffset + FStartFileData;

  // 读取本地文件头标志
  FZipStream.Read(LSignature, Sizeof(LSignature));

  // 检查本地文件头标志
  if LSignature <> SIGNATURE_LOCAL_HEADER then
    raise EZipException.CreateRes(@SZipInvalidLocalHeader);

  // 读本地文件头
  FZipStream.Read(LZipHeader.RequiredVersion, SIZE_LOCAL_HEADER);

  // 读取文件名
  if (LZipHeader.FileNameLength > 0) then
  begin
    SetLength(LZipHeader.FileName, LZipHeader.FileNameLength);
    FZipStream.Read(LZipHeader.FileName[0], LZipHeader.FileNameLength);
  end;

  // 读取扩展信息
  if LZipHeader.ExtraFieldLength > 0 then
  begin
    SetLength(LZipHeader.ExtraField, LZipHeader.ExtraFieldLength);
    FZipStream.Read(LZipHeader.ExtraField[0], LZipHeader.ExtraFieldLength);
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

  if LZipHeader.IsDirectory
    or (LZipHeader.UncompressedSize <= 0) then Exit;

  // 创建解压数据流
  LDecompressStream := CreateDecompressStreamFromHandler(
    TZipCompressionMethod(LZipHeader.CompressionMethod),
    FZipStream, @LZipHeader, FPassword);

  if (LDecompressStream = nil) then
    raise EZipException.CreateRes(@SZipNotSupport);

  try
    if (ADstStream = nil)
      or LZipHeader.IsDirectory
      or (LZipHeader.UncompressedSize <= 0) then Exit;

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

    if LNeedCheckCrc32 and (LCrc32 <> LZipHeader.CRC32) then
      raise EZipException.CreateRes(@SZipCrcError);
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
begin
  Result := False;
  if (AArchiveIndex < 0) or (AArchiveIndex >= FileCount) then Exit;

  LOutStream := TFileStream.Create(ADstFileName, fmCreate);
  try
    ExtractToStream(AArchiveIndex, LOutStream);
  finally
    FreeAndNil(LOutStream);
  end;

  Result := True;
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
  LDir, LFileName: string;
begin
  Result := False;
  if (AArchiveIndex < 0) or (AArchiveIndex >= FileCount) then Exit;

  LZipHeader := FileInfo[AArchiveIndex];
  LIsDirectory := LZipHeader.IsDirectory;

  // 如果这条数据是个目录, 并且参数传了不要创建子目录, 那什么都不用做了
  if LIsDirectory and not ACreateSubdirs then Exit(True);

  LFileName := RawToString(LZipHeader.FileName);
  if (LFileName = '') then Exit;

  // 检查一下要不要给目录名字后面添加个目录分隔符
  if LIsDirectory
    and not LFileName.EndsWith('/', True)
    and not LFileName.EndsWith('\', True) then
    LFileName := LFileName + PathDelim;

  {$IFDEF MSWINDOWS}
  LFileName := StringReplace(LFileName, '/', '\', [rfReplaceAll]);
  {$ENDIF}

  if ACreateSubdirs then
    LFileName := IncludeTrailingPathDelimiter(ADstPath) + LFileName
  else
    LFileName := IncludeTrailingPathDelimiter(ADstPath) + ExtractFileName(LFileName);

  LDir := ExtractFileDir(LFileName);
  if (LDir <> '') then
    ForceDirectories(LDir);

  // 如果这是个目录, 创建完目录之后就可以返回了
  // 因为目录本身没有文件数据
  if LIsDirectory then Exit(True);

  Result := ExtractToFile(AArchiveIndex, LFileName);
end;

function TCrossZip.GetComment: string;
begin
  Result := RawToString(FComment);
end;

function TCrossZip.GetFileComment(Index: Integer): string;
begin
  Result := RawToString(FileInfo[Index]^.FileComment);
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
  Result := RawToString(FileInfo[Index]^.FileName);
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
var
  I: Integer;
begin
  for I := 0 to FileCount - 1 do
  begin
    if SameText(RawToString(FileInfo[I].FileName), AArchiveName) then
      Exit(I);
  end;

  Result := -1;
end;

class procedure TCrossZip.NewHeader(var AHeader: PZipHeader);
begin
  System.New(AHeader);
end;

procedure TCrossZip.Open(const AZipFileStream: TStream;
  const AOpenMode: TZipMode; const AOwned: Boolean);
begin
  Close;

  // 打开新的流之前先释放老的流
  FreeOwnedStream;

  FZipStream := AZipFileStream;
  FOpenMode := AOpenMode;
  FOwnedStream := AOwned;
  FChanged := False;

  FStartFileData := FZipStream.Position;
  if AOpenMode in [zmRead, zmReadWrite] then
  try
    // 读取中心目录文件头, 确定是不是有效的zip文件
    ReadCentralHeader;
  except
    FZipStream := nil;
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
    Open(LFileStream, AOpenMode, True);
    FZipFileName := AZipFileName;
  except
    FreeAndNil(LFileStream);
    raise;
  end;
end;

function TCrossZip.RawToString(const ARaw: TBytes): string;
begin
  if Utf8 then
    Result := TEncoding.UTF8.GetString(ARaw)
  else
    Result := TEncoding.Default.GetString(ARaw);
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
  if (LEndHeader.DiskNumber = MAX_UINT16) or
     (LEndHeader.CentralDirStartDisk = MAX_UINT16) or
     (LEndHeader.NumEntriesThisDisk = MAX_UINT16) or
     (LEndHeader.CentralDirEntries = MAX_UINT16) or
     (LEndHeader.CentralDirSize = MAX_UINT32) or
     (LEndHeader.CentralDirOffset = MAX_UINT32) then
  begin
    VerifyRead(FZipStream, LEndHeader64.Signature, SizeOf(LEndHeader64));
    if (LEndHeader64.Signature <> SIGNATURE_ZIP64_END_HEADER) then
      raise EZipException.CreateRes(@SZipInvalidZip);
    FZipStream.Position := LEndHeader64.Zip64CentralDirOffset;
    VerifyRead(FZipStream, LHeader64.Signature, SizeOf(TZip64Header));
    if (LHeader64.Signature <> SIGNATURE_ZIP64_CENTRAL_HEADER) then
      raise EZipException.CreateRes(@SZipInvalidZip);

    // 结束文件头中包含了中心文件头偏移
    // 根据该属性定位到中心文件头
    FZipStream.Position := LHeader64.CentralDirOffset;
    FEndFileData := LHeader64.CentralDirOffset;
    LCentralDirEntries := LHeader64.CentralDirEntries;
  end else begin
    // 结束文件头中包含了中心文件头偏移
    // 根据该属性定位到中心文件头
    FZipStream.Position := LEndHeader.CentralDirOffset;
    FEndFileData := LEndHeader.CentralDirOffset;
    LCentralDirEntries := LEndHeader.CentralDirEntries;
  end;

  for I := 0 to LCentralDirEntries - 1 do
  begin
    FZipStream.Read(LSignature, Sizeof(LSignature));
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

      FUtf8 := LHeader^.IsUtf8FileName;
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

  // 如果是 zip64 则需要写入相关的扩展信息
  if (FileCount >= MAX_UINT16) or (FEndFileData >= MAX_UINT32) then
  begin
    LHeader64.Signature := SIGNATURE_ZIP64_CENTRAL_HEADER;
    LHeader64.HeaderSize := 44;
    LHeader64.MadeByVersion := 45;
    LHeader64.RequiredVersion := 45;
    LHeader64.NumberOfDisks := 0;
    LHeader64.CentralDirStartDisk := 0;
    LHeader64.NumEntriesThisDisk := FileCount;
    LHeader64.CentralDirEntries := FileCount;
    LHeader64.CentralDirSize := FZipStream.Position - FEndFileData;
    LHeader64.CentralDirOffset := FEndFileData;

    LEndHeader64.Signature := SIGNATURE_ZIP64_END_HEADER;
    LEndHeader64.CentralDirStartDisk := 0;
    LEndHeader64.Zip64CentralDirOffset := FZipStream.Position;
    LEndHeader64.TotalNumberOfDisks := 1;

    VerifyWrite(FZipStream, LHeader64, SizeOf(LHeader64));
    VerifyWrite(FZipStream, LEndHeader64, SizeOf(LEndHeader64));

    LEndOfHeader.CentralDirEntries := MAX_UINT16;
    LEndOfHeader.NumEntriesThisDisk := MAX_UINT16;
    LEndOfHeader.CentralDirSize := MAX_UINT32;
    LEndOfHeader.CentralDirOffset := MAX_UINT32;
  end else begin
    LEndOfHeader.CentralDirEntries := FileCount;
    LEndOfHeader.NumEntriesThisDisk := FileCount;
    LEndOfHeader.CentralDirSize := FZipStream.Position - FEndFileData;
    LEndOfHeader.CentralDirOffset := FEndFileData;
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
  {$IFDEF DEBUG}
  LReadTimes, LCmpTimes: Integer;
  {$ENDIF}
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
  {$IFDEF DEBUG}
  LReadTimes := 0;
  LCmpTimes := 0;
  {$ENDIF}
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
    {$IFDEF DEBUG}
    Inc(LReadTimes);
    {$ENDIF}

    // 查找结束标志
    for I := LReadSize - LEndHeaderAndSignatureSize downto 0 do
    begin
      {$IFDEF DEBUG}
      Inc(LCmpTimes);
      {$ENDIF}
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
          SetLength(FComment, AZipEndHeader.CommentLength);
          AStream.Read(FComment[0], AZipEndHeader.CommentLength);
        end else
          SetLength(FComment, 0);

        // 检查是不是ZIP64文件
        if (AZipEndHeader.DiskNumber = MAX_UINT16) or
           (AZipEndHeader.CentralDirStartDisk = MAX_UINT16) or
           (AZipEndHeader.NumEntriesThisDisk = MAX_UINT16) or
           (AZipEndHeader.CentralDirEntries = MAX_UINT16) or
           (AZipEndHeader.CentralDirSize = MAX_UINT32) or
           (AZipEndHeader.CentralDirOffset = MAX_UINT32) then
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
end;

procedure TCrossZip.SetFileComment(Index: Integer; const Value: string);
begin
  FileInfo[Index]^.FileComment := StringToRaw(Value);
  FileInfo[Index]^.FileCommentLength := Length(FileInfo[Index]^.FileComment);
end;

procedure TCrossZip.SetPassword(const Value: string);
begin
  FPassword := TEncoding.UTF8.GetBytes(Value);
end;

procedure TCrossZip.SetUtf8(const Value: Boolean);
begin
  if not (FOpenMode in [zmReadWrite, zmCreate]) then
    raise EZipException.CreateRes(@SZipInvalideModeSetProp);

  FUtf8 := Value;
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
begin
  inherited Create(AStream, AOwner);

  FZStream.next_out := @FBuffer[0];
  FZStream.avail_out := Length(FBuffer);

(*
  *** deflateInit2参数说明 ***

int level
  作用：压缩级别，控制压缩速度与压缩率的权衡。

  取值范围：
  Z_NO_COMPRESSION (0)：不压缩，仅复制数据。
  Z_BEST_SPEED (1)：最快压缩，但压缩率最低。
  Z_BEST_COMPRESSION (9)：最高压缩率，但速度最慢。
  Z_DEFAULT_COMPRESSION (-1)：默认平衡（通常等价于6）。

  典型场景：
  实时传输：使用低级别（1-3）。
  存储归档：使用高级别（7-9）。


int method
  作用：指定压缩算法。
  唯一有效值：Z_DEFLATED (8)，对应 DEFLATE 算法（基于LZ77和哈夫曼编码）。
  其他值：理论上允许扩展其他方法，但 zlib 仅支持 Z_DEFLATED。


int windowBits
  作用：设置滑动窗口大小（以2为底的对数值），影响压缩率和内存占用。

  取值范围：
  常规模式：8 到 15（窗口大小为2^windowBits字节）。
  例如，windowBits=15 表示窗口大小 32KB（2^15=32768）。

  gzip 模式：在常规值基础上加 16（如 15+16=31），生成 gzip 格式的头部和尾部。
  原始模式：取负值（如 -15），禁用 zlib 头部校验，生成纯 DEFLATE 数据流。

  内存影响：
  每增加1，窗口大小翻倍，内存占用也近似翻倍。
  默认值 15（常规模式）或 31（gzip 模式）。


int memLevel
  作用：控制内部压缩状态的内存使用量（以2为底的对数值）。

  取值范围：1 到 9（内存为2^memLevelKB）。
  默认值 8（256KB）。
  值越大，压缩速度可能越快（更多内存用于哈希表），但内存消耗增加。

  典型建议：
  内存受限环境：使用 1（2KB）或 8（256KB）。
  高性能场景：使用 9（512KB）。


int strategy
  作用：调整压缩算法策略，优化特定类型数据。

  可选值：
  Z_DEFAULT_STRATEGY (0)：通用数据（默认）。
  Z_FILTERED (1)：过滤后的数据（如文本中存在大量重复字符）。
  Z_HUFFMAN_ONLY (2)：仅使用哈夫曼编码，禁用LZ77匹配（适用于不可压缩数据）。
  Z_RLE (3)：游程编码优化（适用于包含连续重复字节的数据，如简单图像）。
  Z_FIXED (4)：使用固定哈夫曼表（减少动态表开销，适合小数据或低熵数据）。

  应用示例：
  文本日志：Z_FILTERED 或 Z_DEFAULT_STRATEGY。
  PNG图像：Z_RLE 可能更高效。
*)
  deflateInit2(
    FZStream,
    ACompressLevel,
    Z_DEFLATED,
    AWindowBits,
    AMemLevel,
    AStrategy
  );
end;

destructor TDeflateCompressStream.Destroy;
begin
  FZStream.next_in := nil;
  FZStream.avail_in := 0;

  try
    if (FStream.Position <> FStreamPos) then
      FStream.Position := FStreamPos;

    while (deflate(FZStream, Z_FINISH) <> Z_STREAM_END) do
    begin
      FStream.WriteBuffer(FBuffer, Length(FBuffer) - Integer(FZStream.avail_out));

      FZStream.next_out := @FBuffer[0];
      FZStream.avail_out := Length(FBuffer);
    end;

    if (Integer(FZStream.avail_out) < Length(FBuffer)) then
    begin
      FStream.WriteBuffer(FBuffer, Length(FBuffer) - Integer(FZStream.avail_out));
    end;
  finally
    deflateEnd(FZStream);
  end;

  inherited;
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
begin
  inherited Create(AStream, AOwner);

  FZStream.next_in := @FBuffer[0];
  FZStream.avail_in := 0;

  inflateInit2(
    FZStream,
    -15);
end;

destructor TDeflateDecompressStream.Destroy;
begin
  inflateEnd(FZStream);
  FStream.Position := FStreamPos - FZStream.avail_in;

  inherited;
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

  FSize := AZipHeader^.CompressedSize - SIZE_ZIP_CRYPT_HEAD;
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
  Randomize;
  for I := 0 to SIZE_ZIP_CRYPT_HEAD - 1 do
    LZipClassicCryptHeader[I] := Byte(Random(256));

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
begin
  // 原地加密, 避免内存复制
  P := @Buffer;
  FZipCrypto.Encrypt(P, Count);
  Result := FZipStream.Write(P^, Count);
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
  LKeyBuf := PBKDF2ToBytes(LSalt, APassword, PBKDF2_ITERATIONS, LKeySize * 2 + 2);
  if (LVerifyCode <> PWord(@LKeyBuf[LKeySize * 2])^) then
    raise EZipException.CreateRes(@SZipInvalidPassword);

  // 加密数据结构:
  // 盐值 + 2字节密码校验值 + AES加密数据 + 10字节认证码
  FSize := AZipHeader^.CompressedSize - LSaltSize - 2{密码校验值} - 10{认证码(HMAC)};
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
end;

destructor TZipAESDecryptStream.Destroy;
begin
  try
    try
      CheckHmac;
    except
      // 忽略析构函数中的异常, 避免资源泄漏
    end;
  finally
    FreeAndNil(FAESCTREncryptor);
    FreeAndNil(FSha1Hmac);
    inherited Destroy;
  end;
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
  LSaltSize, LKeySize, I: Integer;
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
  Randomize;
  for I := 0 to High(LSalt) do
    LSalt[I] := Byte(Random(256));

  // 根据盐值和密码生成密钥
  // 密钥结构: AES密钥(LKeySize字节) + HMAC密钥(LKeySize字节) + 密码校验值(2字节)
  LKeyBuf := PBKDF2ToBytes(LSalt, APassword, PBKDF2_ITERATIONS, LKeySize * 2 + 2);

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
begin
  // 原地加密, 避免内存复制
  P := @Buffer;
  FAESCTREncryptor.Execute(P, Count);
  FSha1Hmac.Update(P, Count);
  Result := FZipStream.Write(P^, Count);
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
