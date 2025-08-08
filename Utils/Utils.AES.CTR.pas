unit Utils.AES.CTR;

{ ***** AES CTR 说明 *****
AES CTR（Counter）模式是一种将块密码转换为流密码的方法。在这种模式下，AES算法不
再直接对明文数据进行加密，而是通过加密一个不断递增的计数器（Counter）来生成一个
伪随机的密钥流（Keystream），然后将这个密钥流与明文进行异或操作，从而得到密文。

下面是AES CTR模式的工作原理和加密过程的详细介绍：

工作原理
  初始化计数器（Counter）‌：首先，需要一个初始计数器值，这个值通常是一个随机或伪随机的数，以确保加密过程的不可预测性。在AES CTR模式中，计数器的大小通常与AES的块大小相同，即128位。
  生成密钥流（Keystream）‌：使用AES算法对初始计数器值进行加密，得到一个固定长度的输出，这个输出就是密钥流的一部分。然后，计数器的值增加1，再次进行AES加密，以此类推，直到生成足够长的密钥流以覆盖整个明文。
  异或操作：将生成的密钥流与明文进行逐位异或操作，得到密文。由于异或操作的特性，同样的密钥流与密文再次进行异或操作，就可以恢复出明文，从而实现解密。

加密过程
  假设我们有一段明文P和一个密钥K，AES CTR模式的加密过程如下：
    初始化计数器C为一个随机或伪随机的初始值。
    对计数器C进行AES加密，得到密钥流Ks。
    将密钥流Ks与明文P进行异或操作，得到密文Ciphertext。
    将计数器C增加1，重复步骤2和3，直到加密完整个明文。
    输出密文Ciphertext和最终的计数器值。

安全特性
  AES CTR模式具有以下安全特性：
    并行处理：由于AES CTR模式的加密和解密过程不依赖于前一个块的状态，因此可以并行处理，提高了效率。
    随机访问：可以在不解密整个密文的情况下，直接解密特定位置的密文块，这在处理大型数据时非常有用。
    安全性：只要计数器的初始值是随机的，AES CTR模式就能提供与AES算法本身同等的安全性。

应用场景
  AES CTR模式适用于多种场景，包括但不限于：
    网络通信：在网络传输中，AES CTR模式可以提供高效的数据加密，保护数据的机密性。
    存储加密：在存储设备上，AES CTR模式可以用来加密存储的数据，防止未授权访问。
    实时加密：对于需要实时加密的应用，如视频会议或实时数据备份，AES CTR模式的并行处理能力可以满足需求。

总之，AES CTR模式是一种灵活且高效的加密模式，它通过将AES算法与计数器相结合，提供了一种强大的流密码解决方案
}

{$I zLib.inc}
{$Q-}

interface

uses
  SysUtils,
  Classes,

  CnAES,
  CnNative;

type
  TAESExpandedKey = record
    case Integer of
      0: (ExpandedKey128: TCnAESExpandedKey128);
      1: (ExpandedKey192: TCnAESExpandedKey192);
      2: (ExpandedKey256: TCnAESExpandedKey256);
  end;

  TAESCTRCryptor = class abstract
  protected
    FKeyBitType: TCnKeyBitType;
    FAESExpandedKey: TAESExpandedKey;
    FCryptBlock, FCryptNonce: TCnAESBuffer;
    FCryptPos: Integer;

    procedure Init(const ANonce: TCnAESBuffer);
    procedure ProcBlock(var ACryptBlock: TCnAESBuffer); virtual; abstract;
  public
    constructor Create(const AKey128: TCnAESKey128; const ANonce: TCnAESBuffer); overload;
    constructor Create(const AKey192: TCnAESKey192; const ANonce: TCnAESBuffer); overload;
    constructor Create(const AKey256: TCnAESKey256; const ANonce: TCnAESBuffer); overload;

    procedure Execute(AData: PByte; ASize: Integer); overload; virtual;
    procedure Execute(var AData: TBytes); overload;
  end;

  TAESCTREncryptor = class(TAESCTRCryptor)
  protected
    procedure ProcBlock(var ACryptBlock: TCnAESBuffer); override;
  end;

implementation

{ TAESCTRCryptor }

constructor TAESCTRCryptor.Create(const AKey128: TCnAESKey128;
  const ANonce: TCnAESBuffer);
begin
  FKeyBitType := kbt128;
  ExpandAESKeyForEncryption128(AKey128, FAESExpandedKey.ExpandedKey128);
  Init(ANonce);
end;

constructor TAESCTRCryptor.Create(const AKey192: TCnAESKey192;
  const ANonce: TCnAESBuffer);
begin
  FKeyBitType := kbt192;
  ExpandAESKeyForEncryption192(AKey192, FAESExpandedKey.ExpandedKey192);
  Init(ANonce);
end;

constructor TAESCTRCryptor.Create(const AKey256: TCnAESKey256;
  const ANonce: TCnAESBuffer);
begin
  FKeyBitType := kbt256;
  ExpandAESKeyForEncryption256(AKey256, FAESExpandedKey.ExpandedKey256);
  Init(ANonce);
end;

procedure TAESCTRCryptor.Execute(AData: PByte; ASize: Integer);
var
  I, J: Integer;
begin
  for I := 0 to ASize - 1 do
  begin
    if (FCryptPos = CN_AES_BLOCKSIZE) then
    begin
      // FCryptNonce 是计数器, 用于生成唯一的加密块。
      // 每次递增低 8 字节的 FCryptNonce, 实现加密块的序列化。
      // 遇到溢出时, 逐字节向更高位进位。
      // 必须使用这个编译开关: {$Q-}, 否则会报 EIntOverflow
      for J := 0 to 7 do
      begin
        Inc(FCryptNonce[J]);
        if (FCryptNonce[J] <> 0) then Break;
      end;

      // 每块数据都用 FCryptNonce 进行加密后生成异或密钥
      // 异或密钥保存在 FCryptBlock 中
      Move(FCryptNonce[0], FCryptBlock[0], CN_AES_BLOCKSIZE);
      ProcBlock(FCryptBlock);
      FCryptPos := 0;
    end;

    // 将数据与密钥进行异或
    AData[I] := (AData[I] xor FCryptBlock[FCryptPos]);
    Inc(FCryptPos);
  end;
end;

procedure TAESCTRCryptor.Execute(var AData: TBytes);
begin
  Execute(Pointer(AData), Length(AData));
end;

procedure TAESCTRCryptor.Init(const ANonce: TCnAESBuffer);
begin
  FCryptNonce := ANonce;
  FCryptPos := CN_AES_BLOCKSIZE;
  FillChar(FCryptBlock, SizeOf(FCryptBlock), 0);
end;

{ TAESCTREncryptor }

procedure TAESCTREncryptor.ProcBlock(var ACryptBlock: TCnAESBuffer);
begin
  case FKeyBitType of
    kbt128: EncryptAES128(ACryptBlock, FAESExpandedKey.ExpandedKey128, ACryptBlock);
    kbt192: EncryptAES192(ACryptBlock, FAESExpandedKey.ExpandedKey192, ACryptBlock);
    kbt256: EncryptAES256(ACryptBlock, FAESExpandedKey.ExpandedKey256, ACryptBlock);
  end;
end;

end.
