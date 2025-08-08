unit Utils.PBKDF2;

interface

uses
  SysUtils,
  Math,

  Utils.Hash;

// PBKDF2(Password-Based Key Derivation Function 2)
// 是一种基于密码的密钥派生函数, 广泛用于从密码生成加密密钥.
// 它通过将密码与盐值结合, 并经过多次迭代的哈希运算来增强安全性,
// 抵御暴力破解和字典攻击
// AES ZIP 密钥就是由 PBKDF2 算法生成
procedure PBKDF2ToBuf(const ASalt, APassword: TBytes; AIterations,
  ADerivedKeyLen: Integer; const ABuf: PByte; const AHashClass: THashClass = nil); overload;
function PBKDF2ToBytes(const ASalt, APassword: TBytes; AIterations,
  ADerivedKeyLen: Integer; const AHashClass: THashClass = nil): TBytes; overload;

implementation

procedure PBKDF2ToBuf(const ASalt, APassword: TBytes; AIterations,
  ADerivedKeyLen: Integer; const ABuf: PByte;
  const AHashClass: THashClass);
var
  LHashClass: THashClass;
  LHashSize, LBlockCount, I, J, K: Integer;
  LSaltWithBlock: TBytes;
  LCurrentBlockHash, LDerivedBlock: TBytes;
begin
  if Assigned(AHashClass) then
    LHashClass := AHashClass
  else
    LHashClass := THashSHA1;

  // 确定哈希输出大小
  LHashSize := LHashClass.GetHashSize;

  LBlockCount := (ADerivedKeyLen + LHashSize - 1) div LHashSize;

  // 设置盐值与块索引
  SetLength(LSaltWithBlock, Length(ASalt) + 4);

  // 处理每个块
  for I := 1 to LBlockCount do
  begin
    // 添加块索引(Big-Endian)
    Move(ASalt[0], LSaltWithBlock[0], Length(ASalt));
    LSaltWithBlock[Length(ASalt)] := Byte((I shr 24) and $FF);
    LSaltWithBlock[Length(ASalt) + 1] := Byte((I shr 16) and $FF);
    LSaltWithBlock[Length(ASalt) + 2] := Byte((I shr 8) and $FF);
    LSaltWithBlock[Length(ASalt) + 3] := Byte(I and $FF);

    // 计算 U_1 = HMAC(Salt || BlockIndex, APassword)
    LCurrentBlockHash := LHashClass.GetHMACBytes(LSaltWithBlock, APassword);
    LDerivedBlock := LCurrentBlockHash; // 初始化 XOR 值为 U_1

    // 迭代计算 HMAC
    for J := 2 to AIterations do
    begin
      // 计算 U_i = HMAC(U_(i-1), APassword)
      LCurrentBlockHash := LHashClass.GetHMACBytes(LCurrentBlockHash, APassword);

      // 按位异或, 累积结果到 LDerivedBlock
      for K := 0 to LHashSize - 1 do
        LDerivedBlock[K] := LDerivedBlock[K] xor LCurrentBlockHash[K];
    end;

    // 将计算结果拷贝到派生密钥中
    Move(LDerivedBlock[0],
      ABuf[(I - 1) * LHashSize],
      Min(LHashSize, ADerivedKeyLen - (I - 1) * LHashSize));
  end;
end;

function PBKDF2ToBytes(const ASalt, APassword: TBytes; AIterations,
  ADerivedKeyLen: Integer; const AHashClass: THashClass): TBytes;
begin
  SetLength(Result, ADerivedKeyLen);
  PBKDF2ToBuf(ASalt, APassword, AIterations, ADerivedKeyLen, Pointer(Result), AHashClass);
end;

end.
