{******************************************************************************}
{                       CnPack For Delphi/C++Builder                           }
{                     �й����Լ��Ŀ���Դ�������������                         }
{                   (C)Copyright 2001-2025 CnPack ������                       }
{                   ------------------------------------                       }
{                                                                              }
{            ���������ǿ�Դ��������������������� CnPack �ķ���Э������        }
{        �ĺ����·�����һ����                                                }
{                                                                              }
{            ������һ��������Ŀ����ϣ�������ã���û���κε���������û��        }
{        �ʺ��ض�Ŀ�Ķ������ĵ���������ϸ���������� CnPack ����Э�顣        }
{                                                                              }
{            ��Ӧ���Ѿ��Ϳ�����һ���յ�һ�� CnPack ����Э��ĸ��������        }
{        ��û�У��ɷ������ǵ���վ��                                            }
{                                                                              }
{            ��վ��ַ��https://www.cnpack.org                                  }
{            �����ʼ���master@cnpack.org                                       }
{                                                                              }
{******************************************************************************}

unit CnFNV;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�FNV �Ӵ��㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack �����飨master@cnpack.org)
* ��    ע������Ԫʵ����һ�ּ��׵Ŀɱ䳤�ȵ��Ӵ��㷨 FNV�������������� FNV-1 �� FNV-1a��
*           �����ض�������ƫ�������ֽ�����������㷨��������Ϊ Fowler-Noll-Vo
* ����ƽ̨��Windows 7 + Delphi 5.0
* ���ݲ��ԣ�
* �� �� �����õ�Ԫ�е��ַ��������ϱ��ػ�����ʽ
* �޸ļ�¼��2023.01.16 V1.0
*               ��ֲ��������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  Classes, SysUtils, CnNative, CnBigNumber;

type
  TCnFNVType = (cft32, cft64, cft128, cft256, cft512, cft1024);
  {* ����ͬ���ȵ� FNV ����}

  TCnFNVHash32    = array[0..3] of Byte;
  {* 32 λҲ���� 4 �ֽڳ��� FNV ���}

  TCnFNVHash64    = array[0..7] of Byte;
  {* 64 λҲ���� 8 �ֽڳ��� FNV ���}

  TCnFNVHash128   = array[0..15] of Byte;
  {* 128 λҲ���� 16 �ֽڳ��� FNV ���}

  TCnFNVHash256   = array[0..31] of Byte;
  {* 256 λҲ���� 32 �ֽڳ��� FNV ���}

  TCnFNVHash512   = array[0..63] of Byte;
  {* 512 λҲ���� 64 �ֽڳ��� FNV ���}

  TCnFNVHash1024  = array[0..127] of Byte;
  {* 1024 λҲ���� 128 �ֽڳ��� FNV ���}

// ������ FNV �Ľ�����ͣ����Դ�˱�ʾ

function FNV1Hash32(Data: TBytes): TCnFNVHash32; overload;
{* ���ֽ������ FNV-1 �Ӵս����������� 32 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash32                   - ���ص� 32 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash64(Data: TBytes): TCnFNVHash64; overload;
{* ���ֽ������ FNV-1 �Ӵս����������� 64 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash64                   - ���ص� 64 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash128(Data: TBytes): TCnFNVHash128; overload;
{* ���ֽ������ FNV-1 �Ӵս����������� 128 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash128                  - ���ص� 128 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash256(Data: TBytes): TCnFNVHash256; overload;
{* ���ֽ������ FNV-1 �Ӵս����������� 256 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash256                  - ���ص� 256 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash512(Data: TBytes): TCnFNVHash512; overload;
{* ���ֽ������ FNV-1 �Ӵս����������� 512 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash512                  - ���ص� 512 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash1024(Data: TBytes): TCnFNVHash1024; overload;
{* ���ֽ������ FNV-1 �Ӵս����������� 1024 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash1024                 - ���ص� 1024 λ FNV-1 �Ӵ�ֵ
}

function FNV1aHash32(Data: TBytes): TCnFNVHash32; overload;
{* ���ֽ������ FNV-1a �Ӵս����������� 32 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash32                   - ���ص� 32 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash64(Data: TBytes): TCnFNVHash64; overload;
{* ���ֽ������ FNV-1a �Ӵս����������� 64 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash64                   - ���ص� 64 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash128(Data: TBytes): TCnFNVHash128; overload;
{* ���ֽ������ FNV-1a �Ӵս����������� 128 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash128                  - ���ص� 128 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash256(Data: TBytes): TCnFNVHash256; overload;
{* ���ֽ������ FNV-1a �Ӵս����������� 256 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash256                  - ���ص� 256 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash512(Data: TBytes): TCnFNVHash512; overload;
{* ���ֽ������ FNV-1a �Ӵս����������� 512 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash512                  - ���ص� 512 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash1024(Data: TBytes): TCnFNVHash1024; overload;
{* ���ֽ������ FNV-1a �Ӵս����������� 1024 λ��

   ������
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��TCnFNVHash1024                 - ���ص� 1024 λ FNV-1a �Ӵ�ֵ
}

function FNV1Hash32(Data: Pointer; DataByteLen: Integer): TCnFNVHash32; overload;
{* �����ݿ�� FNV-1 �Ӵս����������� 32 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash32                   - ���ص� 32 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash64(Data: Pointer; DataByteLen: Integer): TCnFNVHash64; overload;
{* �����ݿ�� FNV-1 �Ӵս����������� 64 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash64                   - ���ص� 64 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash128(Data: Pointer; DataByteLen: Integer): TCnFNVHash128; overload;
{* �����ݿ�� FNV-1 �Ӵս����������� 128 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash128                  - ���ص� 128 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash256(Data: Pointer; DataByteLen: Integer): TCnFNVHash256; overload;
{* �����ݿ�� FNV-1 �Ӵս����������� 256 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash256                  - ���ص� 256 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash512(Data: Pointer; DataByteLen: Integer): TCnFNVHash512; overload;
{* �����ݿ�� FNV-1 �Ӵս����������� 512 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash512                  - ���ص� 512 λ FNV-1 �Ӵ�ֵ
}

function FNV1Hash1024(Data: Pointer; DataByteLen: Integer): TCnFNVHash1024; overload;
{* �����ݿ�� FNV-1 �Ӵս����������� 1024 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash1024                 - ���ص� 1024 λ FNV-1 �Ӵ�ֵ
}

function FNV1aHash32(Data: Pointer; DataByteLen: Integer): TCnFNVHash32; overload;
{* �����ݿ�� FNV-1a �Ӵս����������� 32 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash32                   - ���ص� 32 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash64(Data: Pointer; DataByteLen: Integer): TCnFNVHash64; overload;
{* �����ݿ�� FNV-1a �Ӵս����������� 64 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash64                   - ���ص� 64 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash128(Data: Pointer; DataByteLen: Integer): TCnFNVHash128; overload;
{* �����ݿ�� FNV-1a �Ӵս����������� 128 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash128                  - ���ص� 128 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash256(Data: Pointer; DataByteLen: Integer): TCnFNVHash256; overload;
{* �����ݿ�� FNV-1a �Ӵս����������� 256 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash256                  - ���ص� 256 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash512(Data: Pointer; DataByteLen: Integer): TCnFNVHash512; overload;
{* �����ݿ�� FNV-1a �Ӵս����������� 512 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash512                  - ���ص� 512 λ FNV-1a �Ӵ�ֵ
}

function FNV1aHash1024(Data: Pointer; DataByteLen: Integer): TCnFNVHash1024; overload;
{* �����ݿ�� FNV-1a �Ӵս����������� 1024 λ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���

   ����ֵ��TCnFNVHash1024                 - ���ص� 1024 λ FNV-1a �Ӵ�ֵ
}

implementation

const
  FNV_PRIME_32   = '01000193';
  FNV_PRIME_64   = '00000100000001B3';
  FNV_PRIME_128  = '0000000001000000000000000000013B';
  FNV_PRIME_256  = '0000000000000000000001000000000000000000000000000000000000000163';
  FNV_PRIME_512  = '00000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000157';
  FNV_PRIME_1024 = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018D';

  FNV_OFFSET_BASIS_32   = '811C9DC5';
  FNV_OFFSET_BASIS_64   = 'CBF29CE484222325';
  FNV_OFFSET_BASIS_128  = '6C62272E07BB014262B821756295C58D';
  FNV_OFFSET_BASIS_256  = 'DD268DBCAAC550362D98C384C4E576CCC8B1536847B6BBB31023B4C8CAEE0535';
  FNV_OFFSET_BASIS_512  = 'B86DB0B1171F4416 DCA1E50F309990ACAC87D059C90000000000000000000D21E948F68A34C192F62EA79BC942DBE7CE182036415F56E34BAC982AAC4AFE9FD9';
  FNV_OFFSET_BASIS_1024 = '0000000000000000005F7A76758ECC4D32E56D5A591028B74B29FC4223FDADA16C3BF34EDA3674DA9A21D9000000000000000000000000000000000000000000' +
    '000000000000000000000000000000000000000000000000000000000004C6D7EB6E73802734510A555F256CC005AE556BDE8CC9C6A93B21AFF4B16C71EE90B3';

  FNV_PRIMES: array[Low(TCnFNVType)..High(TCnFNVType)] of string =
    (FNV_PRIME_32, FNV_PRIME_64, FNV_PRIME_128, FNV_PRIME_256, FNV_PRIME_512, FNV_PRIME_1024);

  FNV_OFFSET_BASISES: array[Low(TCnFNVType)..High(TCnFNVType)] of string =
    (FNV_OFFSET_BASIS_32, FNV_OFFSET_BASIS_64, FNV_OFFSET_BASIS_128,
    FNV_OFFSET_BASIS_256, FNV_OFFSET_BASIS_512, FNV_OFFSET_BASIS_1024);

  FNV_BIT_LENGTH: array[Low(TCnFNVType)..High(TCnFNVType)] of Integer =
    (32, 64, 128, 256, 512, 1024);

var
  FNV_PRIMES_BIGNUMBER: array[Low(TCnFNVType)..High(TCnFNVType)] of TCnBigNumber;

procedure SetPrime(FNVType: TCnFNVType; const Prime: TCnBigNumber);
begin
  Prime.SetHex(AnsiString(FNV_PRIMES[FNVType]));
end;

procedure SetOffsetBasis(FNVType: TCnFNVType; const Basis: TCnBigNumber);
begin
  Basis.SetHex(AnsiString(FNV_OFFSET_BASISES[FNVType]));
end;

//    hash := FNV_offset_basis
//
//    for each byte_of_data to be hashed do
//        hash := hash �� FNV_prime
//        hash := hash XOR byte_of_data
//
//    return hash
procedure FNV1(FNVType: TCnFNVType; D: PByte; Len: Integer; const Res: TCnBigNumber);
begin
  if D = nil then Len := 0;
  SetOffsetBasis(FNVType, Res);

  while Len > 0 do
  begin
    BigNumberMul(Res, Res, FNV_PRIMES_BIGNUMBER[FNVType]);
    BigNumberKeepLowBits(Res, FNV_BIT_LENGTH[FNVType]);
    BigNumberXorWord(Res, D^);

    Inc(D);
    Dec(Len);
  end;
end;

//    hash := FNV_offset_basis
//
//    for each byte_of_data to be hashed do
//        hash := hash XOR byte_of_data
//        hash := hash �� FNV_prime
//
//    return hash
procedure FNV1a(FNVType: TCnFNVType; D: PByte; Len: Integer; const Res: TCnBigNumber);
begin
  if D = nil then Len := 0;
  SetOffsetBasis(FNVType, Res);

  while Len > 0 do
  begin
    BigNumberXorWord(Res, D^);
    BigNumberMul(Res, Res, FNV_PRIMES_BIGNUMBER[FNVType]);
    BigNumberKeepLowBits(Res, FNV_BIT_LENGTH[FNVType]);

    Inc(D);
    Dec(Len);
  end;
end;

function FNV1Hash32(Data: TBytes): TCnFNVHash32;
begin
  if Length(Data) <= 0 then
    Result := FNV1Hash32(nil, 0)
  else
    Result := FNV1Hash32(@Data[0], Length(Data));
end;

function FNV1Hash64(Data: TBytes): TCnFNVHash64;
begin
  if Length(Data) <= 0 then
    Result := FNV1Hash64(nil, 0)
  else
    Result := FNV1Hash64(@Data[0], Length(Data));
end;

function FNV1Hash128(Data: TBytes): TCnFNVHash128;
begin
  if Length(Data) <= 0 then
    Result := FNV1Hash128(nil, 0)
  else
    Result := FNV1Hash128(@Data[0], Length(Data));
end;

function FNV1Hash256(Data: TBytes): TCnFNVHash256;
begin
  if Length(Data) <= 0 then
    Result := FNV1Hash256(nil, 0)
  else
    Result := FNV1Hash256(@Data[0], Length(Data));
end;

function FNV1Hash512(Data: TBytes): TCnFNVHash512;
begin
  if Length(Data) <= 0 then
    Result := FNV1Hash512(nil, 0)
  else
    Result := FNV1Hash512(@Data[0], Length(Data));
end;

function FNV1Hash1024(Data: TBytes): TCnFNVHash1024;
begin
  if Length(Data) <= 0 then
    Result := FNV1Hash1024(nil, 0)
  else
    Result := FNV1Hash1024(@Data[0], Length(Data));
end;

function FNV1aHash32(Data: TBytes): TCnFNVHash32;
begin
  if Length(Data) <= 0 then
    Result := FNV1aHash32(nil, 0)
  else
    Result := FNV1aHash32(@Data[0], Length(Data));
end;

function FNV1aHash64(Data: TBytes): TCnFNVHash64;
begin
  if Length(Data) <= 0 then
    Result := FNV1aHash64(nil, 0)
  else
    Result := FNV1aHash64(@Data[0], Length(Data));
end;

function FNV1aHash128(Data: TBytes): TCnFNVHash128;
begin
  if Length(Data) <= 0 then
    Result := FNV1aHash128(nil, 0)
  else
    Result := FNV1aHash128(@Data[0], Length(Data));
end;

function FNV1aHash256(Data: TBytes): TCnFNVHash256;
begin
  if Length(Data) <= 0 then
    Result := FNV1aHash256(nil, 0)
  else
    Result := FNV1aHash256(@Data[0], Length(Data));
end;

function FNV1aHash512(Data: TBytes): TCnFNVHash512;
begin
  if Length(Data) <= 0 then
    Result := FNV1aHash512(nil, 0)
  else
    Result := FNV1aHash512(@Data[0], Length(Data));
end;

function FNV1aHash1024(Data: TBytes): TCnFNVHash1024;
begin
  if Length(Data) <= 0 then
    Result := FNV1aHash1024(nil, 0)
  else
    Result := FNV1aHash1024(@Data[0], Length(Data));
end;

function FNV1Hash32(Data: Pointer; DataByteLen: Integer): TCnFNVHash32;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1(cft32, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft32] div 8);
  finally
    R.Free;
  end;
end;

function FNV1Hash64(Data: Pointer; DataByteLen: Integer): TCnFNVHash64;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1(cft64, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft64] div 8);
  finally
    R.Free;
  end;
end;

function FNV1Hash128(Data: Pointer; DataByteLen: Integer): TCnFNVHash128;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1(cft128, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft128] div 8);
  finally
    R.Free;
  end;
end;

function FNV1Hash256(Data: Pointer; DataByteLen: Integer): TCnFNVHash256;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1(cft256, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft256] div 8);
  finally
    R.Free;
  end;
end;

function FNV1Hash512(Data: Pointer; DataByteLen: Integer): TCnFNVHash512;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1(cft512, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft512] div 8);
  finally
    R.Free;
  end;
end;

function FNV1Hash1024(Data: Pointer; DataByteLen: Integer): TCnFNVHash1024;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1(cft1024, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft1024] div 8);
  finally
    R.Free;
  end;
end;

function FNV1aHash32(Data: Pointer; DataByteLen: Integer): TCnFNVHash32;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1a(cft32, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft32] div 8);
  finally
    R.Free;
  end;
end;

function FNV1aHash64(Data: Pointer; DataByteLen: Integer): TCnFNVHash64;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1a(cft64, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft64] div 8);
  finally
    R.Free;
  end;
end;

function FNV1aHash128(Data: Pointer; DataByteLen: Integer): TCnFNVHash128;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1a(cft128, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft128] div 8);
  finally
    R.Free;
  end;
end;

function FNV1aHash256(Data: Pointer; DataByteLen: Integer): TCnFNVHash256;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1a(cft256, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft256] div 8);
  finally
    R.Free;
  end;
end;

function FNV1aHash512(Data: Pointer; DataByteLen: Integer): TCnFNVHash512;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1a(cft512, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft512] div 8);
  finally
    R.Free;
  end;
end;

function FNV1aHash1024(Data: Pointer; DataByteLen: Integer): TCnFNVHash1024;
var
  R: TCnBigNumber;
begin
  R := TCnBigNumber.Create;
  try
    FNV1a(cft1024, PByte(Data), DataByteLen, R);
    R.ToBinary(@Result[0], FNV_BIT_LENGTH[cft1024] div 8);
  finally
    R.Free;
  end;
end;

procedure CreateFNVPrimes;
var
  I: TCnFNVType;
begin
  for I := Low(TCnFNVType) to High(TCnFNVType) do
  begin
    FNV_PRIMES_BIGNUMBER[I] := TCnBigNumber.Create;
    SetPrime(I, FNV_PRIMES_BIGNUMBER[I]);
  end;
end;

procedure FreeFNVPrimes;
var
  I: TCnFNVType;
begin
  for I := Low(TCnFNVType) to High(TCnFNVType) do
    FNV_PRIMES_BIGNUMBER[I].Free;
end;

initialization
  CreateFNVPrimes;

finalization
  FreeFNVPrimes;

end.
