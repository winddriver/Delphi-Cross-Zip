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

unit CnPoly1305;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�Poly1305 ��Ϣ��֤�㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack �����飨master@cnpack.org)
* ��    ע������Ԫ���� RFC 7539 �淶ʵ����Poly1305 ��Ϣ��֤�㷨��
*           ���㷨������Ϊ���ⳤ�������� 32 �ֽ���Կ����� 16 �ֽ��Ӵ�ֵ����ɢ�Բ����Ǻܺ�
*           ע�⣺���� TCnBigNumber ʹ�õ� Binary ���������ֽ�˳��Ҳ���Ǵ�ˣ�
*           �� RFC ���ֹ涨�����С�ˣ���˴�����Ҫ�ֶ����� ReverseMemory��
*           ���� CPU �Ǵ�˻���С�ˡ�
* ����ƽ̨��Windows 7 + Delphi 5.0
* ���ݲ��ԣ�PWin9X/2000/XP/7 + Delphi 5/6
* �� �� �����õ�Ԫ�е��ַ��������ϱ��ػ�����ʽ
* �޸ļ�¼��2022.07.19 V1.0
*               ������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  Classes, SysUtils, CnNative, CnBigNumber;

const
  CN_POLY1305_KEYSIZE   = 32;
  {* Poly1305 �㷨�����볤�ȣ����� 32 �ֽ�Ҳ���� 256 λ�� Key}

  CN_POLY1305_BLOCKSIZE = 16;
  {* Poly1305 �㷨���ڲ��ֿ鳤�ȣ�ÿ�� 16 �ֽ�}

  CN_POLY1305_DIGSIZE   = 16;
  {* Poly1305 �㷨��ժҪ������ȣ�16 �ֽ�Ҳ���� 128 λ}

type
  TCnPoly1305Key = array[0..CN_POLY1305_KEYSIZE - 1] of Byte;
  {* Poly1305 �㷨�� Key}

  TCnPoly1305Digest = array[0..CN_POLY1305_DIGSIZE - 1] of Byte;
  {* Poly1305 �㷨���Ӵս��}

  TCnPoly1305Context = class
  {* �ֿ���� Poly1305 �������Ķ���}
  private
    R: TCnBigNumber;
    S: TCnBigNumber;
    A: TCnBigNumber;
    N: TCnBigNumber;
  public
    constructor Create;
    destructor Destroy; override;
  end;

function Poly1305Buffer(const Buffer; Count: Cardinal; Key: TCnPoly1305Key): TCnPoly1305Digest;
{* �����ݿ���� Poly1305 ���㣬Buffer һ�㴫����ַ��

   ������
     const Buffer                         - ����������ݿ��ַ
     Count: Cardinal                      - ����������ݿ���ֽڳ���
     Key: TCnPoly1305Key                  - ����

   ����ֵ��TCnPoly1305Digest              - ���ؼ���� Poly 1305 �Ӵ�ֵ
}

function Poly1305Bytes(Data: TBytes; Key: TBytes): TCnPoly1305Digest;
{* �����ֽ������ Poly1305 �Ӵ�ֵ��

   ������
     Data: TBytes                         - ��������ֽ�����
     Key: TBytes                          - �����ֽ�����

   ����ֵ��TCnPoly1305Digest              - ���ؼ���� Poly 1305 �Ӵ�ֵ
}

function Poly1305Data(Data: Pointer; DataByteLength: Cardinal;
  Key: TCnPoly1305Key): TCnPoly1305Digest;
{* �������ݿ�� Poly1305 �Ӵ�ֵ��

   ������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLength: Cardinal             - ����������ݿ��ֽڳ���
     Key: TCnPoly1305Key                  - ����

   ����ֵ��TCnPoly1305Digest              - ���ؼ���� Poly 1305 �Ӵ�ֵ
}

function Poly1305Print(const Digest: TCnPoly1305Digest): string;
{* ��ʮ�����Ƹ�ʽ��� Poly1305 ����ֵ��

   ������
     const Digest: TCnPoly1305Digest      - Poly1305 �Ӵ�ֵ

   ����ֵ��string                         - ����ʮ�������ַ���
}

function Poly1305Match(const D1: TCnPoly1305Digest; const D2: TCnPoly1305Digest): Boolean;
{* �Ƚ����� Poly1305 ����ֵ�Ƿ���ȡ�

   ������
     const D1: TCnPoly1305Digest          - ���Ƚϵ� Poly1305 �Ӵ�ֵһ
     const D2: TCnPoly1305Digest          - ���Ƚϵ� Poly1305 �Ӵ�ֵ��

   ����ֵ��Boolean                        - �������� Poly 1305 �Ӵ�ֵ�Ƿ����
}

function Poly1305DigestToStr(const Digest: TCnPoly1305Digest): string;
{* Poly1305 ����ֵת string��

   ������
     const Digest: TCnPoly1305Digest      - ��ת���� Poly1305 �Ӵ�ֵ

   ����ֵ��string                         - ����ת������ַ������ݣ����������
}

procedure Poly1305Init(out Context: TCnPoly1305Context; Key: TCnPoly1305Key);
{* ��ʼ��һ�� Poly1305 ���������ģ��ڲ����� Context ׼������ Poly1305 �����

   ������
     out Context: TCnPoly1305Context      - ��ʼ���� Poly1305 �����Ľṹ
     Key: TCnPoly1305Key                  - ����

   ����ֵ�����ޣ�
}

procedure Poly1305Update(Context: TCnPoly1305Context; Input: PAnsiChar;
  ByteLength: Cardinal; ZeroPadding: Boolean = False);
{* �Գ�ʼ����������Ķ�һ�����ݽ��� Poly1305 ���㡣
   �ɶ�ε������������㲻ͬ�����ݿ飬���轫��ͬ�����ݿ�ƴ�����������ڴ��С�
   ���� Update ����Ϊ������ĩβ������ʱ��ǿ�м��㣬�����������Ӵ�һ���ݴ����һ�ֻ� Final��
   ZeroPadding ����ĩβ��� 16 ��ʱ�Ƿ� 0��

   ������
     Context: TCnPoly1305Context          - Poly1305 �����Ľṹ
     Input: PAnsiChar                     - ����������ݿ��ַ
     ByteLength: Cardinal                 - ����������ݿ��ֽڳ��ȣ��� 16 �ֽ�����ʱ��ǿ�м���
     ZeroPadding: Boolean                 - ĩβ��� 16 �ֽ���ʱ�Ƿ�ĩβ�� 0

   ����ֵ�����ޣ�
}

procedure Poly1305Final(var Context: TCnPoly1305Context; var Digest: TCnPoly1305Digest);
{* �������ּ��㣬�� Poly130 ��������� Digest �в��ͷ� Context��

   ������
     var Context: TCnPoly1305Context      - Poly1305 �����Ľṹ
     var Digest: TCnPoly1305Digest        - ���ص� Poly1305 �Ӵ�ֵ

   ����ֵ�����ޣ�
}

implementation

var
  Prime: TCnBigNumber = nil; // Poly1305 ʹ�õ�����
  Clamp: TCnBigNumber = nil; // Poly1305 ʹ�õ� Clamp

function Poly1305Bytes(Data: TBytes; Key: TBytes): TCnPoly1305Digest;
var
  AKey: TCnPoly1305Key;
  L: Integer;
begin
  FillChar(AKey[0], SizeOf(TCnPoly1305Key), 0);
  L := Length(Key);
  if L > SizeOf(TCnPoly1305Key) then
    L := SizeOf(TCnPoly1305Key);

  Move(Key[0], AKey[0], L);
  Result := Poly1305Data(@Data[0], Length(Data), AKey);
end;

function Poly1305Buffer(const Buffer; Count: Cardinal; Key: TCnPoly1305Key): TCnPoly1305Digest;
var
  C: TCnPoly1305Context;
begin
  Poly1305Init(C, Key);
  Poly1305Update(C, PAnsiChar(Buffer), Count);
  Poly1305Final(C, Result);
end;

function Poly1305Data(Data: Pointer; DataByteLength: Cardinal;
  Key: TCnPoly1305Key): TCnPoly1305Digest;
var
  I, B, L: Integer;
  R, S, A, N: TCnBigNumber;
  Buf: array[0..CN_POLY1305_BLOCKSIZE] of Byte;
  P: PByteArray;
  RKey: TCnPoly1305Key;
begin
  Move(Key[0], RKey[0], SizeOf(TCnPoly1305Key));

  // ���� TCnBigNumber ʹ�õ� Binary ���������ֽ�˳��Ҳ���Ǵ��
  // �� RFC ���ֹ涨�����С�����Ҫ�ֶ����� ReverseMemory ���� CPU �Ǵ�˻���С��
  ReverseMemory(@RKey[0], CN_POLY1305_BLOCKSIZE);
  ReverseMemory(@RKey[CN_POLY1305_BLOCKSIZE], CN_POLY1305_BLOCKSIZE);

  R := nil;
  S := nil;
  A := nil;
  N := nil;

  try
    R := TCnBigNumber.FromBinary(@RKey[0], CN_POLY1305_BLOCKSIZE);
    BigNumberAnd(R, R, Clamp);

    S := TCnBigNumber.FromBinary(@RKey[CN_POLY1305_BLOCKSIZE], CN_POLY1305_BLOCKSIZE);

    A := TCnBigNumber.Create;
    A.SetZero;

    N := TCnBigNumber.Create;

    B := (DataByteLength + CN_POLY1305_BLOCKSIZE - 1) div CN_POLY1305_BLOCKSIZE;
    P := PByteArray(Data);

    for I := 1 to B do
    begin
      if I <> B then // ��ͨ�飬16 �ֽ�����
        L := CN_POLY1305_BLOCKSIZE
      else           // β�飬���ܲ��� 16 �ֽ�
      begin
        L := DataByteLength mod CN_POLY1305_BLOCKSIZE;
        if L = 0 then
          L := CN_POLY1305_BLOCKSIZE;
      end;

      Move(P^[(I - 1) * CN_POLY1305_BLOCKSIZE], Buf[0], L);  // ��������
      Buf[L] := 1;                                           // ���ڵĸ��ֽ����ø� 1

      ReverseMemory(@Buf[0], L + 1);
      N.SetBinary(@Buf[0], L + 1);

      BigNumberAdd(A, A, N);
      BigNumberDirectMulMod(A, R, A, Prime);
    end;

    BigNumberAdd(A, A, S);
    BigNumberKeepLowBits(A, 8 * CN_POLY1305_DIGSIZE);

    A.ToBinary(@Result[0], CN_POLY1305_DIGSIZE);
    ReverseMemory(@Result[0], SizeOf(TCnPoly1305Digest));
  finally
    N.Free;
    A.Free;
    S.Free;
    R.Free;
  end;
end;

function Poly1305Print(const Digest: TCnPoly1305Digest): string;
begin
  Result := DataToHex(@Digest[0], SizeOf(TCnPoly1305Digest));
end;

function Poly1305Match(const D1, D2: TCnPoly1305Digest): Boolean;
begin
  Result := CompareMem(@D1[0], @D2[0], SizeOf(TCnPoly1305Digest));
end;

function Poly1305DigestToStr(const Digest: TCnPoly1305Digest): string;
begin
  Result := MemoryToString(@Digest[0], SizeOf(TCnPoly1305Digest));
end;

{ TCnPoly1305Context }

constructor TCnPoly1305Context.Create;
begin
  inherited;
  R := TCnBigNumber.Create;
  S := TCnBigNumber.Create;
  A := TCnBigNumber.Create;
  N := TCnBigNumber.Create;
end;

destructor TCnPoly1305Context.Destroy;
begin
  N.Free;
  A.Free;
  S.Free;
  R.Free;
  inherited;
end;

procedure Poly1305Init(out Context: TCnPoly1305Context; Key: TCnPoly1305Key);
var
  RKey: TCnPoly1305Key;
begin
  Move(Key[0], RKey[0], SizeOf(TCnPoly1305Key));
  ReverseMemory(@RKey[0], CN_POLY1305_BLOCKSIZE);
  ReverseMemory(@RKey[CN_POLY1305_BLOCKSIZE], CN_POLY1305_BLOCKSIZE);

  Context := TCnPoly1305Context.Create;

  Context.R.SetBinary(@RKey[0], CN_POLY1305_BLOCKSIZE);
  BigNumberAnd(Context.R, Context.R, Clamp);

  Context.S.SetBinary(@RKey[CN_POLY1305_BLOCKSIZE], CN_POLY1305_BLOCKSIZE);
  Context.A.SetZero;
  Context.N.SetZero;
end;

procedure Poly1305Update(Context: TCnPoly1305Context; Input: PAnsiChar;
  ByteLength: Cardinal; ZeroPadding: Boolean);
var
  I, B, L: Integer;
  Buf: array[0..CN_POLY1305_BLOCKSIZE] of Byte;
  P: PByteArray;
begin
  B := (ByteLength + CN_POLY1305_BLOCKSIZE - 1) div CN_POLY1305_BLOCKSIZE;
  P := PByteArray(Input);

  for I := 1 to B do
  begin
    if I <> B then // ��ͨ�飬16 �ֽ�����
      L := CN_POLY1305_BLOCKSIZE
    else           // β�飬���ܲ��� 16 �ֽ�
    begin
      L := ByteLength mod CN_POLY1305_BLOCKSIZE;
      if L = 0 then
        L := CN_POLY1305_BLOCKSIZE
      else if ZeroPadding then
        FillChar(Buf[0], SizeOf(Buf), 0); // ĩβ�鲻�� 16 ��Ҫ�� 0 ������Ҫ���ȫ 0
    end;

    Move(P^[(I - 1) * CN_POLY1305_BLOCKSIZE], Buf[0], L);  // ��������
    if ZeroPadding then                                    // ĩβ�����Ҫ�� 0 �����油�ˣ�����Ҫ���� 1
      L := CN_POLY1305_BLOCKSIZE;
    Buf[L] := 1;                                           // ���ڵĸ��ֽڣ��� 0 ʱ����ֽڣ����ø� 1

    ReverseMemory(@Buf[0], L + 1);
    Context.N.SetBinary(@Buf[0], L + 1);

    BigNumberAdd(Context.A, Context.A, Context.N);
    BigNumberDirectMulMod(Context.A, Context.R, Context.A, Prime);
  end;
end;

procedure Poly1305Final(var Context: TCnPoly1305Context; var Digest: TCnPoly1305Digest);
begin
  BigNumberAdd(Context.A, Context.A, Context.S);
  BigNumberKeepLowBits(Context.A, 8 * CN_POLY1305_DIGSIZE);

  Context.A.ToBinary(@Digest[0], CN_POLY1305_DIGSIZE);
  ReverseMemory(@Digest[0], SizeOf(TCnPoly1305Digest));

  FreeAndNil(Context);
end;

initialization
  Prime := TCnBigNumber.Create;
  Prime.SetOne;
  Prime.ShiftLeft(130);
  Prime.SubWord(5);

  Clamp := TCnBigNumber.FromHex('0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF');

finalization
  Clamp.Free;
  Prime.Free;

end.
