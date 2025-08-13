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

unit CnRC4;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�RC4 ���ӽ����㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack �����飨master@cnpack.org)
* ��    ע������Ԫʵ���� RC4 ���ӽ����㷨��
* ����ƽ̨��Windows 7 + Delphi 5.0
* ���ݲ��ԣ�PWin9X/2000/XP/7 + Delphi 5/6
* �� �� �����õ�Ԫ�е��ַ��������ϱ��ػ�����ʽ
* �޸ļ�¼��2024.02.25 V1.0
*               ��ֲ��������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  Classes, SysUtils, CnNative;

const
  CN_RC4_MAX_KEY_BYTE_LENGTH = 256;
  {* �֧�� 256 �ֽ�Ҳ���� 2048 λ����Կ��Ҳ���ڲ� S �еĴ�С}

procedure RC4Encrypt(Key: Pointer; KeyByteLength: Integer; Input: Pointer;
  Output: Pointer; ByteLength: Integer);
{* �� Input ��ָ���ֽڳ���Ϊ ByteLength ���������ݿ飬ʹ�� Key ��ָ���ֽڳ��� KeyByteLength ��
   RC4 ��Կ���м��ܣ��������ݷ� Output ��ָ��������������Ҫ���ֽڳ�������ҲΪ ByteLength��
   Input Output ����ָ��ͬһ���ڴ棬���� Output �����ݽ�����ԭ�� Input �����ݡ�

   ������
     Key: Pointer                         - ������Կ���ڴ��ַ
     KeyByteLength: Integer               - ������Կ���ֽڳ���
     Input: Pointer                       - �����ܵ��������ݿ��ַ
     Output: Pointer                      - ��������������ݿ��ַ
     ByteLength: Integer                  - �����ܵ��������ݿ���ֽڳ���

   ����ֵ�����ޣ�
}

procedure RC4Decrypt(Key: Pointer; KeyByteLength: Integer; Input: Pointer;
  Output: Pointer; ByteLength: Integer);
{* �� Input ��ָ���ֽڳ���Ϊ ByteLength ���������ݿ飬ʹ�� Key ��ָ���ֽڳ��� KeyByteLength ��
   RC4 ��Կ���н��ܣ��������ݷ� Output ��ָ��������������Ҫ���ֽڳ�������ҲΪ ByteLength��
   Input Output ����ָ��ͬһ���ڴ棬���� Output �����ݽ�����ԭ�� Input �����ݡ�

   ������
     Key: Pointer                         - ������Կ���ڴ��ַ
     KeyByteLength: Integer               - ������Կ���ֽڳ���
     Input: Pointer                       - �����ܵ��������ݿ��ַ
     Output: Pointer                      - ��������������ݿ��ַ
     ByteLength: Integer                  - �����ܵ��������ݿ���ֽڳ���

   ����ֵ�����ޣ�
}

function RC4EncryptBytes(Key: TBytes; Input: TBytes): TBytes;
{* RC4 �����ֽ����飬���������ֽ����顣

   ������
     Key: TBytes                          - ������Կ�ֽ�����
     Input: TBytes                        - �����ܵ������ֽ�����

   ����ֵ��TBytes                         - ���������ֽ�����
}

function RC4DecryptBytes(Key: TBytes; Input: TBytes): TBytes;
{* RC4 �����ֽ����飬���������ֽ����顣

   ������
     Key: TBytes                          - ������Կ�ֽ�����
     Input: TBytes                        - �����ܵ������ֽ�����

   ����ֵ��TBytes                         - ���������ֽ�����
}

function RC4EncryptStrToHex(const Str: AnsiString; const Key: AnsiString): AnsiString;
{* �����ַ�����ʽ����������Կ��RC4 ���ܷ���ת����ʮ�����Ƶ����ġ�

   ������
     const Str: AnsiString                - �����ܵ�ԭʼ���ֽ��ַ������ڲ����������
     const Key: AnsiString                - ������Կ�ַ���

   ����ֵ��AnsiString                     - ���ؼ��ܺ��ʮ����������
}

function RC4DecryptStrFromHex(const HexStr: AnsiString; const Key: AnsiString): AnsiString;
{* ����ʮ�����Ƶ��������ַ�����ʽ����Կ��RC4 ���ܷ������ġ�

   ������
     const HexStr: AnsiString             - �����ܵ�ʮ����������
     const Key: AnsiString                - ������Կ�ַ���

   ����ֵ��AnsiString                     - ���ؽ��ܺ�ĵ��ֽ��ַ������ģ��ڲ����������
}

implementation

type
  TCnRC4State = packed record
    Permutation: array[0..CN_RC4_MAX_KEY_BYTE_LENGTH - 1] of Byte;
    Index1: Byte;
    Index2: Byte;
  end;

procedure SwapByte(var A, B: Byte); {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
var
  T: Byte;
begin
  T := A;
  A := B;
  B := T;
end;

procedure RC4Init(var State: TCnRC4State; Key: Pointer; KeyByteLength: Integer);
var
  I: Integer;
  K: PByteArray;
  J: Byte;
begin
  for I := 0 to CN_RC4_MAX_KEY_BYTE_LENGTH - 1 do
    State.Permutation[I] := I;
  State.Index1 := 0;
  State.Index2 := 0;

  J := 0;
  K := PByteArray(Key);
  for I := 0 to CN_RC4_MAX_KEY_BYTE_LENGTH - 1 do
  begin
    J := J + State.Permutation[I] + K^[I mod KeyByteLength];
    SwapByte(State.Permutation[I], State.Permutation[J]);
  end;
end;

procedure RC4Crypt(var State: TCnRC4State; Input, Output: Pointer;
  ByteLength: Integer);
var
  I: Integer;
  J: Byte;
  IP, OP: PByteArray;
begin
  IP := PByteArray(Input);
  OP := PByteArray(Output);

  for I := 0 to ByteLength - 1 do
  begin
    Inc(State.Index1);
    Inc(State.Index2, State.Permutation[State.Index1]);

    SwapByte(State.Permutation[State.Index1], State.Permutation[State.Index2]);

    J := State.Permutation[State.Index1] + State.Permutation[State.Index2];
    OP^[I] := IP^[I] xor State.Permutation[J];
  end;
end;

// RC4 �����������㼰�����Ļ����ĵ����Output ������ Input
procedure RC4(Key: Pointer; KeyByteLength: Integer; Input, Output: Pointer;
  ByteLength: Integer);
var
  State: TCnRC4State;
begin
  RC4Init(State, Key, KeyByteLength);
  RC4Crypt(State, Input, Output, ByteLength);
end;

procedure RC4Encrypt(Key: Pointer; KeyByteLength: Integer; Input, Output: Pointer;
  ByteLength: Integer);
begin
  RC4(Key, KeyByteLength, Input, Output, ByteLength);
end;

procedure RC4Decrypt(Key: Pointer; KeyByteLength: Integer; Input, Output: Pointer;
  ByteLength: Integer);
begin
  RC4(Key, KeyByteLength, Input, Output, ByteLength);
end;

function RC4EncryptBytes(Key, Input: TBytes): TBytes;
begin
  if (Length(Key) = 0) or (Length(Input) = 0) then
  begin
    Result := nil;
    Exit;
  end;

  SetLength(Result, Length(Input));
  RC4(@Key[0], Length(Key), @Input[0], @Result[0], Length(Input));
end;

function RC4DecryptBytes(Key, Input: TBytes): TBytes;
begin
  if (Length(Key) = 0) or (Length(Input) = 0) then
  begin
    Result := nil;
    Exit;
  end;

  SetLength(Result, Length(Input));
  RC4(@Key[0], Length(Key), @Input[0], @Result[0], Length(Input));
end;

function RC4EncryptStrToHex(const Str, Key: AnsiString): AnsiString;
var
  Res: TBytes;
begin
  if (Length(Key) = 0) or (Length(Str) = 0) then
  begin
    Result := '';
    Exit;
  end;

  SetLength(Res, Length(Str));
  RC4(@Key[1], Length(Key), @Str[1], @Res[0], Length(Str));
  Result := AnsiString(BytesToHex(Res));
end;

function RC4DecryptStrFromHex(const HexStr, Key: AnsiString): AnsiString;
var
  Res: TBytes;
begin
  if (Length(Key) = 0) or (Length(HexStr) = 0) then
  begin
    Result := '';
    Exit;
  end;

  Res := HexToBytes(string(HexStr));
  RC4(@Key[1], Length(Key), @Res[0], @Res[0], Length(Res));
  Result := BytesToAnsi(Res);
end;

end.
