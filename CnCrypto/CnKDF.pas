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

unit CnKDF;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ���Կ�����㷨��KDF����Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���˻��� RFC2898 �� PBKDF1 �� PBKDF2 ��Կ�����㷨���� PBKDF1 ��֧�� MD2 �㷨��
*           ͬʱҲʵ���˻��� RFC5869 �� HKDF������ HMac ����Կ�����㷨����
*           ������ SM2/SM9 �㷨�й涨�����������㷨��
* ����ƽ̨��WinXP + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2025.01.09 V1.5
*               ���� HKDF ʵ�ֺ���
*           2022.06.21 V1.4
*               �ϲ���һ�������ֽ������ CnSM2SM9KDF ���������� AnsiString �ڸ߰汾 Delphi �¿�������
*           2022.04.26 V1.3
*               �޸� LongWord �� Integer ��ַת����֧�� MacOS64
*           2022.01.02 V1.2
*               ���� CnPBKDF2 ��һ�������Լ��� Unicode �µļ���������
*           2021.11.25 V1.1
*               ���� CnSM2KDF �� Unicode �µļ���������
*           2020.03.30 V1.0
*               ������Ԫ���� CnPemUtils �ж�������
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative, CnMD5, CnSHA1, CnSHA2, CnSHA3, CnSM3;

type
  TCnKeyDeriveHash = (ckdMd5, ckdSha256, ckdSha1);
  {* CnGetDeriveKey ��ʹ�õ��Ӵշ���}

  TCnPBKDF1KeyHash = (cpdfMd2, cpdfMd5, cpdfSha1);
  {* PBKDF1 �涨�������Ӵշ��������� MD2 ���ǲ�֧��}

  TCnPBKDF2KeyHash = (cpdfSha1Hmac, cpdfSha256Hmac);
  {* PBKDF2 �涨�������Ӵշ���}

  TCnHKDFHash = (chkMd5, chkSha1, chkSha256, chkSha3_256, chkSm3);
  {* HKDF��HMAC-based Key Derivation Function��֧�ֵ��Ӵ�����}

  ECnKDFException = class(Exception);
  {* KDF ����쳣}

function CnGetDeriveKey(const Password: AnsiString; const Salt: AnsiString;
  OutKey: PAnsiChar; KeyLength: Cardinal; KeyHash: TCnKeyDeriveHash = ckdMd5): Boolean;
{* ������ Openssl �е� BytesToKey�������������ָ�����Ӵ��㷨���ɼ��� Key��
   Ŀǰ�������� KeyLength ���֧������ Hash��Ҳ���� MD5 32 �ֽڣ�SHA256 64 �ֽڡ�

   ������
     const Password: AnsiString           - ��������
     const Salt: AnsiString               - ��ֵ
     OutKey: PAnsiChar                    - �����Կ�����ݿ��ַ
     KeyLength: Cardinal                  - �����Կ�����ݿ��ֽڳ���
     KeyHash: TCnKeyDeriveHash            - �Ӵ��㷨

   ����ֵ��Boolean                        - �����Ƿ����ɳɹ�
}

function CnPBKDF1(const Password: AnsiString; const Salt: AnsiString; Count: Integer;
  DerivedKeyByteLength: Integer; KeyHash: TCnPBKDF1KeyHash = cpdfMd5): AnsiString;
{* Password Based KDF 1 ʵ�֣��򵥵Ĺ̶��Ӵյ�����ֻ֧�� MD5 �� SHA1�������뷵��ֵ��Ϊ AnsiString��
   DerivedKeyByteLength ���������Կ�ֽ��������ȹ̶���

   ������
     const Password: AnsiString           - ��������
     const Salt: AnsiString               - ��ֵ
     Count: Integer                       - ��������
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���
     KeyHash: TCnPBKDF1KeyHash            - �Ӵ��㷨

   ����ֵ��AnsiString                     - �������ɵ���Կ
}

function CnPBKDF2(const Password: AnsiString; const Salt: AnsiString; Count: Integer;
  DerivedKeyByteLength: Integer; KeyHash: TCnPBKDF2KeyHash = cpdfSha1Hmac): AnsiString;
{* Password Based KDF 2 ʵ�֣����� HMAC-SHA1 �� HMAC-SHA256�������뷵��ֵ��Ϊ AnsiString��
   DerivedKeyByteLength ���������Կ�ֽ��������ȿɱ䣬��������

   ������
     const Password: AnsiString           - ��������
     const Salt: AnsiString               - ��ֵ
     Count: Integer                       - ��������
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���
     KeyHash: TCnPBKDF2KeyHash            - �Ӵ��㷨

   ����ֵ��AnsiString                     - �������ɵ���Կ
}

function CnPBKDF1Bytes(const Password: TBytes; const Salt: TBytes; Count: Integer;
  DerivedKeyByteLength: Integer; KeyHash: TCnPBKDF1KeyHash = cpdfMd5): TBytes;
{* Password Based KDF 1 ʵ�֣��򵥵Ĺ̶��Ӵյ�����ֻ֧�� MD5 �� SHA1�������뷵��ֵ��Ϊ�ֽ����顣
   DerivedKeyByteLength ���������Կ�ֽ��������ȹ̶���

   ������
     const Password: TBytes               - ��������
     const Salt: TBytes                   - ��ֵ
     Count: Integer                       - ��������
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���
     KeyHash: TCnPBKDF1KeyHash            - �Ӵ��㷨

   ����ֵ��TBytes                         - �������ɵ���Կ
}

function CnPBKDF2Bytes(const Password: TBytes; const Salt: TBytes; Count: Integer;
  DerivedKeyByteLength: Integer; KeyHash: TCnPBKDF2KeyHash = cpdfSha1Hmac): TBytes;
{* Password Based KDF 2 ʵ�֣����� HMAC-SHA1 �� HMAC-SHA256�������뷵��ֵ��Ϊ�ֽ����顣
   DerivedKeyByteLength ���������Կ�ֽ��������ȿɱ䣬��������

   ������
     const Password: TBytes               - ��������
     const Salt: TBytes                   - ��ֵ
     Count: Integer                       - ��������
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���
     KeyHash: TCnPBKDF2KeyHash            - �Ӵ��㷨

   ����ֵ��TBytes                         - �������ɵ���Կ
}

// ============ SM2/SM9 �й涨��ͬһ����Կ�������������ַ�װʵ�� ===============

function CnSM2KDF(const Data: AnsiString; DerivedKeyByteLength: Integer): AnsiString;
{* SM2 ��Բ���߹�Կ�����㷨�й涨����Կ����������DerivedKeyLength ���������Կ�ֽ�����
   ���� AnsiString��ͬʱ�ƺ�Ҳ��û�� SharedInfo �� ANSI-X9.63-KDF��

   ������
     const Data: AnsiString               - ����������Կ��ԭʼ���ݣ���������������
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��AnsiString                     - �������ɵ���Կ
}

function CnSM9KDF(Data: Pointer; DataByteLen: Integer; DerivedKeyByteLength: Integer): AnsiString;
{* SM9 ��ʶ�����㷨�й涨����Կ����������DerivedKeyLength ���������Կ�ֽ�����
   ���� AnsiString��ͬʱ�ƺ�Ҳ��û�� SharedInfo �� ANSI-X9.63-KDF��

   ������
     Data: Pointer                        - ����������Կ��ԭʼ���ݿ��ַ
     DataByteLen: Integer                 - ����������Կ��ԭʼ���ݵ��ֽڳ���
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��AnsiString                     - �������ɵ���Կ
}

function CnSM2KDFBytes(const Data: TBytes; DerivedKeyByteLength: Integer): TBytes;
{* ����Ϊ�ֽ�������ʽ�� SM2 ��Բ���߹�Կ�����㷨�й涨����Կ����������
   DerivedKeyLength ���������Կ�ֽ������������ɵ��ֽ����顣

   ������
     const Data: TBytes                   - ����������Կ��ԭʼ���ݵ��ֽ�����
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��TBytes                         - �������ɵ���Կ
}

function CnSM9KDFBytes(Data: Pointer; DataByteLen: Integer; DerivedKeyByteLength: Integer): TBytes;
{* ����Ϊ�ڴ����ʽ�� SM9 ��ʶ�����㷨�й涨����Կ����������
   DerivedKeyLength ���������Կ�ֽ������������ɵ��ֽ����顣

   ������
     Data: Pointer                        - ����������Կ��ԭʼ���ݿ��ַ
     DataByteLen: Integer                 - ����������Կ��ԭʼ���ݵ��ֽڳ���
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��TBytes                         - �������ɵ���Կ
}

function CnSM2SM9KDF(Data: TBytes; DerivedKeyByteLength: Integer): TBytes; overload;
{* ����Ϊ�ֽ�������ʽ�� SM2 ��Բ���߹�Կ�����㷨�� SM9 ��ʶ�����㷨�й涨����Կ����������
   DerivedKeyLength ���������Կ�ֽ������������ɵ���Կ�ֽ����顣

   ������
     Data: TBytes                         - ����������Կ��ԭʼ���ݵ��ֽ�����
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��TBytes                         - �������ɵ���Կ
}

function CnSM2SM9KDF(Data: Pointer; DataByteLen: Integer; DerivedKeyByteLength: Integer): TBytes; overload;
{* ����Ϊ�ڴ����ʽ�� SM2 ��Բ���߹�Կ�����㷨�� SM9 ��ʶ�����㷨�й涨����Կ����������
   DerivedKeyLength ���������Կ�ֽ�����������������Կ�ֽ����顣

   ������
     Data: Pointer                        - ����������Կ��ԭʼ���ݿ��ַ
     DataByteLen: Integer                 - ����������Կ��ԭʼ���ݵ��ֽڳ���
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��TBytes                         - �������ɵ���Կ
}

function CnHKDF(HKDF: TCnHKDFHash; IKM: Pointer; IKMByteLen: Integer;
  Salt: Pointer; SaltByteLen: Integer; Info: Pointer; InfoByteLen: Integer;
  DerivedKeyByteLength: Integer): TBytes; overload;
{* ���� HMAC �� KDF ��Կ�������������� IKM��Salt �� Info������ָ�����ȵ���Կ��
   Salt ��Ϊ�գ������ڲ�ʹ�ù̶��Ӵս�����ȵ�ȫ 0��Info ��Ϊ�ա��������ɵ���Կ��

   ������
     HKDF: TCnHKDFHash                    - �Ӵ��㷨����
     IKM: Pointer                         - ����������Կ�������������ݣ�Input Keying Material�����ַ
     IKMByteLen: Integer                  - ����������Կ�������������ݵ��ֽڳ���
     Salt: Pointer                        - ����������Կ����ֵ���ݿ��ַ
     SaltByteLen: Integer                 - ����������Կ����ֵ���ݵ��ֽڳ���
     Info: Pointer                        - ����������Կ�Ŀ�ѡ����Ϣ���ݿ��ַ
     InfoByteLen: Integer                 - ����������Կ�Ŀ�ѡ����Ϣ���ݵ��ֽڳ���
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��TBytes                         - �������ɵ���Կ
}

function CnHKDFBytes(HKDF: TCnHKDFHash; IKM: TBytes; Salt: TBytes; Info: TBytes;
  DerivedKeyByteLength: Integer): TBytes; overload;
{* ���� HMAC �� KDF ��Կ�������������� IKM��Salt �� Info ���ֽ����飬����ָ�����ȵ���Կ��
   Salt ��Ϊ�գ������ڲ�ʹ�ù̶��Ӵս�����ȵ�ȫ 0��Info ��Ϊ�ա��������ɵ���Կ��

     HKDF: TCnHKDFHash                    - �Ӵ��㷨����
     IKM: TBytes                          - ����������Կ��������������
     Salt: TBytes                         - ����������Կ����ֵ����
     Info: TBytes                         - ����������Կ�Ŀ�ѡ����Ϣ����
     DerivedKeyByteLength: Integer        - �����ɵ���Կ���ֽڳ���

   ����ֵ��TBytes                         - �������ɵ���Կ
}

implementation

resourcestring
  SCnErrorKDFKeyTooLong = 'Derived Key Too Long.';
  SCnErrorKDFParam = 'Invalid Parameters.';
  SCnErrorKDFHashNOTSupport = 'Hash Method NOT Support.';

function Min(A, B: Integer): Integer; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

function CnGetDeriveKey(const Password, Salt: AnsiString; OutKey: PAnsiChar; KeyLength: Cardinal;
  KeyHash: TCnKeyDeriveHash): Boolean;
var
  Md5Dig, Md5Dig2: TCnMD5Digest;
  Sha256Dig, Sha256Dig2: TCnSHA256Digest;
  SaltBuf, PS, PSMD5, PSSHA256: AnsiString;
begin
  Result := False;

  if (Password = '') or (OutKey = nil) or (KeyLength < 8) then
    Exit;

  SetLength(SaltBuf, 8);
  FillChar(SaltBuf[1], Length(SaltBuf), 0);
  if Salt <> '' then
    Move(Salt[1], SaltBuf[1], Min(Length(Salt), 8));

  if not (KeyHash in [ckdMd5, ckdSha256]) then
    raise ECnKDFException.Create(SCnErrorKDFHashNOTSupport);

  PS := AnsiString(Password) + SaltBuf; // �涨ǰ 8 ���ֽ���Ϊ Salt
  if KeyHash = ckdMd5 then
  begin
    SetLength(PSMD5, SizeOf(TCnMD5Digest) + Length(PS));
    Move(PS[1], PSMD5[SizeOf(TCnMD5Digest) + 1], Length(PS));
    Md5Dig := MD5StringA(PS);
    // ������ Salt ƴ������ MD5 �����16 Byte����Ϊ��һ����

    Move(Md5Dig[0], OutKey^, Min(KeyLength, SizeOf(TCnMD5Digest)));
    if KeyLength <= SizeOf(TCnMD5Digest) then
    begin
      Result := True;
      Exit;
    end;

    KeyLength := KeyLength - SizeOf(TCnMD5Digest);
    OutKey := PAnsiChar(TCnNativeUInt(OutKey) + SizeOf(TCnMD5Digest));

    Move(Md5Dig[0], PSMD5[1], SizeOf(TCnMD5Digest));
    Md5Dig2 := MD5StringA(PSMD5);
    Move(Md5Dig2[0], OutKey^, Min(KeyLength, SizeOf(TCnMD5Digest)));
    if KeyLength <= SizeOf(TCnMD5Digest) then
      Result := True;

    // ���� KeyLength ̫�����㲻��
  end
  else if KeyHash = ckdSha256 then
  begin
    SetLength(PSSHA256, SizeOf(TCnSHA256Digest) + Length(PS));
    Move(PS[1], PSSHA256[SizeOf(TCnSHA256Digest) + 1], Length(PS));
    Sha256Dig := SHA256StringA(PS);
    // ������ Salt ƴ������ SHA256 �����32 Byte����Ϊ��һ����

    Move(Sha256Dig[0], OutKey^, Min(KeyLength, SizeOf(TCnSHA256Digest)));
    if KeyLength <= SizeOf(TCnSHA256Digest) then
    begin
      Result := True;
      Exit;
    end;

    KeyLength := KeyLength - SizeOf(TCnSHA256Digest);
    OutKey := PAnsiChar(TCnNativeUInt(OutKey) + SizeOf(TCnSHA256Digest));

    Move(Sha256Dig[0], PSSHA256[1], SizeOf(TCnSHA256Digest));
    Sha256Dig2 := SHA256StringA(PSSHA256);
    Move(Sha256Dig2[0], OutKey^, Min(KeyLength, SizeOf(TCnSHA256Digest)));
    if KeyLength <= SizeOf(TCnSHA256Digest) then
      Result := True;

    // ���� KeyLength ̫�����㲻��
  end;
end;

(*
  T_1 = Hash (P || S) ,
  T_2 = Hash (T_1) ,
  ...
  T_c = Hash (T_{c-1}) ,
  DK = Tc<0..dkLen-1>
*)
function CnPBKDF1(const Password, Salt: AnsiString; Count, DerivedKeyByteLength: Integer;
  KeyHash: TCnPBKDF1KeyHash): AnsiString;
var
  P, S, Res: TBytes;
begin
  P := AnsiToBytes(Password);
  S := AnsiToBytes(Salt);
  Res := CnPBKDF1Bytes(P, S, Count, DerivedKeyByteLength, KeyHash);
  Result := BytesToAnsi(Res);
end;

{
  DK = T1 + T2 + ... + Tdklen/hlen
  Ti = F(Password, Salt, c, i)

  F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc

  U1 = PRF(Password, Salt + INT_32_BE(i))
  U2 = PRF(Password, U1)
  ...
  Uc = PRF(Password, Uc-1)
}
function CnPBKDF2(const Password, Salt: AnsiString; Count, DerivedKeyByteLength: Integer;
  KeyHash: TCnPBKDF2KeyHash): AnsiString;
var
  P, S, Res: TBytes;
begin
  P := AnsiToBytes(Password);
  S := AnsiToBytes(Salt);
  Res := CnPBKDF2Bytes(P, S, Count, DerivedKeyByteLength, KeyHash);
  Result := BytesToAnsi(Res);
end;

function CnPBKDF1Bytes(const Password, Salt: TBytes; Count, DerivedKeyByteLength: Integer;
  KeyHash: TCnPBKDF1KeyHash = cpdfMd5): TBytes;
var
  I: Integer;
  Md5Dig, TM: TCnMD5Digest;
  Sha1Dig, TS: TCnSHA1Digest;
  Ptr: PAnsiChar;
begin
  Result := nil;
  if (Password = nil) or (Count <= 0) or (DerivedKeyByteLength <= 0) then
    raise ECnKDFException.Create(SCnErrorKDFParam);

  case KeyHash of
    cpdfMd5:
      begin
        if DerivedKeyByteLength > SizeOf(TCnMD5Digest) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        SetLength(Result, DerivedKeyByteLength);
        Md5Dig := MD5Bytes(ConcatBytes(Password, Salt));  // Got T1
        if Count > 1 then
        begin
          Ptr := PAnsiChar(@TM[0]);
          for I := 2 to Count do
          begin
            TM := Md5Dig;
            Md5Dig := MD5Buffer(Ptr, SizeOf(TCnMD5Digest)); // Got T_c
          end;
        end;

        Move(Md5Dig[0], Result[0], DerivedKeyByteLength);
      end;
    cpdfSha1:
      begin
        if DerivedKeyByteLength > SizeOf(TCnSHA1Digest) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        SetLength(Result, DerivedKeyByteLength);
        Sha1Dig := SHA1Bytes(ConcatBytes(Password, Salt));  // Got T1
        if Count > 1 then
        begin
          Ptr := PAnsiChar(@TS[0]);
          for I := 2 to Count do
          begin
            TS := Sha1Dig;
            Sha1Dig := SHA1Buffer(Ptr, SizeOf(TCnSHA1Digest)); // Got T_c
          end;
        end;

        Move(Sha1Dig[0], Result[0], DerivedKeyByteLength);
      end;
    else
      raise ECnKDFException.Create(SCnErrorKDFHashNOTSupport);
  end;
end;

function CnPBKDF2Bytes(const Password, Salt: TBytes; Count, DerivedKeyByteLength: Integer;
  KeyHash: TCnPBKDF2KeyHash = cpdfSha1Hmac): TBytes;
var
  HLen, D, I, J, K: Integer;
  Sha1Dig1, Sha1Dig, T1: TCnSHA1Digest;
  Sha256Dig1, Sha256Dig, T256: TCnSHA256Digest;
  S, S1, S256, Pad: TBytes;
  PAddr: Pointer;
begin
  Result := nil;
  if (Salt = nil) or (Count <= 0) or (DerivedKeyByteLength <=0) then
    raise ECnKDFException.Create(SCnErrorKDFParam);

  if (Password = nil) or (Length(Password) = 0) then
    PAddr := nil
  else
    PAddr := @Password[0];

  case KeyHash of
    cpdfSha1Hmac:
      HLen := 20;
    cpdfSha256Hmac:
      HLen := 32;
  else
    raise ECnKDFException.Create(SCnErrorKDFParam);
  end;

  D := (DerivedKeyByteLength div HLen) + 1;
  SetLength(S1, SizeOf(TCnSHA1Digest));
  SetLength(S256, SizeOf(TCnSHA256Digest));

  SetLength(Pad, 4);
  if KeyHash = cpdfSha1Hmac then
  begin
    for I := 1 to D do
    begin
      Pad[0] := I shr 24;
      Pad[1] := I shr 16;
      Pad[2] := I shr 8;
      Pad[3] := I;
      S := ConcatBytes(Salt, Pad);

      SHA1Hmac(PAddr, Length(Password), PAnsiChar(@S[0]), Length(S), Sha1Dig1);
      T1 := Sha1Dig1;

      for J := 2 to Count do
      begin
        SHA1Hmac(PAddr, Length(Password), PAnsiChar(@T1[0]), SizeOf(TCnSHA1Digest), Sha1Dig);
        T1 := Sha1Dig;
        for K := Low(TCnSHA1Digest) to High(TCnSHA1Digest) do
          Sha1Dig1[K] := Sha1Dig1[K] xor T1[K];
      end;

      Move(Sha1Dig1[0], S1[0], Length(S1));
      Result := ConcatBytes(Result, S1);
    end;
    Result := Copy(Result, 0, DerivedKeyByteLength);
  end
  else if KeyHash = cpdfSha256Hmac then
  begin
    for I := 1 to D do
    begin
      Pad[0] := I shr 24;
      Pad[1] := I shr 16;
      Pad[2] := I shr 8;
      Pad[3] := I;
      S := ConcatBytes(Salt, Pad);

      SHA256Hmac(PAddr, Length(Password), PAnsiChar(@S[0]), Length(S), Sha256Dig1);
      T256 := Sha256Dig1;

      for J := 2 to Count do
      begin
        SHA256Hmac(PAddr, Length(Password), PAnsiChar(@T256[0]), SizeOf(TCnSHA256Digest), Sha256Dig);
        T256 := Sha256Dig;
        for K := Low(TCnSHA256Digest) to High(TCnSHA256Digest) do
          Sha256Dig1[K] := Sha256Dig1[K] xor T256[K];
      end;

      Move(Sha256Dig1[0], S256[0], SizeOf(TCnSHA256Digest));
      Result := ConcatBytes(Result, S256);
    end;
    Result := Copy(Result, 0, DerivedKeyByteLength);
  end;
end;

function CnSM2KDF(const Data: AnsiString; DerivedKeyByteLength: Integer): AnsiString;
var
  Res: TBytes;
begin
  if (Data = '') or (DerivedKeyByteLength <= 0) then
    raise ECnKDFException.Create(SCnErrorKDFParam);

  Res := CnSM2SM9KDF(@Data[1], Length(Data), DerivedKeyByteLength);
  Result := BytesToAnsi(Res);
end;

function CnSM9KDF(Data: Pointer; DataByteLen: Integer; DerivedKeyByteLength: Integer): AnsiString;
var
  Res: TBytes;
begin
  Res := CnSM2SM9KDF(Data, DataByteLen, DerivedKeyByteLength);
  Result := BytesToAnsi(Res);
end;

function CnSM2KDFBytes(const Data: TBytes; DerivedKeyByteLength: Integer): TBytes;
begin
  Result := CnSM2SM9KDF(Data, DerivedKeyByteLength);
end;

function CnSM9KDFBytes(Data: Pointer; DataByteLen: Integer; DerivedKeyByteLength: Integer): TBytes;
begin
  Result := CnSM2SM9KDF(Data, DataByteLen, DerivedKeyByteLength);
end;

function CnSM2SM9KDF(Data: TBytes; DerivedKeyByteLength: Integer): TBytes;
begin
  if (Data = nil) or (Length(Data) <= 0) or (DerivedKeyByteLength <= 0) then
    raise ECnKDFException.Create(SCnErrorKDFParam);

  Result := CnSM2SM9KDF(@Data[0], Length(Data), DerivedKeyByteLength);
end;

function CnSM2SM9KDF(Data: Pointer; DataByteLen: Integer; DerivedKeyByteLength: Integer): TBytes; overload;
var
  DArr: TBytes;
  CT, SCT: Cardinal;
  I, CeilLen: Integer;
  IsInt: Boolean;
  SM3D: TCnSM3Digest;
begin
  Result := nil;
  if (Data = nil) or (DataByteLen <= 0) or (DerivedKeyByteLength <= 0) then
    raise ECnKDFException.Create(SCnErrorKDFParam);

  DArr := nil;
  CT := 1;

  try
    SetLength(DArr, DataByteLen + SizeOf(Cardinal));
    Move(Data^, DArr[0], DataByteLen);

    IsInt := DerivedKeyByteLength mod SizeOf(TCnSM3Digest) = 0;
    CeilLen := (DerivedKeyByteLength + SizeOf(TCnSM3Digest) - 1) div SizeOf(TCnSM3Digest);

    SetLength(Result, DerivedKeyByteLength);
    for I := 1 to CeilLen do
    begin
      SCT := UInt32HostToNetwork(CT);  // ��Ȼ�ĵ���û˵����Ҫ����һ��
      Move(SCT, DArr[DataByteLen], SizeOf(Cardinal));
      SM3D := SM3(@DArr[0], Length(DArr));

      if (I = CeilLen) and not IsInt then
      begin
        // �����һ���������� 32 ʱֻ�ƶ�һ����
        Move(SM3D[0], Result[(I - 1) * SizeOf(TCnSM3Digest)], (DerivedKeyByteLength mod SizeOf(TCnSM3Digest)));
      end
      else
        Move(SM3D[0], Result[(I - 1) * SizeOf(TCnSM3Digest)], SizeOf(TCnSM3Digest));

      Inc(CT);
    end;
  finally
    SetLength(DArr, 0);
  end;
end;

function CnHKDF(HKDF: TCnHKDFHash; IKM: Pointer; IKMByteLen: Integer;
  Salt: Pointer; SaltByteLen: Integer; Info: Pointer; InfoByteLen: Integer;
  DerivedKeyByteLength: Integer): TBytes;
const
  MAX_BYTE = 255;
var
  PRKMd5, Md5T: TCnMD5Digest;
  PRKSha1, Sha1T: TCnSHA1Digest;
  PRKSha256, Sha256T: TCnSHA256Digest;
  PRKSha3256, Sha3256T: TCnSHA3_256Digest;
  PRKSm3, Sm3T: TCnSM3Digest;
  T0, T: TBytes;
  N, I, Start, HashLen: Integer;
begin
  if IKM = nil then
    IKMByteLen := 0;

  if Salt = nil then
    SaltByteLen := 0;

  if Info = nil then
    InfoByteLen := 0;

  if (IKMByteLen < 0) or (SaltByteLen < 0) or (InfoByteLen < 0) then
    raise ECnKDFException.Create(SCnErrorKDFParam);

  // Extract������ HMac(Salt, IKM)��ע�� IKM �����ݣ����� HMac �� Key
  case HKDF of
    chkMd5:
      begin
        if (DerivedKeyByteLength <= 0) or (DerivedKeyByteLength > MAX_BYTE * SizeOf(TCnMD5Digest)) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        HashLen := SizeOf(TCnMD5Digest);
        if (Salt = nil) or (SaltByteLen <= 0) then
        begin
          FillChar(PRKMd5[0], HashLen, 0);
          MD5Hmac(@PRKMd5[0], HashLen, IKM, IKMByteLen, PRKMd5);
        end
        else
          MD5Hmac(Salt, SaltByteLen, IKM, IKMByteLen, PRKMd5);
      end;
    chkSha1:
      begin
        if (DerivedKeyByteLength <= 0) or (DerivedKeyByteLength > MAX_BYTE * SizeOf(TCnSHA1Digest)) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        HashLen := SizeOf(TCnSHA1Digest);
        if (Salt = nil) or (SaltByteLen <= 0) then
        begin
          FillChar(PRKSha1[0], HashLen, 0);
          SHA1Hmac(@PRKSha1[0], HashLen, IKM, IKMByteLen, PRKSha1);
        end
        else
          SHA1Hmac(Salt, SaltByteLen, IKM, IKMByteLen, PRKSha1);
      end;
    chkSha256:
      begin
        if (DerivedKeyByteLength <= 0) or (DerivedKeyByteLength > MAX_BYTE * SizeOf(TCnSHA256Digest)) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        HashLen := SizeOf(TCnSHA256Digest);
        if (Salt = nil) or (SaltByteLen <= 0) then
        begin
          FillChar(PRKSha256[0], HashLen, 0);
          SHA256Hmac(@PRKSha256[0], HashLen, IKM, IKMByteLen, PRKSha256);
        end
        else
          SHA256Hmac(Salt, SaltByteLen, IKM, IKMByteLen, PRKSha256);
      end;
    chkSha3_256:
      begin
        if (DerivedKeyByteLength <= 0) or (DerivedKeyByteLength > MAX_BYTE * SizeOf(TCnSHA3_256Digest)) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        HashLen := SizeOf(TCnSHA3_256Digest);
        if (Salt = nil) or (SaltByteLen <= 0) then
        begin
          FillChar(PRKSha3256[0], HashLen, 0);
          SHA3_256Hmac(@PRKSha3256[0], HashLen, IKM, IKMByteLen, PRKSha3256);
        end
        else
          SHA3_256Hmac(Salt, SaltByteLen, IKM, IKMByteLen, PRKSha3256);
      end;
    chkSm3:
      begin
        if (DerivedKeyByteLength <= 0) or (DerivedKeyByteLength > MAX_BYTE * SizeOf(TCnSM3Digest)) then
          raise ECnKDFException.Create(SCnErrorKDFKeyTooLong);

        HashLen := SizeOf(TCnSM3Digest);
        if (Salt = nil) or (SaltByteLen <= 0) then
        begin
          FillChar(PRKSm3[0], HashLen, 0);
          SM3Hmac(@PRKSm3[0], HashLen, IKM, IKMByteLen, PRKSm3);
        end
        else
          SM3Hmac(Salt, SaltByteLen, IKM, IKMByteLen, PRKSm3);
      end;
  else
    raise ECnKDFException.Create(SCnErrorKDFHashNOTSupport);
  end;

  // ��ʼ Expand
  SetLength(T0, InfoByteLen + 1);
  if InfoByteLen > 0 then
    Move(Info^, T0[0], InfoByteLen);
  T0[InfoByteLen] := 1;    // ������ƴװ�� T0 ���������

  // ��ʼ��ÿ�ֵļ�������
  SetLength(T, HashLen + InfoByteLen + 1);

  // ���ý�����Ȳ���������
  N := (DerivedKeyByteLength + HashLen - 1) div HashLen;
  SetLength(Result, DerivedKeyByteLength);

  // �� T0 �������һ�� T1
  case HKDF of
    chkMd5:       MD5Hmac(@PRKMd5[0], HashLen, @T0[0], Length(T0), Md5T);
    chkSha1:      SHA1Hmac(@PRKSha1[0], HashLen, @T0[0], Length(T0), Sha1T);
    chkSha256:    SHA256Hmac(@PRKSha256[0], HashLen, @T0[0], Length(T0), Sha256T);
    chkSha3_256:  SHA3_256Hmac(@PRKSha3256[0], HashLen, @T0[0], Length(T0), Sha3256T);
    chkSm3:       SM3Hmac(@PRKSm3[0], HashLen, @T0[0], Length(T0), Sm3T);
  end;

  Start := 0;
  for I := 1 to N do
  begin
    // �� T1 ƴ�ڽ����
    if DerivedKeyByteLength > HashLen then
    begin
      case HKDF of
        chkMd5:       Move(Md5T[0], Result[Start], HashLen);
        chkSha1:      Move(Sha1T[0], Result[Start], HashLen);
        chkSha256:    Move(Sha256T[0], Result[Start], HashLen);
        chkSha3_256:  Move(Sha3256T[0], Result[Start], HashLen);
        chkSm3:       Move(Sm3T[0], Result[Start], HashLen);
      end;
      Inc(Start, HashLen);
      Dec(DerivedKeyByteLength, HashLen);
    end
    else
    begin
      case HKDF of
        chkMd5:       Move(Md5T[0], Result[Start], DerivedKeyByteLength);
        chkSha1:      Move(Sha1T[0], Result[Start], DerivedKeyByteLength);
        chkSha256:    Move(Sha256T[0], Result[Start], DerivedKeyByteLength);
        chkSha3_256:  Move(Sha3256T[0], Result[Start], DerivedKeyByteLength);
        chkSm3:       Move(Sm3T[0], Result[Start], DerivedKeyByteLength);
      end;
      Break;
    end;

    // ���� T1 �� Info ƴһ�𲢼�һ
    case HKDF of
      chkMd5:       Move(Md5T[0], T[0], HashLen);
      chkSha1:      Move(Sha1T[0], T[0], HashLen);
      chkSha256:    Move(Sha256T[0], T[0], HashLen);
      chkSha3_256:  Move(Sha3256T[0], T[0], HashLen);
      chkSm3:       Move(Sm3T[0], T[0], HashLen);
    end;
    Move(Info^, T[HashLen], InfoByteLen);
    T[HashLen + InfoByteLen] := I + 1;

    // �����Ӵ� T2 ��� T1
    case HKDF of
      chkMd5:       MD5Hmac(@PRKMd5[0], HashLen, @T[0], Length(T), Md5T);
      chkSha1:      SHA1Hmac(@PRKSha1[0], HashLen, @T[0], Length(T), Sha1T);
      chkSha256:    SHA256Hmac(@PRKSha256[0], HashLen, @T[0], Length(T), Sha256T);
      chkSha3_256:  SHA3_256Hmac(@PRKSha3256[0], HashLen, @T[0], Length(T), Sha3256T);
      chkSm3:       SM3Hmac(@PRKSm3[0], HashLen, @T[0], Length(T), Sm3T);
    end;
  end;
end;

function CnHKDFBytes(HKDF: TCnHKDFHash; IKM: TBytes; Salt: TBytes; Info: TBytes;
  DerivedKeyByteLength: Integer): TBytes;
var
  IKMP, SaltP, InfoP: Pointer;
  IKML, SaltL, InfoL: Integer;
begin
  IKMP := nil;
  SaltP := nil;
  InfoP := nil;
  IKML := 0;
  SaltL := 0;
  InfoL := 0;

  if Length(IKM) > 0 then
  begin
    IKMP := @IKM[0];
    IKML := Length(IKM);
  end;
  if Length(Salt) > 0 then
  begin
    SaltP := @Salt[0];
    SaltL := Length(Salt);
  end;
  if Length(Info) > 0 then
  begin
    InfoP := @Info[0];
    InfoL := Length(Info);
  end;

  Result := CnHKDF(HKDF, IKMP, IKML, SaltP, SaltL, InfoP, InfoL, DerivedKeyByteLength);
end;

end.
