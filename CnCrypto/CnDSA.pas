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

unit CnDSA;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�DSA �㷨��Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���˻�����ͨ��ɢ����������Բ������ɢ�������� DSA ǩ����ǩ���ơ�
*           ���ֹ淶���� NIST.FIPS.186-4
* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2024.10.11 V1.0
*               ������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnBigNumber, CnNative, CnMD5, CnSHA1, CnSHA2, CnSM3;

type
  TCnDSAPrimeType = (dptBit1024160, dptBit2048224, dptBit2048256, dptBit3072256);
  {* DSA ������λ�����࣬�ֱ��� P �� Q ��λ��}

  TCnDSAHashType = (dhtAuto, dhtMD5, dhtSHA1, dhtSHA224, dhtSHA256, dhtSM3);
  {* DSA ��ǩ�����Ӵ����ͣ�Auto ��ʾ���� Q ��λ���Զ�ѡ��}

  TCnDSADomainParameter = class(TPersistent)
  {* DSA �������}
  private
    FQ: TCnBigNumber;
    FP: TCnBigNumber;
    FG: TCnBigNumber;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent                  - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    property P: TCnBigNumber read FP;
    property Q: TCnBigNumber read FQ;
    property G: TCnBigNumber read FG;
  end;

  TCnDSAPrivateKey = class(TCnBigNumber);
  {* DSA ��˽Կ��������� X ��}

  TCnDSAPublicKey = class(TCnBigNumber);
  {* DSA �Ĺ�Կ��Y = G �� X �η� mod P}

  TCnDSASignature = class(TPersistent)
  {* DSA ��ǩ������������ R S}
  private
    FS: TCnBigNumber;
    FR: TCnBigNumber;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent                  - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    property R: TCnBigNumber read FR;
    {* ǩ�� R ֵ}
    property S: TCnBigNumber read FS;
    {* ǩ�� S ֵ}
  end;

function CnDSAGenerateParameter(OutParameter: TCnDSADomainParameter;
  PrimeType: TCnDSAPrimeType = dptBit1024160): Boolean;
{* ���� DSA ��������������������� P����Ⱥ�Ľ� Q��������Ԫ G�����������Ƿ�ɹ���
   PrimeType ������ָ���ض��� P �� Q ��λ����

   ������
     OutParameter: TCnDSADomainParameter  - DSA �����
     PrimeType: TCnDSAPrimeType           - ָ��������λ����

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnDSAVerifyParameter(DSAParameter: TCnDSADomainParameter): Boolean;
{* У�� DSA ������Ƿ�Ϸ��������ж����������� P����Ⱥ�Ľ� Q��������Ԫ G �ȣ������Ƿ�Ϸ���

   ������
     DSAParameter: TCnDSADomainParameter  - ��У��� DSA �����

   ����ֵ��Boolean                        - �����Ƿ�Ϸ�
}

function CnDSAGenerateKeys(DSAParameter: TCnDSADomainParameter;
  OutPrivateKey: TCnDSAPrivateKey; OutPublicKey: TCnDSAPublicKey): Boolean;
{* ��ָ���� DSA ������£�����һ�� DSA ��˽Կ�����������Ƿ�ɹ���

   ������
     DSAParameter: TCnDSADomainParameter  - DSA �����
     OutPrivateKey: TCnDSAPrivateKey      - ���ɵ� DSA ˽Կ
     OutPublicKey: TCnDSAPublicKey        - ���ɵ� DSA ��Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnDSAVerifyKeys(DSAParameter: TCnDSADomainParameter;
  PrivateKey: TCnDSAPrivateKey; PublicKey: TCnDSAPublicKey): Boolean;
{* ��ָ���� DSA �������У��һ�� DSA ��˽Կ������У���Ƿ�ɹ���

   ������
     DSAParameter: TCnDSADomainParameter  - DSA �����
     PrivateKey: TCnDSAPrivateKey         - ��У��� DSA ˽Կ
     PublicKey: TCnDSAPublicKey           - ��У��� DSA ��Կ

   ����ֵ��Boolean                        - ����У���Ƿ�ɹ�
}

function CnDSASignData(Data: Pointer; DataByteLen: Integer;
  DSAParameter: TCnDSADomainParameter; PrivateKey: TCnDSAPrivateKey;
  OutSignature: TCnDSASignature; HashType: TCnDSAHashType = dhtAuto): Boolean;
{* ��ָ���� DSA ������£���ָ�� DSA ˽Կ���Ӵ��㷨�����ڴ�����ݽ���ǩ����
   ����ǩ���Ƿ�ɹ����Ӵ��㷨�����粻����Ĭ�� dhtAuto����ʾ���� DSA ������е� Q ��λ���Զ�ƥ�䡣

   ������
     Data: Pointer                        - ��ǩ�������ݿ��ַ
     DataByteLen: Integer                 - ��ǩ�������ݿ��ֽڳ���
     DSAParameter: TCnDSADomainParameter  - DSA �����
     PrivateKey: TCnDSAPrivateKey         - DSA ˽Կ
     OutSignature: TCnDSASignature        - ����� DSA ǩ��ֵ
     HashType: TCnDSAHashType             - �Ӵ��㷨

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnDSAVerifyData(Data: Pointer; DataByteLen: Integer;
  DSAParameter: TCnDSADomainParameter; PublicKey: TCnDSAPublicKey;
  Signature: TCnDSASignature; HashType: TCnDSAHashType = dhtAuto): Boolean;
{* ��ָ���� DSA ������£���ָ�� DSA ��Կ���Ӵ��㷨�����ڴ�����ݽ���ǩ����֤��
   ������֤�Ƿ�ɹ����Ӵ��㷨�����粻����Ĭ�� dhtAuto����ʾ���� DSA ������е� Q ��λ���Զ�ƥ�䡣

   ������
     Data: Pointer                        - ����֤�����ݿ��ַ
     DataByteLen: Integer                 - ����֤�����ݿ��ֽڳ���
     DSAParameter: TCnDSADomainParameter  - DSA �����
     PublicKey: TCnDSAPublicKey           - DSA ��Կ
     Signature: TCnDSASignature           - ����֤�� DSA ǩ��ֵ
     HashType: TCnDSAHashType             - �Ӵ��㷨

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnDSASignBytes(Data: TBytes; DSAParameter: TCnDSADomainParameter;
  PrivateKey: TCnDSAPrivateKey; OutSignature: TCnDSASignature;
  HashType: TCnDSAHashType = dhtAuto): Boolean;
{* ��ָ���� DSA ������£���ָ�� DSA ˽Կ���Ӵ��㷨�����ֽ��������ǩ����
   ����ǩ���Ƿ�ɹ����Ӵ��㷨�����粻����Ĭ�� dhtAuto����ʾ���� DSA ������е� Q ��λ���Զ�ƥ�䡣

   ������
     Data: TBytes                         - ��ǩ�����ֽ�����
     DSAParameter: TCnDSADomainParameter  - DSA �����
     PrivateKey: TCnDSAPrivateKey         - DSA ˽Կ
     OutSignature: TCnDSASignature        - ����� DSA ǩ��ֵ
     HashType: TCnDSAHashType             - �Ӵ��㷨

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnDSAVerifyBytes(Data: TBytes; DSAParameter: TCnDSADomainParameter;
  PublicKey: TCnDSAPublicKey; Signature: TCnDSASignature;
  HashType: TCnDSAHashType = dhtAuto): Boolean;
{* ��ָ���� DSA ������£���ָ�� DSA ��Կ���Ӵ��㷨�����ֽ��������ǩ����֤��
   ������֤�Ƿ�ɹ����Ӵ��㷨�����粻����Ĭ�� dhtAuto����ʾ���� DSA ������е� Q ��λ���Զ�ƥ�䡣

   ������
     Data: TBytes                         - ����֤���ֽ�����
     DSAParameter: TCnDSADomainParameter  - DSA �����
     PublicKey: TCnDSAPublicKey           - DSA ��Կ
     Signature: TCnDSASignature           - ����֤�� DSA ǩ��ֵ
     HashType: TCnDSAHashType             - �Ӵ��㷨

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

implementation

{ TCnDSADomainParameters }

procedure TCnDSADomainParameter.Assign(Source: TPersistent);
begin
  if Source is TCnDSADomainParameter then
  begin
    BigNumberCopy(FP, TCnDSADomainParameter(Source).P);
    BigNumberCopy(FQ, TCnDSADomainParameter(Source).Q);
    BigNumberCopy(FG, TCnDSADomainParameter(Source).G);
  end
  else
    inherited;
end;

constructor TCnDSADomainParameter.Create;
begin
  inherited;
  FP := TCnBigNumber.Create;
  FQ := TCnBigNumber.Create;
  FG := TCnBigNumber.Create;
end;

destructor TCnDSADomainParameter.Destroy;
begin
  FG.Free;
  FQ.Free;
  FP.Free;
  inherited;
end;

{ TCnDSASignature }

procedure TCnDSASignature.Assign(Source: TPersistent);
begin
  if Source is TCnDSASignature then
  begin
    BigNumberCopy(FS, TCnDSASignature(Source).S);
    BigNumberCopy(FR, TCnDSASignature(Source).R);
  end
  else
    inherited;
end;

constructor TCnDSASignature.Create;
begin
  inherited;
  FR := TCnBigNumber.Create;
  FS := TCnBigNumber.Create;
end;

destructor TCnDSASignature.Destroy;
begin
  FS.Free;
  FR.Free;
  inherited;
end;

// ���� DSA �������ͻ��Ӵ����ͼ����Ӵ�ֵ��ֵ�� OutDigest ��
function DSAHashData(Data: Pointer; DataByteLen: Integer; OutDigest: TCnBigNumber;
  Parameter: TCnDSADomainParameter; HashType: TCnDSAHashType = dhtAuto): Boolean;
var
  MD5Dig: TCnMD5Digest;
  SHA1Dig: TCnSHA1Digest;
  SHA224Dig: TCnSHA224Digest;
  SHA256Dig: TCnSHA256Digest;
  SM3Dig: TCnSM3Digest;
begin
  Result := False;
  case HashType of
    dhtAuto:
      begin
        if Parameter <> nil then
        begin
          case Parameter.Q.GetBitsCount of
            160:
              begin
                SHA1Dig := SHA1(PAnsiChar(Data), DataByteLen);
                OutDigest.SetBinary(@SHA1Dig[0], SizeOf(TCnSHA1Digest));
              end;
            224:
              begin
                SHA224Dig := SHA224(PAnsiChar(Data), DataByteLen);
                OutDigest.SetBinary(@SHA224Dig[0], SizeOf(TCnSHA224Digest));
              end;
            256:
              begin
                SHA256Dig := SHA256(PAnsiChar(Data), DataByteLen);
                OutDigest.SetBinary(@SHA256Dig[0], SizeOf(TCnSHA256Digest));
              end;
          else
            Exit;
          end;
        end;
      end;
    dhtMD5:
      begin
        MD5Dig := MD5(PAnsiChar(Data), DataByteLen);
        OutDigest.SetBinary(@MD5Dig[0], SizeOf(TCnMD5Digest));
      end;
    dhtSHA1:
      begin
        SHA1Dig := SHA1(PAnsiChar(Data), DataByteLen);
        OutDigest.SetBinary(@SHA1Dig[0], SizeOf(TCnSHA1Digest));
      end;
    dhtSHA224:
      begin
        SHA224Dig := SHA224(PAnsiChar(Data), DataByteLen);
        OutDigest.SetBinary(@SHA224Dig[0], SizeOf(TCnSHA224Digest));
      end;
    dhtSHA256:
      begin
        SHA256Dig := SHA256(PAnsiChar(Data), DataByteLen);
        OutDigest.SetBinary(@SHA256Dig[0], SizeOf(TCnSHA256Digest));
      end;
    dhtSM3:
      begin
        SM3Dig := SM3(PAnsiChar(Data), DataByteLen);
        OutDigest.SetBinary(@SM3Dig[0], SizeOf(TCnSM3Digest));
      end;
  else
    Exit;
  end;

  Result := True;
end;

function CnDSAGenerateParameter(OutParameter: TCnDSADomainParameter;
  PrimeType: TCnDSAPrimeType = dptBit1024160): Boolean;
var
  PB, QB, KV: Integer;
  K, H: TCnBigNumber;
begin
  Result := False;

  // ������λ�����ٵ� Q��Ȼ�����ȡ K �� Q �ټ� 1 ���ж�λ�������ԣ�����λ������������Ϊ P
  case PrimeType of
    dptBit1024160:
      begin
        PB := 1024;
        QB := 160;
      end;
    dptBit2048224:
      begin
        PB := 2048;
        QB := 224;
      end;
    dptBit2048256:
      begin
        PB := 2048;
        QB := 256;
      end;
    dptBit3072256:
      begin
        PB := 3072;
        QB := 256;
      end;
  else
    Exit;
  end;

  KV := PB - QB; // K �����Ҫ��ô��λ���˻�
  K := nil;
  H := nil;

  try
    K := TCnBigNumber.Create;
    repeat
      // ����ָ���϶�λ�������� Q
      if not BigNumberGeneratePrimeByBitsCount(OutParameter.Q, QB) then Exit;

      // ���ȡ K
      if not BigNumberRandBits(K, KV) then Exit;

      // �˻�����һ�� P
      if not BigNumberMul(OutParameter.P, K, OutParameter.Q) then Exit;

      // TODO: ��� P - 1 �����д����������Կ�����

      if not BigNumberAddWord(OutParameter.P, 1) then Exit;

      // �����λ��������
    until (OutParameter.P.GetBitsCount = PB) and BigNumberIsProbablyPrime(OutParameter.P);

    // �õ��Ϸ��� P �ˣ���������Ԫ G����ʱ K ��ֵ�� (P - 1)/Q
    H := TCnBigNumber.Create;
    repeat
      // ���ȡ H > 1 �� < P - 1
      if not BigNumberRandBits(H, PB) then Exit;
      if BigNumberCompare(H, OutParameter.P) >= 0 then
        if not BigNumberSub(H, H, OutParameter.P) then Exit;

      if H.IsZero or H.IsOne then
        Continue;

      // ���� H^K mod P������� 1�����������Ԫ
      if not BigNumberPowerMod(OutParameter.G, H, K, OutParameter.P) then Exit;
    until not OutParameter.G.IsOne;

    Result := True;
  finally
    H.Free;
    K.Free;
  end;
end;

function CnDSAVerifyParameter(DSAParameter: TCnDSADomainParameter): Boolean;
var
  T: TCnBigNumber;
begin
  Result := False;
  if DSAParameter.P.IsNegative or DSAParameter.Q.IsNegative
    or DSAParameter.G.IsNegative then
    Exit;

  // ������������
  if not BigNumberIsProbablyPrime(DSAParameter.P) then Exit;
  if not BigNumberIsProbablyPrime(DSAParameter.Q) then Exit;

  // G ���ܱ� P - 1 ��
  if BigNumberCompare(DSAParameter.G, DSAParameter.P) >= 0 then Exit;

  T := TCnBigNumber.Create;
  try
    // G �ñ� 2 ��
    T.SetWord(2);
    if BigNumberCompare(DSAParameter.G, T) <= 0 then Exit;

    // P - 1 Ҫ������ Q
    BigNumberCopy(T, DSAParameter.P);
    T.SubWord(1);
    if not BigNumberMod(T, T, DSAParameter.Q) then Exit;

    if not T.IsZero then
      Exit;

    // G ��������Ԫ��Ҳ���� G^Q mod P �� = 1
    if not BigNumberPowerMod(T, DSAParameter.G, DSAParameter.Q, DSAParameter.P) then Exit;
    Result := T.IsOne;
  finally
    T.Free;
  end;
end;

function CnDSAGenerateKeys(DSAParameter: TCnDSADomainParameter;
  OutPrivateKey: TCnDSAPrivateKey; OutPublicKey: TCnDSAPublicKey): Boolean;
begin
  Result := False;
  repeat
    if not BigNumberRandRange(OutPrivateKey, DSAParameter.Q) then
      Exit;
  until not OutPrivateKey.IsZero and not OutPrivateKey.IsOne;

  Result := BigNumberPowerMod(OutPublicKey, DSAParameter.G, OutPrivateKey, DSAParameter.P);
end;

function CnDSAVerifyKeys(DSAParameter: TCnDSADomainParameter;
  PrivateKey: TCnDSAPrivateKey; PublicKey: TCnDSAPublicKey): Boolean;
var
  T: TCnBigNumber;
begin
  Result := False;
  if PrivateKey.IsNegative or PrivateKey.IsZero then
    Exit;

  T := TCnBigNumber.Create;
  try
    if BigNumberPowerMod(T, DSAParameter.G, PrivateKey, DSAParameter.P) then
      Result := BigNumberEqual(T, PublicKey);
  finally
    T.Free;
  end;
end;

function DSASignHashData(Hash: TCnBigNumber; DSAParameter: TCnDSADomainParameter;
  PrivateKey: TCnDSAPrivateKey; OutSignature: TCnDSASignature): Boolean;
var
  K, KInv, T: TCnBigNumber;
begin
  Result := False;

  K := nil;
  KInv := nil;
  T := nil;

  try
    K := TCnBigNumber.Create;
    repeat
      if not BigNumberRandRange(K, DSAParameter.Q) then Exit;

      if K.IsZero then
        K.SetOne;

      // r = (g^k mod p) mod q
      if not BigNumberPowerMod(OutSignature.R, DSAParameter.G, K, DSAParameter.P) then Exit;
      if not BigNumberMod(OutSignature.R, OutSignature.R, DSAParameter.Q) then Exit;

      if OutSignature.R.IsZero then
        Continue;

      // ׼���� K ��ģ��Ԫ
      KInv := TCnBigNumber.Create;
      if not BigNumberModularInverse(KInv, K, DSAParameter.Q) then Exit;

      // T = Hash + ˽Կ * R
      T := TCnBigNumber.Create;
      if not BigNumberMul(T, PrivateKey, OutSignature.R) then Exit;
      if not BigNumberAdd(T, Hash, T) then Exit;

      // �ٳ��� K ģ��Ԫ�� mod Q
      if not BigNumberDirectMulMod(OutSignature.S, KInv, T, DSAParameter.Q) then Exit;
      if OutSignature.S.IsZero then
        Continue;

      Result := True;
      Exit;
    until False;
  finally
    T.Free;
    KInv.Free;
    K.Free;
  end;
end;

function DSAVerifyHashData(Hash: TCnBigNumber; DSAParameter: TCnDSADomainParameter;
  PublicKey: TCnDSAPublicKey; Signature: TCnDSASignature): Boolean;
var
  W, U1, U2, P1, P2: TCnBigNumber;
begin
  Result := False;

  W := nil;
  U1 := nil;
  U2 := nil;
  P1 := nil;
  P2 := nil;

  try
    W := TCnBigNumber.Create;
    // S ��ģ��Ԫ���� W
    if not BigNumberModularInverse(W, Signature.S, DSAParameter.Q) then Exit;

    U1 := TCnBigNumber.Create;
    U2 := TCnBigNumber.Create;

    // ���� Hash * W mod Q
    if not BigNumberDirectMulMod(U1, Hash, W, DSAParameter.Q) then Exit;
    // ���� R * W mod Q
    if not BigNumberDirectMulMod(U2, Signature.R, W, DSAParameter.Q) then Exit;

    // ���� G^U1 mod P
    P1 := TCnBigNumber.Create;
    if not BigNumberPowerMod(P1, DSAParameter.G, U1, DSAParameter.P) then Exit;
    // ���� ��Կ^U2 mod P
    P2 := TCnBigNumber.Create;
    if not BigNumberPowerMod(P2, PublicKey, U2, DSAParameter.P) then Exit;

    // ��������� mod P �� mod Q������ W
    if not BigNumberDirectMulMod(W, P1, P2, DSAParameter.P) then Exit;
    if not BigNumberMod(W, W, DSAParameter.Q) then Exit;

    // ����ȶ� W �� R
    Result := BigNumberEqual(W, Signature.R);
  finally
    P2.Free;
    P1.Free;
    U2.Free;
    U1.Free;
    W.Free;
  end;
end;

function CnDSASignData(Data: Pointer; DataByteLen: Integer;
  DSAParameter: TCnDSADomainParameter; PrivateKey: TCnDSAPrivateKey;
  OutSignature: TCnDSASignature; HashType: TCnDSAHashType = dhtAuto): Boolean;
var
  Dig: TCnBigNumber;
begin
  Result := False;
  Dig := TCnBigNumber.Create;
  try
    if DSAHashData(Data, DataByteLen, Dig, DSAParameter, HashType) then
      Result := DSASignHashData(Dig, DSAParameter, PrivateKey, OutSignature);
  finally
    Dig.Free;
  end;
end;

function CnDSAVerifyData(Data: Pointer; DataByteLen: Integer;
  DSAParameter: TCnDSADomainParameter; PublicKey: TCnDSAPublicKey;
  Signature: TCnDSASignature; HashType: TCnDSAHashType = dhtAuto): Boolean;
var
  Dig: TCnBigNumber;
begin
  Result := False;
  Dig := TCnBigNumber.Create;
  try
    if DSAHashData(Data, DataByteLen, Dig, DSAParameter, HashType) then
      Result := DSAVerifyHashData(Dig, DSAParameter, PublicKey, Signature);
  finally
    Dig.Free;
  end;
end;

function CnDSASignBytes(Data: TBytes; DSAParameter: TCnDSADomainParameter;
  PrivateKey: TCnDSAPrivateKey; OutSignature: TCnDSASignature;
  HashType: TCnDSAHashType = dhtAuto): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnDSASignData(nil, 0, DSAParameter, PrivateKey,
      OutSignature, HashType)
  else
    Result := CnDSASignData(@Data[0], Length(Data), DSAParameter, PrivateKey,
      OutSignature, HashType);
end;

function CnDSAVerifyBytes(Data: TBytes; DSAParameter: TCnDSADomainParameter;
  PublicKey: TCnDSAPublicKey; Signature: TCnDSASignature;
  HashType: TCnDSAHashType = dhtAuto): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnDSAVerifyData(nil, 0, DSAParameter, PublicKey,
      Signature, HashType)
  else
    Result := CnDSAVerifyData(@Data[0], Length(Data), DSAParameter, PublicKey,
      Signature, HashType);
end;

end.
