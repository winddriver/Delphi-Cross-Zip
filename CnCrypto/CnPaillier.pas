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

unit CnPaillier;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�Paillier �㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���� Int64 ��Χ���Լ���������Χ�ڵļӷ�̬ͬ Paillier �㷨��
*
*           Paillier ���ܵ����ԣ������ĸ��Լ��ܺ�Ľ����ˣ��˻���Ϊ���Ľ⿪��
*           �õ��Ľ����ԭʼ��������ӣ��ӷ�̬ͬ������Эͬ��Կ���ƵĻ�����
*
*           ���ĳ������� N �Ľף��Ǹ�������С�η�ģ N Ϊ 1 ���Ǹ��η���
*           �ױ�Ȼ�ܹ������� N ���ص�������ŷ������������׿�ö��ŷ����������������
*           ����׵��� N ��ŷ����������˵��������һ·�˷�ģ N ��ȥ�ܹ����� N ��
*           �����л������ݣ�����׾���ԭ����

* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2022.05.22 V1.0
*               ������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes {$IFDEF MSWINDOWS}, Windows {$ENDIF},
  CnConsts, CnNative, CnBigNumber;

const
  CN_PAILLIER_DEFAULT_PRIMEBITS = 2048;
  {* Paillier �㷨��Ĭ������λ��}

  // ������
  ECN_PAILLIER_OK                      = ECN_OK;
  {* Paillier ϵ�д����룺�޴���ֵΪ 0}

  ECN_PAILLIER_ERROR_BASE              = ECN_CUSTOM_ERROR_BASE + $300;
  {* Paillier ϵ�д�����Ļ�׼��ʼֵ��Ϊ ECN_CUSTOM_ERROR_BASE ���� $300}

  ECN_PAILLIER_INVALID_INPUT           = ECN_PAILLIER_ERROR_BASE + 1;
  {* Paillier ������֮����Ϊ�ջ򳤶ȴ���}
  ECN_PAILLIER_RANDOM_ERROR            = ECN_PAILLIER_ERROR_BASE + 2;
  {* Paillier ������֮�������ش���}

type
  TCnInt64PaillierPrivateKey = packed record
  {* Int64 ��Χ�ڵ� Paillier ˽Կ}
    P: TUInt64;
    Q: TUInt64;              // ����������Ϊ�����������Χ������ Integer ��
    Lambda: TUInt64;
    Mu: TUInt64;
  end;
  PCnInt64PaillierPrivateKey = ^TCnInt64PaillierPrivateKey;

  TCnInt64PaillierPublicKey = packed record
  {* Int64 ��Χ�ڵ� Paillier ��Կ}
    N: TUInt64;              // �������˻�
    G: TUInt64;
  end;
  PCnInt64PaillierPublicKey = ^TCnInt64PaillierPublicKey;

  TCnPaillierPrivateKey = class(TPersistent)
  {* ������Χ�ڵ� Paillier ˽Կ}
  private
    FP: TCnBigNumber;
    FQ: TCnBigNumber;
    FMu: TCnBigNumber;
    FLambda: TCnBigNumber;
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
    {* ������һ}
    property Q: TCnBigNumber read FQ;
    {* ��������}
    property Lambda: TCnBigNumber read FLambda;
    {* ���������Լ�һ�ĳ˻�}
    property Mu: TCnBigNumber read FMu;
    {* ͨ��ģ��Ԫ��������� Mu}
  end;

  TCnPaillierPublicKey = class(TPersistent)
  {* ������Χ�ڵ� Paillier ��Կ}
  private
    FG: TCnBigNumber;
    FN: TCnBigNumber;
    FN2: TCnBigNumber;
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

    property N: TCnBigNumber read FN;
    {* �������˻�}
    property G: TCnBigNumber read FG;
    {* �������˻���һ}
    property N2: TCnBigNumber read FN2;
    {* N ��ƽ�������ŷ������}
  end;

function CnGenerateInt64PaillierKeys(var PrivateKey: TCnInt64PaillierPrivateKey;
  var PublicKey: TCnInt64PaillierPublicKey): Boolean;
{* �������һ�� Int64 ��Χ�ڵ� Paillier ��˽Կ�����������Ƿ�ɹ���

   ������
     var PrivateKey: TCnInt64PaillierPrivateKey - ���ɵ� Paillier ˽Կ
     var PublicKey: TCnInt64PaillierPublicKey   - ���ɵ� Paillier ��Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnInt64PaillierEncrypt(var PublicKey: TCnInt64PaillierPublicKey;
  Data: Int64; out Res: Int64; RandFactor: Int64 = 0): Boolean;
{* Int64 ��Χ�ڵ� Paillier ��Կ�����������ݵõ����ģ����ؼ����Ƿ�ɹ���
   �����ⲿ�����������0 ��ʾ�ڲ����ɡ�

   ������
     var PublicKey: TCnInt64PaillierPublicKey   - Paillier ��Կ
     Data: Int64                                - �����ܵ���������
     out Res: Int64                             - ���������
     RandFactor: Int64                          - �����

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnInt64PaillierDecrypt(var PrivateKey: TCnInt64PaillierPrivateKey;
  var PublicKey: TCnInt64PaillierPublicKey; EnData: Int64; out Res: Int64): Boolean;
{* Int64 ��Χ�ڵ� Paillier ˽Կ�����������ݵõ����ģ����ؽ����Ƿ�ɹ���

   ������
     var PrivateKey: TCnInt64PaillierPrivateKey - Paillier ˽Կ
     var PublicKey: TCnInt64PaillierPublicKey   - Paillier ��Կ
     EnData: Int64                              - �����ܵ���������
     out Res: Int64                             - ���������

   ����ֵ��Boolean                        - ���ؽ����Ƿ�ɹ�
}

function CnInt64PaillierAddPlain(Data1: Int64; Data2: Int64;
  var PublicKey: TCnInt64PaillierPublicKey): Int64;
{* Int64 ��Χ�� Paillier �ӷ�̬ͬ�����ļӷ����ڲ���ģ N �ӡ�

   ������
     Data1: Int64                               - ���ļ���һ
     Data2: Int64                               - ���ļ�����
     var PublicKey: TCnInt64PaillierPublicKey   - Paillier ��Կ

   ����ֵ��Int64                          - ���غ�
}

function CnInt64PaillierAddCipher(EnData1: Int64; EnData2: Int64;
  var PublicKey: TCnInt64PaillierPublicKey): Int64;
{* Int64 ��Χ�� Paillier �ӷ�̬ͬ�����ļӷ����ڲ���ģ N^2 �ˡ�

   ������
     EnData1: Int64                             - ���ĳ���һ
     EnData2: Int64                             - ���ĳ�����
     var PublicKey: TCnInt64PaillierPublicKey   - Paillier ��Կ

   ����ֵ��Int64                          - ���ػ�
}

function CnGeneratePaillierKeys(PrivateKey: TCnPaillierPrivateKey;
  PublicKey: TCnPaillierPublicKey; PrimeBits: Integer = CN_PAILLIER_DEFAULT_PRIMEBITS): Boolean;
{* �������һ�Դ�����Χ�ڵ� Paillier ��˽Կ�����������Ƿ�ɹ���

   ������
     PrivateKey: TCnPaillierPrivateKey    - ���ɵ� Paillier ˽Կ
     PublicKey: TCnPaillierPublicKey      - ���ɵ� Paillier ��Կ
     PrimeBits: Integer                   - ����λ��

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnPaillierEncrypt(PublicKey: TCnPaillierPublicKey;
  Data: TCnBigNumber; Res: TCnBigNumber; RandFactor: TCnBigNumber = nil): Boolean;
{* ������Χ�ڵ� Paillier ��Կ�����������ݵõ����ģ����ؼ����Ƿ�ɹ���

   ������
     PublicKey: TCnPaillierPublicKey      - Paillier ��Կ
     Data: TCnBigNumber                   - �����ܵ����Ĵ���
     Res: TCnBigNumber                    - ��������Ĵ���
     RandFactor: TCnBigNumber             - �����

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnPaillierDecrypt(PrivateKey: TCnPaillierPrivateKey;
  PublicKey: TCnPaillierPublicKey; EnData: TCnBigNumber; Res: TCnBigNumber): Boolean;
{* ������Χ�ڵ� Paillier ˽Կ�����������ݵõ����ģ����ؽ����Ƿ�ɹ���

   ������
     PrivateKey: TCnPaillierPrivateKey    - Paillier ˽Կ
     PublicKey: TCnPaillierPublicKey      - Paillier ��Կ
     EnData: TCnBigNumber                 - �����ܵ����Ĵ���
     Res: TCnBigNumber                    - ��������Ĵ���

   ����ֵ��Boolean                        - ���ؽ����Ƿ�ɹ�
}

function CnPaillierAddPlain(Res: TCnBigNumber; Data1: TCnBigNumber; Data2: TCnBigNumber;
  PublicKey: TCnPaillierPublicKey): Boolean;
{* ������Χ�� Paillier �ӷ�̬ͬ�����ļӷ����ڲ���ģ N �ӡ�

   ������
     Res: TCnBigNumber                    - ���غ�
     Data1: TCnBigNumber                  - ���ļ���һ
     Data2: TCnBigNumber                  - ���ļ�����
     PublicKey: TCnPaillierPublicKey      - Paillier ��Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnPaillierAddCipher(Res: TCnBigNumber; EnData1: TCnBigNumber; EnData2: TCnBigNumber;
  PublicKey: TCnPaillierPublicKey): Boolean;
{* ������Χ�� Paillier �ӷ�̬ͬ�����ļӷ����ڲ���ģ N^2 �ˡ�

   ������
     Res: TCnBigNumber                    - ���ػ�
     EnData1: TCnBigNumber                - ���ĳ���һ
     EnData2: TCnBigNumber                - ���ĳ�����
     PublicKey: TCnPaillierPublicKey      - Paillier ��Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

implementation

uses
  CnPrime, CnRandom;

function CnGenerateInt64PaillierKeys(var PrivateKey: TCnInt64PaillierPrivateKey;
  var PublicKey: TCnInt64PaillierPublicKey): Boolean;
var
  AN, Lam: Int64;
  AP, AQ: Integer;
begin
  // ������������� Integer ��Χ�ڵ�����
  repeat
    repeat
      AP := CnPickRandomSmallPrime;
      AN := Trunc(Random * 100); // ���� AN���Ե��� CnPickRandomSmallPrime �ڲ��������������
      Sleep(AN);
      AQ := CnPickRandomSmallPrime;
    until (AP > 0) and (AQ > 0) and (AP <> AQ);

    // �õ����������黥��
    AN := CnInt64GreatestCommonDivisor(Int64(AP) * Int64(AQ), Int64(AP - 1) * Int64(AQ - 1));
  until AN = 1;

  AN := Int64(AP) * Int64(AQ);
  Lam := CnInt64LeastCommonMultiple(AP - 1, AQ - 1);
  // �õ��� N �� Lambda������ѡ�� G��G Ҫ�� N^2 ���أ������ N^2 �Ľ�Ҫ�ܱ� N ������������һ���õ���ֵ�� N ����Ԫ
  // ֱ���� N + 1 ò�ƿ��ԣ�
  // ��Ϊ��1��N �� N + 1 ģ N^2 �Ľף�ԭ�� (N + 1)^N mod N^2 �ö���ʽչ����ȥ�õ� = N^2 + 1 mod N^2 = 1����������㱻 N ����������
  // �� Mu �Ļ�����ʽ���Լ�
  // (N + 1)^((P-1)*(Q-1)) mod N^2 ����ʽչ����ȥ���õ� 1 + (P-1)*(Q-1)*N������ L ��������һ�� N �Ǹ������õ� (P-1)*(Q-1)
  // ���Ե� G ȡ N + 1 ʱ��Mu �� (P-1)*(Q-1) �� N ����Ԫ

  PrivateKey.P := AP;
  PrivateKey.Q := AQ;
  PrivateKey.Lambda := Lam;

  PublicKey.N := AN;
  PublicKey.G := AN + 1;

  PrivateKey.Mu := CnInt64ModularInverse2(Lam, AN);

  Result := True;
end;

function CnInt64PaillierEncrypt(var PublicKey: TCnInt64PaillierPublicKey;
  Data: Int64; out Res: Int64; RandFactor: Int64): Boolean;
var
  T1, T2, R, N2, G: TUInt64;
begin
  // ��Կ���ܣ�������� R < N��Ȼ������ = (G^M * R^N) mod N^2
  Result := False;
  if Data >= PublicKey.N then
    Exit;

  N2 := UInt64Mul(PublicKey.N, PublicKey.N);
  R := RandFactor;
  if R = 0 then
    R := RandomInt64LessThan(PublicKey.N - 2) // ע�⣡R ����� N ���ʣ�Ҳ���ǲ����� P �� Q �ı�����
  else
    R := UInt64Mod(R, PublicKey.N - 2); // ������洫��̫��

  //  �������� 2 ���ܹ��
  G := CnInt64GreatestCommonDivisor(R, PublicKey.N);
  if G > 1 then
  begin
    R := R + 1;
    G := CnInt64GreatestCommonDivisor(R, PublicKey.N);
    if G > 1 then
      R := R + 1;
  end;

{$IFDEF SUPPORT_UINT64}
  T1 := MontgomeryPowerMod(PublicKey.G, UInt64(Data), N2);
{$ELSE}
  T1 := MontgomeryPowerMod(PublicKey.G, Data, N2);
{$ENDIF}
  T2 := MontgomeryPowerMod(R, PublicKey.N, N2);
  Res := UInt64NonNegativeMulMod(T1, T2, N2); // ����������为Ҳ��

  Result := True;
end;

function CnInt64PaillierDecrypt(var PrivateKey: TCnInt64PaillierPrivateKey;
  var PublicKey: TCnInt64PaillierPublicKey; EnData: Int64; out Res: Int64): Boolean;
var
  T, N2: TUInt64;
begin
  // ˽Կ���ܣ����� = ((((����^Lambda mod N^2) - 1) / N) * Mu) mod N
  N2 := UInt64Mul(PublicKey.N, PublicKey.N);

{$IFDEF SUPPORT_UINT64}
  T := MontgomeryPowerMod(UInt64(EnData), PrivateKey.Lambda, N2);
{$ELSE}
  T := MontgomeryPowerMod(EnData, PrivateKey.Lambda, N2);
{$ENDIF}

  T := UInt64Div(T - 1, PublicKey.N); // ���ﰴ G ���趨��������
  Res := Int64NonNegativeMulMod(T, PrivateKey.Mu, PublicKey.N);

  Result := True;
end;

function CnInt64PaillierAddPlain(Data1, Data2: Int64;
  var PublicKey: TCnInt64PaillierPublicKey): Int64;
begin
  Result := UInt64NonNegativeAddMod(Data1, Data2, PublicKey.N);
end;

function CnInt64PaillierAddCipher(EnData1, EnData2: Int64;
  var PublicKey: TCnInt64PaillierPublicKey): Int64;
begin
  Result := UInt64NonNegativeMulMod(EnData1, EnData2, UInt64Mul(PublicKey.N, PublicKey.N));
end;

{ TCnPaillierPrivateKey }

procedure TCnPaillierPrivateKey.Assign(Source: TPersistent);
begin
  if Source is TCnPaillierPrivateKey then
  begin
    BigNumberCopy(FP, (Source as TCnPaillierPrivateKey).P);
    BigNumberCopy(FQ, (Source as TCnPaillierPrivateKey).Q);
    BigNumberCopy(FMu, (Source as TCnPaillierPrivateKey).Mu);
    BigNumberCopy(FLambda, (Source as TCnPaillierPrivateKey).Lambda);
  end
  else
    inherited;
end;

constructor TCnPaillierPrivateKey.Create;
begin
  inherited;
  FP := TCnBigNumber.Create;
  FQ := TCnBigNumber.Create;
  FLambda := TCnBigNumber.Create;
  FMu := TCnBigNumber.Create;
end;

destructor TCnPaillierPrivateKey.Destroy;
begin
  FMu.Free;
  FLambda.Free;
  FQ.Free;
  FP.Free;
  inherited;
end;

{ TCnPaillierPublicKey }

procedure TCnPaillierPublicKey.Assign(Source: TPersistent);
begin
  if Source is TCnPaillierPublicKey then
  begin
    BigNumberCopy(FN, (Source as TCnPaillierPublicKey).N);
    BigNumberCopy(FG, (Source as TCnPaillierPublicKey).G);
  end
  else
    inherited;
end;

constructor TCnPaillierPublicKey.Create;
begin
  inherited;
  FN := TCnBigNumber.Create;
  FG := TCnBigNumber.Create;
  FN2 := TCnBigNumber.Create;
end;

destructor TCnPaillierPublicKey.Destroy;
begin
  FN2.Free;
  FG.Free;
  FN.Free;
  inherited;
end;

function CnGeneratePaillierKeys(PrivateKey: TCnPaillierPrivateKey;
  PublicKey: TCnPaillierPublicKey; PrimeBits: Integer): Boolean;
var
  Suc: Boolean;
  AN, T, Lam, AP, AQ: TCnBigNumber;
begin
  Result := False;
  if (PrivateKey = nil) or (PublicKey = nil) or (PrimeBits < 128) then
  begin
    _CnSetLastError(ECN_PAILLIER_INVALID_INPUT);
    Exit;
  end;

  AP := nil;
  AQ := nil;
  AN := nil;
  T := nil;
  Lam := nil;

  try
    AP := TCnBigNumber.Create;
    AQ := TCnBigNumber.Create;
    AN := TCnBigNumber.Create;
    T := TCnBigNumber.Create;
    Lam := TCnBigNumber.Create;

    Suc := False;
    repeat
      if not BigNumberGeneratePrimeByBitsCount(PrivateKey.P, PrimeBits) then
        Exit;
      if not BigNumberGeneratePrimeByBitsCount(PrivateKey.Q, PrimeBits) then
        Exit;

      if BigNumberEqual(PrivateKey.P, PrivateKey.Q) then // �������
        Continue;

      if not BigNumberMul(AN, PrivateKey.P, PrivateKey.Q) then // ���� P * Q
        Exit;

      if BigNumberCopy(AP, PrivateKey.P) = nil then
        Exit;
      if BigNumberCopy(AQ, PrivateKey.Q) = nil then
        Exit;

      AP.SubWord(1);
      AQ.SubWord(1);

      if not BigNumberMul(Lam, AP, AQ) then // ���� (P - 1) * (Q - 1)
        Exit;

      if not BigNumberGcd(T, AN, Lam) then
        Exit;

      if T.IsOne then // PQ �� (P-1)*(Q-1) ����
        Suc := True;
    until Suc;

    if BigNumberCopy(PublicKey.N, AN) = nil then
      Exit;

    if not BigNumberMul(PublicKey.N2, PublicKey.N, PublicKey.N) then // ���� N2
      Exit;

    if BigNumberCopy(PublicKey.G, AN) = nil then
      Exit;

    PublicKey.G.AddWord(1);  // G := N + 1

    if BigNumberCopy(PrivateKey.Lambda, Lam) = nil then
      Exit;

    // ���� Mu��������Ԫ
    if not BigNumberModularInverse(PrivateKey.Mu, Lam, AN) then
      Exit;

    Result := True;
    _CnSetLastError(ECN_PAILLIER_OK);
  finally
    Lam.Free;
    T.Free;
    AN.Free;
    AQ.Free;
    AP.Free;
  end;
end;

function CnPaillierEncrypt(PublicKey: TCnPaillierPublicKey;
  Data: TCnBigNumber; Res: TCnBigNumber; RandFactor: TCnBigNumber): Boolean;
var
  R, T1, T2, G, M: TCnBigNumber;
begin
  // ��Կ���ܣ�������� R < N��Ȼ������ = (G^M * R^N) mod N^2
  Result := False;
  if BigNumberCompare(Data, PublicKey.N) >= 0 then // �����ܵ��������ֲ��ܱ� N ��
  begin
    _CnSetLastError(ECN_PAILLIER_INVALID_INPUT);
    Exit;
  end;

  T1 := nil;
  R := nil;
  M := nil;
  G := nil;
  T2 := nil;

  try
    T1 := TCnBigNumber.Create;

    // ���Լ򻯡�g = n + 1 ������£�g^m mod n^2 = m*n + 1 mod n^2
    if BigNumberCopy(T1, PublicKey.G) = nil then
      Exit;

    T1.SubWord(1);
    if BigNumberEqual(T1, PublicKey.N) then // �ж� g = n + 1
    begin
      if not BigNumberMul(T1, Data, PublicKey.N) then // Data * N
        Exit;

      T1.AddWord(1);                                     // Data * N + 1
      if not BigNumberMod(T1, T1, PublicKey.N2) then     // �� mod N^2
        Exit;
    end
    else
    begin
      if not BigNumberPowerMod(T1, PublicKey.G, Data, PublicKey.N2) then
        Exit;
    end;

    // �������ֵ��ע�⣡R ����� N ���ʣ�Ҳ���ǲ����� P �� Q �ı�����
    R := TCnBigNumber.Create;
    M := TCnBigNumber.Create;
    if BigNumberCopy(M, PublicKey.N) = nil then
      Exit;

    M.SubWord(2); // �Ա���һ������ʱ�Ӷ�����

    if (RandFactor <> nil) and not RandFactor.IsZero then // ����紫��������
    begin
      if BigNumberCopy(R, RandFactor) = nil then
        Exit;

      if R.IsNegative then // Ԥ��Ϊ��
        R.Negate;

      if not BigNumberMod(R, R, M) then // Ԥ�����������
        Exit;
    end
    else
    begin
      if not BigNumberRandRange(R, M) then
      begin
        _CnSetLastError(ECN_PAILLIER_RANDOM_ERROR);
        Exit;
      end;
    end;

    G := TCnBigNumber.Create;
    if not BigNumberGcd(G, R, PublicKey.N) then
      Exit;

    // �жϻ��ʣ���������� 1 ���㹻��
    if not G.IsOne then
    begin
      R.AddWord(1);
      if not BigNumberGcd(G, R, PublicKey.N) then
        Exit;

      if not G.IsOne then
        R.AddWord(1);
    end;

    T2 := TCnBigNumber.Create;
    if not BigNumberPowerMod(T2, R, PublicKey.N, PublicKey.N2) then
      Exit;

    if not BigNumberDirectMulMod(Res, T1, T2, PublicKey.N2) then
      Exit;

    Result := True;
    _CnSetLastError(ECN_PAILLIER_OK);
  finally
    T2.Free;
    G.Free;
    M.Free;
    R.Free;
    T1.Free;
  end;
end;

function CnPaillierDecrypt(PrivateKey: TCnPaillierPrivateKey;
  PublicKey: TCnPaillierPublicKey; EnData: TCnBigNumber; Res: TCnBigNumber): Boolean;
var
  T: TCnBigNumber;
begin
  // ˽Կ���ܣ����� = ((((����^Lambda mod N^2) - 1) / N) * Mu) mod N
  Result := False;

  T := nil;

  try
    T := TCnBigNumber.Create;
    if not BigNumberPowerMod(T, EnData, PrivateKey.Lambda, PublicKey.N2) then
      Exit;

    T.SubWord(1);
    if not BigNumberDiv(T, nil, T, PublicKey.N) then
      Exit;

    if not BigNumberDirectMulMod(Res, T, PrivateKey.Mu, PublicKey.N) then
      Exit;

    Result := True;
    _CnSetLastError(ECN_PAILLIER_OK);
  finally
    T.Free;
  end;
end;

function CnPaillierAddPlain(Res: TCnBigNumber; Data1, Data2: TCnBigNumber;
  PublicKey: TCnPaillierPublicKey): Boolean;
begin
  Result := BigNumberAddMod(Res, Data1, Data2, PublicKey.N);
end;

function CnPaillierAddCipher(Res: TCnBigNumber; EnData1, EnData2: TCnBigNumber;
  PublicKey: TCnPaillierPublicKey): Boolean;
begin
  Result := BigNumberDirectMulMod(Res, EnData1, EnData2, PublicKey.N2);
end;

end.
