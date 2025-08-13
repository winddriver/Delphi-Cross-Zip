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

unit CnLattice;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ���������㵥Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫ����ʵ���˻��ڸ�Lattice���� NTRU �ӽ����㷨��
* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2023.09.10 V1.1
*               ʵ�� NTRU �ļӽ����㷨
*           2023.08.25 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative, CnVector, CnBigNumber, CnPolynomial, CnRandom, CnBits;

type
  ECnLatticeException = class(Exception);
  {* NTRU ����쳣}

  TCnNTRUParamType = (cnptCustomized, cnptClassic, cnptHPS2048509, cnptHPS2048677,
    cnptHPS4096821);
  {* NTRU �����Ƽ�����}

  TCnNTRUPrivateKey = class
  {* Number Theory Research Unit ��˽Կ��F G ��������ʽ����ģ��}
  private
    FFQ: TCnInt64Polynomial;
    FF: TCnInt64Polynomial;
    FG: TCnInt64Polynomial;
    FFP: TCnInt64Polynomial;
    procedure SetFF(const Value: TCnInt64Polynomial);
    procedure SetFFP(const Value: TCnInt64Polynomial);
    procedure SetFFQ(const Value: TCnInt64Polynomial);
    procedure SetFG(const Value: TCnInt64Polynomial);
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ��ʾ F �� G ���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property F: TCnInt64Polynomial read FF write SetFF;
    {* ˽Կ����ʽ F���������ʱҪ���� D+1 �� 1��D �� -1�������� 0}
    property G: TCnInt64Polynomial read FG write SetFG;
    {* ˽Կ����ʽ G���������ʱҪ���� D �� 1��D �� -1�������� 0}
    property FQ: TCnInt64Polynomial read FFQ write SetFFQ;
    {* ˽Կ����ʽ F �Դ�ģ Q ��ģ�����ʽ������������裬�����������}
    property FP: TCnInt64Polynomial read FFP write SetFFP;
    {* ˽Կ����ʽ F ��С����ģ P ��ģ�����ʽ������������裬�����������}
  end;

  TCnNTRUPublicKey = class
  {* Number Theory Research Unit �Ĺ�Կ��һ�� H ����ʽ}
  private
    FH: TCnInt64Polynomial;
    procedure SetFH(const Value: TCnInt64Polynomial);
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ��ʾ H ���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property H: TCnInt64Polynomial read FH write SetFH;
    {* ��Կ����ʽ}
  end;

  TCnNTRU = class
  {* Number Theory Research Unit ʵ����}
  private
    FQ: Int64;
    FQExponent: Integer;
    FD: Integer;
    FN: Integer;
    FPrime: Integer;
    FRing: TCnInt64Polynomial;
  protected
    procedure RandPolynomial(P: TCnInt64Polynomial; MaxDegree: Integer;
      OneCount: Integer; MinusOneCount: Integer); overload;
    {* ���������ߴ����� MaxDegree �Ķ���ʽ���� OneCount �� 1��MinusOneCount �� -1�������� 0��

       ������
         P: TCnInt64Polynomial            - ���ɵĽ������ʽ
         MaxDegree: Integer               - ��ߴ���
         OneCount: Integer                - 1 �ĸ���
         MinusOneCount: Integer           - -1 �ĸ���

       ����ֵ�����ޣ�
    }

    procedure RandPolynomial(P: TCnInt64Polynomial; MaxDegree: Integer); overload;
    {* ���������ߴ����� MaxDegree �Ķ���ʽ���ڲ�ϵ�� 1 0 -1 �����ע���� FPrime �޹ء�

       ������
         P: TCnInt64Polynomial            - ���ɵĽ������ʽ
         MaxDegree: Integer               - ��ߴ���

       ����ֵ�����ޣ�
    }

  public
    constructor Create(NTRUType: TCnNTRUParamType = cnptClassic); virtual;
    {* ���캯����ָ�� NTRU �������͡�

       ������
         NTRUType: TCnNTRUParamType       - NTRU ��������

       ����ֵ��TCnNTRU                    - ����ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure Load(Predefined: TCnNTRUParamType);
    {* ����Ԥ�����͵� NTRU ������

       ������
         Predefined: TCnNTRUParamType     - NTRU ��������

       ����ֵ�����ޣ�
    }

    procedure GenerateKeys(PrivateKey: TCnNTRUPrivateKey; PublicKey: TCnNTRUPublicKey);
    {* ����һ�Թ�˽Կ��

       ������
         PrivateKey: TCnNTRUPrivateKey    - ���ɵ� NTRU ˽Կ
         PublicKey: TCnNTRUPublicKey      - ���ɵ� NTRU ��Կ

       ����ֵ�����ޣ�
    }

    procedure Encrypt(PublicKey: TCnNTRUPublicKey; PlainData: TCnInt64Polynomial;
      OutEnData: TCnInt64Polynomial);
    {* �ù�Կ�������Ķ���ʽ�õ����Ķ���ʽ�����ߴ������ N - 1����Ϊ���� X^N - 1��

       ������
         PublicKey: TCnNTRUPublicKey      - NTRU ��Կ
         PlainData: TCnInt64Polynomial    - �����ܵ����Ķ���ʽ
         OutEnData: TCnInt64Polynomial    - ��������Ķ���ʽ

       ����ֵ�����ޣ�
    }

    procedure Decrypt(PrivateKey: TCnNTRUPrivateKey; EnData: TCnInt64Polynomial;
      OutPlainData: TCnInt64Polynomial);
    {* ��˽Կ�������Ķ���ʽ�õ����Ķ���ʽ�����ߴ������ N - 1����Ϊ���� X^N - 1��

       ������
         PrivateKey: TCnNTRUPrivateKey    - NTRU ˽Կ
         EnData: TCnInt64Polynomial       - �����ܵ����Ķ���ʽ
         OutPlainData: TCnInt64Polynomial - ��������Ķ���ʽ

       ����ֵ�����ޣ�
    }

    function EncryptBytes(PublicKey: TCnNTRUPublicKey; Data: TBytes): TBytes;
    {* �ù�Կ���������ֽ����飬���ؼ��ܽ����ע�����Ļᱻ�� #0 ���涨���ȡ�

       ������
         PublicKey: TCnNTRUPublicKey      - NTRU ��Կ
         Data: TBytes                     - �����ܵ������ֽ�����

       ����ֵ��TBytes                     - ���������ֽ�����
    }

    function DecryptBytes(PrivateKey: TCnNTRUPrivateKey; EnData: TBytes): TBytes;
    {* ��˽Կ���������ֽ����飬���ؽ��ܽ����ע�����Ļᱻ�� #0 ���涨���ȡ�

       ������
         PrivateKey: TCnNTRUPrivateKey    - NTRU ˽Կ
         EnData: TBytes                   - �����ܵ������ֽ�����

       ����ֵ��TBytes                     - ���������ֽ�����
    }

    property Ring: TCnInt64Polynomial read FRing;
    {* ����ʽ��}
    property N: Integer read FN write FN;
    {* ����ʽλ��}
    property D: Integer read FD write FD;
    {* ����˽Կ����ʽ�Ĳ�����Χ}
    property Prime: Integer read FPrime write FPrime;
    {* С����ģ��Ĭ�� 3}
    property QExponent: Integer read FQExponent write FQExponent;
    {* ��������ģ����ָ������Ϊ 2��ģΪ 2^QExponent}
  end;

procedure NTRUDataToInt64Polynomial(Res: TCnInt64Polynomial; Data: Pointer;
  ByteLength: Integer; N: Int64; Modulus: Int64; CheckSum: Boolean = True);
{* ���� NTRU �Ĺ淶����������ת��Ϊģ���Ķ���ʽ���ӽ��ܣ������ݳ��������쳣��
   �� Q �Ķ�����λ��Ϊ��λ�������ݣ��� CheckSum Ϊ True����ȡǰ N - 1 ��ϵ����С��ת��Ϊ
   ����ʽ�� 0 �ε� N - 2 ����ϵ����N - 1 ��ϵ�����Ǹ�ϵ���� mod Q ��ȡ�����ʺ�������ת����
   �� CheckSum Ϊ False����ȡǰ N ��ϵ����С��ת��Ϊ����ʽ�� 0 �ε� N - 1 ����ϵ�����ʺ�������ת����
   ����ת���Ƿ�ɹ���

   ������
     Res: TCnInt64Polynomial              - ����Ľ������ʽ
     Data: Pointer                        - ��ת�������ݿ��ַ
     ByteLength: Integer                  - ��ת�������ݿ��ֽڳ���
     N: Int64                             - ����ʽλ��
     Modulus: Int64                       - ģ��
     CheckSum: Boolean                    - ȡϵ��У��ķ�ʽ

   ����ֵ�����ޣ�
}                                                                              

function NTRUInt64PolynomialToData(P: TCnInt64Polynomial; N: Int64; Modulus: Int64;
  Data: Pointer; CheckSum: Boolean = True): Integer;
{* ���� NTRU �Ĺ淶��ģ���Ķ���ʽת��Ϊ�������ݲ����� Data ��ָ���ڴ��У����ط��õ��ڴ泤�ȡ�
   �� CheckSum Ϊ True��ֻȡ 0 �� N - 1 �ι� N - 2 ��ϵ�����ʺ�������ת����
   �� CheckSum Ϊ False ��ȡ 0 �� N �ι� N - 1 ��ϵ�����ʺ�������ת����
   �Ƚ�����ʽϵ�� mod �� 0 �� Q - 1 �ķ�Χ��ÿ��ֵ������ Q �Ķ�����λ��Ϊ��λ�����ݿ飬
   ��ƴ������ 0 ���������ֽڡ���� Data �� nil���򷵻�������ڴ泤�ȡ�

   ������
     P: TCnInt64Polynomial                - ��ת���Ķ���ʽ
     N: Int64                             - ����ʽλ��
     Modulus: Int64                       - ģ��
     Data: Pointer                        - ���������ݵ������ַ
     CheckSum: Boolean                    - ȡϵ��У��ķ�ʽ

   ����ֵ��Integer                        - ��� Data �� nil���򷵻�������ڴ泤�ȡ�����������ط��õ��ڴ泤�ȡ�
}

function Int64GaussianLatticeReduction(V1: TCnInt64Vector; V2: TCnInt64Vector;
  X: TCnInt64Vector; Y: TCnInt64Vector): Boolean;
{* ��������ά Int64 �������������ϵĽ��Ƹ�˹���Լ��������ά SVP ���⣬�����Ƿ�ɹ���

   ������
     V1: TCnInt64Vector                   - ��Լ���Ķ�ά����һ
     V2: TCnInt64Vector                   - ��Լ���Ķ�ά������
     X: TCnInt64Vector                    - Լ���Ķ�ά�������һ
     Y: TCnInt64Vector                    - Լ���Ķ�ά���������

   ����ֵ��Boolean                        - ����Լ���Ƿ�ɹ�
}

function BigNumberGaussianLatticeReduction(V1: TCnBigNumberVector; V2: TCnBigNumberVector;
  X: TCnBigNumberVector; Y: TCnBigNumberVector): Boolean;
{* ��������ά�������������������ϵĽ��Ƹ�˹���Լ��������ά SVP ���⣬�����Ƿ�ɹ���
   �õ���Ȼ�Ǹ���ķ-ʩ���ص�������˼�룬����������������ġ�

   ������
     V1: TCnBigNumberVector               - ��Լ���Ķ�ά����������һ
     V2: TCnBigNumberVector               - ��Լ���Ķ�ά������������
     X: TCnBigNumberVector                - Լ���Ķ�ά�������������һ
     Y: TCnBigNumberVector                - Լ���Ķ�ά���������������

   ����ֵ��Boolean                        - ����Լ���Ƿ�ɹ�
}

implementation

resourcestring
  SCnErrorLatticeNTRUInvalidParam = 'Invalid NTRU Value.';
  SCnErrorLatticeModulusTooMuch = 'Modulus Too Much %d';
  SCnErrorLatticeDataTooLong = 'Data Too Long %d';

type
  TCnNTRUPredefinedParams = packed record
    N: Int64;
    D: Int64;
    P: Int64;
    QExp: Int64;
  end;

const
  NTRU_PRE_DEFINED_PARAMS: array[TCnNTRUParamType] of TCnNTRUPredefinedParams = (
    (N: 11; D: 3; P: 3; QExp: 2),
    (N: 251; D: 72; P: 3; QExp: 8),
    (N: 509; D: 127; P: 3; QExp: 11),  // D �ڲ��� 2^QExp div 16 - 1
    (N: 677; D: 127; P: 3; QExp: 11),  // D �ڲ��� 2^QExp div 16 - 1
    (N: 821; D: 255; P: 3; QExp: 12)   // D �ڲ��� 2^QExp div 16 - 1
    // (N: 702; D: 0; P: 3; QExp: 13)
  );

var
  FBigNumberPool: TCnBigNumberPool = nil;
  FInt64PolynomialPool: TCnInt64PolynomialPool = nil;
  FBigNumberVectorPool: TCnBigNumberVectorPool = nil;

function Int64GaussianLatticeReduction(V1: TCnInt64Vector; V2: TCnInt64Vector;
  X: TCnInt64Vector; Y: TCnInt64Vector): Boolean;
var
  U1, U2, T: TCnInt64Vector;
  M: Int64;
  K: Extended;
begin
  U1 := nil;
  U2 := nil;
  T := nil;

  try
    U1 := TCnInt64Vector.Create;
    U2 := TCnInt64Vector.Create;
    T := TCnInt64Vector.Create;

    Int64VectorCopy(U1, X);
    Int64VectorCopy(U2, Y);

    if Int64VectorModule(U1) > Int64VectorModule(U2) then
      Int64VectorSwap(U1, U2);

    while True do
    begin
      K := Int64VectorDotProduct(U2, U1) / Int64VectorDotProduct(U1, U1);
      M := Round(K);  // K ���ܱ�ȡ����� M ��

      Int64VectorMul(T, U1, M);
      Int64VectorSub(U2, U2, T);
//      if M > K then   // �����ø��ƺ����岻���Ҹ��汾��һ
//        Int64VectorNegate(U2, U2);

      if Int64VectorModule(U1) <= Int64VectorModule(U2) then
      begin
        Int64VectorCopy(V1, U1);
        Int64VectorCopy(V2, U2);
        Result := True;
        Exit;
      end
      else
        Int64VectorSwap(U1, U2);
    end;
  finally
    T.Free;
    U2.Free;
    U1.Free;
  end;
end;

function BigNumberGaussianLatticeReduction(V1: TCnBigNumberVector; V2: TCnBigNumberVector;
  X: TCnBigNumberVector; Y: TCnBigNumberVector): Boolean;
var
  U1, U2, T: TCnBigNumberVector;
  M, M1, M2: TCnBigNumber;
  Ru: Boolean;
begin
  U1 := nil;
  U2 := nil;
  T := nil;
  M := nil;
  M1 := nil;
  M2 := nil;

  try
    U1 := FBigNumberVectorPool.Obtain;
    U2 := FBigNumberVectorPool.Obtain;
    T := FBigNumberVectorPool.Obtain;
    M := FBigNumberPool.Obtain;
    M1 := FBigNumberPool.Obtain;
    M2 := FBigNumberPool.Obtain;

    // ȷ�� |X| <= |Y|
    BigNumberVectorCopy(U1, X);
    BigNumberVectorCopy(U2, Y);

    BigNumberVectorModuleSquare(M1, U1);
    BigNumberVectorModuleSquare(M2, U2);
    if BigNumberCompare(M1, M2) > 0 then
      BigNumberVectorSwap(U1, U2);

    // U1 := X;  U2 := Y;
    while True do
    begin
      BigNumberVectorDotProduct(M2, U2, U1);
      BigNumberVectorDotProduct(M1, U1, U1);
      BigNumberRoundDiv(M, M2, M1, Ru); // Ru ���Ϊ True ��ʾ���� M ����ʵ�����

      BigNumberVectorMul(T, U1, M);
      BigNumberVectorSub(U2, U2, T);
//      if Ru then   // �����ø��ƺ����岻���Ҹ��汾��һ
//        BigNumberVectorNegate(U2, U2);

      BigNumberVectorModuleSquare(M1, U1);
      BigNumberVectorModuleSquare(M2, U2);
      if BigNumberCompare(M1, M2) <= 0 then
      begin
        BigNumberVectorCopy(V1, U1);
        BigNumberVectorCopy(V2, U2);
        Result := True;
        Exit;
      end
      else
        BigNumberVectorSwap(U1, U2);
    end;
  finally
    FBigNumberPool.Recycle(M2);
    FBigNumberPool.Recycle(M1);
    FBigNumberPool.Recycle(M);
    FBigNumberVectorPool.Recycle(T);
    FBigNumberVectorPool.Recycle(U2);
    FBigNumberVectorPool.Recycle(U1);
  end;
end;

procedure NTRUDataToInt64Polynomial(Res: TCnInt64Polynomial; Data: Pointer;
  ByteLength: Integer; N, Modulus: Int64; CheckSum: Boolean);
var
  I, Blk, C: Integer;
  Bld: TCnBitBuilder;
  B: Cardinal;
  Sum: Int64;
begin
  Blk := GetUInt64HighBits(Modulus);
  if (Res = nil) or (Blk < 0) or (N <= 1) then
    Exit;

  if Blk > 31 then // ������ Cardinal �ڵ�ģ��
    raise ECnLatticeException.CreateFmt(SCnErrorLatticeModulusTooMuch, [Modulus]);

  if CheckSum then
    C := N - 1  // �� N - 1 ������ N ��������У���
  else
    C := N;     // �� N ��

  // һ��Ҫ����Blk * C ��λ����������������ֽ���������ô��λ��ռ���ֽ��������׳��쳣
  if ByteLength > (Blk * C + 7) div 8 then
    raise ECnLatticeException.CreateFmt(SCnErrorLatticeDataTooLong, [ByteLength]);

  Bld := TCnBitBuilder.Create;
  try
    Bld.ReadFrom(Data, ByteLength); // ����������
    if Bld.BitLength < Blk * C then  // �������̫�̲��� Blk * C ��λ����Ҫ����
      Bld.BitLength := Blk * C;

    Res.MaxDegree := N - 1; // �� N - 1 ��ʱ N - 1 ����У��λ���� N ��ʱ��� N - 1 ��
    Sum := 0;
    for I := 0 to C - 1 do
    begin
      B := Bld.Copy(Blk * I, Blk);  // TODO: ����Ƿ�ҪС�ˣ�
      B := Int64NonNegativeMod(B, Modulus);
      Res[I] := B;
      Sum := Sum + B;
    end;

    if CheckSum then
      Res[N - 1] := -Int64NonNegativeMod(Sum, Modulus);
  finally
    Bld.Free;
  end;
end;

function NTRUInt64PolynomialToData(P: TCnInt64Polynomial; N, Modulus: Int64;
  Data: Pointer; CheckSum: Boolean): Integer;
var
  I, Blk, C: Integer;
  B: Cardinal;
  Bld: TCnBitBuilder;
begin
  Result := 0;
  Blk := GetUInt64HighBits(Modulus);
  if (P = nil) or (Blk < 0) or (N <= 1) then
    Exit;

  if Blk > 31 then // ������ Cardinal �ڵ�ģ��
    raise ECnLatticeException.CreateFmt(SCnErrorLatticeModulusTooMuch, [Modulus]);

  if CheckSum then
    C := N - 1
  else
    C := N;

  // ����ʽ��� C ����� 0 �� C - 1 �Σ������ĺ��ԣ�����Ļ��� Data �󲿲� 0
  Result := (C * Blk + 7) div 8;
  if Data = nil then
    Exit;

  FillChar(Data^, Result, 0);
  Bld := TCnBitBuilder.Create;
  try
    for I := 0 to C - 1 do
    begin
      B := Cardinal(Int64NonNegativeMod(P[I], Modulus));
      Bld.AppendDWordRange(B, Blk - 1); // 0 �� Blk - 1 �� Blk λ
    end;
    // CheckSum Ϊ True ʱ��ߵ� N - 1 �����Ǽ��������������

    Bld.WriteTo(Data);
  finally
    Bld.Free;
  end;
end;

{ TCnNTRUPublicKey }

constructor TCnNTRUPublicKey.Create;
begin
  inherited;
  FH := TCnInt64Polynomial.Create;
end;

destructor TCnNTRUPublicKey.Destroy;
begin
  FH.Free;
  inherited;
end;

procedure TCnNTRUPublicKey.SetFH(const Value: TCnInt64Polynomial);
begin
  Int64PolynomialCopy(FH, Value);
end;

function TCnNTRUPublicKey.ToString: string;
begin
  Result := H.ToString;
end;

{ TCnNTRUPrivateKey }

constructor TCnNTRUPrivateKey.Create;
begin
  inherited;
  FF := TCnInt64Polynomial.Create;
  FG := TCnInt64Polynomial.Create;
  FFP := TCnInt64Polynomial.Create;
  FFQ := TCnInt64Polynomial.Create;
end;

destructor TCnNTRUPrivateKey.Destroy;
begin
  FFQ.Free;
  FFP.Free;
  FG.Free;
  FF.Free;
  inherited;
end;

procedure TCnNTRUPrivateKey.SetFF(const Value: TCnInt64Polynomial);
begin
  Int64PolynomialCopy(FF, Value);
end;

procedure TCnNTRUPrivateKey.SetFFP(const Value: TCnInt64Polynomial);
begin
  Int64PolynomialCopy(FFP, Value);
end;

procedure TCnNTRUPrivateKey.SetFFQ(const Value: TCnInt64Polynomial);
begin
  Int64PolynomialCopy(FFQ, Value);
end;

procedure TCnNTRUPrivateKey.SetFG(const Value: TCnInt64Polynomial);
begin
  Int64PolynomialCopy(FG, Value);
end;

function TCnNTRUPrivateKey.ToString: string;
begin
  Result := FF.ToString + ',' + FG.ToString;
end;

{ TCnNTRU }

constructor TCnNTRU.Create(NTRUType: TCnNTRUParamType);
begin
  inherited Create;
  FRing := TCnInt64Polynomial.Create;
  Load(NTRUType);
end;

procedure TCnNTRU.Decrypt(PrivateKey: TCnNTRUPrivateKey; EnData,
  OutPlainData: TCnInt64Polynomial);
begin
  // �� Ring �ϼ��� F * ���� mod FQ �� mod Prime �ٳ��� Fp mod Prime
  Int64PolynomialGaloisMul(OutPlainData, PrivateKey.F, EnData, FQ, FRing);
  Int64PolynomialCentralize(OutPlainData, FQ);

  Int64PolynomialNonNegativeModWord(OutPlainData, FPrime);
  Int64PolynomialGaloisMul(OutPlainData, OutPlainData, PrivateKey.FP, FPrime, FRing);
  Int64PolynomialCentralize(OutPlainData, FPrime);
end;

function TCnNTRU.DecryptBytes(PrivateKey: TCnNTRUPrivateKey; EnData: TBytes): TBytes;
var
  En, De: TCnInt64Polynomial;
  L: Integer;
begin
  Result := nil;
  En := nil;
  De := nil;

  try
    En := FInt64PolynomialPool.Obtain;
    NTRUDataToInt64Polynomial(En, @EnData[0], Length(EnData), FN, FQ, False);
    // ��������ת����ʽ��ģ��Ҫ�ô�ģ�����Ҳ���Ҫ�������У��

    De := FInt64PolynomialPool.Obtain;
    Decrypt(PrivateKey, En, De);

    // ���Ķ���ʽת�������ݣ�ģ������С����
    L := NTRUInt64PolynomialToData(De, FN, FPrime, nil);
    if L > 0 then
    begin
      SetLength(Result, L);
      NTRUInt64PolynomialToData(De, FN, FPrime, @Result[0]);
    end;
  finally
    FInt64PolynomialPool.Recycle(De);
    FInt64PolynomialPool.Recycle(En);
  end;
end;

destructor TCnNTRU.Destroy;
begin
  FRing.Free;
  inherited;
end;

procedure TCnNTRU.Encrypt(PublicKey: TCnNTRUPublicKey; PlainData,
  OutEnData: TCnInt64Polynomial);
var
  R: TCnInt64Polynomial;
begin
  // �� Ring �ϼ������ R * H + PlainData mod FQ
  R := nil;

  try
    R := FInt64PolynomialPool.Obtain;
    RandPolynomial(R, FN - 1);

    Int64PolynomialGaloisMul(OutEnData, R, PublicKey.H, FQ, FRing);
    Int64PolynomialGaloisAdd(OutEnData, OutEnData, PlainData, FQ, FRing);
  finally
    FInt64PolynomialPool.Recycle(R);
  end;
end;

function TCnNTRU.EncryptBytes(PublicKey: TCnNTRUPublicKey; Data: TBytes): TBytes;
var
  Pl, En: TCnInt64Polynomial;
  L: Integer;
begin
  Result := nil;
  Pl := nil;
  En := nil;

  try
    Pl := FInt64PolynomialPool.Obtain;
    NTRUDataToInt64Polynomial(Pl, @Data[0], Length(Data), FN, FPrime);
    // ��������ת���Ķ���ʽ��ģ��Ҫ��С����

    En := FInt64PolynomialPool.Obtain;
    Encrypt(PublicKey, Pl, En);

    // ���Ķ���ʽת�������ݣ�ģ��Ҫ�ô�ģ���������λ����У��
    L := NTRUInt64PolynomialToData(En, FN, FQ, nil, False);
    if L > 0 then
    begin
      SetLength(Result, L);
      NTRUInt64PolynomialToData(En, FN, FQ, @Result[0], False);
    end;
  finally
    FInt64PolynomialPool.Recycle(En);
    FInt64PolynomialPool.Recycle(Pl);
  end;
end;

procedure TCnNTRU.GenerateKeys(PrivateKey: TCnNTRUPrivateKey;
  PublicKey: TCnNTRUPublicKey);
var
  HasInv: Boolean;
begin
  repeat
    // ������������ɶ���ʽ F�������棬ȷ��������
    //���ƺ� D �� 1��D �� -1 ʼ�����棬���� D + 1 �� 1��
    RandPolynomial(PrivateKey.F, FN - 1, D + 1, D);
    HasInv := True;
    try
      Int64PolynomialGaloisModularInverse(PrivateKey.FP, PrivateKey.F,
        FRing, FPrime, True);
    except
      HasInv := False;
    end;

    if HasInv then
    begin
      HasInv := Int64PolynomialGaloisPrimePowerModularInverse(PrivateKey.FQ,
        PrivateKey.F, FRing, 2, FQExponent);
      if HasInv then
        Break;
    end;
  until False;

  // ��������ɶ���ʽ G���� F һ����Ϊ˽Կ��ͬʱ FQ FP ��һ��һС��ģ�����ʽ��������������
  RandPolynomial(PrivateKey.G, FN - 1, D, D);

  // ����� H �����Ļ�����Ϊ��Կ
  Int64PolynomialGaloisMul(PublicKey.H, PrivateKey.FQ, PrivateKey.G, FQ, FRing);
  Int64PolynomialGaloisMulWord(PublicKey.H, FPrime, FQ);
  Int64PolynomialCentralize(PublicKey.H, FQ);
end;

procedure TCnNTRU.Load(Predefined: TCnNTRUParamType);
begin
  FN := NTRU_PRE_DEFINED_PARAMS[Predefined].N;
  FD := NTRU_PRE_DEFINED_PARAMS[Predefined].D;
  FPrime := NTRU_PRE_DEFINED_PARAMS[Predefined].P;
  FQExponent := NTRU_PRE_DEFINED_PARAMS[Predefined].QExp;

  FQ := Int64NonNegativPower(2, FQExponent);

  FRing.SetZero;
  FRing.MaxDegree := N;
  FRing[N] := 1;
  FRing[0] := -1;
end;

procedure TCnNTRU.RandPolynomial(P: TCnInt64Polynomial; MaxDegree,
  OneCount, MinusOneCount: Integer);
var
  F: array of Integer;
  I: Integer;
begin
  if (MaxDegree < 0) or (OneCount < 0) or (MinusOneCount < 0) or
    (OneCount + MinusOneCount >= MaxDegree) then
    raise ECnLatticeException.Create(SCnErrorLatticeNTRUInvalidParam);

  SetLength(F, MaxDegree + 1);
  for I := 0 to OneCount - 1 do
    F[I] := 1;
  for I := OneCount to OneCount + MinusOneCount - 1 do
    F[I] := -1;
  for I := OneCount + MinusOneCount to MaxDegree do
    F[I] := 0;

  // ϴ���㷨
  CnKnuthShuffle(@F[0], SizeOf(Integer), Length(F));

  P.MaxDegree := MaxDegree;
  for I := 0 to MaxDegree do
    P[I] := F[I];

  SetLength(F, 0);
end;

procedure TCnNTRU.RandPolynomial(P: TCnInt64Polynomial; MaxDegree: Integer);
var
  I: Integer;
begin
  if MaxDegree < 0 then
    raise ECnLatticeException.Create(SCnErrorLatticeNTRUInvalidParam);

  P.MaxDegree := MaxDegree;
  for I := 0 to MaxDegree do
    P[I] := RandomUInt32LessThan(3) - 1; // [0, 3) Ҳ���� 0 1 2 ����һ���� -1 0 1
end;

initialization
  FBigNumberPool := TCnBigNumberPool.Create;
  FInt64PolynomialPool := TCnInt64PolynomialPool.Create;
  FBigNumberVectorPool := TCnBigNumberVectorPool.Create;

finalization
  FBigNumberVectorPool.Free;
  FInt64PolynomialPool.Free;
  FBigNumberPool.Free;

end.
