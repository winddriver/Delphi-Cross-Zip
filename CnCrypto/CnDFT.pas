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

unit CnDFT;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ����ڸ��㸴������ɢ����Ҷ�任�Լ����� Int 64 �Ŀ������۱任ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���˻��ڸ��㸴������ɢ����Ҷ�任�Լ����� Int 64 �Ŀ������۱任
*           ʹ�ÿ��ٸ���Ҷ�任ʵ����ɢ����Ҷ�任�����Լ��ٶ���ʽ�˷������򸡵���ڻ���ʧ����
*           ʹ�ÿ������۱任��û������⡣���������۱任Ҳ�����ƣ�
*           һ�Ƕ���ʽϵ������Ϊ������С��ģ��������ϵ������֪����δ�����
*           ���Ƕ���ʽ��������С�� 2^23������Ԫģ�����ƣ���
*
* ����ƽ̨��Win 7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2022.06.29 V1.2
*               ����һ��ά��ɢ���ұ任������任
*           2021.08.29 V1.1
*               ���ӿ������۱任��ʹ���ض�����
*           2020.11.23 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative, CnComplex, CnMatrix;

procedure ButterflyChangeComplex(CA: PCnComplexArray; Len: Integer);
{* �����任���������������ڲ�Ԫ�ص�˳���Ա���ż���Ρ�

   ������
     CA: PCnComplexArray                  - ָ������к����任�ĸ�������
     Len: Integer                         - ������ĸ�������

   ����ֵ�����ޣ�
}

procedure ButterflyChangeInt64(IA: PInt64Array; Len: Integer);
{* �����任������ Int64 �����ڲ�Ԫ�ص�˳���Ա���ż���Ρ�

   ������
     IA: PInt64Array                      - ָ������к����任�� Int64 ����
     Len: Integer                         - ������� Int64 ����

   ����ֵ�����ޣ�
}

function CnFFT(Data: PCnComplexArray; Len: Integer): Boolean;
{* ���ٸ���Ҷ�任��������ʽ��ϵ����������ת��Ϊ��ֵ�����������飬Ҫȷ�� Len Ϊ 2 ���������ݡ�

   ������
     Data: PCnComplexArray                - ָ������п��ٸ���Ҷ�任�ĸ�������
     Len: Integer                         - ������ĸ��������������� 2 ����������

   ����ֵ��Boolean                        - ���ر任�Ƿ�ɹ�
}

function CnIFFT(Data: PCnComplexArray; Len: Integer): Boolean;
{* ���ٸ���Ҷ��任������ֵ������������ת��Ϊ����ʽ��ϵ���������飬Ҫȷ�� Len Ϊ 2 ���������ݡ�

   ������
     Data: PCnComplexArray                - ָ������п��ٸ���Ҷ��任�ĸ�������
     Len: Integer                         - ������ĸ��������������� 2 ����������

   ����ֵ��Boolean                        - ������任�Ƿ�ɹ�
}

function CnNTT(Data: PInt64Array; Len: Integer): Boolean;
{* �������۱任��������ʽ��ϵ�� int 64 ����ת��Ϊ��ֵ���� int64 ���飬
   ע��Ҫȷ�� Len Ϊ 2 ���������ݣ����� Data ��ϵ��������� 0 ��С�� CN_P��

   ������
     Data: PInt64Array                    - ָ������п������۱任�� Int64 ����
     Len: Integer                         - ������� Int64 �������������� 2 ����������

   ����ֵ��Boolean                        - ���ر任�Ƿ�ɹ�
}

function CnINTT(Data: PInt64Array; Len: Integer): Boolean;
{* ����������任������ֵ���� int 64 ����ת��Ϊ����ʽ��ϵ�� int 64 ���飬
   ע��Ҫȷ�� Len Ϊ 2 ���������ݣ����� Data ��ϵ��������� 0 ��С�� CN_P��

   ������
     Data: PInt64Array                    - ָ������п���������任�� Int64 ����
     Len: Integer                         - ������� Int64 �������������� 2 ����������

   ����ֵ��Boolean                        - ������任�Ƿ�ɹ�
}

function CnDCT(Data: PExtendedArray; Res: PExtendedArray; Len: Integer): Boolean;
{* һά DCT �任����ɢ���ң����� Data ��ָ�ĸ���������һ��һά��ɢ���ұ任��
   ������� Res ��ָ�ĸ��������У�Ҫ�����鳤�Ⱦ�Ϊ Len�����ر任�Ƿ�ɹ���

   ������
     Data: PExtendedArray                 - ָ�������һά DCT �任�ĸ�������
     Res: PExtendedArray                  - ָ��任����ĸ�������
     Len: Integer                         - ������ĸ���������

   ����ֵ��Boolean                        - ���ر任�Ƿ�ɹ�
}

function CnIDCT(Data: PExtendedArray; Res: PExtendedArray; Len: Integer): Boolean;
{* һά�� DCT �任����ɢ���ң����� Data ��ָ�ĸ���������һ��һά����ɢ���ұ任��
   ������� Res ��ָ�ĸ��������У�Ҫ�����鳤�Ⱦ�Ϊ Len��������任�Ƿ�ɹ���

   ������
     Data: PExtendedArray                 - ָ�������һά�� DCT �任�ĸ�������
     Res: PExtendedArray                  - ָ����任����ĸ�������
     Len: Integer                         - ������ĸ���������

   ����ֵ��Boolean                        - ������任�Ƿ�ɹ�
}

function CnGenerateDCT2Matrix(M: TCnFloatMatrix; N: Integer): Boolean;
{* ���� N �׶�ά DCT �任���󣬸þ���Ϊ����

   ������
     M: TCnFloatMatrix                    - �����ɵĶ�ά DCT �任����
     N: Integer                           - ����Ľ�

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnDCT2(Data: TCnFloatMatrix; Res: TCnFloatMatrix; DCTM: TCnFloatMatrix = nil;
  DCTMT: TCnFloatMatrix = nil; T: TCnFloatMatrix = nil): Boolean;
{* ��ά DCT �任����ɢ���ң����� Data ������ĸ��������һ�ζ�ά��ɢ���ұ任��
   ������� Res ������ĸ�������У�Ҫ��������Ϊ�����ҳߴ���ȣ�
   DCTM/DCTMT ����ΪԤ����ı任��������ת�þ���T Ϊ��ʱ������󣬷��ر任�Ƿ�ɹ���

   ������
     Data: TCnFloatMatrix                 - �����ж�ά DCT �任�ĸ������
     Res: TCnFloatMatrix                  - �������
     DCTM: TCnFloatMatrix                 - Ԥ����ı任����
     DCTMT: TCnFloatMatrix                - Ԥ����ı任�����ת�þ���
     T: TCnFloatMatrix                    - ��ʱ�������

   ����ֵ��Boolean                        - ���ر任�Ƿ�ɹ�
}

function CnIDCT2(Data: TCnFloatMatrix; Res: TCnFloatMatrix; DCTM: TCnFloatMatrix = nil;
  DCTMT: TCnFloatMatrix = nil; T: TCnFloatMatrix = nil): Boolean;
{* ��ά�� DCT �任����ɢ���ң����� Data ������ĸ��������һ�ζ�ά����ɢ���ұ任��
   ������� Res ������ĸ�������У�Ҫ��������Ϊ�����ҳߴ���ȣ�
   DCTM/DCTMT ����ΪԤ����ı任��������ת�þ���T Ϊ��ʱ������󣬷�����任�Ƿ�ɹ���

   ������
     Data: TCnFloatMatrix                 - �����ж�ά�� DCT �任�ĸ������
     Res: TCnFloatMatrix                  - �������
     DCTM: TCnFloatMatrix                 - Ԥ����ı任����
     DCTMT: TCnFloatMatrix                - Ԥ����ı任�����ת�þ���
     T: TCnFloatMatrix                    - ��ʱ�������

   ����ֵ��Boolean                        - ������任�Ƿ�ɹ�
}

implementation

uses
  CnPrime;

const
  Pi = 3.1415926535897932384626;

  CN_NR = 1 shl 22;     // 2 �� 23 �η���һ�룬���ֻ�ܴ������Ϊ CN_NR �Ķ���ʽ
  CN_G = 3;             // ����������ԭ���� 3
  CN_G_INV = 332748118; // ��ԭ���Ը���������ԪΪ 332748118
  CN_P = 998244353;     // ѡȡ����Ϊ 998244353 = 2^23*119 + 1��С�� Int32 �����ֵ 2147483647

// �����任�����������ڲ�Ԫ�ص�˳��Ҫȷ�� Len Ϊ 2 ����������
procedure ButterflyChangeComplex(CA: PCnComplexArray; Len: Integer);
var
  I: Integer;
  R: array of Integer;
begin
  if Len <= 1 then
    Exit;

  SetLength(R, Len);
  for I := 0 to Len - 1 do
  begin
    R[I] := R[I shr 1] shr 1;
    if (I and 1) <> 0 then
      R[I] := R[I] or (Len shr 1);
  end;

  for I := 0 to Len - 1 do
  begin
    if I < R[I] then
      ComplexNumberSwap(CA^[I], CA^[R[I]]);
  end;
  SetLength(R, 0);
end;

// �����任�����������ڲ�Ԫ�ص�˳��Ҫȷ�� Len Ϊ 2 ����������
procedure ButterflyChangeInt64(IA: PInt64Array; Len: Integer);
var
  I: Integer;
  R: array of Integer;
  T: Int64;
begin
  if Len <= 1 then
    Exit;

  SetLength(R, Len);
  for I := 0 to Len - 1 do
  begin
    R[I] := R[I shr 1] shr 1;
    if (I and 1) <> 0 then
      R[I] := R[I] or (Len shr 1);
  end;

  for I := 0 to Len - 1 do
  begin
    if I < R[I] then
    begin
      T := IA^[I];
      IA^[I] := IA^[R[I]];
      IA^[R[I]] := T;
    end;
  end;
  SetLength(R, 0);
end;

// �����ǵݹ鷽ʽʵ�ֵĿ��ٸ���Ҷ�任������任
function FFT(Data: PCnComplexArray; Len: Integer; IsReverse: Boolean): Boolean;
var
  J, T, M, R, K: Integer;
  WN, W, X, Y: TCnComplexNumber;
begin
  Result := False;
  if (Data = nil) or (Len <= 0) then
    Exit;

  // Len ���� 2 ����������
  if not IsUInt32PowerOf2(Cardinal(Len)) then
    Exit;

  if IsReverse then
    T := -1
  else
    T := 1;

  ButterflyChangeComplex(Data, Len);

  M := 1;
  while M < Len do
  begin
    WN.R := Cos(Pi / M);
    WN.I := Sin(Pi / M) * T;

    J := 0;
    R := M shl 1;
    while J < Len do
    begin
      W.R := 1.0;
      W.I := 0;

      K := 0;
      while K < M do
      begin
        ComplexNumberCopy(X, Data^[J + K]);
        ComplexNumberMul(Y, Data^[J + K + M], W);

        ComplexNumberAdd(Data^[J + K], X, Y);
        ComplexNumberSub(Data^[J + K + M], X, Y);

        ComplexNumberMul(W, W, WN);
        Inc(K);
      end;

      J := J + R;
    end;

    M := M shl 1;
  end;

  if IsReverse then
    for J := 0 to Len - 1 do
      ComplexNumberDiv(Data^[J], Data^[J], Len);

  Result := True;
end;

function CnFFT(Data: PCnComplexArray; Len: Integer): Boolean;
begin
  Result := FFT(Data, Len, False);
end;

function CnIFFT(Data: PCnComplexArray; Len: Integer): Boolean;
begin
  Result := FFT(Data, Len, True);
end;

// �����ǵݹ鷽ʽʵ�ֵĿ������۱任������任
function NTT(Data: PInt64Array; Len: Integer; IsReverse: Boolean): Boolean;
var
  M, K, J, R: Integer;
  G0, GN, X, Y: Int64;
begin
  Result := False;
  if (Data = nil) or (Len <= 0) or (Len > CN_NR) then
    Exit;

  // Len ���� 2 ����������
  if not IsUInt32PowerOf2(Cardinal(Len)) then
    Exit;

  ButterflyChangeInt64(Data, Len);

  M := 1;
  while M < Len do
  begin
    // MontgomeryPowerMod ��Ѹ��� Int64 ��Ϊ�����޷��� UInt64���������ϵ����Ϊ��������ʹ��
    if IsReverse then
      GN := MontgomeryPowerMod(CN_G_INV, (CN_P - 1) div (M shl 1), CN_P)
    else
      GN := MontgomeryPowerMod(CN_G, (CN_P - 1) div (M shl 1) , CN_P);

    J := 0;
    R := M shl 1;
    while J < Len do
    begin
      G0 := 1;
      K := 0;

      while K < M do
      begin
        X := Data^[J + K];
        Y := Int64MultipleMod(G0, Data^[J + K + M], CN_P);
        Data^[J + K] := Int64AddMod(X, Y, CN_P);

        X := X - Y;
        if X < 0 then
          X := X + CN_P; // X - Y �����Ǹ����������� AddMod
        Data^[J + K + M] := X mod CN_P;

        G0 := Int64MultipleMod(G0, GN, CN_P);
        Inc(K);
      end;

      J := J + R;
    end;

    M := M shl 1;
  end;

  if IsReverse then
    for J := 0 to Len - 1 do
      Data^[J] := Data^[J] div Len;

  Result := True;
end;

function CnNTT(Data: PInt64Array; Len: Integer): Boolean;
begin
  Result := NTT(Data, Len, False);
end;

function CnINTT(Data: PInt64Array; Len: Integer): Boolean;
begin
  Result := NTT(Data, Len, True);
end;

function CnDCT(Data, Res: PExtendedArray; Len: Integer): Boolean;
var
  X, U: Integer;
  C: Extended;
begin
  Result := False;
  if (Len <= 0) or (Data = nil) or (Res = nil) then
    Exit;

  Res^[0] := 0;
  for X := 0 to Len - 1 do
    Res^[0] := Res^[0] + Data^[X];

  Res^[0] := Res^[0] / Sqrt(Len); // ������� F0

  for U := 1 to Len - 1 do
  begin
    // �� FU
    Res^[U] := 0;
    for X := 0 to Len - 1 do
    begin
      C := Cos(Pi * U * (2 * X + 1) / (2 * Len));
      Res^[U] := Res^[U] + Data^[X] * C;
    end;
    Res^[U] := Res^[U] * Sqrt(2.0 / Len);
  end;
  Result := True;
end;

function CnIDCT(Data, Res: PExtendedArray; Len: Integer): Boolean;
var
  X, U: Integer;
  A1, A2, C: Extended;
begin
  Result := False;
  if (Len <= 0) or (Data = nil) or (Res = nil) then
    Exit;

  A1 := 1.0 / Sqrt(Len);
  A2 := Sqrt(2.0 / Len);

  for X := 0 to Len - 1 do
  begin
    // �� fx
    Res^[X] := 0;
    for U := 0 to Len - 1 do
    begin
      C := Cos(Pi * U * (2 * X + 1) / (2 * Len));
      if U = 0 then
        Res^[X] := Res^[X] + Data^[U] * C * A1
      else
        Res^[X] := Res^[X] + Data^[U] * C * A2;
    end;
  end;
  Result := True;
end;

function CnGenerateDCT2Matrix(M: TCnFloatMatrix; N: Integer): Boolean;
var
  I, J: Integer;
  A1, A2: Extended;
begin
  Result := False;
  if (M = nil) or (N < 2) then
    Exit;

  M.RowCount := N;
  M.ColCount := N;

  A1 := 1.0 / Sqrt(N);
  A2 := Sqrt(2.0 / N);

  for I := 0 to M.RowCount - 1 do
  begin
    for J := 0 to M.ColCount - 1 do
    begin
      M.Value[I, J] := Cos(I * (J + 0.5) * Pi / N);

      if I = 0 then
        M.Value[I, J] := M.Value[I, J] * A1
      else
        M.Value[I, J] := M.Value[I, J] * A2;
    end;
  end;
  Result := True;
end;

function CnDCT2(Data, Res: TCnFloatMatrix; DCTM: TCnFloatMatrix;
  DCTMT: TCnFloatMatrix; T: TCnFloatMatrix): Boolean;
var
  MIsNil, MTIsNil, TIsNil: Boolean;
begin
  // Res := M * Data * M'
  Result := False;
  if (Data = nil) or (Res = nil) then
    Exit;

  if Data.RowCount <> Data.ColCount then
    Exit;

  MIsNil := DCTM = nil;
  MTIsNil := DCTMT = nil;
  TIsNil := T = nil;

  try
    if MIsNil then
    begin
      DCTM := TCnFloatMatrix.Create;
      CnGenerateDCT2Matrix(DCTM, Data.RowCount);
    end;

    if MTIsNil then
    begin
      DCTMT := TCnFloatMatrix.Create;
      CnMatrixTranspose(DCTM, DCTMT);
    end;

    if TIsNil then
      T := TCnFloatMatrix.Create;

    CnMatrixMul(DCTM, Data, T);
    CnMatrixMul(T, DCTMT, Res);

    Result := True;
  finally
    if TIsNil then
      T.Free;
    if MIsNil then
      DCTM.Free;
    if MTIsNil then
      DCTMT.Free;
  end;
end;

function CnIDCT2(Data, Res: TCnFloatMatrix; DCTM: TCnFloatMatrix;
  DCTMT: TCnFloatMatrix; T: TCnFloatMatrix): Boolean;
var
  MIsNil, MTIsNil, TIsNil: Boolean;
begin
  // Res := M' * Data * M
  Result := False;
  if (Data = nil) or (Res = nil) then
    Exit;

  if Data.RowCount <> Data.ColCount then
    Exit;

  MIsNil := DCTM = nil;
  MTIsNil := DCTMT = nil;
  TIsNil := T = nil;

  try
    if MIsNil then
    begin
      DCTM := TCnFloatMatrix.Create;
      CnGenerateDCT2Matrix(DCTM, Data.RowCount);
    end;

    if MTIsNil then
    begin
      DCTMT := TCnFloatMatrix.Create;
      CnMatrixTranspose(DCTM, DCTMT);
    end;

    if TIsNil then
      T := TCnFloatMatrix.Create;

    CnMatrixMul(DCTMT, Data, T);
    CnMatrixMul(T, DCTM, Res);

    Result := True;
  finally
    if TIsNil then
      T.Free;
    if MIsNil then
      DCTM.Free;
    if MTIsNil then
      DCTMT.Free;
  end;
end;

end.
