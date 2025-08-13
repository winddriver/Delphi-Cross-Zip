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

unit CnVector;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ��������㵥Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���� Int64 ����������Χ�ڵ�������ؼ��㡣
*           Լ���±� 0 ���������б��ʽ����߻��б��ʽ�������ά�ȵ����ݡ�
*           ���⣬û���������Ҳ���������ʵ�֣���Ϊ�������ά��������ά�ƹ�����ѡ�
* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2023.08.22 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative, CnContainers, CnBigNumber;

type
  ECnVectorException = class(Exception);
  {* ������ص��쳣}

  TCnInt64Vector = class(TCnInt64List)
  {* Int64 �����������±�ֵ��Ϊ��Ӧά��ֵ}
  private
    function GetDimension: Integer;
    procedure SetDimension(const Value: Integer);
  public
    constructor Create(ADimension: Integer = 1); virtual;
    {* ���캯��������������ά�ȡ�

       ������
         ADimension: Integer              - ����ά��

       ����ֵ��TCnInt64Vector             - ���ش����Ķ���
    }

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* �� Int64 ����ת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - ���������ַ���
    }

    property Dimension: Integer read GetDimension write SetDimension;
    {* ����ά��}
  end;

  TCnBigNumberVector = class(TCnBigNumberList)
  {* �������������±�ֵ��Ϊ��Ӧά��ֵ}
  private
    function GetDimension: Integer;
    procedure SetDimension(const Value: Integer);
  public
    constructor Create(ADimension: Integer = 1); virtual;
    {* ���캯��������������ά�ȡ�

       ������
         ADimension: Integer              - ����ά��

       ����ֵ��TCnBigNumberVector         - ���ش����Ķ���
    }

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������������ת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - ���������ַ���
    }

    property Dimension: Integer read GetDimension write SetDimension;
    {* ����ά�ȣ����ú��ڲ����Զ�������������}
  end;

  TCnBigNumberVectorPool = class(TCnMathObjectPool)
  {* ������������ʵ���࣬����ʹ�õ������������ĵط����д���������������}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnBigNumberVector; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnBigNumberVector         - ���س��еĴ�������������
    }

    procedure Recycle(Num: TCnBigNumberVector); reintroduce;
    {* ��һ������黹������ء�

       ������
         Num: TCnBigNumberVector          - ���黹�����еĶ���

       ����ֵ�����ޣ�
    }
  end;

// ======================== Int64 �����������㺯�� =============================

function Int64VectorToString(V: TCnInt64Vector): string;
{* �� Int64 ����ת��Ϊ�ַ�����ʽ�������

   ������
     V: TCnInt64Vector                    - ��ת��������

   ����ֵ��string                         - �����������ַ�����ʽ
}

function Int64VectorModule(V: TCnInt64Vector): Extended;
{* ���� Int64 �������ȣ�ģ������Ҳ������ƽ���͵�ƽ������

   ������
     V: TCnInt64Vector                    - �����������

   ����ֵ��Extended                       - ����������ģ��
}

function Int64VectorModuleSquare(V: TCnInt64Vector): Int64;
{* ���� Int64 �������ȣ�ģ������ƽ����Ҳ������ƽ���ĺ͡�

   ������
     V: TCnInt64Vector                    - �����������

   ����ֵ��Int64                          - ����������ģ����ƽ��
}

procedure Int64VectorCopy(Dst: TCnInt64Vector; Src: TCnInt64Vector);
{* ���� Int64 ���������ݡ�

   ������
     Dst: TCnInt64Vector                  - Ŀ������
     Src: TCnInt64Vector                  - Դ����

   ����ֵ�����ޣ�
}

procedure Int64VectorSwap(A: TCnInt64Vector; B: TCnInt64Vector);
{* ������ Int64 ���������ݣ�Ҫ����������ͬά��

   ������
     A: TCnInt64Vector                    - ������������һ
     B: TCnInt64Vector                    - ��������������

   ����ֵ�����ޣ�
}

function Int64VectorEqual(A: TCnInt64Vector; B: TCnInt64Vector): Boolean;
{* �ж��� Int64 �����Ƿ���ȡ�

   ������
     A: TCnInt64Vector                    - ���Ƚϵ�����һ
     B: TCnInt64Vector                    - ���Ƚϵ�������

   ����ֵ��Boolean                        - �������������Ƿ����
}

procedure Int64VectorNegate(Res: TCnInt64Vector; A: TCnInt64Vector);
{* �� Int64 �����ķ�������Res �� A ������ͬһ������

   ������
     Res: TCnInt64Vector                  - ���������
     A: TCnInt64Vector                    - ԭ����

   ����ֵ�����ޣ�
}

procedure Int64VectorAdd(Res: TCnInt64Vector; A: TCnInt64Vector; B: TCnInt64Vector);
{* �� Int64 �����ļӷ������������ظ�ά�ȶ�Ӧ�͡�Res �� A��B ������ͬһ������

   ������
     Res: TCnInt64Vector                  - ������
     A: TCnInt64Vector                    - ��������һ
     B: TCnInt64Vector                    - ����������

   ����ֵ�����ޣ�
}

procedure Int64VectorSub(Res: TCnInt64Vector; A: TCnInt64Vector; B: TCnInt64Vector);
{* �� Int64 �����ļ��������������ظ�ά�ȶ�Ӧ�Res �� A��B ������ͬһ������

   ������
     Res: TCnInt64Vector                  - ������
     A: TCnInt64Vector                    - ����������
     B: TCnInt64Vector                    - ��������

   ����ֵ�����ޣ�
}

procedure Int64VectorMul(Res: TCnInt64Vector; A: TCnInt64Vector; N: Int64);
{* Int64 ���������ı����˷���Ҳ��ÿ��ά�ȳ��Ը�����Res �� A ������ͬһ������

   ������
     Res: TCnInt64Vector                  - ���������ı����˽��
     A: TCnInt64Vector                    - �������˵�����
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

function Int64VectorDotProduct(A: TCnInt64Vector; B: TCnInt64Vector): Int64;
{* �� Int64 �����ı����˷�Ҳ���ǵ�˻��߽��ڻ������ظ�ά�ȶ�Ӧ�˻�֮�͡�A �� B ������ͬһ������

   ������
     A: TCnInt64Vector                    - �������һ
     B: TCnInt64Vector                    - ���������

   ����ֵ��Int64                          - ���ص�˽��
}

// ========================= �������������㺯�� ================================

function BigNumberVectorToString(V: TCnBigNumberVector): string;
{* ������������ת��Ϊ�ַ�����ʽ�������

   ������
     V: TCnBigNumberVector                - ��ת��������

   ����ֵ��string                         - �����������ַ�����ʽ
}

procedure BigNumberVectorModule(Res: TCnBigNumber; V: TCnBigNumberVector);
{* ���ش������������ȣ�ģ������Ҳ������ƽ���͵�ƽ����������ȡ����

   ������
     Res: TCnBigNumber                    - �����������
     V: TCnBigNumberVector                - ������ģ��������ȡ��

   ����ֵ�����ޣ�
}

procedure BigNumberVectorModuleSquare(Res: TCnBigNumber; V: TCnBigNumberVector);
{* ���ش������������ȣ�ģ������ƽ����Ҳ������ƽ���ĺ͡�

   ������
     Res: TCnBigNumber                    - �����������
     V: TCnBigNumberVector                - ������ģ����ƽ��������ȡ��

   ����ֵ�����ޣ�
}

procedure BigNumberVectorCopy(Dst: TCnBigNumberVector; Src: TCnBigNumberVector);
{* ���ƴ��������������ݡ�

   ������
     Dst: TCnBigNumberVector              - Ŀ������
     Src: TCnBigNumberVector              - Դ����

   ����ֵ�����ޣ�
}

procedure BigNumberVectorSwap(A: TCnBigNumberVector; B: TCnBigNumberVector);
{* ���������������������ݡ�

   ������
     A: TCnBigNumberVector                - ������������һ
     B: TCnBigNumberVector                - ��������������

   ����ֵ�����ޣ�
}

function BigNumberVectorEqual(A: TCnBigNumberVector; B: TCnBigNumberVector): Boolean;
{* �ж��������������Ƿ���ȡ�

   ������
     A: TCnBigNumberVector                - ���Ƚϵ�����һ
     B: TCnBigNumberVector                - ���Ƚϵ�������

   ����ֵ��Boolean                        - �������������Ƿ����
}

procedure BigNumberVectorNegate(Res: TCnBigNumberVector; A: TCnBigNumberVector);
{* ������������ķ�������Res �� A ������ͬһ������

   ������
     Res: TCnBigNumberVector              - ���������
     A: TCnBigNumberVector                - ԭ����

   ����ֵ�����ޣ�
}

procedure BigNumberVectorAdd(Res: TCnBigNumberVector; A: TCnBigNumberVector; B: TCnBigNumberVector);
{* �������������ļӷ������������ظ�ά�ȶ�Ӧ�͡�Res �� A��B ������ͬһ������

   ������
     Res: TCnBigNumberVector              - ������
     A: TCnBigNumberVector                - ��������һ
     B: TCnBigNumberVector                - ����������

   ����ֵ�����ޣ�
}

procedure BigNumberVectorSub(Res: TCnBigNumberVector; A: TCnBigNumberVector; B: TCnBigNumberVector);
{* �������������ļ��������������ظ�ά�ȶ�Ӧ�Res �� A��B ������ͬһ������

   ������
     Res: TCnBigNumberVector              - ������
     A: TCnBigNumberVector                - ����������
     B: TCnBigNumberVector                - ��������

   ����ֵ�����ޣ�
}

procedure BigNumberVectorMul(Res: TCnBigNumberVector; A: TCnBigNumberVector; N: TCnBigNumber);
{* ���������������ı����˷���Ҳ��ÿ��ά�ȳ��Ը�����Res �� A ������ͬһ������

   ������
     Res: TCnBigNumberVector              - ���������ı����˽��
     A: TCnBigNumberVector                - �������˵�����
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberVectorDotProduct(Res: TCnBigNumber; A: TCnBigNumberVector; B: TCnBigNumberVector);
{* �������������ı����˷�Ҳ���ǵ�ˣ����ظ�ά�ȶ�Ӧ�˻�֮�͡�A �� B ������ͬһ������

   ������
     Res: TCnBigNumber                    - ��˽��
     A: TCnBigNumberVector                - �������һ
     B: TCnBigNumberVector                - ���������

   ����ֵ�����ޣ�
}

implementation

resourcestring
  SCnErrorVectorDimensionInvalid = 'Invalid Dimension!';
  SCnErrorVectorDimensionNotEqual = 'Error Dimension NOT Equal!';

var
  FBigNumberPool: TCnBigNumberPool = nil;

procedure CheckInt64VectorDimensionEqual(A, B: TCnInt64Vector);
begin
  if A.Dimension <> B.Dimension then
    raise ECnVectorException.Create(SCnErrorVectorDimensionNotEqual);
end;

function Int64VectorToString(V: TCnInt64Vector): string;
var
  I: Integer;
begin
  Result := '(';
  for I := 0 to V.Dimension - 1 do
  begin
    if I = 0 then
      Result := Result + IntToStr(V[I])
    else
      Result := Result + ', ' + IntToStr(V[I]);
  end;
  Result := Result + ')';
end;

function Int64VectorModule(V: TCnInt64Vector): Extended;
var
  T: Extended;
begin
  T := Int64VectorModuleSquare(V);
  Result := Sqrt(T);
end;

function Int64VectorModuleSquare(V: TCnInt64Vector): Int64;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to V.Dimension - 1 do
    Result := Result + V[I] * V[I];
end;

procedure Int64VectorCopy(Dst: TCnInt64Vector; Src: TCnInt64Vector);
var
  I: Integer;
begin
  if Src <> Dst then
  begin
    Dst.Dimension := Src.Dimension;
    for I := 0 to Src.Dimension - 1 do
      Dst[I] := Src[I];
  end;
end;

procedure Int64VectorSwap(A: TCnInt64Vector; B: TCnInt64Vector);
var
  I: Integer;
  T: Int64;
begin
  if A <> B then
  begin
    CheckInt64VectorDimensionEqual(A, B);

    for I := 0 to A.Dimension - 1 do
    begin
      T := A[I];
      A[I] := B[I];
      B[I] := T;
    end;
  end;
end;

function Int64VectorEqual(A: TCnInt64Vector; B: TCnInt64Vector): Boolean;
var
  I: Integer;
begin
  Result := A.Dimension = B.Dimension;
  if Result then
  begin
    for I := 0 to A.Dimension - 1 do
    begin
      if A[I] <> B[I] then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

procedure Int64VectorNegate(Res: TCnInt64Vector; A: TCnInt64Vector);
var
  I: Integer;
begin
  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    Res[I] := -A[I];
end;

procedure Int64VectorAdd(Res: TCnInt64Vector; A: TCnInt64Vector; B: TCnInt64Vector);
var
  I: Integer;
begin
  CheckInt64VectorDimensionEqual(A, B);

  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    Res[I] := A[I] + B[I];
end;

procedure Int64VectorSub(Res: TCnInt64Vector; A: TCnInt64Vector; B: TCnInt64Vector);
var
  I: Integer;
begin
  CheckInt64VectorDimensionEqual(A, B);

  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    Res[I] := A[I] - B[I];
end;

procedure Int64VectorMul(Res: TCnInt64Vector; A: TCnInt64Vector; N: Int64);
var
  I: Integer;
begin
  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    Res[I] := A[I] * N;
end;

function Int64VectorDotProduct(A: TCnInt64Vector; B: TCnInt64Vector): Int64;
var
  I: Integer;
begin
  CheckInt64VectorDimensionEqual(A, B);

  Result := 0;
  for I := 0 to A.Dimension - 1 do
    Result := Result + A[I] * B[I];
end;

{ TCnInt64Vector }

constructor TCnInt64Vector.Create(ADimension: Integer);
begin
  inherited Create;
  SetDimension(ADimension);
end;

function TCnInt64Vector.GetDimension: Integer;
begin
  Result := Count;
end;

procedure TCnInt64Vector.SetDimension(const Value: Integer);
begin
  if Value <= 0 then
    raise ECnVectorException.Create(SCnErrorVectorDimensionInvalid);

  SetCount(Value);
end;

function TCnInt64Vector.ToString: string;
begin
  Result := Int64VectorToString(Self);
end;

{ TCnBigNumberVector }

constructor TCnBigNumberVector.Create(ADimension: Integer);
begin
  inherited Create;
  SetDimension(ADimension);
end;

function TCnBigNumberVector.GetDimension: Integer;
begin
  Result := Count;
end;

procedure TCnBigNumberVector.SetDimension(const Value: Integer);
var
  I, OC: Integer;
begin
  if Value <= 0 then
    raise ECnVectorException.Create(SCnErrorVectorDimensionInvalid);

  OC := Count;
  Count := Value; // ֱ������ Count�����С�����Զ��ͷŶ���Ķ���

  if Count > OC then  // ���ӵĲ��ִ����¶���
  begin
    for I := OC to Count - 1 do
      Items[I] := TCnBigNumber.Create;
  end;
end;

procedure CheckBigNumberVectorDimensionEqual(A, B: TCnBigNumberVector);
begin
  if A.Dimension <> B.Dimension then
    raise ECnVectorException.Create(SCnErrorVectorDimensionNotEqual);
end;

function BigNumberVectorToString(V: TCnBigNumberVector): string;
var
  I: Integer;
begin
  Result := '(';
  for I := 0 to V.Dimension - 1 do
  begin
    if I = 0 then
      Result := Result + V[I].ToString
    else
      Result := Result + ', ' + V[I].ToString;
  end;
  Result := Result + ')';
end;

procedure BigNumberVectorModule(Res: TCnBigNumber; V: TCnBigNumberVector);
begin
  BigNumberVectorModuleSquare(Res, V);
  BigNumberSqrt(Res, Res);
end;

procedure BigNumberVectorModuleSquare(Res: TCnBigNumber; V: TCnBigNumberVector);
var
  I: Integer;
  T: TCnBigNumber;
begin
  Res.SetZero;
  T := FBigNumberPool.Obtain;
  try
    for I := 0 to V.Dimension - 1 do
    begin
      BigNumberMul(T, V[I], V[I]);
      BigNumberAdd(Res, Res, T);
    end;
  finally
    FBigNumberPool.Recycle(T);
  end;
end;

procedure BigNumberVectorCopy(Dst: TCnBigNumberVector; Src: TCnBigNumberVector);
var
  I: Integer;
begin
  if Src <> Dst then
  begin
    Dst.Dimension := Src.Dimension;
    for I := 0 to Src.Dimension - 1 do
      BigNumberCopy(Dst[I], Src[I]);
  end;
end;

procedure BigNumberVectorSwap(A: TCnBigNumberVector; B: TCnBigNumberVector);
var
  I: Integer;
begin
  if A <> B then
  begin
    CheckBigNumberVectorDimensionEqual(A, B);

    for I := 0 to A.Dimension - 1 do
      BigNumberSwap(A[I], B[I]);
  end;
end;

function BigNumberVectorEqual(A: TCnBigNumberVector; B: TCnBigNumberVector): Boolean;
var
  I: Integer;
begin
  Result := A.Dimension = B.Dimension;
  if Result then
  begin
    for I := 0 to A.Dimension - 1 do
    begin
      if not BigNumberEqual(A[I], B[I]) then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

procedure BigNumberVectorNegate(Res: TCnBigNumberVector; A: TCnBigNumberVector);
var
  I: Integer;
begin
  BigNumberVectorCopy(Res, A);
  for I := 0 to A.Dimension - 1 do
    Res[I].Negate;
end;

procedure BigNumberVectorAdd(Res: TCnBigNumberVector; A: TCnBigNumberVector; B: TCnBigNumberVector);
var
  I: Integer;
begin
  CheckBigNumberVectorDimensionEqual(A, B);

  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    BigNumberAdd(Res[I], A[I], B[I]);
end;

procedure BigNumberVectorSub(Res: TCnBigNumberVector; A: TCnBigNumberVector; B: TCnBigNumberVector);
var
  I: Integer;
begin
  CheckBigNumberVectorDimensionEqual(A, B);

  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    BigNumberSub(Res[I], A[I], B[I]);
end;

procedure BigNumberVectorMul(Res: TCnBigNumberVector; A: TCnBigNumberVector; N: TCnBigNumber);
var
  I: Integer;
begin
  Res.Dimension := A.Dimension;
  for I := 0 to A.Dimension - 1 do
    BigNumberMul(Res[I], A[I], N);
end;

procedure BigNumberVectorDotProduct(Res: TCnBigNumber; A: TCnBigNumberVector; B: TCnBigNumberVector);
var
  I: Integer;
  T: TCnBigNumber;
begin
  CheckBigNumberVectorDimensionEqual(A, B);

  Res.SetZero;
  T := FBigNumberPool.Obtain;
  try
    for I := 0 to A.Dimension - 1 do
    begin
      BigNumberMul(T, A[I], B[I]);
      BigNumberAdd(Res, Res, T);
    end;
  finally
    FBigNumberPool.Recycle(T);
  end;
end;

function TCnBigNumberVector.ToString: string;
begin
  Result := BigNumberVectorToString(Self);
end;

{ TCnBigNumberVectorPool }

function TCnBigNumberVectorPool.CreateObject: TObject;
begin
  Result := TCnBigNumberVector.Create(1);
end;

function TCnBigNumberVectorPool.Obtain: TCnBigNumberVector;
begin
  Result := TCnBigNumberVector(inherited Obtain);
  Result.SetDimension(1);
end;

procedure TCnBigNumberVectorPool.Recycle(Num: TCnBigNumberVector);
begin
  inherited Recycle(Num);
end;

initialization
  FBigNumberPool := TCnBigNumberPool.Create;

finalization
  FBigNumberPool.Free;

end.
