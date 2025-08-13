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

unit CnPolynomial;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�����ʽ����ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ����ϵ��Ϊ Int64 ����������һԪ���Ԫ����ʽ���㣬�Լ�һԪ�����ʽ�����㡣
*
*           ֧����ͨ����ϵ������ʽ�������㣬����ֻ֧�ֳ�����ߴ���Ϊ 1 �������
*           ֧����������Χ�ڵĶ���ʽ�������㣬ϵ���� mod p ���ҽ���Ա�ԭ����ʽ���ࡣ
*           ֧�ִ�����ϵ������ʽ�Լ������ʽ����ͨ���������Լ�����������Χ�ڵ����㡣
*
*           ע��������ģ�¶���ʽ������ϵ������ʽ�����ж��㷨��Դ�ڡ�һ���µ���ģʣ���໷��Ԫ������󷨡���
*              �ӱ�ʡ��ѧԺѧ����2009 �� 3 �£�ע�����еļ����㷨�����ף���
*              ʵ�ʼ����㷨��Դ�� stackoverflow �� William Whyte �Լ� Sonel Sharam �����ӡ�
*
* ����ƽ̨��PWin7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2023.09.01 V1.7
*               ʵ��������ģ�¶���ʽ������ϵ������ʽ����
*           2021.12.01 V1.6
*               ʵ�� BigNumber ��Χ�ڵĶ�Ԫ��ϵ������ʽ�������㣬������������
*           2021.11.17 V1.5
*               ʵ�� Int64 ��Χ�ڵĶ�Ԫ��ϵ������ʽ�������㣬������������
*           2020.08.29 V1.4
*               ʵ�� Int64 ��Χ�ڵĿ������۱任/���ٸ���Ҷ�任����ʽ�˷���������������
*           2020.11.14 V1.3
*               ʵ������������ Int64 �Լ���������Χ�ڵ������ʽ�Ĵ���
*           2020.11.08 V1.3
*               ʵ�����������д�������Χ�ڵĶ���ʽ�Լ������ʽ��������
*           2020.10.20 V1.2
*               ʵ������������ Int64 ��Χ�ڵ������ʽ��������
*           2020.08.28 V1.1
*               ʵ������������ Int64 ��Χ�ڵĶ���ʽ�������㣬�����Ա�ԭ����ʽ�����ģ��Ԫ
*           2020.08.21 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, SysConst, Math, Contnrs, CnPrime, CnNative,
  CnMatrix, CnContainers, CnBigNumber, CnBigRational, CnComplex, CnDFT;

type
  ECnPolynomialException = class(Exception);
  {* ����ʽ����쳣}

// =============================================================================
//
//                    һԪ��ϵ������ʽ��һԪ��ϵ�������ʽ
//
// =============================================================================

  TCnInt64Polynomial = class(TCnInt64List)
  {* һԪ��ϵ������ʽ��ϵ����ΧΪ Int64}
  private
    function GetMaxDegree: Integer;
    procedure SetMaxDegree(const Value: Integer);
  public
    constructor Create(LowToHighCoefficients: array of const); overload;
    {* ���캯��������Ϊ�ӵ͵��ߵ�ϵ����ע��ϵ����ʼ��ʱ���� MaxInt32/MaxInt64 �Ļᱻ���� Integer/Int64 ���为��

       ������
         LowToHighCoefficients: array of const            - �� 0 ��ʼ�ĵʹε��ߴεĶ���ʽϵ��

       ����ֵ��                                           - ���ش����Ķ���ʵ��
    }

    constructor Create; overload;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    procedure SetCoefficents(LowToHighCoefficients: array of const);
    {* һ���������ôӵ͵��ߵ�ϵ����

       ������
         LowToHighCoefficients: array of const            - �� 0 ��ʼ�ĵʹε��ߴεĶ���ʽϵ��

       ����ֵ��                                           - ���ش����Ķ���ʵ��
    }

    procedure CorrectTop;
    {* �޳��ߴε� 0 ϵ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ʽת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetString(const Poly: string);
    {* ������ʽ�ַ���ת��Ϊ����������ݡ�

       ������
         const Poly: string               - ��ת�����ַ���

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �����Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    procedure SetZero;
    {* ��Ϊ 0}

    function IsOne: Boolean;
    {* �����Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure SetOne;
    {* ��Ϊ 1}

    function IsNegOne: Boolean;
    {* �����Ƿ�Ϊ -1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ -1
    }

    procedure Negate;
    {* ����ϵ����}

    function IsMonic: Boolean;
    {* �Ƿ���һ����ʽ��Ҳ����ߴ�ϵ���Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ���һ����ʽ
    }

    property MaxDegree: Integer read GetMaxDegree write SetMaxDegree;
    {* ��ߴ�����0 ��ʼ������ Count ����ֻ���� Integer���±����ʱʹ�� 0 �� MaxDegree}
  end;

  TCnInt64RationalPolynomial = class(TPersistent)
  {* һԪ��ϵ�������ʽ����ĸ���ӷֱ�ΪһԪ��ϵ������ʽ}
  private
    FNominator: TCnInt64Polynomial;
    FDenominator: TCnInt64Polynomial;
  protected
    procedure AssignTo(Dest: TPersistent); override;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function IsInt: Boolean; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    {* �Ƿ�������ʽ��Ҳ�����жϷ�ĸ�Ƿ������� 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�������ʽ
    }

    function IsZero: Boolean; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    {* �Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    function IsOne: Boolean; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    {* �Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure Reciprocal;
    {* ��ɵ���}

    procedure Neg;
    {* ��ɸ���}

    procedure SetZero;
    {* ��Ϊ 0}

    procedure SetOne;
    {* ��Ϊ 1}

    procedure Reduce;
    {* Լ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetString(const Rational: string);
    {* ������ʽ���ʽ�ַ���ת��Ϊ����������ݡ�

       ������
         const Rational: string           -

       ����ֵ�����ޣ�
    }

    property Nominator: TCnInt64Polynomial read FNominator;
    {* ����ʽ}
    property Denominator: TCnInt64Polynomial read FDenominator;
    {* ��ĸʽ}
  end;

  TCnInt64PolynomialPool = class(TCnMathObjectPool)
  {* һԪ��ϵ������ʽ��ʵ���࣬����ʹ�õ�һԪ��ϵ������ʽ�ĵط����д���һԪ��ϵ������ʽ��}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnInt64Polynomial; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnInt64Polynomial         - ���صĶ���ʽ����
    }

    procedure Recycle(Poly: TCnInt64Polynomial); reintroduce;
    {* ��һ������黹������ء�

       ������
         Poly: TCnInt64Polynomial         - ���黹�Ķ���ʽ����

       ����ֵ�����ޣ�
    }
  end;

  TCnInt64RationalPolynomialPool = class(TCnMathObjectPool)
  {* һԪ��ϵ�������ʽ��ʵ���࣬����ʹ�õ�һԪ��ϵ�������ʽ�ĵط����д�����һԪϵ�������ʽ��}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnInt64RationalPolynomial; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnInt64RationalPolynomial - ���صĶ���ʽ����
    }

    procedure Recycle(Poly: TCnInt64RationalPolynomial); reintroduce;
    {* ��һ������黹������ء�

       ������
         Poly: TCnInt64RationalPolynomial - ���黹�Ķ���ʽ����

       ����ֵ�����ޣ�
    }
  end;

// =============================================================================
//
//                 һԪ����ϵ������ʽ��һԪ����ϵ�������ʽ
//
// =============================================================================

  TCnBigNumberPolynomial = class(TCnBigNumberList)
  {* һԪ����ϵ������ʽ}
  private
    function GetMaxDegree: Integer;
    procedure SetMaxDegree(const Value: Integer);
  public
    constructor Create(LowToHighCoefficients: array of const); overload;
    {* ���캯��������Ϊ�ӵ͵��ߵ�ϵ����ע��ϵ����ʼ��ʱ���� MaxInt32/MaxInt64 �Ļᱻ���� Integer/Int64 ���为��

       ������
         LowToHighCoefficients: array of const            - �� 0 ��ʼ�ĵʹε��ߴεĶ���ʽϵ��

       ����ֵ��                                           - ���ش����Ķ���ʵ��
    }

    constructor Create; overload;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    procedure SetCoefficents(LowToHighCoefficients: array of const);
    {* һ���������ôӵ͵��ߵ�ϵ����

       ������
         LowToHighCoefficients: array of const            - �� 0 ��ʼ�ĵʹε��ߴεĶ���ʽϵ��

       ����ֵ�����ޣ�
    }

    procedure CorrectTop;
    {* �޳��ߴε� 0 ϵ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ʽת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetString(const Poly: string);
    {* ������ʽ�ַ���ת��Ϊ����������ݡ�

       ������
         const Poly: string               - ��ת�����ַ���

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �����Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    procedure SetZero;
    {* ��Ϊ 0}

    function IsOne: Boolean;
    {* �����Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure SetOne;
    {* ��Ϊ 1}

    function IsNegOne: Boolean;
    {* �����Ƿ�Ϊ -1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ -1
    }

    procedure Negate;
    {* ����ϵ����}

    function IsMonic: Boolean;
    {* �Ƿ���һ����ʽ��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ���һ����ʽ
    }

    property MaxDegree: Integer read GetMaxDegree write SetMaxDegree;
    {* ��ߴ�����0 ��ʼ}
  end;

  TCnBigNumberRationalPolynomial = class(TPersistent)
  {* һԪ����ϵ�������ʽ����ĸ���ӷֱ�ΪһԪ����ϵ������ʽ}
  private
    FNominator: TCnBigNumberPolynomial;
    FDenominator: TCnBigNumberPolynomial;
  protected
    procedure AssignTo(Dest: TPersistent); override;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function IsInt: Boolean; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    {* �Ƿ�������ʽ��Ҳ�����жϷ�ĸ�Ƿ������� 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�������ʽ
    }

    function IsZero: Boolean; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    {* �Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    function IsOne: Boolean; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    {* �Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure Reciprocal;
    {* ��Ϊ����}

    procedure Neg;
    {* ��Ϊ����}

    procedure SetZero;
    {* ��Ϊ 0}

    procedure SetOne;
    {* ��Ϊ 1}

    procedure Reduce;
    {* Լ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת�����ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetString(const Rational: string);
    {* ������ʽ���ʽ�ַ���ת��Ϊ����������ݡ�

       ������
         const Rational: string           - ��ת�����ַ���

       ����ֵ�����ޣ�
    }

    property Nominator: TCnBigNumberPolynomial read FNominator;
    {* ���Ӷ���ʽ}
    property Denominator: TCnBigNumberPolynomial read FDenominator;
    {* ��ĸ����ʽ}
  end;

  TCnBigNumberPolynomialPool = class(TCnMathObjectPool)
  {* һԪ����ϵ������ʽ��ʵ���࣬����ʹ�õ�һԪ������ϵ������ʽ�ĵط����д���һԪ������ϵ������ʽ��}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnBigNumberPolynomial; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnBigNumberPolynomial     - ���صĶ���ʽ����
    }

    procedure Recycle(Poly: TCnBigNumberPolynomial); reintroduce;
    {* ��һ������黹������ء�

       ������
         Poly: TCnBigNumberPolynomial     - ���黹�Ķ���ʽ����

       ����ֵ�����ޣ�
    }
  end;

  TCnBigNumberRationalPolynomialPool = class(TCnMathObjectPool)
  {* һԪ����ϵ�������ʽ��ʵ���࣬����ʹ�õ�һԪ����ϵ�������ʽ�ĵط����д���һԪ����ϵ�������ʽ��}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnBigNumberRationalPolynomial; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnBigNumberRationalPolynomial             - ���صĶ���ʽ����
    }

    procedure Recycle(Poly: TCnBigNumberRationalPolynomial); reintroduce;
    {* ��һ������黹������ء�

       ������
         Poly: TCnBigNumberRationalPolynomial             - ���黹�Ķ���ʽ����

       ����ֵ�����ޣ�
    }
  end;

// ====================== һԪ��ϵ������ʽ�������� =============================

function Int64PolynomialNew: TCnInt64Polynomial;
{* ����һ����̬�����һԪ��ϵ������ʽ���󣬵�ͬ�� TCnInt64Polynomial.Create��

   ������
     ���ޣ�

   ����ֵ��TCnInt64Polynomial             - ���ش�����һԪ��ϵ������ʽ����
}

procedure Int64PolynomialFree(P: TCnInt64Polynomial);
{* �ͷ�һ��һԪ��ϵ������ʽ���󣬵�ͬ�� TCnInt64Polynomial.Free

   ������
     P: TCnInt64Polynomial                - ���ͷŵ�һԪ��ϵ������ʽ

   ����ֵ�����ޣ�
}

function Int64PolynomialDuplicate(P: TCnInt64Polynomial): TCnInt64Polynomial;
{* ��һ��һԪ��ϵ������ʽ�����¡һ���¶���

   ������
     P: TCnInt64Polynomial                - �����Ƶ�һԪ��ϵ������ʽ

   ����ֵ��TCnInt64Polynomial             - �����½���һԪ��ϵ������ʽ
}

function Int64PolynomialCopy(Dst: TCnInt64Polynomial; Src: TCnInt64Polynomial): TCnInt64Polynomial;
{* ����һ��һԪ��ϵ������ʽ���󣬳ɹ����� Dst��

   ������
     Dst: TCnInt64Polynomial              - Ŀ��һԪ��ϵ������ʽ
     Src: TCnInt64Polynomial              - ԴһԪ��ϵ������ʽ

   ����ֵ��TCnInt64Polynomial             - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function Int64PolynomialToString(P: TCnInt64Polynomial; const VarName: string = 'X'): string;
{* ��һ��һԪ��ϵ������ʽ����ת���ַ�����δ֪��Ĭ���� X ��ʾ��

   ������
     P: TCnInt64Polynomial                - ��ת����һԪ��ϵ������ʽ
     const VarName: string                - ����δ֪�����ַ���

   ����ֵ��string                         - �����ַ���
}

function Int64PolynomialSetString(P: TCnInt64Polynomial;
  const Str: string; const VarName: string = 'X'): Boolean;
{* ���ַ�����ʽ��һԪ��ϵ������ʽ��ֵ��һԪ��ϵ������ʽ���󣬷����Ƿ�ֵ�ɹ���

   ������
     P: TCnInt64Polynomial                - �������ɽ����һԪ��ϵ������ʽ
     const Str: string                    - ����ʽ�ַ���
     const VarName: string                - ����δ֪�����ַ���

   ����ֵ��Boolean                        - �����Ƿ�ֵ�ɹ�
}

function Int64PolynomialIsZero(P: TCnInt64Polynomial): Boolean;
{* �ж�һ��һԪ��ϵ������ʽ�����Ƿ�Ϊ 0��

   ������
     P: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

procedure Int64PolynomialSetZero(P: TCnInt64Polynomial);
{* ��һ��һԪ��ϵ������ʽ������Ϊ 0��

   ������
     P: TCnInt64Polynomial                - �����õ�һԪ��ϵ������ʽ

   ����ֵ�����ޣ�
}

function Int64PolynomialIsOne(P: TCnInt64Polynomial): Boolean;
{* �ж�һ��һԪ��ϵ������ʽ�����Ƿ�Ϊ 1��

   ������
     P: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 1
}

procedure Int64PolynomialSetOne(P: TCnInt64Polynomial);
{* ��һ��һԪ��ϵ������ʽ������Ϊ 1��

   ������
     P: TCnInt64Polynomial                - �����õ�һԪ��ϵ������ʽ

   ����ֵ�����ޣ�
}

function Int64PolynomialIsNegOne(P: TCnInt64Polynomial): Boolean;
{* �ж�һ��һԪ��ϵ������ʽ�����Ƿ�Ϊ -1��

   ������
     P: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ -1
}

procedure Int64PolynomialNegate(P: TCnInt64Polynomial);
{* ��һ��һԪ��ϵ������ʽ��������ϵ���󷴡�

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ

   ����ֵ�����ޣ�
}

function Int64PolynomialIsMonic(P: TCnInt64Polynomial): Boolean;
{* �ж�һ��һԪ��ϵ������ʽ�Ƿ�����һ����ʽ��Ҳ�����ж���ߴ�ϵ���Ƿ�Ϊ 1��

   ������
     P: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ��һ����ʽ
}

procedure Int64PolynomialShiftLeft(P: TCnInt64Polynomial; N: Integer);
{* ��һ��һԪ��ϵ������ʽ�������� N �Σ�Ҳ���Ǹ���ָ������ N��

   ������
     P: TCnInt64Polynomial                - �����Ƶ�һԪ��ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

procedure Int64PolynomialShiftRight(P: TCnInt64Polynomial; N: Integer);
{* ��һ��һԪ��ϵ������ʽ�������� N �Σ�Ҳ���Ǹ���ָ������ N��С�� 0 �Ĵ���������ˡ�

   ������
     P: TCnInt64Polynomial                - �����Ƶ�һԪ��ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

function Int64PolynomialEqual(A: TCnInt64Polynomial; B: TCnInt64Polynomial): Boolean;
{* �ж���һԪ��ϵ������ʽÿ��ϵ���Ƿ��Ӧ��ȣ����򷵻� True��

   ������
     A: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽһ
     B: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����
}

// ====================== һԪ��ϵ������ʽ��ͨ���� =============================

procedure Int64PolynomialAddWord(P: TCnInt64Polynomial; N: Int64);
{* ��һ��һԪ��ϵ������ʽ����ĳ�ϵ������ N��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ��ϵ������

   ����ֵ�����ޣ�
}

procedure Int64PolynomialSubWord(P: TCnInt64Polynomial; N: Int64);
{* ��һ��һԪ��ϵ������ʽ����ĳ�ϵ����ȥ N��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ��ϵ������

   ����ֵ�����ޣ�
}

procedure Int64PolynomialMulWord(P: TCnInt64Polynomial; N: Int64);
{* ��һ��һԪ��ϵ������ʽ����ĸ���ϵ�������� N��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64PolynomialDivWord(P: TCnInt64Polynomial; N: Int64);
{* ��һ��һԪ��ϵ������ʽ����ĸ���ϵ�������� N���粻��������ȡ����

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64PolynomialNonNegativeModWord(P: TCnInt64Polynomial; N: Int64);
{* ��һ��һԪ��ϵ������ʽ����ĸ���ϵ������ N �Ǹ����࣬�������������򻯡�

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

function Int64PolynomialAdd(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
{* ����һԪ��ϵ������ʽ������ӣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ����һ
     P2: TCnInt64Polynomial               - ������

   ����ֵ��Boolean                        - �����Ƿ���ӳɹ�
}

function Int64PolynomialSub(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
{* ����һԪ��ϵ������ʽ���������������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ������
     P2: TCnInt64Polynomial               - ����

   ����ֵ��Boolean                        - �����Ƿ�����ɹ�
}

function Int64PolynomialMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
{* ����һԪ��ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ����һ
     P2: TCnInt64Polynomial               - ������

   ����ֵ��Boolean                        - �����Ƿ���˳ɹ�
}

function Int64PolynomialDftMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
{* ����һԪ��ϵ������ʽ����ʹ����ɢ����Ҷ�任����ɢ����Ҷ��任��ˣ�������� Res �У�
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��
   ע��ʹ�ø������ٵ���Ϊ����Ե�ʿ��ܳ��ֲ���ϵ���и�λ�����Ǻ��Ƽ�ʹ�á�

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ����һ
     P2: TCnInt64Polynomial               - ������

   ����ֵ��Boolean                        - �����Ƿ���˳ɹ�
}

function Int64PolynomialNttMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
{* ����һԪ��ϵ������ʽ����ʹ�ÿ������۱任�����������任��ˣ�������� Res �У�
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��
   ע������ʽϵ��ֻ֧�� [0, CN_P) ���䣬����ʽ��������С��ģ���� 2^23��������÷�ΧҲ���㡣

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ����һ
     P2: TCnInt64Polynomial               - ������

   ����ֵ��Boolean                        - �����Ƿ���˳ɹ�
}

function Int64PolynomialDiv(Res: TCnInt64Polynomial; Remain: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Divisor: TCnInt64Polynomial; ErrMulFactor: PInt64 = nil): Boolean;
{* ����һԪ��ϵ������ʽ����������̷��� Res �У���ʽ���� Remain �У���������Ƿ�ɹ���
   ע�⵱��ʽ����ʽ�����޷������ķ���ʱ�᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   ���� False ʱ�� ErrMulFactor ������Ϊ�գ���᷵�ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     Remain: TCnInt64Polynomial           - ����������ʽ��һԪ��ϵ������ʽ
     P: TCnInt64Polynomial                - ������
     Divisor: TCnInt64Polynomial          - ����
     ErrMulFactor: PInt64                 - �ṩָ�룬����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ�����ɹ�
}

function Int64PolynomialMod(Res: TCnInt64Polynomial; P: TCnInt64Polynomial;
  Divisor: TCnInt64Polynomial; ErrMulFactor: PInt64 = nil): Boolean;
{* ����һԪ��ϵ������ʽ�������࣬��ʽ���� Res �У����������Ƿ�ɹ���
   ע�⵱��ʽ����ʽ�����޷������ķ���ʱ�᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   ���� False ʱ�� ErrMulFactor ������Ϊ�գ���᷵�ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ��
   Res ������ P �� Divisor��P ������ Divisor��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64Polynomial                - ������
     Divisor: TCnInt64Polynomial          - ����
     ErrMulFactor: PInt64                 - �ṩָ�룬����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ�����ɹ�
}

function Int64PolynomialPower(Res: TCnInt64Polynomial; P: TCnInt64Polynomial; Exponent: Int64): Boolean;
{* ����һԪ��ϵ������ʽ�� Exponent ���ݣ�������ϵ����������⣬�����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64Polynomial                - ����
     Exponent: Int64                      - ָ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialReduce(P: TCnInt64Polynomial): Integer;
{* ����һԪ��ϵ������ʽϵ����Ҳ�����Ҷ���ʽϵ�������Լ��������ϵ�����������������Լ����

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ

   ����ֵ��Integer                        - ���ظ�ϵ�������Լ��
}

procedure Int64PolynomialCentralize(P: TCnInt64Polynomial; Modulus: Int64);
{* ��һԪ��ϵ������ʽϵ���������Ļ�����Ҳ���� [0, M - 1] ��Ϊ [1 - (M + 1) div 2, M div 2]��
   Ҳ������ M div 2 ��ϵ��Ҫ�� M��ע�� Modulus ��һ����������

   ������
     P: TCnInt64Polynomial                - �����Ļ���һԪ��ϵ������ʽ
     Modulus: Int64                       - ģ��

   ����ֵ�����ޣ�
}

function Int64PolynomialGreatestCommonDivisor(Res: TCnInt64Polynomial;
  P1: TCnInt64Polynomial; P2: TCnInt64Polynomial): Boolean;
{* ��������һԪ��ϵ������ʽ�������ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��
   ע�������ܻ���Ϊϵ������������ʧ�ܣ���ʹ���������б�֤ P1 P2 ��Ϊ��һ����ʽҲ���ܱ�֤��
   �緵�� False�������߿ɸɴ���Ϊ���أ������ʽΪ 1�������� Res �

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - �����������ʽ��һԪ��ϵ������ʽһ
     P2: TCnInt64Polynomial               - �����������ʽ��һԪ��ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialLeastCommonMultiple(Res: TCnInt64Polynomial;
  P1: TCnInt64Polynomial; P2: TCnInt64Polynomial): Boolean;
{* ��������һԪ��ϵ������ʽ����С����ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��
   ע�������ܻ���Ϊϵ������������ʧ�ܣ���ʹ���������б�֤ P1 P2 ��Ϊ��һ����ʽҲ���ܱ�֤��
   �緵�� False�������߿ɸɴ���Ϊ���أ���С����ʽΪ������ˣ������м��㡣

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ��������С����ʽ��һԪ��ϵ������ʽһ
     P2: TCnInt64Polynomial               - ��������С����ʽ��һԪ��ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialCompose(Res: TCnInt64Polynomial;
  F: TCnInt64Polynomial; P: TCnInt64Polynomial): Boolean;
{* һԪ��ϵ������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���Res ������ F �� P��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     F: TCnInt64Polynomial                - ����ԭʽ
     P: TCnInt64Polynomial                - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialGetValue(F: TCnInt64Polynomial; X: Int64): Int64;
{* һԪ��ϵ������ʽ��ֵ��Ҳ���Ǽ��� F(x)�����ؼ�������

   ������
     F: TCnInt64Polynomial                - ����ֵ��һԪ��ϵ������ʽ
     X: Int64                             - δ֪����ֵ

   ����ֵ��Int64                          - ���ؼ�����
}

procedure Int64PolynomialReduce2(P1: TCnInt64Polynomial; P2: TCnInt64Polynomial);
{* �������һԪ��ϵ������ʽ����Լ�֣�Ҳ�����������أ����������ʽԼ�����㡣

   ������
     P1: TCnInt64Polynomial               - ��Լ�ֵ�һԪ��ϵ������ʽһ
     P2: TCnInt64Polynomial               - ��Լ�ֵ�һԪ��ϵ������ʽ��

   ����ֵ�����ޣ�
}

// ===================== ���������µ���ϵ������ʽģ���� ========================

function Int64PolynomialGaloisEqual(A: TCnInt64Polynomial;
  B: TCnInt64Polynomial; Prime: Int64): Boolean;
{* ����һԪ��ϵ������ʽ��ģ Prime ���������Ƿ���ȡ�

   ������
     A: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽһ
     B: TCnInt64Polynomial                - ���жϵ�һԪ��ϵ������ʽ��
     Prime: Int64                         - ģ��

   ����ֵ��Boolean                        - �����Ƿ����
}

procedure Int64PolynomialGaloisNegate(P: TCnInt64Polynomial; Prime: Int64);
{* ��һ��һԪ��ϵ������ʽ��������ϵ����ģ Prime ���������󷴡�

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

function Int64PolynomialGaloisAdd(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil): Boolean;
{* ����һԪ��ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ����һ
     P2: TCnInt64Polynomial               - ������
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ���ӳɹ�
}

function Int64PolynomialGaloisSub(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil): Boolean;
{* ����һԪ��ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ������
     P2: TCnInt64Polynomial               - ����
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ�����ɹ�
}

function Int64PolynomialGaloisMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil): Boolean;
{* ����һԪ��ϵ������ʽ������ Prime �η�������������ˣ�������� Res �У�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ����һ
     P2: TCnInt64Polynomial               - ������
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ���˳ɹ�
}

function Int64PolynomialGaloisDiv(Res: TCnInt64Polynomial; Remain: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Divisor: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil;
  ErrMulFactor: PInt64 = nil): Boolean;
{* ����һԪ��ϵ������ʽ������ Prime �η�����������������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   ���� False ʱ�� ErrMulFactor ������Ϊ�գ���᷵�ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     Remain: TCnInt64Polynomial           - ����������ʽ��һԪ��ϵ������ʽ
     P: TCnInt64Polynomial                - ������
     Divisor: TCnInt64Polynomial          - ����
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ
     ErrMulFactor: PInt64                 - �ṩָ�룬����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ�����ɹ�
}

function Int64PolynomialGaloisMod(Res: TCnInt64Polynomial; P: TCnInt64Polynomial;
  Divisor: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil;
  ErrMulFactor: PInt64 = nil): Boolean;
{* ����һԪ��ϵ������ʽ������ Prime �η��������������࣬�������� Res �У����������Ƿ�ɹ���
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ
   ���� False ʱ�� ErrMulFactor ������Ϊ�գ���᷵�ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ
   Res ������ P �� Divisor��P ������ Divisor

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64Polynomial                - ������
     Divisor: TCnInt64Polynomial          - ����
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ
     ErrMulFactor: PInt64                 - �ṩָ�룬����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ�����ɹ�
}

function Int64PolynomialGaloisPower(Res: TCnInt64Polynomial; P: TCnInt64Polynomial;
  Exponent: Int64; Prime: Int64; Primitive: TCnInt64Polynomial = nil;
  ExponentHi: Int64 = 0): Boolean;
{* ����һԪ��ϵ������ʽ�� Prime �η����������ϵ� Exponent ���ݣ�Exponent ������ 128 λ��
   Exponent ������������Ǹ�ֵ���Զ�ת�� UInt64��
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   �����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64Polynomial                - ����
     Exponent: Int64                      - ָ���� 64 λ
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ
     ExponentHi: Int64                    - ָ���� 64 λ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure Int64PolynomialGaloisAddWord(P: TCnInt64Polynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵ�һԪ��ϵ������ʽ�ĳ�ϵ������ N �� mod Prime��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ��ϵ������
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64PolynomialGaloisSubWord(P: TCnInt64Polynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵ�һԪ��ϵ������ʽ�ĳ�ϵ����ȥ N �� mod Prime��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ��ϵ������
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64PolynomialGaloisMulWord(P: TCnInt64Polynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵ�һԪ��ϵ������ʽ����ϵ������ N �� mod Prime��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ����
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64PolynomialGaloisDivWord(P: TCnInt64Polynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵ�һԪ��ϵ������ʽ����ϵ������ N��Ҳ���ǳ��� N ����Ԫ�� mod Prime��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     N: Int64                             - ��ϵ������
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

function Int64PolynomialGaloisMonic(P: TCnInt64Polynomial; Prime: Int64): Integer;
{* �� Prime �η����������ϵ�һԪ��ϵ������ʽ����ϵ��ͬ������ʹ����Ϊһ�����س���ֵ��

   ������
     P: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Integer                        - ���س���ֵ
}

function Int64PolynomialGaloisGreatestCommonDivisor(Res: TCnInt64Polynomial;
  P1: TCnInt64Polynomial; P2: TCnInt64Polynomial; Prime: Int64): Boolean;
{* ��������һԪ��ϵ������ʽ�� Prime �η����������ϵ������ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - �����������ʽ��һԪ��ϵ������ʽһ
     P2: TCnInt64Polynomial               - �����������ʽ��һԪ��ϵ������ʽ��
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialGaloisLeastCommonMultiple(Res: TCnInt64Polynomial;
  P1: TCnInt64Polynomial; P2: TCnInt64Polynomial; Prime: Int64): Boolean;
{* ��������һԪ��ϵ������ʽ�� Prime �η����������ϵ���С����ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P1: TCnInt64Polynomial               - ��������С����ʽ��һԪ��ϵ������ʽһ
     P2: TCnInt64Polynomial               - ��������С����ʽ��һԪ��ϵ������ʽ��
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure Int64PolynomialGaloisExtendedEuclideanGcd(A: TCnInt64Polynomial;
  B: TCnInt64Polynomial; X: TCnInt64Polynomial; Y: TCnInt64Polynomial; Prime: Int64);
{* ��չŷ�����շת������� Prime �η��������������Ԫһ�β�����ϵ������ʽ���� A * X + B * Y = 1 �Ľ⡣

   ������
     A: TCnInt64Polynomial                - ��Ԫһ�β�����ϵ������ʽ����ϵ�� A
     B: TCnInt64Polynomial                - ��Ԫһ�β�����ϵ������ʽ����ϵ�� B
     X: TCnInt64Polynomial                - �������ɽ�� X ��һԪ��ϵ������ʽ
     Y: TCnInt64Polynomial                - �������ɽ�� Y ��һԪ��ϵ������ʽ
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64PolynomialGaloisModularInverse(Res: TCnInt64Polynomial;
  X: TCnInt64Polynomial; Modulus: TCnInt64Polynomial; Prime: Int64; CheckGcd: Boolean = False);
{* ��һԪ��ϵ������ʽ X �� Prime �η�������������� Modulus ��ģ������ʽ���ģ��Ԫ����ʽ Y��
   ���� (X * Y) mod M = 1���������뾡����֤ X��Modulus ���أ��� Res ����Ϊ X �� Modulus��
   CheckGcd ����Ϊ True ʱ���ڲ����� X��Modulus �Ƿ��أ����������׳��쳣��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     X: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     Modulus: TCnInt64Polynomial          - ģ��
     Prime: Int64                         - �������Ͻ�
     CheckGcd: Boolean                    - �Ƿ��黥��

   ����ֵ�����ޣ�
}

function Int64PolynomialGaloisPrimePowerModularInverse(Res: TCnInt64Polynomial;
  X: TCnInt64Polynomial; Modulus: TCnInt64Polynomial; PrimeRoot: Integer; Exponent: Integer): Boolean;
{* ��һԪ��ϵ������ʽ X ������Ķ����ģ��Ҳ������ PrimeRoot �� Exponent �η����������ϣ�
   ��� Modulus �� X ��ģ������ʽ���ģ��Ԫ����ʽ Y������ (X * Y) mod M = 1��
   ���������Ƿ�ɹ���Res ����Ϊ X �� Modulus��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     X: TCnInt64Polynomial                - �������һԪ��ϵ������ʽ
     Modulus: TCnInt64Polynomial          - ģ��
     PrimeRoot: Integer                   - ����������
     Exponent: Integer                    - ������ָ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialGaloisCompose(Res: TCnInt64Polynomial; F: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil): Boolean;
{* �� Prime �η����������Ͻ���һԪ��ϵ������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���Res ������ F �� P��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     F: TCnInt64Polynomial                - ����ԭʽ
     P: TCnInt64Polynomial                - ������ʽ
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64PolynomialGaloisGetValue(F: TCnInt64Polynomial; X: Int64; Prime: Int64): Int64;
{* �� Prime �η����������Ͻ���һԪ��ϵ������ʽ��ֵ��Ҳ���Ǽ��� F(x)�����ؼ�������

   ������
     F: TCnInt64Polynomial                - ����ֵ��һԪ��ϵ������ʽ
     X: Int64                             - δ֪����ֵ
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Int64                          - ���ؼ�����
}

function Int64PolynomialGaloisCalcDivisionPolynomial(A: Int64; B: Int64; Degree: Int64;
  OutDivisionPolynomial: TCnInt64Polynomial; Prime: Int64): Boolean;
{* �ݹ����ָ����Բ������ Prime �η����������ϵ� N �׿ɳ�����ʽ�������Ƿ����ɹ���
   ע�� Degree ������ʱ���ɳ�����ʽ�Ǵ� x �Ķ���ʽ��ż��ʱ���ǣ�x �Ķ���ʽ��* y ����ʽ��
   �����ֻ���� x �Ķ���ʽ���֡�
   ����ο��� F. MORAIN �����²����ϳ��� 2 ���Ƶ�����
  ��COMPUTING THE CARDINALITY OF CM ELLIPTIC CURVES USING TORSION POINTS��

   ������
     A: Int64                                             - κ��˹����˹��Բ���߷��̵� a ����
     B: Int64                                             - κ��˹����˹��Բ���߷��̵� b ����
     Degree: Int64                                        - �����Ŀɳ�����ʽ����
     OutDivisionPolynomial: TCnInt64Polynomial            - �������ɽ����һԪ��ϵ������ʽ
     Prime: Int64                                         - �������Ͻ�

   ����ֵ��Boolean                                        - �����Ƿ����ɹ�
}

procedure Int64PolynomialGaloisReduce2(P1: TCnInt64Polynomial; P2: TCnInt64Polynomial; Prime: Int64);
{* �� Prime �η������������������һԪ��ϵ������ʽ����Լ�֣�Ҳ�����������أ����������ʽԼ�����㡣

   ������
     P1: TCnInt64Polynomial               - ��Լ�ֵ�һԪ��ϵ������ʽһ
     P2: TCnInt64Polynomial               - ��Լ�ֵ�һԪ��ϵ������ʽ��
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

// ===================== һԪ��ϵ�������ʽ�������� ============================

function Int64RationalPolynomialEqual(R1: TCnInt64RationalPolynomial;
  R2: TCnInt64RationalPolynomial): Boolean;
{* �Ƚ�����һԪ��ϵ�������ʽ�Ƿ���ȡ�

   ������
     R1: TCnInt64RationalPolynomial       - ���Ƚϵ�һԪ��ϵ�������ʽһ
     R2: TCnInt64RationalPolynomial       - ���Ƚϵ�һԪ��ϵ�������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����
}

function Int64RationalPolynomialCopy(Dst: TCnInt64RationalPolynomial;
  Src: TCnInt64RationalPolynomial): TCnInt64RationalPolynomial;
{* һԪ��ϵ�������ʽ���ơ�

   ������
     Dst: TCnInt64RationalPolynomial      - Ŀ��һԪ��ϵ�������ʽ
     Src: TCnInt64RationalPolynomial      - ԴһԪ��ϵ�������ʽ

   ����ֵ��TCnInt64RationalPolynomial     - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

procedure Int64RationalPolynomialAdd(R1: TCnInt64RationalPolynomial; R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ��ͨ�ӷ�����������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     R2: TCnInt64RationalPolynomial                       - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialSub(R1: TCnInt64RationalPolynomial; R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ��ͨ��������������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     R2: TCnInt64RationalPolynomial                       - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialMul(R1: TCnInt64RationalPolynomial; R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ��ͨ�˷�����������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     R2: TCnInt64RationalPolynomial                       - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialDiv(R1: TCnInt64RationalPolynomial; R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ��ͨ��������������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     R2: TCnInt64RationalPolynomial                       - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialAddWord(R: TCnInt64RationalPolynomial; N: Int64);
{* һԪ��ϵ�������ʽ��ͨ�ӷ����� Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialSubWord(R: TCnInt64RationalPolynomial; N: Int64);
{* һԪ��ϵ�������ʽ��ͨ������ȥ Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialMulWord(R: TCnInt64RationalPolynomial; N: Int64);
{* һԪ��ϵ�������ʽ��ͨ�˷����� Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialDivWord(R: TCnInt64RationalPolynomial; N: Int64);
{* һԪ��ϵ�������ʽ��ͨ�������� Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialAdd(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ����ͨ�ӷ���RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     P1: TCnInt64Polynomial                               - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialSub(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ����ͨ������RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     P1: TCnInt64Polynomial                               - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialMul(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ����ͨ�˷���RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     P1: TCnInt64Polynomial                               - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialDiv(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ����ͨ������RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     P1: TCnInt64Polynomial                               - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ

   ����ֵ�����ޣ�
}

function Int64RationalPolynomialCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64RationalPolynomial; P: TCnInt64RationalPolynomial): Boolean; overload;
{* һԪ��ϵ�������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnInt64RationalPolynomial      - �������ɽ����һԪ��ϵ�������ʽ
     F: TCnInt64RationalPolynomial        - ����ԭʽ
     P: TCnInt64RationalPolynomial        - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64RationalPolynomialCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64RationalPolynomial; P: TCnInt64Polynomial): Boolean; overload;
{* һԪ��ϵ�������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnInt64RationalPolynomial      - �������ɽ����һԪ��ϵ�������ʽ
     F: TCnInt64RationalPolynomial        - ����ԭʽ
     P: TCnInt64Polynomial                - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64RationalPolynomialCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64Polynomial; P: TCnInt64RationalPolynomial): Boolean; overload;
{* һԪ��ϵ�������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnInt64RationalPolynomial      - �������ɽ����һԪ��ϵ�������ʽ
     F: TCnInt64Polynomial                - ����ԭʽ
     P: TCnInt64RationalPolynomial        - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure Int64RationalPolynomialGetValue(Res: TCnRationalNumber;
  F: TCnInt64RationalPolynomial; X: Int64);
{* һԪ��ϵ�������ʽ��ֵ��Ҳ���Ǽ��� F(x)����������� Res �С�

   ������
     Res: TCnRationalNumber               - �������ɽ��������������
     F: TCnInt64RationalPolynomial        - ����ֵ��һԪ��ϵ�������ʽ
     X: Int64                             - δ֪����ֵ

   ����ֵ�����ޣ�
}

// ================= һԪ��ϵ�������ʽ���������ϵ�ģ���� ======================

function Int64RationalPolynomialGaloisEqual(R1: TCnInt64RationalPolynomial;
  R2: TCnInt64RationalPolynomial; Prime: Int64; Primitive: TCnInt64Polynomial = nil): Boolean;
{* �Ƚ�����ģϵ��һԪ��ϵ�������ʽ�Ƿ���ȡ�

   ������
     R1: TCnInt64RationalPolynomial       - ���Ƚϵ�һԪ��ϵ�������ʽһ
     R2: TCnInt64RationalPolynomial       - ���Ƚϵ�һԪ��ϵ�������ʽ��
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����
}

procedure Int64RationalPolynomialGaloisNegate(P: TCnInt64RationalPolynomial;
  Prime: Int64);
{* ��һ��һԪ��ϵ�������ʽ������ӵ�����ϵ����ģ Prime ���������󷴡�

   ������
     P: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisAdd(R1: TCnInt64RationalPolynomial;
  R2: TCnInt64RationalPolynomial; RationalResult: TCnInt64RationalPolynomial;
  Prime: Int64); overload;
{* һԪ��ϵ�������ʽģϵ���ӷ�����������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     R2: TCnInt64RationalPolynomial                       - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisSub(R1: TCnInt64RationalPolynomial;
  R2: TCnInt64RationalPolynomial; RationalResult: TCnInt64RationalPolynomial;
  Prime: Int64); overload;
{* һԪ��ϵ�������ʽģϵ����������������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     R2: TCnInt64RationalPolynomial                       - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisMul(R1: TCnInt64RationalPolynomial;
  R2: TCnInt64RationalPolynomial; RationalResult: TCnInt64RationalPolynomial;
  Prime: Int64); overload;
{* һԪ��ϵ�������ʽģϵ���˷�����������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     R2: TCnInt64RationalPolynomial                       - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisDiv(R1: TCnInt64RationalPolynomial;
  R2: TCnInt64RationalPolynomial; RationalResult: TCnInt64RationalPolynomial;
  Prime: Int64); overload;
{* һԪ��ϵ�������ʽģϵ����������������������ͬһ����

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     R2: TCnInt64RationalPolynomial                       - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisAddWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
{* һԪ��ϵ�������ʽģϵ���ӷ����� Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisSubWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
{* һԪ��ϵ�������ʽģϵ��������ȥ Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisMulWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
{* һԪ��ϵ�������ʽģϵ���˷����� Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisDivWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
{* һԪ��ϵ�������ʽģϵ���������� Int64��

   ������
     R: TCnInt64RationalPolynomial        - �������һԪ��ϵ�������ʽ
     N: Int64                             - ����
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisAdd(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ��ģϵ���ӷ���RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     P1: TCnInt64Polynomial                               - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisSub(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ��ģϵ��������RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     P1: TCnInt64Polynomial                               - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisMul(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ��ģϵ���˷���RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ����һ
     P1: TCnInt64Polynomial                               - ������
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64RationalPolynomialGaloisDiv(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
{* һԪ��ϵ�������ʽ����ϵ������ʽ��ģϵ��������RationalResult ������ R1��

   ������
     R1: TCnInt64RationalPolynomial                       - ������
     P1: TCnInt64Polynomial                               - ����
     RationalResult: TCnInt64RationalPolynomial           - �������ɽ����һԪ��ϵ�������ʽ
     Prime: Int64                                         - ģ��

   ����ֵ�����ޣ�
}

function Int64RationalPolynomialGaloisCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64RationalPolynomial; P: TCnInt64RationalPolynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial = nil): Boolean; overload;
{* һԪ��ϵ�������ʽģϵ��������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ�

   ������
     Res: TCnInt64RationalPolynomial      - �������ɽ����һԪ��ϵ�������ʽ
     F: TCnInt64RationalPolynomial        - ����ԭʽ
     P: TCnInt64RationalPolynomial        - ������ʽ
     Prime: Int64                         - ģ��
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64RationalPolynomialGaloisCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64RationalPolynomial; P: TCnInt64Polynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial = nil): Boolean; overload;
{* һԪ��ϵ�������ʽģϵ��������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnInt64RationalPolynomial      - �������ɽ����һԪ��ϵ�������ʽ
     F: TCnInt64RationalPolynomial        - ����ԭʽ
     P: TCnInt64Polynomial                - ������ʽ
     Prime: Int64                         - ģ��
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64RationalPolynomialGaloisCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64Polynomial; P: TCnInt64RationalPolynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial = nil): Boolean; overload;
{* һԪ��ϵ�������ʽģϵ��������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnInt64RationalPolynomial      - �������ɽ����һԪ��ϵ�������ʽ
     F: TCnInt64Polynomial                - ����ԭʽ
     P: TCnInt64RationalPolynomial        - ������ʽ
     Prime: Int64                         - ģ��
     Primitive: TCnInt64Polynomial        - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64RationalPolynomialGaloisGetValue(F: TCnInt64RationalPolynomial;
  X: Int64; Prime: Int64): Int64;
{* һԪ��ϵ�������ʽģϵ����ֵ��Ҳ����ģ���� F(x)�������ó˷�ģ��Ԫ��ʾ��

   ������
     F: TCnInt64RationalPolynomial        - ����ֵ��һԪ��ϵ�������ʽ
     X: Int64                             - δ֪����ֵ
     Prime: Int64                         - ģ��

   ����ֵ��Int64                          - ������ֵ���
}

// ===================== һԪ����ϵ������ʽ�������� ============================

function BigNumberPolynomialNew: TCnBigNumberPolynomial;
{* ����һ����̬�����һԪ����ϵ������ʽ���󣬵�ͬ�� TCnBigNumberPolynomial.Create��

   ������
     ���ޣ�

   ����ֵ��TCnBigNumberPolynomial         - ���ش�����һԪ����ϵ������ʽ����
}

procedure BigNumberPolynomialFree(P: TCnBigNumberPolynomial);
{* �ͷ�һ��һԪ����ϵ������ʽ���󣬵�ͬ�� TCnBigNumberPolynomial.Free��

   ������
     P: TCnBigNumberPolynomial            - ���ͷŵ�һԪ����ϵ������ʽ����

   ����ֵ�����ޣ�
}

function BigNumberPolynomialDuplicate(P: TCnBigNumberPolynomial): TCnBigNumberPolynomial;
{* ��һ��һԪ����ϵ������ʽ�����¡һ���¶���

   ������
     P: TCnBigNumberPolynomial            - �����Ƶ�һԪ����ϵ������ʽ

   ����ֵ��TCnBigNumberPolynomial         - �����½���һԪ����ϵ������ʽ
}

function BigNumberPolynomialCopy(Dst: TCnBigNumberPolynomial;
  Src: TCnBigNumberPolynomial): TCnBigNumberPolynomial;
{* ����һ��һԪ����ϵ������ʽ���󣬳ɹ����� Dst��

   ������
     Dst: TCnBigNumberPolynomial          - Ŀ��һԪ����ϵ������ʽ
     Src: TCnBigNumberPolynomial          - ԴһԪ����ϵ������ʽ

   ����ֵ��TCnBigNumberPolynomial         - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function BigNumberPolynomialToString(P: TCnBigNumberPolynomial;
  const VarName: string = 'X'): string;
{* ��һ��һԪ����ϵ������ʽ����ת���ַ�����δ֪��Ĭ���� X ��ʾ��

   ������
     P: TCnBigNumberPolynomial            - ��ת����һԪ����ϵ������ʽ
     const VarName: string                - ����δ֪�����ַ���

   ����ֵ��string                         - �����ַ���
}

function BigNumberPolynomialSetString(P: TCnBigNumberPolynomial;
  const Str: string; const VarName: string = 'X'): Boolean;
{* ���ַ�����ʽ��һԪ����ϵ������ʽ��ֵ����ϵ������ʽ���󣬷����Ƿ�ֵ�ɹ���

   ������
     P: TCnBigNumberPolynomial            - ����ֵ��һԪ����ϵ������ʽ
     const Str: string                    - ����ʽ�ַ���
     const VarName: string                - ����δ֪�����ַ���

   ����ֵ��Boolean                        - �����Ƿ�ֵ�ɹ�
}

function BigNumberPolynomialIsZero(P: TCnBigNumberPolynomial): Boolean;
{* �ж�һ��һԪ����ϵ������ʽ�����Ƿ�Ϊ 0��

   ������
     P: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

procedure BigNumberPolynomialSetZero(P: TCnBigNumberPolynomial);
{* ��һ��һԪ����ϵ������ʽ������Ϊ 0��

   ������
     P: TCnBigNumberPolynomial            - �����õ�һԪ����ϵ������ʽ

   ����ֵ�����ޣ�
}

function BigNumberPolynomialIsOne(P: TCnBigNumberPolynomial): Boolean;
{* �ж�һ��һԪ����ϵ������ʽ�����Ƿ�Ϊ 1��

   ������
     P: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 1
}

procedure BigNumberPolynomialSetOne(P: TCnBigNumberPolynomial);
{* ��һ��һԪ����ϵ������ʽ������Ϊ 1��

   ������
     P: TCnBigNumberPolynomial            - �����õ�һԪ����ϵ������ʽ

   ����ֵ�����ޣ�
}

function BigNumberPolynomialIsNegOne(P: TCnBigNumberPolynomial): Boolean;
{* �ж�һ��һԪ����ϵ������ʽ�����Ƿ�Ϊ -1��

   ������
     P: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ -1��
}

procedure BigNumberPolynomialNegate(P: TCnBigNumberPolynomial);
{* ��һ��һԪ����ϵ������ʽ��������ϵ���󷴡�

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ

   ����ֵ�����ޣ�
}

function BigNumberPolynomialIsMonic(P: TCnBigNumberPolynomial): Boolean;
{* �ж�һ��һԪ����ϵ������ʽ�Ƿ�����һ����ʽ��Ҳ�����ж���ߴ�ϵ���Ƿ�Ϊ 1��

   ������
     P: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ���һ����ʽ
}

procedure BigNumberPolynomialShiftLeft(P: TCnBigNumberPolynomial; N: Integer);
{* ��һ��һԪ����ϵ������ʽ�������� N �Σ�Ҳ���Ǹ���ָ������ N��

   ������
     P: TCnBigNumberPolynomial            - �����Ƶ�һԪ����ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialShiftRight(P: TCnBigNumberPolynomial; N: Integer);
{* ��һ��һԪ����ϵ������ʽ�������� N �Σ�Ҳ���Ǹ���ָ������ N��С�� 0 �ĺ����ˡ�

   ������
     P: TCnBigNumberPolynomial            - �����Ƶ�һԪ����ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

function BigNumberPolynomialEqual(A: TCnBigNumberPolynomial; B: TCnBigNumberPolynomial): Boolean;
{* �ж�����һԪ����ϵ������ʽÿ��ϵ���Ƿ��Ӧ��ȣ����򷵻� True��

   ������
     A: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽһ
     B: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����
}

// ======================== һԪ����ϵ������ʽ��ͨ���� =============================

procedure BigNumberPolynomialAddWord(P: TCnBigNumberPolynomial; N: Cardinal);
{* ��һ��һԪ����ϵ������ʽ����ĳ�ϵ������ N��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ��ϵ������

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialSubWord(P: TCnBigNumberPolynomial; N: Cardinal);
{* ��һ��һԪ����ϵ������ʽ����ĳ�ϵ����ȥ N��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ��ϵ������

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialMulWord(P: TCnBigNumberPolynomial; N: Cardinal);
{* ��һ��һԪ����ϵ������ʽ����ĸ���ϵ�������� N��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialDivWord(P: TCnBigNumberPolynomial; N: Cardinal);
{* ��һ��һԪ����ϵ������ʽ����ĸ���ϵ�������� N���粻��������ȡ����

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialNonNegativeModWord(P: TCnBigNumberPolynomial; N: Cardinal);
{* ��һ��һԪ����ϵ������ʽ����ĸ���ϵ������ N �Ǹ����࣬�������������򻯡�

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialAddBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
{* ��һ��һԪ����ϵ������ʽ����ĳ�ϵ�����ϴ��� N��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialSubBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
{* ��һ��һԪ����ϵ������ʽ����ĳ�ϵ����ȥ���� N��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialMulBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
{* ��һ��һԪ����ϵ������ʽ����ĸ���ϵ�������Դ��� N��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialDivBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
{* ��һ��һԪ����ϵ������ʽ����ĸ���ϵ�������Դ��� N���粻��������ȡ����

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialNonNegativeModBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
{* ��һ��һԪ����ϵ������ʽ����ĸ���ϵ�����Դ��� N �Ǹ����ࡣ

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

function BigNumberPolynomialAdd(Res: TCnBigNumberPolynomial; P1: TCnBigNumberPolynomial;
  P2: TCnBigNumberPolynomial): Boolean;
{* ����һԪ����ϵ������ʽ������ӣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ����һ
     P2: TCnBigNumberPolynomial           - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialSub(Res: TCnBigNumberPolynomial; P1: TCnBigNumberPolynomial;
  P2: TCnBigNumberPolynomial): Boolean;
{* ����һԪ����ϵ������ʽ���������������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ������
     P2: TCnBigNumberPolynomial           - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialMul(Res: TCnBigNumberPolynomial; P1: TCnBigNumberPolynomial;
  P2: TCnBigNumberPolynomial): Boolean;
{* ����һԪ����ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ����һ
     P2: TCnBigNumberPolynomial           - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialDiv(Res: TCnBigNumberPolynomial; Remain: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Divisor: TCnBigNumberPolynomial; ErrMulFactor: TCnBigNumber = nil): Boolean;
{* ����һԪ����ϵ������ʽ����������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   ע�⵱��ʽ����ʽ�����޷������ķ���ʱ�᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   ���� False ʱ�� ErrMulFactor ������Ϊ�գ���᷵�ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     Remain: TCnBigNumberPolynomial       - ��������������һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ������
     Divisor: TCnBigNumberPolynomial      - ����
     ErrMulFactor: TCnBigNumber           - ����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialMod(Res: TCnBigNumberPolynomial; P: TCnBigNumberPolynomial;
  Divisor: TCnBigNumberPolynomial; ErrMulFactor: TCnBigNumber = nil): Boolean;
{* ����һԪ����ϵ������ʽ�������࣬�������� Res �У����������Ƿ�ɹ���
   ע�⵱��ʽ����ʽ�����޷������ķ���ʱ�᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   ���� False ʱ�� ErrMulFactor ������Ϊ�գ���᷵�ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ��
   Res ������ P �� Divisor��P ������ Divisor��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ������
     Divisor: TCnBigNumberPolynomial      - ����
     ErrMulFactor: TCnBigNumber           - ����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialPower(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Exponent: TCnBigNumber): Boolean;
{* ����һԪ����ϵ������ʽ�� Exponent ���ݣ������Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ����
     Exponent: TCnBigNumber               - ָ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberPolynomialReduce(P: TCnBigNumberPolynomial);
{* ����һԪ����ϵ������ʽϵ����Ҳ�����Ҷ���ʽϵ�������Լ��������ϵ����������

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialCentralize(P: TCnBigNumberPolynomial; Modulus: TCnBigNumber);
{* ��һԪ����ϵ������ʽϵ���������Ļ�����Ҳ���� [0, M - 1] ��Ϊ [1 - (M + 1) div 2, M div 2]��
   Ҳ������ M div 2 ��ϵ��Ҫ�� M��ע�� Modulus ��һ����������

   ������
     P: TCnBigNumberPolynomial            - �����Ļ���һԪ����ϵ������ʽ
     Modulus: TCnBigNumber                - ģ��

   ����ֵ�����ޣ�
}

function BigNumberPolynomialGreatestCommonDivisor(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial): Boolean;
{* ��������һԪ����ϵ������ʽ�������ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��
   ע�������ܻ���Ϊϵ������������ʧ�ܣ���ʹ���������б�֤ P1 P2 ��Ϊ��һ����ʽҲ���ܱ�֤�С�
   �緵�� False�������߿ɸɴ���Ϊ���أ������ʽΪ 1��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - �����������ʽ��һԪ����ϵ������ʽһ
     P2: TCnBigNumberPolynomial           - �����������ʽ��һԪ����ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialLeastCommonMultiple(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial): Boolean;
{* ��������һԪ����ϵ������ʽ����С����ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��
   ע�������ܻ���Ϊϵ������������ʧ�ܣ���ʹ���������б�֤ P1 P2 ��Ϊ��һ����ʽҲ���ܱ�֤�С�
   �緵�� False�������߿ɸɴ���Ϊ���أ���С����ʽΪ������ˣ������м��㡣

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ��������С����ʽ��һԪ����ϵ������ʽһ
     P2: TCnBigNumberPolynomial           - ��������С����ʽ��һԪ����ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialCompose(Res: TCnBigNumberPolynomial;
  F: TCnBigNumberPolynomial; P: TCnBigNumberPolynomial): Boolean;
{* һԪ����ϵ������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���Res ������ F �� P��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     F: TCnBigNumberPolynomial            - ����ԭʽ
     P: TCnBigNumberPolynomial            - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberPolynomialGetValue(Res: TCnBigNumber; F: TCnBigNumberPolynomial;
  X: TCnBigNumber);
{* һԪ����ϵ������ʽ��ֵ��Ҳ���Ǽ��� F(x)�������Ƿ����ɹ���Res ������ X��

   ������
     Res: TCnBigNumber                    - �������ɽ���Ĵ�������
     F: TCnBigNumberPolynomial            - ����ֵ��һԪ����ϵ������ʽ
     X: TCnBigNumber                      - δ֪����ֵ

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialReduce2(P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial);
{* �������һԪ����ϵ������ʽ����Լ�֣�Ҳ�����������أ����������ʽԼ�����㡣

   ������
     P1: TCnBigNumberPolynomial           - ��Լ�ֵ�һԪ����ϵ������ʽһ
     P2: TCnBigNumberPolynomial           - ��Լ�ֵ�һԪ����ϵ������ʽ��

   ����ֵ�����ޣ�
}

// ===================== ���������µ���ϵ������ʽģ���� ========================

function BigNumberPolynomialGaloisEqual(A: TCnBigNumberPolynomial;
  B: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean;
{* ����һԪ����ϵ������ʽ��ģ Prime ���������Ƿ����

   ������
     A: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽһ
     B: TCnBigNumberPolynomial            - ���жϵ�һԪ����ϵ������ʽ��
     Prime: TCnBigNumber                  - ģ��

   ����ֵ��Boolean                        - �����Ƿ����
}

procedure BigNumberPolynomialGaloisNegate(P: TCnBigNumberPolynomial;
  Prime: TCnBigNumber);
{* ��һ��һԪ����ϵ������ʽ��������ϵ����ģ Prime ����������

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     Prime: TCnBigNumber                  - ģ��

   ����ֵ�����ޣ�
}

function BigNumberPolynomialGaloisAdd(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
{* ����һԪ����ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ����һ
     P2: TCnBigNumberPolynomial           - ������
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisSub(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
{* ����һԪ����ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ������
     P2: TCnBigNumberPolynomial           - ����
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisMul(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
{* ����һԪ����ϵ������ʽ������ Prime �η�������������ˣ�������� Res �У�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ����һ
     P2: TCnBigNumberPolynomial           - ������
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisDiv(Res: TCnBigNumberPolynomial;
  Remain: TCnBigNumberPolynomial; P: TCnBigNumberPolynomial;
  Divisor: TCnBigNumberPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial = nil; ErrMulFactor: TCnBigNumber = nil): Boolean;
{* ����һԪ����ϵ������ʽ������ Prime �η�����������������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     Remain: TCnBigNumberPolynomial       - ����������ʽ��һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ������
     Divisor: TCnBigNumberPolynomial      - ����
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ
     ErrMulFactor: TCnBigNumber           - ����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisMod(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Divisor: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil; ErrMulFactor: TCnBigNumber = nil): Boolean;
{* ����һԪ����ϵ������ʽ������ Prime �η��������������࣬�������� Res �У����������Ƿ�ɹ���
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   Res ������ P �� Divisor��P ������ Divisor��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ������
     Divisor: TCnBigNumberPolynomial      - ����
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ
     ErrMulFactor: TCnBigNumber           - ����ֵ False ʱ�˴��ɷ��ر���ʽ��ϵ��Ӧ�����϶��ٲſ���������ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisPower(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Exponent: TCnBigNumber; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial = nil): Boolean; overload;
{* ����һԪ����ϵ������ʽ�� Prime �η����������ϵ� Exponent ���ݣ�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   �����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ����
     Exponent: TCnBigNumber               - ָ��
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisPower(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Exponent: Cardinal; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial = nil): Boolean; overload;
{* ����һԪ����ϵ������ʽ�� Prime �η����������ϵ� Exponent ���ݣ�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   �����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberPolynomial            - ����
     Exponent: Cardinal                   - ָ��
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisAddWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ�ĳ�ϵ������ N �� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ��ϵ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisSubWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ�ĳ�ϵ����ȥ N �� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ��ϵ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisMulWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ����ϵ������ N �� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisDivWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
{* �� Prime �η����������ϵ���ϵ������ʽ����ϵ������ N��Ҳ���ǳ��� N ����Ԫ�� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: Cardinal                          - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberPolynomialGaloisAddBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ�ĳ�ϵ������ N �� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ��ϵ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialGaloisSubBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ�ĳ�ϵ����ȥ N �� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ��ϵ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialGaloisMulBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ����ϵ������ N �� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialGaloisDivBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ����ϵ������ N��Ҳ���ǳ��� N ����Ԫ�� mod Prime��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     N: TCnBigNumber                      - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialGaloisMonic(P: TCnBigNumberPolynomial; Prime: TCnBigNumber);
{* �� Prime �η����������ϵ�һԪ����ϵ������ʽ����ϵ��ͬ������ʹ����Ϊһ��

   ������
     P: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

function BigNumberPolynomialGaloisGreatestCommonDivisor(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean;
{* ��������һԪ����ϵ������ʽ�� Prime �η����������ϵ������ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - �����������ʽ��һԪ����ϵ������ʽһ
     P2: TCnBigNumberPolynomial           - �����������ʽ��һԪ����ϵ������ʽ��
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisLeastCommonMultiple(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean;
{* ��������һԪ����ϵ������ʽ�� Prime �η����������ϵ���С����ʽ�������Ƿ����ɹ���Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P1: TCnBigNumberPolynomial           - ��������С����ʽ��һԪ����ϵ������ʽһ
     P2: TCnBigNumberPolynomial           - ��������С����ʽ��һԪ����ϵ������ʽ��
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberPolynomialGaloisExtendedEuclideanGcd(A: TCnBigNumberPolynomial;
  B: TCnBigNumberPolynomial; X: TCnBigNumberPolynomial; Y: TCnBigNumberPolynomial;
  Prime: TCnBigNumber);
{* ��չŷ�����շת������� Prime �η��������������Ԫһ�β���һԪ����ϵ������ʽ���� A * X + B * Y = 1 �Ľ⡣

   ������
     A: TCnBigNumberPolynomial            - ��Ԫһ�β�������ϵ������ʽ����ϵ�� A
     B: TCnBigNumberPolynomial            - ��Ԫһ�β�������ϵ������ʽ����ϵ�� B
     X: TCnBigNumberPolynomial            - �������ɽ�� X ��һԪ����ϵ������ʽ
     Y: TCnBigNumberPolynomial            - �������ɽ�� Y ��һԪ����ϵ������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberPolynomialGaloisModularInverse(Res: TCnBigNumberPolynomial;
  X: TCnBigNumberPolynomial; Modulus: TCnBigNumberPolynomial; Prime: TCnBigNumber;
  CheckGcd: Boolean = False);
{* ��һԪ����ϵ������ʽ X �� Prime �η�������������� Modulus ��ģ������ʽ���ģ��Ԫ����ʽ Y��
   ���� (X * Y) mod M = 1���������뾡����֤ X��Modulus ���أ��� Res ����Ϊ X �� Modulus��
   CheckGcd ����Ϊ True ʱ���ڲ����� X��Modulus �Ƿ��ء�

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     X: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     Modulus: TCnBigNumberPolynomial      - ģ��
     Prime: TCnBigNumber                  - �������Ͻ�
     CheckGcd: Boolean                    - �Ƿ��黥��

   ����ֵ�����ޣ�
}

function BigNumberPolynomialGaloisPrimePowerModularInverse(Res: TCnBigNumberPolynomial;
  X: TCnBigNumberPolynomial; Modulus: TCnBigNumberPolynomial; PrimeRoot: TCnBigNumber;
  Exponent: Integer): Boolean;
{* ��һԪ����ϵ������ʽ X �������Ķ����ģ��Ҳ���� PrimeRoot �� Exponent �η����������ϣ�
   ��� Modulus �� X ��ģ������ʽ���ģ��Ԫ����ʽ Y������ (X * Y) mod M = 1��
   ���������Ƿ�ɹ���Res ����Ϊ X �� Modulus��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     X: TCnBigNumberPolynomial            - �������һԪ����ϵ������ʽ
     Modulus: TCnBigNumberPolynomial      - ģ��
     PrimeRoot: TCnBigNumber              - ����������
     Exponent: Integer                    - ������ָ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisCompose(Res: TCnBigNumberPolynomial;
  F: TCnBigNumberPolynomial; P: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
{* �� Prime �η����������Ͻ���һԪ����ϵ������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���Res ������ F �� P��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     F: TCnBigNumberPolynomial            - ����ԭʽ
     P: TCnBigNumberPolynomial            - ������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisGetValue(Res: TCnBigNumber;
  F: TCnBigNumberPolynomial; X: TCnBigNumber; Prime: TCnBigNumber): Boolean;
{* �� Prime �η����������Ͻ���һԪ����ϵ������ʽ��ֵ��Ҳ���Ǽ��� F(x)�������Ƿ����ɹ���

   ������
     Res: TCnBigNumber                    - �������ɽ���Ĵ�������
     F: TCnBigNumberPolynomial            - ����ֵ��һԪ����ϵ������ʽ
     X: TCnBigNumber                      - δ֪����ֵ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisCalcDivisionPolynomial(A: Integer; B: Integer;
  Degree: Integer; OutDivisionPolynomial: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean; overload;
{* �ݹ����ָ����Բ������ Prime �η����������ϵ� N �׿ɳ�����ʽ�������Ƿ����ɹ���
   ע�� Degree ������ʱ���ɳ�����ʽ�Ǵ� x �Ķ���ʽ��ż��ʱ���ǣ�x �Ķ���ʽ��* y ����ʽ��
   �����ֻ���� x �Ķ���ʽ���֣�Ҳ���� f ����ʽ��ż��ʱ�Ѿ����� y�������� ������ʽ��
   ���� A B �� 32 λ�з���������

   ������
     A: Integer                                           - κ��˹����˹��Բ���߷��̵� a ����
     B: Integer                                           - κ��˹����˹��Բ���߷��̵� b ����
     Degree: Integer                                      - �����Ŀɳ�����ʽ����
     OutDivisionPolynomial: TCnBigNumberPolynomial        - �������ɽ����һԪ����ϵ������ʽ
     Prime: TCnBigNumber                                  - �������Ͻ�

   ����ֵ��Boolean                                        - �����Ƿ����ɹ�
}

function BigNumberPolynomialGaloisCalcDivisionPolynomial(A: TCnBigNumber; B: TCnBigNumber;
  Degree: Integer; OutDivisionPolynomial: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean; overload;
{* �ݹ����ָ����Բ������ Prime �η����������ϵ� N �׿ɳ�����ʽ�������Ƿ����ɹ�
   ע�� Degree ������ʱ���ɳ�����ʽ�Ǵ� x �Ķ���ʽ��ż��ʱ���ǣ�x �Ķ���ʽ��* y ����ʽ��
   �����ֻ���� x �Ķ���ʽ���֡�
   ����ο��� F. MORAIN �����²����ϳ��� 2 ���Ƶ�����
  ��COMPUTING THE CARDINALITY OF CM ELLIPTIC CURVES USING TORSION POINTS��

   ������
     A: TCnBigNumber                                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                                      - κ��˹����˹��Բ���߷��̵� b ����
     Degree: Integer                                      - �����Ŀɳ�����ʽ����
     OutDivisionPolynomial: TCnBigNumberPolynomial        - �������ɽ����һԪ����ϵ������ʽ
     Prime: TCnBigNumber                                  - �������Ͻ�

   ����ֵ��Boolean                                        - �����Ƿ����ɹ�
}

procedure BigNumberPolynomialGaloisReduce2(P1: TCnBigNumberPolynomial;
  P2: TCnBigNumberPolynomial; Prime: TCnBigNumber);
{* �� Prime �η������������������һԪ����ϵ������ʽ����Լ�֣�Ҳ�����������أ����������ʽԼ������

   ������
     P1: TCnBigNumberPolynomial           - ��Լ�ֵ�һԪ����ϵ������ʽһ
     P2: TCnBigNumberPolynomial           - ��Լ�ֵ�һԪ����ϵ������ʽ��
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

// ===================== һԪ����ϵ�������ʽ�������� ==========================

function BigNumberRationalPolynomialEqual(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial): Boolean;
{* �Ƚ�����һԪ����ϵ�������ʽ�Ƿ���ȡ�

   ������
     R1: TCnBigNumberRationalPolynomial   - ���Ƚϵ�һԪ����ϵ�������ʽһ
     R2: TCnBigNumberRationalPolynomial   - ���Ƚϵ�һԪ����ϵ�������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����
}

function BigNumberRationalPolynomialCopy(Dst: TCnBigNumberRationalPolynomial;
  Src: TCnBigNumberRationalPolynomial): TCnBigNumberRationalPolynomial;
{* һԪ����ϵ�������ʽ���ơ�

   ������
     Dst: TCnBigNumberRationalPolynomial  - Ŀ��һԪ����ϵ�������ʽ
     Src: TCnBigNumberRationalPolynomial  - ԴһԪ����ϵ�������ʽ

   ����ֵ��TCnBigNumberRationalPolynomial - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

procedure BigNumberRationalPolynomialAdd(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��ͨ�ӷ�����������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     R2: TCnBigNumberRationalPolynomial                   - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialSub(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��ͨ��������������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     R2: TCnBigNumberRationalPolynomial                   - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialMul(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��ͨ�˷�����������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     R2: TCnBigNumberRationalPolynomial                   - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialDiv(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��ͨ��������������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     R2: TCnBigNumberRationalPolynomial                   - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialAddBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
{* һԪ����ϵ�������ʽ��ͨ�ӷ�������һ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialSubBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
{* һԪ����ϵ�������ʽ��ͨ��������ȥһ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialMulBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
{* һԪ����ϵ�������ʽ��ͨ�˷�������һ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialDivBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
{* һԪ����ϵ�������ʽ��ͨ����������һ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialAdd(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ����ͨ�ӷ���RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     P1: TCnBigNumberPolynomial                           - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialSub(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ����ͨ������RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     P1: TCnBigNumberPolynomial                           - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialMul(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ����ͨ�˷���RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     P1: TCnBigNumberPolynomial                           - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialDiv(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
{* һԪ����ϵ�������ʽ����ϵ������ʽ����ͨ������RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     P1: TCnBigNumberPolynomial                           - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

function BigNumberRationalPolynomialCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberRationalPolynomial; P: TCnBigNumberRationalPolynomial): Boolean; overload;
{* һԪ����ϵ�������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnBigNumberRationalPolynomial  - �������ɽ����һԪ����ϵ�������ʽ
     F: TCnBigNumberRationalPolynomial    - ����ԭʽ
     P: TCnBigNumberRationalPolynomial    - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberRationalPolynomialCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberRationalPolynomial; P: TCnBigNumberPolynomial): Boolean; overload;
{* һԪ����ϵ�������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnBigNumberRationalPolynomial  - �������ɽ����һԪ����ϵ�������ʽ
     F: TCnBigNumberRationalPolynomial    - ����ԭʽ
     P: TCnBigNumberPolynomial            - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberRationalPolynomialCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberPolynomial; P: TCnBigNumberRationalPolynomial): Boolean; overload;
{* ��ϵ�������ʽ������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnBigNumberRationalPolynomial  - �������ɽ����һԪ����ϵ�������ʽ
     F: TCnBigNumberPolynomial            - ����ԭʽ
     P: TCnBigNumberRationalPolynomial    - ������ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberRationalPolynomialGetValue(Res: TCnBigRational;
  F: TCnBigNumberRationalPolynomial; X: TCnBigNumber);
{* һԪ����ϵ�������ʽ��ֵ��Ҳ���Ǽ��� F(x)����������� Res �С�

   ������
     F: TCnBigNumberRationalPolynomial    - ����ֵ��һԪ����ϵ�������ʽ
     X: TCnBigNumber                      - δ֪����ֵ
     Res: TCnBigRational                  - �������ɽ����һԪ����ϵ�������ʽ

   ����ֵ�����ޣ�
}

// ================== һԪ����ϵ�������ʽ���������ϵ�ģ���� ===================

function BigNumberRationalPolynomialGaloisEqual(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
{* �Ƚ�����һԪ����ϵ��ģϵ�������ʽ�Ƿ���ȡ�

   ������
     R1: TCnBigNumberRationalPolynomial   - ���Ƚϵ�һԪ����ϵ�������ʽһ
     R2: TCnBigNumberRationalPolynomial   - ���Ƚϵ�һԪ����ϵ�������ʽ��
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����
}

procedure BigNumberRationalPolynomialGaloisNegate(P: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber);
{* ��һ��һԪ����ϵ�������ʽ������ӵ�����ϵ����ģ Prime ���������󷴡�

   ������
     P: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisAdd(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽģϵ���ӷ�����������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     R2: TCnBigNumberRationalPolynomial                   - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisSub(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽģϵ����������������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     R2: TCnBigNumberRationalPolynomial                   - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisMul(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽģϵ���˷�����������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     R2: TCnBigNumberRationalPolynomial                   - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisDiv(R1: TCnBigNumberRationalPolynomial;
  R2: TCnBigNumberRationalPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽģϵ����������������������ͬһ����

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     R2: TCnBigNumberRationalPolynomial                   - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisAddBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
{* һԪ����ϵ�������ʽģϵ���ӷ�������һ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����
     Prime: TCnBigNumber                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisSubBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
{* һԪ����ϵ�������ʽģϵ����������ȥһ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����
     Prime: TCnBigNumber                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisMulBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
{* һԪ����ϵ�������ʽģϵ���˷�������һ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����
     Prime: TCnBigNumber                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisDivBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
{* һԪ����ϵ�������ʽģϵ������������һ��������

   ������
     R: TCnBigNumberRationalPolynomial    - �������һԪ����ϵ�������ʽ
     Num: TCnBigNumber                    - ����
     Prime: TCnBigNumber                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisAdd(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ��ģϵ���ӷ���RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     P1: TCnBigNumberPolynomial                           - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisSub(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ��ģϵ��������RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     P1: TCnBigNumberPolynomial                           - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisMul(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ��ģϵ���˷���RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ����һ
     P1: TCnBigNumberPolynomial                           - ������
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

procedure BigNumberRationalPolynomialGaloisDiv(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber); overload;
{* һԪ����ϵ�������ʽ��һԪ����ϵ������ʽ��ģϵ��������RationalResult ������ R1��

   ������
     R1: TCnBigNumberRationalPolynomial                   - ������
     P1: TCnBigNumberPolynomial                           - ����
     RationalResult: TCnBigNumberRationalPolynomial       - �������ɽ����һԪ����ϵ�������ʽ
     Prime: TCnBigNumber                                  - ģ��

   ����ֵ�����ޣ�
}

function BigNumberRationalPolynomialGaloisCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberRationalPolynomial; P: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial = nil): Boolean; overload;
{* һԪ����ϵ�������ʽģϵ��������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnBigNumberRationalPolynomial  - �������ɽ����һԪ����ϵ�������ʽ
     F: TCnBigNumberRationalPolynomial    - ����ԭʽ
     P: TCnBigNumberRationalPolynomial    - ������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberRationalPolynomialGaloisCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberRationalPolynomial; P: TCnBigNumberPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial = nil): Boolean; overload;
{* һԪ����ϵ�������ʽģϵ��������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnBigNumberRationalPolynomial  - �������ɽ����һԪ����ϵ�������ʽ
     F: TCnBigNumberRationalPolynomial    - ����ԭʽ
     P: TCnBigNumberPolynomial            - ������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberRationalPolynomialGaloisCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberPolynomial; P: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial = nil): Boolean; overload;
{* һԪ����ϵ�������ʽģϵ��������Ҳ���Ǽ��� F(P(x))�������Ƿ����ɹ���

   ������
     Res: TCnBigNumberRationalPolynomial  - �������ɽ����һԪ����ϵ�������ʽ
     F: TCnBigNumberPolynomial            - ����ԭʽ
     P: TCnBigNumberRationalPolynomial    - ������ʽ
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberPolynomial    - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberRationalPolynomialGaloisGetValue(Res: TCnBigNumber;
  F: TCnBigNumberRationalPolynomial; X: TCnBigNumber; Prime: TCnBigNumber);
{* һԪ����ϵ�������ʽģϵ����ֵ��Ҳ����ģ���� F(x)�������ó˷�ģ��Ԫ��ʾ��

   ������
     Res: TCnBigNumber                    - �������ɽ���Ĵ�������
     F: TCnBigNumberRationalPolynomial    - ����ֵ��һԪ����ϵ�������ʽ
     X: TCnBigNumber                      - δ֪����ֵ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

// =============================================================================
//
//                            ��Ԫ��ϵ������ʽ
//
// =============================================================================

{
   FXs TObjectList
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | X^n   �� Y ϵ�� List  | -> | X^n*Y^0 ��ϵ��  |X^n*Y^1 ��ϵ��   | ......
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | X^n-1 �� Y ϵ�� List  | -> | X^n-1*Y^0 ��ϵ��|X^n-1*Y^1 ��ϵ�� | ......
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |......                 | -> |
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | X^0   �� Y ϵ�� List  | -> | X^0*Y^0 ��ϵ��  | X^0*Y^1 ��ϵ��  | ......
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

}
type
  TCnInt64BiPolynomial = class
  {* ��Ԫ��ϵ������ʽ���ڲ�ʵ�ַ�ϡ�裬���һ������ױ��ڴ�}
  private
    FXs: TObjectList; // Ԫ��Ϊ TCnInt64List���洢�� X ���ݵ�ÿһ����ͬ�� Y ���ݵ�ϵ��
    procedure EnsureDegrees(XDegree: Integer; YDegree: Integer);
    {* ȷ�� XDegree, YDegree ��Ԫ�ش���}
    function GetMaxXDegree: Integer;
    function GetMaxYDegree: Integer;
    procedure SetMaxXDegree(const Value: Integer);
    procedure SetMaxYDegree(const Value: Integer);
    function GetYFactorsList(Index: Integer): TCnInt64List;
    function GetSafeValue(XDegree: Integer; YDegree: Integer): Int64;
    procedure SetSafeValue(XDegree: Integer; YDegree: Integer; const Value: Int64);
  protected
    function CompactYDegree(YList: TCnInt64List): Boolean;
    {* ȥ��һ�� Y ϵ���ߴ������ȫ 0 �򷵻� True��

       ������
         YList: TCnInt64List              - �������ϵ���б�

       ����ֵ��Boolean                    - �����Ƿ�ȫ 0
    }

    property YFactorsList[Index: Integer]: TCnInt64List read GetYFactorsList;
    {* ��װ�Ķ� X �� Index ����� Y ϵ���б�}
    procedure Clear;
    {* �ڲ�����������ݣ�ֻ�� FXs[0] ��һ�� List��һ�㲻����ʹ��}
  public
    constructor Create(XDegree: Integer = 0; YDegree: Integer = 0);
    {* ���캯�������� X �� Y ����ߴ�������Ĭ��Ϊ 0���Ժ��ٲ��衣

       ������
         XDegree: Integer                 - X ����ߴ�ϵ��
         YDegree: Integer                 - Y ����ߴ�ϵ��

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure SetYCoefficentsFromPolynomial(XDegree: Integer; PY: TCnInt64Polynomial);
    {* ����ض������� X����һԪ�� Y ����ʽ��һ���������� Y ��ϵ����

       ������
         XDegree: Integer                 - X ����
         PY: TCnInt64Polynomial           - ���� Y ϵ���б�Ķ���ʽ

       ����ֵ�����ޣ�
    }

    procedure SetYCoefficents(XDegree: Integer; LowToHighYCoefficients: array of const);
    {* ����ض������� X��һ���������� Y �ӵ͵��ߵ�ϵ����

       ������
         XDegree: Integer                                 - X ����
         LowToHighYCoefficients: array of const           - Y ϵ���б�

       ����ֵ�����ޣ�
    }

    procedure SetXCoefficents(YDegree: Integer; LowToHighXCoefficients: array of const);
    {* ����ض������� Y��һ���������� X �ӵ͵��ߵ�ϵ����

       ������
         YDegree: Integer                                 - Y ����
         LowToHighYCoefficients: array of const           - X ϵ���б�

       ����ֵ�����ޣ�
    }

    procedure SetXYCoefficent(XDegree: Integer; YDegree: Integer; ACoefficient: Int64);
    {* ����ض������� X �� Y��������ϵ����

       ������
         XDegree: Integer                 - X ����
         YDegree: Integer                 - Y ����
         ACoefficient: Int64              - ϵ��

       ����ֵ�����ޣ�
    }

    procedure CorrectTop;
    {* �޳��ߴε� 0 ϵ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ʽת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetString(const Poly: string);
    {* ������ʽ�ַ���ת��Ϊ����������ݡ�

       ������
         const Poly: string               - ��ת�����ַ���

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �����Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    procedure SetZero;
    {* ��Ϊ 0}

    procedure SetOne;
    {* ��Ϊ 1}

    procedure Negate;
    {* ����ϵ����}

    function IsMonicX: Boolean;
    {* �Ƿ��ǹ��� X ����һ����ʽ��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ���� X ����һ����ʽ
    }

    procedure Transpose;
    {* ת�ã�Ҳ���ǻ��� X Y Ԫ}

    property MaxXDegree: Integer read GetMaxXDegree write SetMaxXDegree;
    {* X Ԫ����ߴ�����0 ��ʼ������ Count ����ֻ���� Integer}
    property MaxYDegree: Integer read GetMaxYDegree write SetMaxYDegree;
    {* X Ԫ����ߴ�����0 ��ʼ������ Count ����ֻ���� Integer}

    property SafeValue[XDegree, YDegree: Integer]: Int64 read GetSafeValue write SetSafeValue;
    {* ��ȫ�Ķ�дϵ����������������ʱ���� 0��д������ʱ�Զ���չ}
  end;

  TCnInt64BiPolynomialPool = class(TCnMathObjectPool)
  {* ��Ԫ��ϵ������ʽ��ʵ���࣬����ʹ�õ���Ԫ��ϵ������ʽ�ĵط����д�����Ԫ��ϵ������ʽ��}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnInt64BiPolynomial; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnInt64BiPolynomial       - ���صĶ���ʽ����
    }

    procedure Recycle(Poly: TCnInt64BiPolynomial); reintroduce;
    {* ��һ������黹������ء�

       ������
         Poly: TCnInt64BiPolynomial       - ���黹�Ķ���ʽ����

       ����ֵ�����ޣ�
    }
  end;

function Int64BiPolynomialNew: TCnInt64BiPolynomial;
{* ����һ����Ԫ��ϵ������ʽ���󣬵�ͬ�� TCnInt64BiPolynomial.Create��

   ������
     ���ޣ�

   ����ֵ��TCnInt64BiPolynomial           - ���ش����Ķ�Ԫ��ϵ������ʽ����
}

procedure Int64BiPolynomialFree(P: TCnInt64BiPolynomial);
{* �ͷ�һ����Ԫ��ϵ������ʽ���󣬵�ͬ�� TCnInt64BiPolynomial.Free��

   ������
     P: TCnInt64BiPolynomial              - ���ͷŵĶ�Ԫ��ϵ������ʽ����

   ����ֵ�����ޣ�
}

function Int64BiPolynomialDuplicate(P: TCnInt64BiPolynomial): TCnInt64BiPolynomial;
{* ��һ����Ԫ��ϵ������ʽ�����¡һ���¶���

   ������
     P: TCnInt64BiPolynomial              - �����ƵĶ�Ԫ��ϵ������ʽ

   ����ֵ��TCnInt64BiPolynomial           - �����½��Ķ�Ԫ��ϵ������ʽ
}

function Int64BiPolynomialCopy(Dst: TCnInt64BiPolynomial;
  Src: TCnInt64BiPolynomial): TCnInt64BiPolynomial;
{* ����һ����Ԫ��ϵ������ʽ���󣬳ɹ����� Dst��

   ������
     Dst: TCnInt64BiPolynomial            - Ŀ���Ԫ��ϵ������ʽ
     Src: TCnInt64BiPolynomial            - Դ��Ԫ��ϵ������ʽ

   ����ֵ��TCnInt64BiPolynomial           - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function Int64BiPolynomialCopyFromX(Dst: TCnInt64BiPolynomial;
  SrcX: TCnInt64Polynomial): TCnInt64BiPolynomial;
{* ��һԪ X ��ϵ������ʽ�и���һ����Ԫ��ϵ������ʽ���󣬳ɹ����� Dst��

   ������
     Dst: TCnInt64BiPolynomial            - Ŀ���Ԫ��ϵ������ʽ
     SrcX: TCnInt64Polynomial             - ԴһԪ X ��ϵ������ʽ

   ����ֵ��TCnInt64BiPolynomial           - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function Int64BiPolynomialCopyFromY(Dst: TCnInt64BiPolynomial;
  SrcY: TCnInt64Polynomial): TCnInt64BiPolynomial;
{* ��һԪ Y ��ϵ������ʽ�и���һ����Ԫ��ϵ������ʽ���󣬳ɹ����� Dst

   ������
     Dst: TCnInt64BiPolynomial            - Ŀ���Ԫ��ϵ������ʽ
     SrcY: TCnInt64Polynomial             - ԴһԪ Y ��ϵ������ʽ

   ����ֵ��TCnInt64BiPolynomial           - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function Int64BiPolynomialToString(P: TCnInt64BiPolynomial;
  const Var1Name: string = 'X'; const Var2Name: string = 'Y'): string;
{* ��һ����Ԫ��ϵ������ʽ����ת���ַ�����δ֪��Ĭ���� X �� Y ��ʾ��

   ������
     P: TCnInt64BiPolynomial              - ��ת���Ķ�Ԫ��ϵ������ʽ
     const Var1Name: string               - �����һ��δ֪�����ַ���
     const Var2Name: string               - ����ڶ���δ֪�����ַ���

   ����ֵ��string                         - �����ַ���
}

function Int64BiPolynomialSetString(P: TCnInt64BiPolynomial;
  const Str: string; const Var1Name: string = 'X'; const Var2Name: string = 'Y'): Boolean;
{* ���ַ�����ʽ�Ķ�Ԫ��ϵ������ʽ��ֵ����Ԫ��ϵ������ʽ���󣬷����Ƿ�ֵ�ɹ���

   ������
     P: TCnInt64BiPolynomial              - ����ֵ�Ķ�Ԫ��ϵ������ʽ
     const Str: string                    - ����ʽ�ַ���
     const Var1Name: string               - �����һ��δ֪�����ַ���
     const Var2Name: string               - ����ڶ���δ֪�����ַ���

   ����ֵ��Boolean                        - �����Ƿ�ֵ�ɹ�
}

function Int64BiPolynomialIsZero(P: TCnInt64BiPolynomial): Boolean;
{* �ж�һ����Ԫ��ϵ������ʽ�����Ƿ�Ϊ 0��

   ������
     P: TCnInt64BiPolynomial              - ���жϵĶ�Ԫ��ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

procedure Int64BiPolynomialSetZero(P: TCnInt64BiPolynomial);
{* ��һ����Ԫ��ϵ������ʽ������Ϊ 0��

   ������
     P: TCnInt64BiPolynomial              - �����õĶ�Ԫ��ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialSetOne(P: TCnInt64BiPolynomial);
{* ��һ����Ԫ��ϵ������ʽ������Ϊ 1��

   ������
     P: TCnInt64BiPolynomial              - �����õĶ�Ԫ��ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialNegate(P: TCnInt64BiPolynomial);
{* ��һ����Ԫ��ϵ������ʽ��������ϵ���󷴡�

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ

   ����ֵ�����ޣ�
}

function Int64BiPolynomialIsMonicX(P: TCnInt64BiPolynomial): Boolean;
{* �ж�һ����Ԫ��ϵ������ʽ�Ƿ��ǹ��� X ����һ����ʽ��Ҳ�����ж� X ��ߴε�ϵ���Ƿ�Ϊ 1��

   ������
     P: TCnInt64BiPolynomial              - ���жϵĶ�Ԫ��ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ� X ����һ����ʽ
}

procedure Int64BiPolynomialShiftLeftX(P: TCnInt64BiPolynomial; N: Integer);
{* ��һ����Ԫ��ϵ������ʽ����� X ���� N �Σ�Ҳ���� X ����ָ������ N��

   ������
     P: TCnInt64BiPolynomial              - �����ƵĶ�Ԫ��ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialShiftRightX(P: TCnInt64BiPolynomial; N: Integer);
{* ��һ����Ԫ��ϵ������ʽ����� X ���� N �Σ�Ҳ���� X ����ָ������ N��С�� 0 �ĺ����ˡ�

   ������
     P: TCnInt64BiPolynomial              - �����ƵĶ�Ԫ��ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

function Int64BiPolynomialEqual(A: TCnInt64BiPolynomial; B: TCnInt64BiPolynomial): Boolean;
{* �ж�����Ԫ��ϵ������ʽÿ��ϵ���Ƿ��Ӧ��ȣ����򷵻� True��

   ������
     A: TCnInt64BiPolynomial              - ���жϵĶ�Ԫ��ϵ������ʽһ
     B: TCnInt64BiPolynomial              - ���жϵĶ�Ԫ��ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����
}

// ====================== ��Ԫ��ϵ������ʽ��ͨ���� =============================

procedure Int64BiPolynomialAddWord(P: TCnInt64BiPolynomial; N: Int64);
{* ��һ����Ԫ��ϵ������ʽ����ĸ���ϵ������ N��

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialSubWord(P: TCnInt64BiPolynomial; N: Int64);
{* ��һ����Ԫ��ϵ������ʽ����ĸ���ϵ����ȥ N��

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialMulWord(P: TCnInt64BiPolynomial; N: Int64);
{* ��һ����Ԫ��ϵ������ʽ����ĸ���ϵ�������� N��

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialDivWord(P: TCnInt64BiPolynomial; N: Int64);
{* ��һ����Ԫ��ϵ������ʽ����ĸ���ϵ�������� N���粻��������ȡ����

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialNonNegativeModWord(P: TCnInt64BiPolynomial; N: Int64);
{* ��һ����Ԫ��ϵ������ʽ����ĸ���ϵ������ N �Ǹ����࣬�������������򻯡�

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

function Int64BiPolynomialAdd(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial): Boolean;
{* ������Ԫ��ϵ������ʽ������ӣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     P2: TCnInt64BiPolynomial             - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialSub(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial): Boolean;
{* ������Ԫ��ϵ������ʽ���������������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ������
     P2: TCnInt64BiPolynomial             - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialMul(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial): Boolean;
{* ������Ԫ��ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     P2: TCnInt64BiPolynomial             - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialMulX(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PX: TCnInt64Polynomial): Boolean;
{* һ����Ԫ��ϵ������ʽ������һ�� X ��һԪ��ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     PX: TCnInt64Polynomial               - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialMulY(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PY: TCnInt64Polynomial): Boolean;
{* һ����Ԫ��ϵ������ʽ������һ�� Y ��һԪ��ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     PY: TCnInt64Polynomial               - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialDivX(Res: TCnInt64BiPolynomial; Remain: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Divisor: TCnInt64BiPolynomial): Boolean;
{* ������Ԫ��ϵ������ʽ������ X Ϊ��������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   ע�� Divisor ������ X ����һ����ʽ������᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     Remain: TCnInt64BiPolynomial         - ����������ʽ�Ķ�Ԫ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������
     Divisor: TCnInt64BiPolynomial        - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialModX(Res: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Divisor: TCnInt64BiPolynomial): Boolean;
{* ������Ԫ��ϵ������ʽ������ X Ϊ�����࣬�������� Res �У����������Ƿ�ɹ���
   ע�� Divisor ������ X ����һ����ʽ������᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   Res ������ P �� Divisor��P ������ Divisor

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������
     Divisor: TCnInt64BiPolynomial        - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialPower(Res: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Exponent: Int64): Boolean;
{* �����Ԫ��ϵ������ʽ�� Exponent ���ݣ�������ϵ����������⣬�����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ����
     Exponent: Int64                      - ָ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialEvaluateByY(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; YValue: Int64): Boolean;
{* ��һ���� Y ֵ�����Ԫ��ϵ������ʽ���õ�ֻ���� X ��һԪ��ϵ������ʽ��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     YValue: Int64                        - δ֪�� Y ��ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialEvaluateByX(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; XValue: Int64): Boolean;
{* ��һ���� X ֵ�����Ԫ��ϵ������ʽ���õ�ֻ���� Y ��һԪ��ϵ������ʽ��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     XValue: Int64                        - δ֪�� X ��ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure Int64BiPolynomialTranspose(Dst: TCnInt64BiPolynomial; Src: TCnInt64BiPolynomial);
{* ����Ԫ��ϵ������ʽ�� X Y Ԫ��������һ����Ԫ��ϵ������ʽ�����У�Src �� Dst ������ͬ��

   ������
     Dst: TCnInt64BiPolynomial            - Ŀ���Ԫ��ϵ������ʽ
     Src: TCnInt64BiPolynomial            - Դ��Ԫ��ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialExtractYByX(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; XDegree: Int64);
{* ����Ԫ��ϵ������ʽ�� X �η�ϵ����ȡ�����ŵ�һ�� Y ��һԪ����ʽ�

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ����ȡ�Ķ�Ԫ��ϵ������ʽ
     XDegree: Int64                       - ָ�� X �Ĵ���

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialExtractXByY(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; YDegree: Int64);
{* ����Ԫ��ϵ������ʽ�� Y �η�ϵ����ȡ�����ŵ�һ�� X ��һԪ����ʽ�

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ����ȡ�Ķ�Ԫ��ϵ������ʽ
     YDegree: Int64                       - ָ�� Y �Ĵ���

   ����ֵ�����ޣ�
}

// =================== ��Ԫ��ϵ������ʽʽ���������ϵ�ģ���� ====================

function Int64BiPolynomialGaloisEqual(A: TCnInt64BiPolynomial;
  B: TCnInt64BiPolynomial; Prime: Int64): Boolean;
{* ������Ԫ��ϵ������ʽ��ģ Prime ���������Ƿ���ȡ�

   ������
     A: TCnInt64BiPolynomial              - ���жϵĶ�Ԫ��ϵ������ʽһ
     B: TCnInt64BiPolynomial              - ���жϵĶ�Ԫ��ϵ������ʽһ
     Prime: Int64                         - ģ��

   ����ֵ��Boolean                        - �����Ƿ����
}

procedure Int64BiPolynomialGaloisNegate(P: TCnInt64BiPolynomial; Prime: Int64);
{* ��һ����Ԫ��ϵ������ʽ��������ϵ����ģ Prime ���������󷴡�

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     Prime: Int64                         - ģ��

   ����ֵ�����ޣ�
}

function Int64BiPolynomialGaloisAdd(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* ������Ԫ��ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     P2: TCnInt64BiPolynomial             - ������
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisSub(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* ������Ԫ��ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ������
     P2: TCnInt64BiPolynomial             - ����
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisMul(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* ������Ԫ��ϵ������ʽ������ Prime �η�������������ˣ�������� Res �У�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     P2: TCnInt64BiPolynomial             - ������
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisMulX(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PX: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* һ����Ԫ��ϵ������ʽ������һ�� X ��һԪ��ϵ������ʽ������ Prime �η�������������ˣ�
  ������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     PX: TCnInt64Polynomial               - ������
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisMulY(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PY: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* һ����Ԫ��ϵ������ʽ������һ�� Y ��һԪ��ϵ������ʽ������ Prime �η�������������ˣ�
  ������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P1: TCnInt64BiPolynomial             - ����һ
     PY: TCnInt64Polynomial               - ������
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisDivX(Res: TCnInt64BiPolynomial; Remain: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Divisor: TCnInt64BiPolynomial; Prime: Int64;
  Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* ������Ԫ��ϵ������ʽ������ Prime �η�����������������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   �����������б�֤ Divisor �� X ����һ����ʽ�� Prime �������ұ�ԭ����ʽ Primitive Ϊ X �Ĳ���Լ����ʽ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��
   ע�⣺��һԪ����ʽ��ͬ��ֻ��ϵ����ģ�ˡ�

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     Remain: TCnInt64BiPolynomial         - ����������ʽ�Ķ�Ԫ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������
     Divisor: TCnInt64BiPolynomial        - ����
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisModX(Res: TCnInt64BiPolynomial; P: TCnInt64BiPolynomial;
  Divisor: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial = nil): Boolean;
{* ������Ԫ��ϵ������ʽ������ Prime �η��������������࣬�������� Res �У����������Ƿ�ɹ���
   �����������б�֤ Divisor �� X ����һ����ʽ�� Prime �������ұ�ԭ����ʽ Primitive Ϊ X �Ĳ���Լ����ʽ��
   Res ������ P �� Divisor��P ������ Divisor��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������
     Divisor: TCnInt64BiPolynomial        - ����
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisPower(Res: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Exponent: Int64; Prime: Int64;
  Primitive: TCnInt64BiPolynomial = nil; ExponentHi: Int64 = 0): Boolean;
{* �����Ԫ��ϵ������ʽ�� Prime �η����������ϵ� Exponent ���ݣ�Exponent ������ 128 λ��
   Exponent ������������Ǹ�ֵ���Զ�ת�� UInt64��
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   �����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnInt64BiPolynomial            - �������ɽ���Ķ�Ԫ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ����
     Exponent: Int64                      - ָ���� 64 λ
     Prime: Int64                         - �������Ͻ�
     Primitive: TCnInt64BiPolynomial      - ��ԭ����ʽ
     ExponentHi: Int64                    - ָ���� 64 λ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisEvaluateByY(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; YValue: Int64; Prime: Int64): Boolean;
{* ��һ���� Y ֵ�����Ԫ��ϵ������ʽ���õ�ֻ���� X ��һԪ��ϵ������ʽ��ϵ����� Prime ȡģ��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     YValue: Int64                        - δ֪�� Y ��ֵ
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function Int64BiPolynomialGaloisEvaluateByX(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; XValue: Int64; Prime: Int64): Boolean;
{* ��һ���� X ֵ�����Ԫ��ϵ������ʽ���õ�ֻ���� Y ��һԪ��ϵ������ʽ��ϵ����� Prime ȡģ��

   ������
     Res: TCnInt64Polynomial              - �������ɽ����һԪ��ϵ������ʽ
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     XValue: Int64                        - δ֪�� X ��ֵ
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure Int64BiPolynomialGaloisAddWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵĶ�Ԫ��ϵ������ʽ�ĸ���ϵ������ N �� mod Prime��ע�ⲻ�ǳ�ϵ����

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialGaloisSubWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵĶ�Ԫ��ϵ������ʽ�ĸ���ϵ����ȥ N �� mod Prime��ע�ⲻ�ǳ�ϵ����

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialGaloisMulWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵĶ�Ԫ��ϵ������ʽ����ϵ������ N �� mod Prime��

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64BiPolynomialGaloisDivWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
{* �� Prime �η����������ϵĶ�Ԫ��ϵ������ʽ����ϵ������ N��Ҳ���ǳ��� N ����Ԫ�� mod Prime��

   ������
     P: TCnInt64BiPolynomial              - ������Ķ�Ԫ��ϵ������ʽ
     N: Int64                             - ����
     Prime: Int64                         - �������Ͻ�

   ����ֵ�����ޣ�
}

// =============================================================================
//
//                           ��Ԫ����ϵ������ʽ
//
// =============================================================================

{
   FXs TObjectList
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | X^n   �� Y ϵ�� Sparse| -> | X^n*Y^0 ��ϵ��  |X^n*Y^3 ��ϵ��   | ......
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | X^n-1 �� Y ϵ�� Sparse| -> | X^n-1*Y^2 ��ϵ��|X^n-1*Y^5 ��ϵ�� | ......
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |......                 | -> |
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | X^0   �� Y ϵ�� Sparse| -> | X^0*Y^4 ��ϵ��  | X^0*Y^7 ��ϵ��  | ......
  +-+-+-+-+-+-+-+-+-+-+-+-+    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

}

type
  TCnBigNumberBiPolynomial = class
  {* ��Ԫ����ϵ������ʽ���ڲ���ȡϡ�跽ʽ����΢��ռ���ڴ�}
  private
    FXs: TCnRefObjectList; // Ԫ��Ϊ TCnSparseBigNumberList���洢�� X ���ݵ�ÿһ����ͬ�� Y ���ݵ�ϵ��
    procedure EnsureDegrees(XDegree: Integer; YDegree: Integer);
    {* ȷ�� XDegree, YDegree ��Ԫ�ش���}
    function GetMaxXDegree: Integer;
    function GetMaxYDegree: Integer;
    procedure SetMaxXDegree(const Value: Integer);
    procedure SetMaxYDegree(const Value: Integer);
    function GetYFactorsList(Index: Integer): TCnSparseBigNumberList;
    function GetSafeValue(XDegree: Integer; YDegree: Integer): TCnBigNumber;
    procedure SetSafeValue(XDegree: Integer; YDegree: Integer; const Value: TCnBigNumber);
    function GetReadonlyValue(XDegree: Integer; YDegree: Integer): TCnBigNumber;
  protected
    function CompactYDegree(YList: TCnSparseBigNumberList): Boolean;
    {* ȥ��һ�� Y ϵ���ߴ�������� nil �������ݵ�ȫ 0 �򷵻� True��

       ������
         YList: TCnSparseBigNumberList    - �������ϵ���б�

       ����ֵ��Boolean                    - �����Ƿ�ȫ 0
    }

    property YFactorsList[Index: Integer]: TCnSparseBigNumberList read GetYFactorsList;
    {* ��װ�Ķ� X �� Index ����� Y ϵ���б�FXs[Index] Ϊ nil ʱ���Զ�����������FXs.Count ����ʱ���Զ�����}
    procedure Clear;
    {* �ڲ�����������ݣ�ֻ�� FXs[0] ��һ�� List��һ�㲻����ʹ��}
  public
    constructor Create(XDegree: Integer = 0; YDegree: Integer = 0);
    {* ���캯�������� X �� Y ����ߴ�������Ĭ��Ϊ 0���Ժ��ٲ��衣

       ������
         XDegree: Integer                 - X ����ߴ�ϵ��
         YDegree: Integer                 - Y ����ߴ�ϵ��

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure SetYCoefficentsFromPolynomial(XDegree: Integer; PY: TCnInt64Polynomial); overload;
    {* ����ض������� X����һԪ�� Y ����ʽ��һ���������� Y ��ϵ����

       ������
         XDegree: Integer                 - X ����
         PY: TCnInt64Polynomial           - ���� Y ϵ���б�Ķ���ʽ

       ����ֵ�����ޣ�
    }

    procedure SetYCoefficentsFromPolynomial(XDegree: Integer; PY: TCnBigNumberPolynomial); overload;
    {* ����ض������� X����һԪ�Ĵ���ϵ�� Y ����ʽ��һ���������� Y ��ϵ����

       ������
         XDegree: Integer                 - X ����
         PY: TCnBigNumberPolynomial       - ���� Y ϵ���б�Ķ���ʽ

       ����ֵ�����ޣ�
    }

    procedure SetYCoefficents(XDegree: Integer; LowToHighYCoefficients: array of const);
    {* ����ض������� X��һ���������� Y �ӵ͵��ߵ�ϵ����

       ������
         XDegree: Integer                                 - X ����
         LowToHighYCoefficients: array of const           - Y ϵ���б�

       ����ֵ�����ޣ�
    }

    procedure SetXCoefficents(YDegree: Integer; LowToHighXCoefficients: array of const);
    {* ����ض������� Y��һ���������� X �ӵ͵��ߵ�ϵ����

       ������
         YDegree: Integer                                 - Y ����
         LowToHighXCoefficients: array of const           - X ϵ���б�

       ����ֵ�����ޣ�
    }

    procedure SetXYCoefficent(XDegree: Integer; YDegree: Integer; ACoefficient: TCnBigNumber);
    {* ����ض������� X �� Y��������ϵ����

       ������
         XDegree: Integer                 - X ����
         YDegree: Integer                 - Y ����
         ACoefficient: TCnBigNumber       - ϵ��

       ����ֵ�����ޣ�
    }

    procedure CorrectTop;
    {* �޳��ߴε� 0 ϵ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ʽת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetString(const Poly: string);
    {* ������ʽ�ַ���ת��Ϊ����������ݡ�

       ������
         const Poly: string               - ��ת�����ַ���

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �����Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    procedure SetZero;
    {* ��Ϊ 0}

    procedure SetOne;
    {* ��Ϊ 1}

    procedure Negate;
    {* ����ϵ����}

    function IsMonicX: Boolean;
    {* �Ƿ��ǹ��� X ����һ����ʽ��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ��ǹ��� X ����һ����ʽ
    }

    procedure Transpose;
    {* ת�ã�Ҳ���ǻ��� X Y Ԫ}

    property MaxXDegree: Integer read GetMaxXDegree write SetMaxXDegree;
    {* X Ԫ����ߴ�����0 ��ʼ������ Count ����ֻ���� Integer��
      ���ú��ܱ�֤������ÿ�� XDegree�����Ӧ�� SparseBigNumberList ������}
    property MaxYDegree: Integer read GetMaxYDegree write SetMaxYDegree;
    {* X Ԫ����ߴ�����0 ��ʼ������ Count ����ֻ���� Integer}

    property SafeValue[XDegree, YDegree: Integer]: TCnBigNumber read GetSafeValue write SetSafeValue;
    {* ��ȫ�Ķ�дϵ����������������ʱ���� 0��д������ʱ�Զ���չ���ڲ����ƴ���ֵ}
    property ReadonlyValue[XDegree, YDegree: Integer]: TCnBigNumber read GetReadonlyValue;
    {* ֻ���ĸ��ݲ������� Exponent ��ȡ�����ķ�������ʱ���ڲ��鲻�����᷵��һ�̶�����ֵ TCnBigNumber ���������޸���ֵ}
  end;

  TCnBigNumberBiPolynomialPool = class(TCnMathObjectPool)
  {* ��Ԫ����ϵ������ʽ��ʵ���࣬����ʹ�õ���Ԫ����ϵ������ʽ�ĵط����д�����Ԫ����ϵ������ʽ��}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnBigNumberBiPolynomial; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnBigNumberBiPolynomial   - ���صĶ���ʽ����
    }

    procedure Recycle(Poly: TCnBigNumberBiPolynomial); reintroduce;
    {* ��һ������黹������ء�

       ������
         Poly: TCnBigNumberBiPolynomial   - ���黹�Ķ���ʽ����

       ����ֵ�����ޣ�
    }
  end;

function BigNumberBiPolynomialNew: TCnBigNumberBiPolynomial;
{* ����һ����Ԫ����ϵ������ʽ���󣬵�ͬ�� TCnBigNumberBiPolynomial.Create��

   ������
     ���ޣ�

   ����ֵ��TCnBigNumberBiPolynomial       - ���ش����Ķ�Ԫ����ϵ������ʽ����
}

procedure BigNumberBiPolynomialFree(P: TCnBigNumberBiPolynomial);
{* �ͷ�һ����Ԫ����ϵ������ʽ���󣬵�ͬ�� TCnBigNumberBiPolynomial.Free��

   ������
     P: TCnBigNumberBiPolynomial          - ���ͷŵĶ�Ԫ����ϵ������ʽ����

   ����ֵ�����ޣ�
}

function BigNumberBiPolynomialDuplicate(P: TCnBigNumberBiPolynomial): TCnBigNumberBiPolynomial;
{* ��һ����Ԫ����ϵ������ʽ�����¡һ���¶���

   ������
     P: TCnBigNumberBiPolynomial          - �����ƵĶ�Ԫ����ϵ������ʽ

   ����ֵ��TCnBigNumberBiPolynomial       - �����½��Ķ�Ԫ����ϵ������ʽ
}

function BigNumberBiPolynomialCopy(Dst: TCnBigNumberBiPolynomial;
  Src: TCnBigNumberBiPolynomial): TCnBigNumberBiPolynomial;
{* ����һ����Ԫ����ϵ������ʽ���󣬳ɹ����� Dst��

   ������
     Dst: TCnBigNumberBiPolynomial        - Ŀ���Ԫ����ϵ������ʽ
     Src: TCnBigNumberBiPolynomial        - Դ��Ԫ����ϵ������ʽ

   ����ֵ��TCnBigNumberBiPolynomial       - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function BigNumberBiPolynomialCopyFromX(Dst: TCnBigNumberBiPolynomial;
  SrcX: TCnBigNumberPolynomial): TCnBigNumberBiPolynomial;
{* ��һԪ X ����ϵ������ʽ�и���һ����Ԫ����ϵ������ʽ���󣬳ɹ����� Dst��

   ������
     Dst: TCnBigNumberBiPolynomial        - Ŀ���Ԫ����ϵ������ʽ
     SrcX: TCnBigNumberPolynomial         - ԴһԪ X ����ϵ������ʽ

   ����ֵ��TCnBigNumberBiPolynomial       - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function BigNumberBiPolynomialCopyFromY(Dst: TCnBigNumberBiPolynomial;
  SrcY: TCnBigNumberPolynomial): TCnBigNumberBiPolynomial;
{* ��һԪ Y ����ϵ������ʽ�и���һ����Ԫ����ϵ������ʽ���󣬳ɹ����� Dst

   ������
     Dst: TCnBigNumberBiPolynomial        - Ŀ���Ԫ����ϵ������ʽ
     SrcY: TCnBigNumberPolynomial         - ԴһԪ Y ����ϵ������ʽ

   ����ֵ��TCnBigNumberBiPolynomial       - �ɹ��򷵻�Ŀ�����ʧ���򷵻� nil
}

function BigNumberBiPolynomialToString(P: TCnBigNumberBiPolynomial;
  const Var1Name: string = 'X'; const Var2Name: string = 'Y'): string;
{* ��һ����Ԫ����ϵ������ʽ����ת���ַ�����δ֪��Ĭ���� X �� Y ��ʾ��

   ������
     P: TCnBigNumberBiPolynomial          - ��ת���Ķ�Ԫ����ϵ������ʽ
     const Var1Name: string               - �����һ��δ֪�����ַ���
     const Var2Name: string               - ����ڶ���δ֪�����ַ���

   ����ֵ��string                         - �����ַ���
}

function BigNumberBiPolynomialSetString(P: TCnBigNumberBiPolynomial;
  const Str: string; const Var1Name: string = 'X'; const Var2Name: string = 'Y'): Boolean;
{* ���ַ�����ʽ�Ķ�Ԫ����ϵ������ʽ��ֵ����Ԫ����ϵ������ʽ���󣬷����Ƿ�ֵ�ɹ���

   ������
     P: TCnBigNumberBiPolynomial          - ����ֵ�Ķ�Ԫ����ϵ������ʽ
     const Str: string                    - ����ʽ�ַ���
     const Var1Name: string               - �����һ��δ֪�����ַ���
     const Var2Name: string               - ����ڶ���δ֪�����ַ���

   ����ֵ��Boolean                        - �����Ƿ�ֵ�ɹ�
}

function BigNumberBiPolynomialIsZero(P: TCnBigNumberBiPolynomial): Boolean;
{* �ж�һ����Ԫ����ϵ������ʽ�����Ƿ�Ϊ 0��

   ������
     P: TCnBigNumberBiPolynomial          - ���жϵĶ�Ԫ����ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

procedure BigNumberBiPolynomialSetZero(P: TCnBigNumberBiPolynomial);
{* ��һ����Ԫ����ϵ������ʽ������Ϊ 0��

   ������
     P: TCnBigNumberBiPolynomial          - �����õĶ�Ԫ����ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialSetOne(P: TCnBigNumberBiPolynomial);
{* ��һ����Ԫ����ϵ������ʽ������Ϊ 1��

   ������
     P: TCnBigNumberBiPolynomial          - �����õĶ�Ԫ����ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialNegate(P: TCnBigNumberBiPolynomial);
{* ��һ����Ԫ����ϵ������ʽ��������ϵ���󷴡�

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ

   ����ֵ�����ޣ�
}

function BigNumberBiPolynomialIsMonicX(P: TCnBigNumberBiPolynomial): Boolean;
{* �ж�һ����Ԫ����ϵ������ʽ�Ƿ��ǹ��� X ����һ����ʽ��Ҳ�����ж� X ��ߴε�ϵ���Ƿ�Ϊ 1��

   ������
     P: TCnBigNumberBiPolynomial          - ���жϵĶ�Ԫ����ϵ������ʽ

   ����ֵ��Boolean                        - �����Ƿ� X ����һ����ʽ
}

procedure BigNumberBiPolynomialShiftLeftX(P: TCnBigNumberBiPolynomial; N: Integer);
{* ��һ����Ԫ����ϵ������ʽ����� X ���� N �Σ�Ҳ���� X ����ָ������ N��

   ������
     P: TCnBigNumberBiPolynomial          - �����ƵĶ�Ԫ����ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialShiftRightX(P: TCnBigNumberBiPolynomial; N: Integer);
{* ��һ����Ԫ����ϵ������ʽ����� X ���� N �Σ�Ҳ���� X ����ָ������ N��С�� 0 �ĺ����ˡ�

   ������
     P: TCnBigNumberBiPolynomial          - �����ƵĶ�Ԫ����ϵ������ʽ
     N: Integer                           - ���ƴ���

   ����ֵ�����ޣ�
}

function BigNumberBiPolynomialEqual(A: TCnBigNumberBiPolynomial; B: TCnBigNumberBiPolynomial): Boolean;
{* �ж�������Ԫ����ϵ������ʽÿ��ϵ���Ƿ��Ӧ��ȣ����򷵻� True��

   ������
     A: TCnBigNumberBiPolynomial          - ���жϵĶ�Ԫ����ϵ������ʽһ
     B: TCnBigNumberBiPolynomial          - ���жϵĶ�Ԫ����ϵ������ʽ��

   ����ֵ��Boolean                        - �����Ƿ����
}

// ===================== ��Ԫ����ϵ������ʽ��ͨ���� ============================

// procedure BigNumberBiPolynomialAddWord(P: TCnBigNumberBiPolynomial; N: Int64);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ������ N��������ϡ���б���˵ûɶ���壬��ʵ��}

// procedure BigNumberBiPolynomialSubWord(P: TCnBigNumberBiPolynomial; N: Int64);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ����ȥ N��������ϡ���б���˵ûɶ���壬��ʵ��}

procedure BigNumberBiPolynomialMulWord(P: TCnBigNumberBiPolynomial; N: Int64);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ�������� N��

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialDivWord(P: TCnBigNumberBiPolynomial; N: Int64);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ�������� N���粻��������ȡ����

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialNonNegativeModWord(P: TCnBigNumberBiPolynomial; N: Int64);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ������ N �Ǹ����࣬�������������򻯡�

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: Int64                             - ����

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialMulBigNumber(P: TCnBigNumberBiPolynomial; N: TCnBigNumber);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ�������Դ��� N��

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialDivBigNumber(P: TCnBigNumberBiPolynomial; N: TCnBigNumber);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ�������Դ��� N���粻��������ȡ����

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialNonNegativeModBigNumber(P: TCnBigNumberBiPolynomial; N: TCnBigNumber);
{* ��һ����Ԫ����ϵ������ʽ����ĸ���ϵ������ N �Ǹ����࣬�������������򻯡�

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: TCnBigNumber                      - ����

   ����ֵ�����ޣ�
}

function BigNumberBiPolynomialAdd(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial): Boolean;
{* ������Ԫ����ϵ������ʽ������ӣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     P2: TCnBigNumberBiPolynomial         - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialSub(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial): Boolean;
{* ������Ԫ����ϵ������ʽ���������������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ������
     P2: TCnBigNumberBiPolynomial         - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialMul(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial): Boolean;
{* ������Ԫ����ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     P2: TCnBigNumberBiPolynomial         - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialMulX(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PX: TCnBigNumberPolynomial): Boolean;
{* һ����Ԫ����ϵ������ʽ������һ�� X ��һԪ����ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     PX: TCnBigNumberPolynomial           - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialMulY(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PY: TCnBigNumberPolynomial): Boolean;
{* һ����Ԫ����ϵ������ʽ������һ�� Y ��һԪ����ϵ������ʽ������ˣ�������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     PY: TCnBigNumberPolynomial           - ������

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialDivX(Res: TCnBigNumberBiPolynomial; Remain: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Divisor: TCnBigNumberBiPolynomial): Boolean;
{* ������Ԫ����ϵ������ʽ������ X Ϊ��������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   ע�� Divisor ������ X ����һ����ʽ������᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     Remain: TCnBigNumberBiPolynomial     - ����������ʽ�Ķ�Ԫ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������
     Divisor: TCnBigNumberBiPolynomial    - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialModX(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Divisor: TCnBigNumberBiPolynomial): Boolean;
{* ������Ԫ����ϵ������ʽ������ X Ϊ�����࣬�������� Res �У����������Ƿ�ɹ���
   ע�� Divisor ������ X ����һ����ʽ������᷵�� False����ʾ�޷�֧�֣�����������жϷ���ֵ��
   Res ������ P �� Divisor��P ������ Divisor��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������
     Divisor: TCnBigNumberBiPolynomial    - ����

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialPower(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Exponent: TCnBigNumber): Boolean;
{* �����Ԫ����ϵ������ʽ�� Exponent ���ݣ�������ϵ����������⣬�����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ����
     Exponent: TCnBigNumber               - ָ��

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialEvaluateByY(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; YValue: TCnBigNumber): Boolean;
{* ��һ���� Y ֵ�����Ԫ����ϵ������ʽ���õ�ֻ���� X ��һԪ����ϵ������ʽ��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ��ϵ������ʽ
     YValue: TCnBigNumber                 - δ֪�� Y ��ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialEvaluateByX(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; XValue: TCnBigNumber): Boolean;
{* ��һ���� X ֵ�����Ԫ����ϵ������ʽ���õ�ֻ���� Y ��һԪ����ϵ������ʽ��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ��ϵ������ʽ
     XValue: TCnBigNumber                 - δ֪�� X ��ֵ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

procedure BigNumberBiPolynomialTranspose(Dst: TCnBigNumberBiPolynomial;
  Src: TCnBigNumberBiPolynomial);
{* ����Ԫ����ϵ������ʽ�� X Y Ԫ��������һ����Ԫ����ϵ������ʽ�����У�Src �� Dst ������ͬ��

   ������
     Dst: TCnBigNumberBiPolynomial        - Ŀ���Ԫ����ϵ������ʽ
     Src: TCnBigNumberBiPolynomial        - Դ��Ԫ����ϵ������ʽ

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialExtractYByX(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; XDegree: Integer);
{* ����Ԫ����ϵ������ʽ�� X �η�ϵ����ȡ�����ŵ�һ�� Y ��һԪ����ʽ�

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ����ȡ�Ķ�Ԫ����ϵ������ʽ
     XDegree: Integer                     - ָ�� X �Ĵ���

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialExtractXByY(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; YDegree: Integer);
{* ����Ԫ����ϵ������ʽ�� Y �η�ϵ����ȡ�����ŵ�һ�� X ��һԪ����ʽ�

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ����ȡ�Ķ�Ԫ����ϵ������ʽ
     YDegree: Integer                     - ָ�� Y �Ĵ���

   ����ֵ�����ޣ�
}

// ================== ��Ԫ����ϵ������ʽ���������ϵ�ģ���� =====================

function BigNumberBiPolynomialGaloisEqual(A: TCnBigNumberBiPolynomial;
  B: TCnBigNumberBiPolynomial; Prime: TCnBigNumber): Boolean;
{* ������Ԫ����ϵ������ʽ��ģ Prime ���������Ƿ���ȡ�

   ������
     A: TCnBigNumberBiPolynomial          - ���жϵĶ�Ԫ����ϵ������ʽһ
     B: TCnBigNumberBiPolynomial          - ���жϵĶ�Ԫ����ϵ������ʽ��
     Prime: TCnBigNumber                  - ģ��

   ����ֵ��Boolean                        - �����Ƿ����
}

procedure BigNumberBiPolynomialGaloisNegate(P: TCnBigNumberBiPolynomial; Prime: TCnBigNumber);
{* ��һ����Ԫ����ϵ������ʽ��������ϵ����ģ Prime ���������󷴡�

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     Prime: TCnBigNumber                  - ģ��

   ����ֵ�����ޣ�
}

function BigNumberBiPolynomialGaloisAdd(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* ������Ԫ����ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     P2: TCnBigNumberBiPolynomial         - ������
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisSub(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* ������Ԫ����ϵ������ʽ������ Prime �η�������������ӣ�������� Res �У�
   �����������б�֤ Prime �������� Res �������ڱ�ԭ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ������
     P2: TCnBigNumberBiPolynomial         - ����
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisMul(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* ������Ԫ����ϵ������ʽ������ Prime �η�������������ˣ�������� Res �У�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   ��������Ƿ�ɹ���P1 ������ P2��Res ������ P1 �� P2��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     P2: TCnBigNumberBiPolynomial         - ������
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisMulX(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PX: TCnBigNumberPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* һ����Ԫ����ϵ������ʽ������һ�� X ��һԪ����ϵ������ʽ������ Prime �η�������������ˣ�
  ������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     PX: TCnBigNumberPolynomial           - ������
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisMulY(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PY: TCnBigNumberPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* һ����Ԫ����ϵ������ʽ������һ�� Y ��һԪ����ϵ������ʽ������ Prime �η�������������ˣ�
  ������� Res �У���������Ƿ�ɹ���Res ������ P1��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P1: TCnBigNumberBiPolynomial         - ����һ
     PY: TCnBigNumberPolynomial           - ������
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisDivX(Res: TCnBigNumberBiPolynomial;
  Remain: TCnBigNumberBiPolynomial; P: TCnBigNumberBiPolynomial;
  Divisor: TCnBigNumberBiPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* ������Ԫ����ϵ������ʽ������ Prime �η�����������������̷��� Res �У��������� Remain �У���������Ƿ�ɹ���
   �����������б�֤ Divisor �� X ����һ����ʽ�� Prime �������ұ�ԭ����ʽ Primitive Ϊ X �Ĳ���Լ����ʽ��
   Res �� Remail ������ nil����������Ӧ�����P ������ Divisor��Res ������ P �� Divisor��
   ע�⣺��һԪ����ʽ��ͬ��ֻ��ϵ����ģ�ˡ�

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     Remain: TCnBigNumberBiPolynomial     - ����������ʽ�Ķ�Ԫ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������
     Divisor: TCnBigNumberBiPolynomial    - ����
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisModX(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Divisor: TCnBigNumberBiPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* ������Ԫ����ϵ������ʽ������ Prime �η��������������࣬�������� Res �У����������Ƿ�ɹ���
   �����������б�֤ Divisor �� X ����һ����ʽ�� Prime �������ұ�ԭ����ʽ Primitive Ϊ X �Ĳ���Լ����ʽ��
   Res ������ P �� Divisor��P ������ Divisor��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������
     Divisor: TCnBigNumberBiPolynomial    - ����
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisPower(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Exponent: TCnBigNumber; Prime: TCnBigNumber;
  Primitive: TCnBigNumberBiPolynomial = nil): Boolean;
{* �����Ԫ����ϵ������ʽ�� Prime �η����������ϵ� Exponent ���ݡ�
   �����������б�֤ Prime �������ұ�ԭ����ʽ Primitive Ϊ����Լ����ʽ��
   �����Ƿ����ɹ���Res ������ P��

   ������
     Res: TCnBigNumberBiPolynomial        - �������ɽ���Ķ�Ԫ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ����
     Exponent: TCnBigNumber               - ָ��
     Prime: TCnBigNumber                  - �������Ͻ�
     Primitive: TCnBigNumberBiPolynomial  - ��ԭ����ʽ

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisEvaluateByY(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; YValue: TCnBigNumber; Prime: TCnBigNumber): Boolean;
{* ��һ���� Y ֵ�����Ԫ����ϵ������ʽ���õ�ֻ���� X ��һԪ����ϵ������ʽ��ϵ����� Prime ȡģ��

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     YValue: TCnBigNumber                 - δ֪�� Y ��ֵ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function BigNumberBiPolynomialGaloisEvaluateByX(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; XValue: TCnBigNumber; Prime: TCnBigNumber): Boolean;
{* ��һ���� X ֵ�����Ԫ����ϵ������ʽ���õ�ֻ���� Y ��һԪ����ϵ������ʽ��ϵ����� Prime ȡģ

   ������
     Res: TCnBigNumberPolynomial          - �������ɽ����һԪ����ϵ������ʽ
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     XValue: TCnBigNumber                 - δ֪�� X ��ֵ
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

// procedure BigNumberBiPolynomialGaloisAddWord(P: TCnBigNumberBiPolynomial; N: Int64; Prime: TCnBigNumber);
{* �� Prime �η����������ϵĶ�Ԫ����ϵ������ʽ�ĸ���ϵ������ N �� mod Prime��ע�ⲻ�ǳ�ϵ����������ϡ���б���˵ûɶ���壬��ʵ��}

// procedure BigNumberBiPolynomialGaloisSubWord(P: TCnBigNumberBiPolynomial; N: Int64; Prime: TCnBigNumber);
{* �� Prime �η����������ϵĶ�Ԫ����ϵ������ʽ�ĸ���ϵ����ȥ N �� mod Prime��ע�ⲻ�ǳ�ϵ����������ϡ���б���˵ûɶ���壬��ʵ��}

procedure BigNumberBiPolynomialGaloisMulWord(P: TCnBigNumberBiPolynomial; N: Int64; Prime: TCnBigNumber);
{* �� Prime �η����������ϵĶ�Ԫ����ϵ������ʽ����ϵ������ N �� mod Prime��

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: Int64                             - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure BigNumberBiPolynomialGaloisDivWord(P: TCnBigNumberBiPolynomial; N: Int64; Prime: TCnBigNumber);
{* �� Prime �η����������ϵĶ�Ԫ����ϵ������ʽ����ϵ������ N��Ҳ���ǳ��� N ����Ԫ�� mod Prime��

   ������
     P: TCnBigNumberBiPolynomial          - ������Ķ�Ԫ����ϵ������ʽ
     N: Int64                             - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure Int64PolynomialToBigNumberPolynomial(Dst: TCnBigNumberPolynomial; Src: TCnInt64Polynomial);
{* ��һԪ��ϵ������ʽ��ֵ��һ����ϵ������ʽ��

   ������
     Dst: TCnBigNumberPolynomial          - Ŀ��һԪ����ϵ������ʽ
     Src: TCnInt64Polynomial              - ԴһԪ��ϵ������ʽ

   ����ֵ�����ޣ�
}

var
  CnInt64PolynomialOne: TCnInt64Polynomial = nil;
  {* ��ʾ 1 �� Int64 ����ʽ����}
  CnInt64PolynomialZero: TCnInt64Polynomial = nil;
  {* ��ʾ 0 �� Int64 ����ʽ����}

  CnBigNumberPolynomialOne: TCnBigNumberPolynomial = nil;
  {* ��ʾ 1 �Ĵ�������ʽ����}
  CnBigNumberPolynomialZero: TCnBigNumberPolynomial = nil;
  {* ��ʾ 0 �Ĵ�������ʽ����}

implementation

resourcestring
  SCnErrorPolynomialInvalidDegree = 'Invalid Degree %d';
  SCnErrorPolynomialInvalidExponent = 'Invalid Exponent %d';
  SCnErrorPolynomialDegreeTooLarge = 'Degree Too Large';
  SCnErrorPolynomialGCDMustOne = 'Modular Inverse Need GCD = 1';
  SCnErrorPolynomialGaloisInvalidDegree = 'Galois Division Polynomial Invalid Degree';

var
  FLocalInt64PolynomialPool: TCnInt64PolynomialPool = nil;
  FLocalInt64RationalPolynomialPool: TCnInt64RationalPolynomialPool = nil;
  FLocalBigNumberPolynomialPool: TCnBigNumberPolynomialPool = nil;
  FLocalBigNumberRationalPolynomialPool: TCnBigNumberRationalPolynomialPool = nil;
  FLocalBigNumberPool: TCnBigNumberPool = nil;
  FLocalInt64BiPolynomialPool: TCnInt64BiPolynomialPool = nil;
  FLocalBigNumberBiPolynomialPool: TCnBigNumberBiPolynomialPool = nil;

procedure CheckDegree(Degree: Integer);
begin
  if Degree < 0 then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidDegree, [Degree]);
end;

function VarPower(const VarName: string; E: Integer): string;
begin
  if E = 0 then
    Result := ''
  else if E = 1 then
    Result := VarName
  else
    Result := VarName + '^' + IntToStr(E);
end;

function VarPower2(const Var1Name, Var2Name: string; E1, E2: Integer): string;
begin
  Result := VarPower(Var1Name, E1) + VarPower(Var2Name, E2);
end;

// ����ʽϵ��ת�ַ���ʱ��װ�Ĺ���DecStr �Ǹ�ϵ�����ַ�����ʽ�������� - �ţ�
// ����ֵ��ϵ���� 0 ʱΪ True����ʾ������Ҫ�ӵ���ʽ
function VarItemFactor(var Res: string; ExpsIsZero: Boolean; const DecStr: string): Boolean;
var
  IsPositive, IsNegative, IsZero, IsOne, IsNegOne: Boolean;
begin
  Result := True;
  if Length(DecStr) = 0 then
    Exit;

  IsZero := (DecStr = '0') or (DecStr = '-0');
  IsOne := DecStr = '1';
  IsNegOne := DecStr = '-1';

  IsNegative := (not IsZero) and (DecStr[1] = '-');
  IsPositive := (not IsZero) and (DecStr[1] <> '-');

  if IsZero then // ��ϵ��
  begin
    if ExpsIsZero and (Res = '') then
      Res := '0';
    // ����� Res ɶ������
    Result := False;
  end
  else if IsPositive then // ���� 0
  begin
    if IsOne and not ExpsIsZero then  // �ǳ������ 1 ϵ��������ʾ
    begin
      if Res <> '' then  // ����� Res Ϊ�գ�����Ӻ�
        Res := Res + '+';
    end
    else
    begin
      if Res = '' then  // ���������Ӻ�
        Res := DecStr
      else
        Res := Res + '+' + DecStr;
    end;
  end
  else if IsNegative then // С�� 0��Ҫ�ü���
  begin
    if IsNegOne and not ExpsIsZero then // �ǳ������ -1 ������ʾ 1��ֻ�����
      Res := Res + '-'
    else
      Res := Res + DecStr; // DecStr ���м���
  end;
end;

// ��װ�Ĵ� TVarRec Ҳ���� array of const Ԫ���ﷵ�� Int64 �ĺ���
function ExtractInt64FromArrayConstElement(Element: TVarRec): Int64;
begin
  case Element.VType of
  vtInteger:
    begin
      Result := Element.VInteger;
    end;
  vtInt64:
    begin
      Result := Element.VInt64^;
    end;
  vtBoolean:
    begin
      if Element.VBoolean then
        Result := 1
      else
        Result := 0;
    end;
  vtString:
    begin
      Result := StrToInt(string(Element.VString^));
    end;
  else
    raise ECnPolynomialException.CreateFmt(SInvalidInteger, ['Coefficients ' + Element.VString^]);
  end;
end;

// ��װ�Ĵ� TVarRec Ҳ���� array of const Ԫ���ﷵ�ش����ַ����ĺ���
function ExtractBigNumberFromArrayConstElement(Element: TVarRec): string;
begin
  Result := '';
  case Element.VType of
  vtInteger:
    begin
      Result := IntToStr(Element.VInteger);
    end;
  vtInt64:
    begin
      Result := IntToStr(Element.VInt64^);
    end;
  vtBoolean:
    begin
      if Element.VBoolean then
        Result := '1'
      else
        Result := '0';
    end;
  vtString:
    begin
      Result := string(Element.VString^);
    end;
  vtObject:
    begin
      // ���� TCnBigNumber �����и���ֵ
      if Element.VObject is TCnBigNumber then
        Result := (Element.VObject as TCnBigNumber).ToDec;
    end;
  else
    raise ECnPolynomialException.CreateFmt(SInvalidInteger, ['Coefficients ' + Element.VString^]);
  end;
end;

function Exponent128IsZero(Exponent, ExponentHi: Int64): Boolean;
begin
  Result := (Exponent = 0) and (ExponentHi = 0);
end;

function Exponent128IsOne(Exponent, ExponentHi: Int64): Boolean;
begin
  Result := (Exponent = 1) and (ExponentHi = 0);
end;

procedure ExponentShiftRightOne(var Exponent, ExponentHi: Int64);
begin
  Exponent := Exponent shr 1;
  if (ExponentHi and 1) <> 0 then
    Exponent := Exponent or $8000000000000000;
  ExponentHi := ExponentHi shr 1;
end;

{ TCnInt64Polynomial }

procedure TCnInt64Polynomial.CorrectTop;
begin
  while (MaxDegree > 0) and (Items[MaxDegree] = 0) do
    Delete(MaxDegree);
end;

constructor TCnInt64Polynomial.Create;
begin
  inherited;
  Add(0);   // ��ϵ����
end;

constructor TCnInt64Polynomial.Create(LowToHighCoefficients: array of const);
begin
  inherited Create;
  SetCoefficents(LowToHighCoefficients);
end;

destructor TCnInt64Polynomial.Destroy;
begin

  inherited;
end;

function TCnInt64Polynomial.GetMaxDegree: Integer;
begin
  if Count = 0 then
    Add(0);
  Result := Count - 1;
end;

function TCnInt64Polynomial.IsMonic: Boolean;
begin
  Result := Int64PolynomialIsMonic(Self);
end;

function TCnInt64Polynomial.IsNegOne: Boolean;
begin
  Result := Int64PolynomialIsNegOne(Self);
end;

function TCnInt64Polynomial.IsOne: Boolean;
begin
  Result := Int64PolynomialIsOne(Self);
end;

function TCnInt64Polynomial.IsZero: Boolean;
begin
  Result := Int64PolynomialIsZero(Self);
end;

procedure TCnInt64Polynomial.Negate;
begin
  Int64PolynomialNegate(Self);
end;

procedure TCnInt64Polynomial.SetCoefficents(LowToHighCoefficients: array of const);
var
  I: Integer;
begin
  Clear;
  for I := Low(LowToHighCoefficients) to High(LowToHighCoefficients) do
    Add(ExtractInt64FromArrayConstElement(LowToHighCoefficients[I]));

  if Count = 0 then
    Add(0)
  else
    CorrectTop;
end;

procedure TCnInt64Polynomial.SetMaxDegree(const Value: Integer);
begin
  CheckDegree(Value);
  Count := Value + 1;
end;

procedure TCnInt64Polynomial.SetOne;
begin
  Int64PolynomialSetOne(Self);
end;

procedure TCnInt64Polynomial.SetString(const Poly: string);
begin
  Int64PolynomialSetString(Self, Poly);
end;

procedure TCnInt64Polynomial.SetZero;
begin
  Int64PolynomialSetZero(Self);
end;

function TCnInt64Polynomial.ToString: string;
begin
  Result := Int64PolynomialToString(Self);
end;

// ============================ ����ʽϵ�в������� =============================

function Int64PolynomialNew: TCnInt64Polynomial;
begin
  Result := TCnInt64Polynomial.Create;
end;

procedure Int64PolynomialFree(P: TCnInt64Polynomial);
begin
  P.Free;
end;

function Int64PolynomialDuplicate(P: TCnInt64Polynomial): TCnInt64Polynomial;
begin
  if P = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := Int64PolynomialNew;
  if Result <> nil then
    Int64PolynomialCopy(Result, P);
end;

function Int64PolynomialCopy(Dst: TCnInt64Polynomial;
  Src: TCnInt64Polynomial): TCnInt64Polynomial;
var
  I: Integer;
begin
  Result := Dst;
  if Src <> Dst then
  begin
    Dst.Clear;
    for I := 0 to Src.Count - 1 do
      Dst.Add(Src[I]);
    Dst.CorrectTop;
  end;
end;

function Int64PolynomialToString(P: TCnInt64Polynomial; const VarName: string): string;
var
  I: Integer;
begin
  Result := '';
  if Int64PolynomialIsZero(P) then
  begin
    Result := '0';
    Exit;
  end;

  for I := P.MaxDegree downto 0 do
  begin
    if VarItemFactor(Result, (I = 0), IntToStr(P[I])) then
      Result := Result + VarPower(VarName, I);
  end;
end;

{$WARNINGS OFF}

function Int64PolynomialSetString(P: TCnInt64Polynomial;
  const Str: string; const VarName: string): Boolean;
var
  C, Ptr: PChar;
  Num: string;
  MDFlag, E: Integer;
  F: Int64;
  IsNeg: Boolean;
begin
  Result := False;
  if Str = '' then
    Exit;

  MDFlag := -1;
  C := @Str[1];

  while C^ <> #0 do
  begin
    if not (C^ in ['+', '-', '0'..'9']) and (C^ <> VarName) then
    begin
      Inc(C);
      Continue;
    end;

    IsNeg := False;
    if C^ = '+' then
      Inc(C)
    else if C^ = '-' then
    begin
      IsNeg := True;
      Inc(C);
    end;

    F := 1;
    if C^ in ['0'..'9'] then // ��ϵ��
    begin
      Ptr := C;
      while C^ in ['0'..'9'] do
        Inc(C);

      // Ptr �� C ֮�������֣�����һ��ϵ��
      SetString(Num, Ptr, C - Ptr);
      F := StrToInt64(Num);
      if IsNeg then
        F := -F;
    end
    else if IsNeg then
      F := -F;

    if C^ = VarName then
    begin
      E := 1;
      Inc(C);
      if C^ = '^' then // ��ָ��
      begin
        Inc(C);
        if C^ in ['0'..'9'] then
        begin
          Ptr := C;
          while C^ in ['0'..'9'] do
            Inc(C);

          // Ptr �� C ֮�������֣�����һ��ָ��
          SetString(Num, Ptr, C - Ptr);
          E := StrToInt64(Num);
        end;
      end;
    end
    else
      E := 0;

    // ָ�������ˣ���
    if MDFlag = -1 then // ��һ��ָ���� MaxDegree
    begin
      P.MaxDegree := E;
      MDFlag := 0;
    end;

    P[E] := F;
  end;
end;

{$WARNINGS ON}

function Int64PolynomialIsZero(P: TCnInt64Polynomial): Boolean;
begin
  Result := (P.MaxDegree = 0) and (P[0] = 0);
end;

procedure Int64PolynomialSetZero(P: TCnInt64Polynomial);
begin
  P.Clear;
  P.Add(0);
end;

function Int64PolynomialIsOne(P: TCnInt64Polynomial): Boolean;
begin
  Result := (P.MaxDegree = 0) and (P[0] = 1);
end;

procedure Int64PolynomialSetOne(P: TCnInt64Polynomial);
begin
  P.Clear;
  P.Add(1);
end;

function Int64PolynomialIsNegOne(P: TCnInt64Polynomial): Boolean;
begin
  Result := (P.MaxDegree = 0) and (P[0] = -1);
end;

procedure Int64PolynomialNegate(P: TCnInt64Polynomial);
var
  I: Integer;
begin
  for I := 0 to P.MaxDegree do
    P[I] := -P[I];
end;

function Int64PolynomialIsMonic(P: TCnInt64Polynomial): Boolean;
begin
  Result := P[P.MaxDegree] = 1;
end;

procedure Int64PolynomialShiftLeft(P: TCnInt64Polynomial; N: Integer);
begin
  if N = 0 then
    Exit
  else if N < 0 then
    Int64PolynomialShiftRight(P, -N)
  else
    P.InsertBatch(0, N);
end;

procedure Int64PolynomialShiftRight(P: TCnInt64Polynomial; N: Integer);
begin
  if N = 0 then
    Exit
  else if N < 0 then
    Int64PolynomialShiftLeft(P, -N)
  else
  begin
    P.DeleteLow(N);

    if P.Count = 0 then
      P.Add(0);
  end;
end;

function Int64PolynomialEqual(A, B: TCnInt64Polynomial): Boolean;
var
  I: Integer;
begin
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  Result := A.MaxDegree = B.MaxDegree;
  if Result then
  begin
    for I := A.MaxDegree downto 0 do
    begin
      if A[I] <> B[I] then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

procedure Int64PolynomialAddWord(P: TCnInt64Polynomial; N: Int64);
begin
  P[0] := P[0] + N;
end;

procedure Int64PolynomialSubWord(P: TCnInt64Polynomial; N: Int64);
begin
  P[0] := P[0] - N;
end;

procedure Int64PolynomialMulWord(P: TCnInt64Polynomial; N: Int64);
var
  I: Integer;
begin
  if N = 0 then
    Int64PolynomialSetZero(P)
  else if N <> 1 then
  begin
    for I := 0 to P.MaxDegree do
      P[I] := P[I] * N;
  end;
end;

procedure Int64PolynomialDivWord(P: TCnInt64Polynomial; N: Int64);
var
  I: Integer;
begin
  if N = 0 then
    raise ECnPolynomialException.Create(SZeroDivide);

  if N <> 1 then
    for I := 0 to P.MaxDegree do
      P[I] := P[I] div N;
end;

procedure Int64PolynomialNonNegativeModWord(P: TCnInt64Polynomial; N: Int64);
var
  I: Integer;
begin
  if N = 0 then
    raise ECnPolynomialException.Create(SZeroDivide);

  for I := 0 to P.MaxDegree do
    P[I] := Int64NonNegativeMod(P[I], N);
end;

function Int64PolynomialAdd(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
var
  I, D1, D2: Integer;
  PBig: TCnInt64Polynomial;
begin
  D1 := Max(P1.MaxDegree, P2.MaxDegree);
  D2 := Min(P1.MaxDegree, P2.MaxDegree);

  if D1 > D2 then
  begin
    if P1.MaxDegree > P2.MaxDegree then
      PBig := P1
    else
      PBig := P2;

    Res.MaxDegree := D1; // ���ǵ� Res ������ P1 �� P2�����Ը� Res �� MaxDegree ��ֵ�÷�����ıȽ�֮��
    for I := D1 downto D2 + 1 do
      Res[I] := PBig[I];
  end
  else // D1 = D2 ˵������ʽͬ��
    Res.MaxDegree := D1;

  for I := D2 downto 0 do
    Res[I] := P1[I] + P2[I];
  Res.CorrectTop;
  Result := True;
end;

function Int64PolynomialSub(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
var
  I, D1, D2: Integer;
begin
  D1 := Max(P1.MaxDegree, P2.MaxDegree);
  D2 := Min(P1.MaxDegree, P2.MaxDegree);

  Res.MaxDegree := D1;
  if D1 > D2 then
  begin
    if P1.MaxDegree > P2.MaxDegree then // ����ʽ��
    begin
      for I := D1 downto D2 + 1 do
        Res[I] := P1[I];
    end
    else  // ��ʽ��
    begin
      for I := D1 downto D2 + 1 do
        Res[I] := -P2[I];
    end;
  end;

  for I := D2 downto 0 do
    Res[I] := P1[I] - P2[I];
  Res.CorrectTop;
  Result := True;
end;

function Int64PolynomialMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
var
  R: TCnInt64Polynomial;
  I, J: Integer;
begin
  if Int64PolynomialIsZero(P1) or Int64PolynomialIsZero(P2) then
  begin
    Int64PolynomialSetZero(Res);
    Result := True;
    Exit;
  end;

  if (Res = P1) or (Res = P2) then
    R := FLocalInt64PolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxDegree := P1.MaxDegree + P2.MaxDegree;

  for I := 0 to P1.MaxDegree do
  begin
    // �ѵ� I �η������ֳ��� P2 ��ÿһ�����֣��ӵ������ I ��ͷ�Ĳ���
    for J := 0 to P2.MaxDegree do
    begin
      R[I + J] := R[I + J] + P1[I] * P2[J];
    end;
  end;

  R.CorrectTop;
  if (Res = P1) or (Res = P2) then
  begin
    Int64PolynomialCopy(Res, R);
    FLocalInt64PolynomialPool.Recycle(R);
  end;
  Result := True;
end;

function Int64PolynomialDftMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
var
  M1, M2: PCnComplexNumber;
  C1, C2: PCnComplexArray;
  M, I: Integer;
begin
  Result := False;
  M := P1.MaxDegree;
  if M < P2.MaxDegree then
    M := P2.MaxDegree;

  if M < 0 then
    Exit;

  if M = 0 then // �������ֱ����
  begin
    Res.SetMaxDegree(0);
    Res[0] := P1[0] * P2[0];
    Result := True;
    Exit;
  end;

  // M �õ���ߴ������� 1 ��ʾ����ʽ�������
  Inc(M);

  // ���� 2 ��ʾ����ʽ�����������
  M := M shl 1;

  // ���ұ� M ����ߵ��� M �� 2 ����������
  if not IsUInt32PowerOf2(Cardinal(M)) then
  begin
    // ������� 2 ����������
    M := GetUInt32HighBits(Cardinal(M)); // M �õ����λ�� 1 ��λ�ã������� -1
    if M > 30 then
      raise ECnPolynomialException.Create(SCnErrorPolynomialDegreeTooLarge);

    Inc(M);
    M := 1 shl M; // �õ��� M �����С�� 2 ����������
  end;

  M1 := GetMemory(M * SizeOf(TCnComplexNumber));
  M2 := GetMemory(M * SizeOf(TCnComplexNumber));

  C1 := PCnComplexArray(M1);
  C2 := PCnComplexArray(M2);

  try
    for I := 0 to M - 1 do
    begin
      ComplexNumberSetZero(C1^[I]);
      ComplexNumberSetZero(C2^[I]);
    end;

    for I := 0 to P1.MaxDegree do
    begin
      C1^[I].R := P1[I];
      C1^[I].I := 0.0;
    end;
    for I := 0 to P2.MaxDegree do
    begin
      C2^[I].R := P2[I];
      C2^[I].I := 0.0;
    end;

    CnFFT(C1, M);
    CnFFT(C2, M);        // �õ������ֵ

    for I := 0 to M - 1 do   // ��ֵ���
      ComplexNumberMul(C1^[I], C1^[I], C2^[I]);

    Result := CnIFFT(C1, M);       // ��ֵ���ϵ�����ʽ

    Res.SetZero;
    Res.SetMaxDegree(M);
    for I := 0 to M - 1 do   // ��ֵ����������������ȡ��
      Res[I] := Round(C1^[I].R);

    Res.CorrectTop;
  finally
    FreeMemory(M1);
    FreeMemory(M2);
  end;
end;

function Int64PolynomialNttMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial): Boolean;
var
  M1, M2: PInt64;
  C1, C2: PInt64Array;
  M, I: Integer;
begin
  Result := False;
  M := P1.MaxDegree;
  if M < P2.MaxDegree then
    M := P2.MaxDegree;

  if M < 0 then
    Exit;

  if M = 0 then // �������ֱ����
  begin
    Res.SetMaxDegree(0);
    Res[0] := P1[0] * P2[0];
    Result := True;
    Exit;
  end;

  // M �õ���ߴ������� 1 ��ʾ����ʽ�������
  Inc(M);

  // ���� 2 ��ʾ����ʽ�����������
  M := M shl 1;

  // ���ұ� M ����ߵ��� M �� 2 ����������
  if not IsUInt32PowerOf2(Cardinal(M)) then
  begin
    // ������� 2 ����������
    M := GetUInt32HighBits(Cardinal(M)); // M �õ����λ�� 1 ��λ�ã������� -1
    if M > 30 then
      raise ECnPolynomialException.Create(SCnErrorPolynomialDegreeTooLarge);

    Inc(M);
    M := 1 shl M; // �õ��� M �����С�� 2 ����������
  end;

  M1 := GetMemory(M * SizeOf(Int64));
  M2 := GetMemory(M * SizeOf(Int64));

  C1 := PInt64Array(M1);
  C2 := PInt64Array(M2);

  try
    for I := 0 to M - 1 do
    begin
      C1^[I] := 0;
      C2^[I] := 0;
    end;

    for I := 0 to P1.MaxDegree do
      C1^[I] := P1[I];

    for I := 0 to P2.MaxDegree do
      C2^[I] := P2[I];

    CnNTT(C1, M);
    CnNTT(C2, M);        // �õ������ֵ

    for I := 0 to M - 1 do   // ��ֵ��ˣ����������
      C1^[I] := C1^[I] * C2^[I];

    Result := CnINTT(C1, M);       // ��ֵ���ϵ�����ʽ

    Res.SetZero;
    Res.SetMaxDegree(M);
    for I := 0 to M - 1 do
      Res[I] := C1^[I];

    Res.CorrectTop;
  finally
    FreeMemory(M1);
    FreeMemory(M2);
  end;
end;

function Int64PolynomialDiv(Res: TCnInt64Polynomial; Remain: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Divisor: TCnInt64Polynomial; ErrMulFactor: PInt64): Boolean;
var
  SubRes: TCnInt64Polynomial; // ���ɵݼ���
  MulRes: TCnInt64Polynomial; // ���ɳ����˻�
  DivRes: TCnInt64Polynomial; // ������ʱ��
  I, D: Integer;
  T: Int64;
begin
  if Int64PolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxDegree > P.MaxDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      Int64PolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      Int64PolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;

  try
    SubRes := FLocalInt64PolynomialPool.Obtain;
    Int64PolynomialCopy(SubRes, P);

    D := P.MaxDegree - Divisor.MaxDegree;
    DivRes := FLocalInt64PolynomialPool.Obtain;
    DivRes.MaxDegree := D;
    MulRes := FLocalInt64PolynomialPool.Obtain;

    for I := 0 to D do
    begin
      if P.MaxDegree - I > SubRes.MaxDegree then                 // �м���������λ
        Continue;

      // �ж� Divisor[Divisor.MaxDegree] �Ƿ������� SubRes[P.MaxDegree - I] ������˵�����������Ͷ���ʽ��Χ���޷�֧�֣�ֻ�ܳ���
      if (SubRes[P.MaxDegree - I] mod Divisor[Divisor.MaxDegree]) <> 0 then
      begin
        Result := False;
        if ErrMulFactor <> nil then
        begin
          // Divisor[Divisor.MaxDegree] �������ߵ����Լ��
          ErrMulFactor^ := Divisor[Divisor.MaxDegree] *
            CnInt64GreatestCommonDivisor(SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]);
        end;
        Exit;
      end;

      Int64PolynomialCopy(MulRes, Divisor);
      Int64PolynomialShiftLeft(MulRes, D - I);                 // ���뵽 SubRes ����ߴ�
      T := SubRes[P.MaxDegree - I] div MulRes[MulRes.MaxDegree];
      Int64PolynomialMulWord(MulRes, T); // ��ʽ�˵���ߴ�ϵ����ͬ
      DivRes[D - I] := T;                // �̷ŵ� DivRes λ��
      Int64PolynomialSub(SubRes, SubRes, MulRes);              // ���������·Ż� SubRes
    end;

    if Remain <> nil then
      Int64PolynomialCopy(Remain, SubRes);
    if Res <> nil then
      Int64PolynomialCopy(Res, DivRes);

    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(SubRes);
    FLocalInt64PolynomialPool.Recycle(MulRes);
    FLocalInt64PolynomialPool.Recycle(DivRes);
  end;
end;

function Int64PolynomialMod(Res: TCnInt64Polynomial; P: TCnInt64Polynomial;
  Divisor: TCnInt64Polynomial; ErrMulFactor: PInt64): Boolean;
begin
  Result := Int64PolynomialDiv(nil, Res, P, Divisor, ErrMulFactor);
end;

function Int64PolynomialPower(Res: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Exponent: Int64): Boolean;
var
  T: TCnInt64Polynomial;
begin
  if Exponent = 0 then
  begin
    Res.SetCoefficents([1]);
    Result := True;
    Exit;
  end
  else if Exponent = 1 then
  begin
    if Res <> P then
      Int64PolynomialCopy(Res, P);
    Result := True;
    Exit;
  end
  else if Exponent < 0 then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidExponent, [Exponent]);

  T := FLocalInt64PolynomialPool.Obtain;
  Int64PolynomialCopy(T, P);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetCoefficents([1]);
    while Exponent > 0 do
    begin
      if (Exponent and 1) <> 0 then
        Int64PolynomialMul(Res, Res, T);

      Exponent := Exponent shr 1;
      if Exponent > 0 then
        Int64PolynomialMul(T, T, T);
    end;
    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(T);
  end;
end;

function Int64PolynomialReduce(P: TCnInt64Polynomial): Integer;
var
  I: Integer;
  D: Int64;

  function Gcd(A, B: Int64): Int64;
  var
    T: Int64;
  begin
    while B <> 0 do
    begin
      T := B;
      B := A mod B;
      A := T;
    end;
    Result := A;
  end;

begin
  if P.MaxDegree = 0 then
  begin
    Result := P[P.MaxDegree];
    if P[P.MaxDegree] <> 0 then
      P[P.MaxDegree] := 1;
  end
  else
  begin
    D := P[0];
    for I := 0 to P.MaxDegree - 1 do
    begin
      D := Gcd(D, P[I + 1]);
      if D = 1 then
        Break;
    end;

    Result := D;
    if Result > 1 then
      Int64PolynomialDivWord(P, Result);
  end;
end;

procedure Int64PolynomialCentralize(P: TCnInt64Polynomial; Modulus: Int64);
var
  I: Integer;
  K: Int64;
begin
  K := Modulus div 2;
  for I := 0 to P.MaxDegree do
    if P[I] > K then
      P[I] := P[I] - Modulus;
end;

function Int64PolynomialGreatestCommonDivisor(Res: TCnInt64Polynomial;
  P1, P2: TCnInt64Polynomial): Boolean;
var
  A, B, C: TCnInt64Polynomial;
  MF: Int64;
begin
  A := nil;
  B := nil;
  C := nil;

  try
    A := FLocalInt64PolynomialPool.Obtain;
    B := FLocalInt64PolynomialPool.Obtain;

    if P1.MaxDegree >= P2.MaxDegree then
    begin
      Int64PolynomialCopy(A, P1);
      Int64PolynomialCopy(B, P2);
    end
    else
    begin
      Int64PolynomialCopy(A, P2);
      Int64PolynomialCopy(B, P1);
    end;

    C := FLocalInt64PolynomialPool.Obtain;
    while not B.IsZero do
    begin
      Int64PolynomialCopy(C, B);        // ���� B
      while not Int64PolynomialMod(B, A, B, @MF) do   // A mod B �� B
        Int64PolynomialMulWord(A, MF);

      // B Ҫϵ��Լ�ֻ���
      Int64PolynomialReduce(B);
      Int64PolynomialCopy(A, C);        // ԭʼ B �� A
    end;

    Int64PolynomialCopy(Res, A);
    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(A);
    FLocalInt64PolynomialPool.Recycle(B);
    FLocalInt64PolynomialPool.Recycle(C);
  end;
end;

function Int64PolynomialLeastCommonMultiple(Res: TCnInt64Polynomial;
  P1, P2: TCnInt64Polynomial): Boolean;
var
  G, M, R: TCnInt64Polynomial;
begin
  Result := False;
  if Int64PolynomialEqual(P1, P2) then
  begin
    Int64PolynomialCopy(Res, P1);
    Result := True;
    Exit;
  end;

  G := nil;
  M := nil;
  R := nil;

  try
    G := FLocalInt64PolynomialPool.Obtain;
    M := FLocalInt64PolynomialPool.Obtain;
    R := FLocalInt64PolynomialPool.Obtain;

    if not Int64PolynomialMul(M, P1, P2) then
      Exit;

    if not Int64PolynomialGreatestCommonDivisor(G, P1, P2) then
      Exit;

    if not Int64PolynomialDiv(Res, R, M, G) then
      Exit;

    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(R);
    FLocalInt64PolynomialPool.Recycle(M);
    FLocalInt64PolynomialPool.Recycle(G);
  end;
end;

function Int64PolynomialCompose(Res: TCnInt64Polynomial;
  F, P: TCnInt64Polynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnInt64Polynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    Res[0] := F[0];
    Result := True;
    Exit;
  end;

  if (Res = F) or (Res = P) then
    R := FLocalInt64PolynomialPool.Obtain
  else
    R := Res;

  X := FLocalInt64PolynomialPool.Obtain;
  T := FLocalInt64PolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      Int64PolynomialCopy(T, X);
      Int64PolynomialMulWord(T, F[I]);
      Int64PolynomialAdd(R, R, T);

      if I <> F.MaxDegree then
        Int64PolynomialMul(X, X, P);
    end;

    if (Res = F) or (Res = P) then
    begin
      Int64PolynomialCopy(Res, R);
      FLocalInt64PolynomialPool.Recycle(R);
    end;
  finally
    FLocalInt64PolynomialPool.Recycle(X);
    FLocalInt64PolynomialPool.Recycle(T);
  end;
  Result := True;
end;

function Int64PolynomialGetValue(F: TCnInt64Polynomial; X: Int64): Int64;
var
  I: Integer;
  T: Int64;
begin
  Result := F[0];
  if (X = 0) or (F.MaxDegree = 0) then    // ֻ�г����������£��ó�����
    Exit;

  T := X;

  // �� F �е�ÿ��ϵ������ X �Ķ�Ӧ������ˣ�������
  for I := 1 to F.MaxDegree do
  begin
    Result := Result + F[I] * T;
    if I <> F.MaxDegree then
      T := T * X;
  end;
end;

procedure Int64PolynomialReduce2(P1, P2: TCnInt64Polynomial);
var
  D: TCnInt64Polynomial;
begin
  if P1 = P2 then
  begin
    P1.SetOne;
    Exit;
  end;

  D := FLocalInt64PolynomialPool.Obtain;
  try
    if not Int64PolynomialGreatestCommonDivisor(D, P1, P2) then
      Exit;

    if not D.IsOne then
    begin
      Int64PolynomialDiv(P1, nil, P1, D);
      Int64PolynomialDiv(P1, nil, P1, D);
    end;
  finally
    FLocalInt64PolynomialPool.Recycle(D);
  end;
end;

function Int64PolynomialGaloisEqual(A, B: TCnInt64Polynomial; Prime: Int64): Boolean;
var
  I: Integer;
begin
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  Result := A.MaxDegree = B.MaxDegree;
  if Result then
  begin
    for I := A.MaxDegree downto 0 do
    begin
      if (A[I] <> B[I]) and (Int64NonNegativeMod(A[I], Prime) <> Int64NonNegativeMod(B[I], Prime)) then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

procedure Int64PolynomialGaloisNegate(P: TCnInt64Polynomial; Prime: Int64);
var
  I: Integer;
begin
  for I := 0 to P.MaxDegree do
    P[I] := Int64NonNegativeMod(-P[I], Prime);
end;

function Int64PolynomialGaloisAdd(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial): Boolean;
begin
  Result := Int64PolynomialAdd(Res, P1, P2);
  if Result then
  begin
    Int64PolynomialNonNegativeModWord(Res, Prime);
    if Primitive <> nil then
      Int64PolynomialGaloisMod(Res, Res, Primitive, Prime);
  end;
end;

function Int64PolynomialGaloisSub(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial): Boolean;
begin
  Result := Int64PolynomialSub(Res, P1, P2);
  if Result then
  begin
    Int64PolynomialNonNegativeModWord(Res, Prime);
    if Primitive <> nil then
      Int64PolynomialGaloisMod(Res, Res, Primitive, Prime);
  end;
end;

function Int64PolynomialGaloisMul(Res: TCnInt64Polynomial; P1: TCnInt64Polynomial;
  P2: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial): Boolean;
var
  R: TCnInt64Polynomial;
  I, J: Integer;
  T: Int64;
begin
  if Int64PolynomialIsZero(P1) or Int64PolynomialIsZero(P2) then
  begin
    Int64PolynomialSetZero(Res);
    Result := True;
    Exit;
  end;

  if (Res = P1) or (Res = P2) then
    R := FLocalInt64PolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxDegree := P1.MaxDegree + P2.MaxDegree;

  for I := 0 to P1.MaxDegree do
  begin
    // �ѵ� I �η������ֳ��� P2 ��ÿһ�����֣��ӵ������ I ��ͷ�Ĳ��֣���ȡģ
    for J := 0 to P2.MaxDegree do
    begin
      // �������������ֱ�����
      T := Int64NonNegativeMulMod(P1[I], P2[J], Prime);
      R[I + J] := Int64NonNegativeMod(R[I + J] + Int64NonNegativeMod(T, Prime), Prime);
      // TODO: ��δ����ӷ���������
    end;
  end;

  R.CorrectTop;

  // �ٶԱ�ԭ����ʽȡģ��ע�����ﴫ��ı�ԭ����ʽ�� mod �����ĳ��������Ǳ�ԭ����ʽ����
  if Primitive <> nil then
    Int64PolynomialGaloisMod(R, R, Primitive, Prime);

  if (Res = P1) or (Res = P2) then
  begin
    Int64PolynomialCopy(Res, R);
    FLocalInt64PolynomialPool.Recycle(R);
  end;
  Result := True;
end;

function Int64PolynomialGaloisDiv(Res: TCnInt64Polynomial; Remain: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Divisor: TCnInt64Polynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial; ErrMulFactor: PInt64): Boolean;
var
  SubRes: TCnInt64Polynomial; // ���ɵݼ���
  MulRes: TCnInt64Polynomial; // ���ɳ����˻�
  DivRes: TCnInt64Polynomial; // ������ʱ��
  I, D: Integer;
  K, T: Int64;
begin
  if Int64PolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  // ���赣�Ĳ������������⣬��Ϊ����Ԫ�� mod ����������Ԫ������ʱ������ֻ�ܳ���

  if Divisor.MaxDegree > P.MaxDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      Int64PolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      Int64PolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;

  try
    SubRes := FLocalInt64PolynomialPool.Obtain;
    Int64PolynomialCopy(SubRes, P);

    D := P.MaxDegree - Divisor.MaxDegree;
    DivRes := FLocalInt64PolynomialPool.Obtain;
    DivRes.MaxDegree := D;
    MulRes := FLocalInt64PolynomialPool.Obtain;

    if Divisor[Divisor.MaxDegree] = 1 then
      K := 1
    else
      K := CnInt64ModularInverse2(Divisor[Divisor.MaxDegree], Prime); // K �ǳ�ʽ���λ����Ԫ��ע�����Ϊ 0

    for I := 0 to D do
    begin
      if P.MaxDegree - I > SubRes.MaxDegree then               // �м���������λ
        Continue;
      Int64PolynomialCopy(MulRes, Divisor);
      Int64PolynomialShiftLeft(MulRes, D - I);                 // ���뵽 SubRes ����ߴ�

      if K <> 0 then // ��ģ��Ԫ
      begin
        // ��ʽҪ��һ������������� SubRes ���λ���Գ�ʽ���λ�õ��Ľ����Ҳ�� SubRes ���λ���Գ�ʽ���λ����Ԫ�� mod Prime
        T := Int64NonNegativeMulMod(SubRes[P.MaxDegree - I], K, Prime);
        Int64PolynomialGaloisMulWord(MulRes, T, Prime);          // ��ʽ�˵���ߴ�ϵ����ͬ
      end
      else  // Prime �ͳ�ʽ���λ������ʱģ��Ԫ K �����ڣ�Ҫ�������Ͳ������������
      begin
        T := SubRes[P.MaxDegree - I] mod Divisor[Divisor.MaxDegree];
        if T <> 0 then  // ��������û��ģ��Ԫ��������ζ�û������ֻ�ܳ����˳�
        begin
          Result := False;
          if ErrMulFactor <> nil then
          begin
            // Divisor[Divisor.MaxDegree] �������ߵ����Լ��
            ErrMulFactor^ := Divisor[Divisor.MaxDegree] *
              CnInt64GreatestCommonDivisor(SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]);
          end;
          Exit;
        end
        else
        begin
          T := SubRes[P.MaxDegree - I] div Divisor[Divisor.MaxDegree];
          Int64PolynomialGaloisMulWord(MulRes, T, Prime);      // ��ʽ�˵���ߴ�ϵ����ͬ
        end;
      end;

      DivRes[D - I] := T;                                      // ��Ӧλ���̷ŵ� DivRes λ��
      Int64PolynomialGaloisSub(SubRes, SubRes, MulRes, Prime); // ����ģ�������·Ż� SubRes
    end;

    // ������ʽ����Ҫ��ģ��ԭ����ʽ
    if Primitive <> nil then
    begin
      Int64PolynomialGaloisMod(SubRes, SubRes, Primitive, Prime);
      Int64PolynomialGaloisMod(DivRes, DivRes, Primitive, Prime);
    end;

    if Remain <> nil then
      Int64PolynomialCopy(Remain, SubRes);
    if Res <> nil then
      Int64PolynomialCopy(Res, DivRes);
    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(SubRes);
    FLocalInt64PolynomialPool.Recycle(MulRes);
    FLocalInt64PolynomialPool.Recycle(DivRes);
  end;
end;

function Int64PolynomialGaloisMod(Res: TCnInt64Polynomial;
  P: TCnInt64Polynomial; Divisor: TCnInt64Polynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial; ErrMulFactor: PInt64): Boolean;
begin
  Result := Int64PolynomialGaloisDiv(nil, Res, P, Divisor, Prime, Primitive, ErrMulFactor);
end;

function Int64PolynomialGaloisPower(Res, P: TCnInt64Polynomial;
  Exponent: Int64; Prime: Int64; Primitive: TCnInt64Polynomial;
  ExponentHi: Int64): Boolean;
var
  T: TCnInt64Polynomial;
begin
  if Exponent128IsZero(Exponent, ExponentHi) then
  begin
    Res.SetCoefficents([1]);
    Result := True;
    Exit;
  end
  else if Exponent128IsOne(Exponent, ExponentHi) then
  begin
    if Res <> P then
      Int64PolynomialCopy(Res, P);
    Result := True;
    Exit;
  end;

  T := FLocalInt64PolynomialPool.Obtain;
  Int64PolynomialCopy(T, P);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetCoefficents([1]);
    while not Exponent128IsZero(Exponent, ExponentHi) do
    begin
      if (Exponent and 1) <> 0 then
        Int64PolynomialGaloisMul(Res, Res, T, Prime, Primitive);

      ExponentShiftRightOne(Exponent, ExponentHi);
      if not Exponent128IsZero(Exponent, ExponentHi) then
        Int64PolynomialGaloisMul(T, T, T, Prime, Primitive);
    end;
    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(T);
  end;
end;

procedure Int64PolynomialGaloisAddWord(P: TCnInt64Polynomial; N: Int64;
  Prime: Int64);
begin
  if N <> 0 then
    P[0] := Int64NonNegativeMod(P[0] + N, Prime);
end;

procedure Int64PolynomialGaloisSubWord(P: TCnInt64Polynomial; N: Int64;
  Prime: Int64);
begin
  if N <> 0 then
    P[0] := Int64NonNegativeMod(P[0] - N, Prime);
end;

procedure Int64PolynomialGaloisMulWord(P: TCnInt64Polynomial; N: Int64;
  Prime: Int64);
var
  I: Integer;
begin
  if N = 0 then
  begin
    Int64PolynomialSetZero(P);
  end
  else if N <> 1 then
  begin
    for I := 0 to P.MaxDegree do
      P[I] := Int64NonNegativeMulMod(P[I], N, Prime);
  end;
end;

procedure Int64PolynomialGaloisDivWord(P: TCnInt64Polynomial; N: Int64;
  Prime: Int64);
var
  I: Integer;
  K: Int64;
  B: Boolean;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero);

  B := N < 0;
  if B then
    N := -N;

  K := CnInt64ModularInverse2(N, Prime);
  for I := 0 to P.MaxDegree do
  begin
    P[I] := Int64NonNegativeMulMod(P[I], K, Prime);
    if B then
      P[I] := Prime - P[I];
  end;
end;

function Int64PolynomialGaloisMonic(P: TCnInt64Polynomial; Prime: Int64): Integer;
begin
  Result := P[P.MaxDegree];
  if (Result <> 1) and (Result <> 0) then
    Int64PolynomialGaloisDivWord(P, Result, Prime);
end;

function Int64PolynomialGaloisGreatestCommonDivisor(Res: TCnInt64Polynomial;
  P1, P2: TCnInt64Polynomial; Prime: Int64): Boolean;
var
  A, B, C: TCnInt64Polynomial;
begin
  Result := False;
  A := nil;
  B := nil;
  C := nil;

  try
    A := FLocalInt64PolynomialPool.Obtain;
    B := FLocalInt64PolynomialPool.Obtain;

    if P1.MaxDegree >= P2.MaxDegree then
    begin
      Int64PolynomialCopy(A, P1);
      Int64PolynomialCopy(B, P2);
    end
    else
    begin
      Int64PolynomialCopy(A, P2);
      Int64PolynomialCopy(B, P1);
    end;

    C := FLocalInt64PolynomialPool.Obtain;
    while not B.IsZero do
    begin
      Int64PolynomialCopy(C, B);          // ���� B
      if not Int64PolynomialGaloisMod(B, A, B, Prime) then  // A mod B �� B
        Exit;

      if B.MaxDegree = 0 then  // ����ǳ��������Ϊ 1
      begin
        if B[0] <> 0 then
          B[0] := 1;
      end;

      Int64PolynomialCopy(A, C);          // ԭʼ B �� A
    end;

    Int64PolynomialCopy(Res, A);
    Int64PolynomialGaloisMonic(Res, Prime);      // ���Ϊһ
    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(A);
    FLocalInt64PolynomialPool.Recycle(B);
    FLocalInt64PolynomialPool.Recycle(C);
  end;
end;

function Int64PolynomialGaloisLeastCommonMultiple(Res: TCnInt64Polynomial;
  P1, P2: TCnInt64Polynomial; Prime: Int64): Boolean;
var
  G, M, R: TCnInt64Polynomial;
begin
  Result := False;
  if Int64PolynomialEqual(P1, P2) then
  begin
    Int64PolynomialCopy(Res, P1);
    Result := True;
    Exit;
  end;

  G := nil;
  M := nil;
  R := nil;

  try
    G := FLocalInt64PolynomialPool.Obtain;
    M := FLocalInt64PolynomialPool.Obtain;
    R := FLocalInt64PolynomialPool.Obtain;

    if not Int64PolynomialGaloisMul(M, P1, P2, Prime) then
      Exit;

    if not Int64PolynomialGaloisGreatestCommonDivisor(G, P1, P2, Prime) then
      Exit;

    if not Int64PolynomialGaloisDiv(Res, R, M, G, Prime) then
      Exit;

    Result := True;
  finally
    FLocalInt64PolynomialPool.Recycle(R);
    FLocalInt64PolynomialPool.Recycle(M);
    FLocalInt64PolynomialPool.Recycle(G);
  end;
end;

procedure Int64PolynomialGaloisExtendedEuclideanGcd(A, B: TCnInt64Polynomial;
  X, Y: TCnInt64Polynomial; Prime: Int64);
var
  T, P, M: TCnInt64Polynomial;
begin
  if B.IsZero then
  begin
    X.SetZero;
    X[0] := CnInt64ModularInverse2(A[0], Prime);
    // X ���� A ���� P ��ģ��Ԫ��������������շת����������� 1
    // ��Ϊ A �����ǲ����� 1 ������
    Y.SetZero;
  end
  else
  begin
    T := nil;
    P := nil;
    M := nil;

    try
      T := FLocalInt64PolynomialPool.Obtain;
      P := FLocalInt64PolynomialPool.Obtain;
      M := FLocalInt64PolynomialPool.Obtain;

      Int64PolynomialGaloisMod(P, A, B, Prime);

      Int64PolynomialGaloisExtendedEuclideanGcd(B, P, Y, X, Prime);

      // Y := Y - (A div B) * X;
      Int64PolynomialGaloisDiv(P, M, A, B, Prime);
      Int64PolynomialGaloisMul(P, P, X, Prime);
      Int64PolynomialGaloisSub(Y, Y, P, Prime);
    finally
      FLocalInt64PolynomialPool.Recycle(M);
      FLocalInt64PolynomialPool.Recycle(P);
      FLocalInt64PolynomialPool.Recycle(T);
    end;
  end;
end;

procedure Int64PolynomialGaloisModularInverse(Res: TCnInt64Polynomial;
  X, Modulus: TCnInt64Polynomial; Prime: Int64; CheckGcd: Boolean);
var
  X1, Y, G: TCnInt64Polynomial;
begin
  X1 := nil;
  Y := nil;
  G := nil;

  try
    if CheckGcd then
    begin
      G := FLocalInt64PolynomialPool.Obtain;
      Int64PolynomialGaloisGreatestCommonDivisor(G, X, Modulus, Prime);
      if not G.IsOne then
        raise ECnPolynomialException.Create(SCnErrorPolynomialGCDMustOne);
    end;

    X1 := FLocalInt64PolynomialPool.Obtain;
    Y := FLocalInt64PolynomialPool.Obtain;

    Int64PolynomialCopy(X1, X);

    // ��չŷ�����շת��������Ԫһ�β�����ϵ������ʽ���� A * X - B * Y = 1 ��������
    Int64PolynomialGaloisExtendedEuclideanGcd(X1, Modulus, Res, Y, Prime);
  finally
    FLocalInt64PolynomialPool.Recycle(X1);
    FLocalInt64PolynomialPool.Recycle(Y);
    FLocalInt64PolynomialPool.Recycle(G);
  end;
end;

function Int64PolynomialGaloisPrimePowerModularInverse(Res: TCnInt64Polynomial;
  X, Modulus: TCnInt64Polynomial; PrimeRoot, Exponent: Integer): Boolean;
var
  F, G, T: TCnInt64Polynomial;
  N: Integer;
  P: Int64;
begin
  // ԭʼ X �� Modulus ��ģ PrimeRoot^Exponent �µģ���ϵ���� PrimeRoot ��ģ�õ� F �� G ������ʽ

  if Exponent < 2 then
    raise ECnPolynomialException.Create(SCnErrorPolynomialInvalidExponent);

  F := nil;
  G := nil;
  T := nil;

  try
    F := FLocalInt64PolynomialPool.Obtain;
    G := FLocalInt64PolynomialPool.Obtain;

    Int64PolynomialCopy(F, X);
    Int64PolynomialCopy(G, Modulus);

    Int64PolynomialNonNegativeModWord(F, PrimeRoot);
    Int64PolynomialNonNegativeModWord(G, PrimeRoot);

    T := FLocalInt64PolynomialPool.Obtain;
    Int64PolynomialGaloisGreatestCommonDivisor(T, F, G, PrimeRoot);

    Result := T.IsOne;  // F G �ͷ��˿��Ը���
    if not Result then  // �� PrimeRoot �»��� PrimeRoot^Exponent �²�����Ԫ
      Exit;

    Int64PolynomialGaloisModularInverse(T, F, G, PrimeRoot); // �� PrimeRoot ģ�µ������ʽ

    N := 2;
    while N <= Exponent do
    begin
      // T := (p * T - X * T^2) in Ring(p^n, M)

      P := Int64NonNegativPower(PrimeRoot, N);

      Int64PolynomialGaloisMul(F, T, T, P);
      Int64PolynomialGaloisMul(F, F, X, P);

      Int64PolynomialGaloisMulWord(T, PrimeRoot, P);
      Int64PolynomialGaloisSub(T, T, F, P, Modulus);

      N := N + 1;
    end;

    // Result := T in Ring(p^e, M)
    P := Int64NonNegativPower(PrimeRoot, Exponent);
    Result := Int64PolynomialGaloisMod(Res, T, Modulus, P);
  finally
    FLocalInt64PolynomialPool.Recycle(T);
    FLocalInt64PolynomialPool.Recycle(G);
    FLocalInt64PolynomialPool.Recycle(F);
  end;
end;

function Int64PolynomialGaloisCompose(Res: TCnInt64Polynomial;
  F, P: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64Polynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnInt64Polynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    Res[0] := Int64NonNegativeMod(F[0], Prime);
    Result := True;
    Exit;
  end;

  if (Res = F) or (Res = P) then
    R := FLocalInt64PolynomialPool.Obtain
  else
    R := Res;

  X := FLocalInt64PolynomialPool.Obtain;
  T := FLocalInt64PolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      Int64PolynomialCopy(T, X);
      Int64PolynomialGaloisMulWord(T, F[I], Prime);
      Int64PolynomialGaloisAdd(R, R, T, Prime);

      if I <> F.MaxDegree then
        Int64PolynomialGaloisMul(X, X, P, Prime);
    end;

    if Primitive <> nil then
      Int64PolynomialGaloisMod(R, R, Primitive, Prime);

    if (Res = F) or (Res = P) then
    begin
      Int64PolynomialCopy(Res, R);
      FLocalInt64PolynomialPool.Recycle(R);
    end;
  finally
    FLocalInt64PolynomialPool.Recycle(X);
    FLocalInt64PolynomialPool.Recycle(T);
  end;
  Result := True;
end;

function Int64PolynomialGaloisGetValue(F: TCnInt64Polynomial; X, Prime: Int64): Int64;
var
  I: Integer;
  T: Int64;
begin
  Result := Int64NonNegativeMod(F[0], Prime);
  if (X = 0) or (F.MaxDegree = 0) then    // ֻ�г����������£��ó�����
    Exit;

  T := X;

  // �� F �е�ÿ��ϵ������ X �Ķ�Ӧ������ˣ�������
  for I := 1 to F.MaxDegree do
  begin
    Result := Int64NonNegativeMod(Result + Int64NonNegativeMulMod(F[I], T, Prime), Prime);
    if I <> F.MaxDegree then
      T := Int64NonNegativeMulMod(T, X, Prime);
  end;
  Result := Int64NonNegativeMod(Result, Prime);
end;

{
  �ɳ�����ʽ�����֣�һ���Ǻ� x y �� F��һ����ֻ�� x �� f�����߶��� y ��������Ҫ����˸� y
  ���� Fn �� n Ϊż��ʱ��Ȼ���� y * ������Կ��Թ涨 Fn = fn * y ��n Ϊż����fn = Fn ��n Ϊ�棩

  F0 = 0
  F1 = 1
  F2 = 2y
  F3 = 3x^4 + 6Ax^2 + 12Bx - A^2
  F4 = 4y * (x^6 + 5Ax^4 + 20Bx^3 - 5A^2x^2 - 4ABx - 8B^2 - A^3)
  F5 = 5x^12 + 62Ax^10 + 380Bx^9 + 105A^2x^8 + 240BAx^7 + (-300A^3 - 240B^2)x^6
    - 696BA^2x^5 + (-125A^4 - 1920B^2A)x^4 + (-80BA^3 - 1600B^3)x^3 + (-50A^5 - 240B^2A^2)x^2
    + (100BA^4 - 640B^3A)x + (A^6 - 32B^2A^3 - 256B4)
  ......

  һ�㣺
    F2n+1 = Fn+2 * Fn^3 - Fn-1 * Fn+1^3
    F2n   = (Fn/2y) * (Fn+2 * Fn-1^2 - Fn-2 * Fn+1^2)       // �𿴳��� 2y��ʵ���ϱ�Ȼ�� * y ��

  ��Ӧ�ģ�

  f0 = 0
  f1 = 1
  f2 = 2
  f3 = 3x^4 + 6Ax^2 + 12Bx - A^2
  f4 = 4 * (x^6 + 5Ax^4 + 20Bx^3 - 5A^2x^2 - 4ABx - 8B^2 - A^3)
  f5 = 5x^12 + 62Ax^10 + 380Bx^9 + 105A^2x^8 + 240BAx^7 + (-300A^3 - 240B^2)x^6
    - 696BA^2x^5 + (-125A^4 - 1920B^2A)x^4 + (-80BA^3 - 1600B^3)x^3 + (-50A^5 - 240B^2A^2)x^2
    + (100BA^4 - 640B^3A)x + (A^6 - 32B^2A^3 - 256B4)
  ......

  һ�㣺
    f2n = fn * (fn+2 * fn-1 ^ 2 - fn-2 * fn+1 ^ 2) / 2
    f2n+1 = fn+2 * fn^3 - fn-1 * fn+1^3 * (x^3 + Ax + B)^2     //  nΪ��
          = (x^3 + Ax + B)^2 * fn+2 * fn^3 - fn-1 * fn+1^3     //  nΪż

}
function Int64PolynomialGaloisCalcDivisionPolynomial(A, B: Int64; Degree: Int64;
  OutDivisionPolynomial: TCnInt64Polynomial; Prime: Int64): Boolean;
var
  N: Integer;
  MI, T1, T2: Int64;
  D1, D2, D3, Y4: TCnInt64Polynomial;
begin
  if Degree < 0 then
    raise ECnPolynomialException.Create(SCnErrorPolynomialGaloisInvalidDegree)
  else if Degree = 0 then
  begin
    OutDivisionPolynomial.SetCoefficents([0]);  // f0(X) = 0
    Result := True;
  end
  else if Degree = 1 then
  begin
    OutDivisionPolynomial.SetCoefficents([1]);  // f1(X) = 1
    Result := True;
  end
  else if Degree = 2 then
  begin
    OutDivisionPolynomial.SetCoefficents([2]);  // f2(X) = 2
    Result := True;
  end
  else if Degree = 3 then   // f3(X) = 3 X4 + 6 a X2 + 12 b X - a^2
  begin
    OutDivisionPolynomial.MaxDegree := 4;
    OutDivisionPolynomial[4] := 3;
    OutDivisionPolynomial[3] := 0;
    OutDivisionPolynomial[2] := Int64NonNegativeMulMod(6, A, Prime);
    OutDivisionPolynomial[1] := Int64NonNegativeMulMod(12, B, Prime);
    OutDivisionPolynomial[0] := Int64NonNegativeMulMod(-A, A, Prime);

    Result := True;
  end
  else if Degree = 4 then // f4(X) = 4 X6 + 20 a X4 + 80 b X3 - 20 a2X2 - 16 a b X - 4 a3 - 32 b^2
  begin
    OutDivisionPolynomial.MaxDegree := 6;
    OutDivisionPolynomial[6] := 4;
    OutDivisionPolynomial[5] := 0;
    OutDivisionPolynomial[4] := Int64NonNegativeMulMod(20, A, Prime);
    OutDivisionPolynomial[3] := Int64NonNegativeMulMod(80, B, Prime);
    OutDivisionPolynomial[2] := Int64NonNegativeMulMod(Int64NonNegativeMulMod(-20, A, Prime), A, Prime);
    OutDivisionPolynomial[1] := Int64NonNegativeMulMod(Int64NonNegativeMulMod(-16, A, Prime), B, Prime);
    T1 := Int64NonNegativeMulMod(Int64NonNegativeMulMod(Int64NonNegativeMulMod(-4, A, Prime), A, Prime), A, Prime);
    T2 := Int64NonNegativeMulMod(Int64NonNegativeMulMod(-32, B, Prime), B, Prime);
    OutDivisionPolynomial[0] := Int64NonNegativeMod(T1 + T2, Prime); // TODO: ��δ������������ȡģ

    Result := True;
  end
  else
  begin
    D1 := nil;
    D2 := nil;
    D3 := nil;
    Y4 := nil;

    try
      // ��ʼ�ݹ����
      N := Degree shr 1;
      if (Degree and 1) = 0 then // Degree ��ż�������� fn * (fn+2 * fn-1 ^ 2 - fn-2 * fn+1 ^ 2) / 2
      begin
        D1 := FLocalInt64PolynomialPool.Obtain;
        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N + 2, D1, Prime);

        D2 := FLocalInt64PolynomialPool.Obtain;        // D1 �õ� fn+2
        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N - 1, D2, Prime);
        Int64PolynomialGaloisMul(D2, D2, D2, Prime);   // D2 �õ� fn-1 ^2

        Int64PolynomialGaloisMul(D1, D1, D2, Prime);   // D1 �õ� fn+2 * fn-1 ^ 2

        D3 := FLocalInt64PolynomialPool.Obtain;
        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N - 2, D3, Prime);  // D3 �õ� fn-2

        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N + 1, D2, Prime);
        Int64PolynomialGaloisMul(D2, D2, D2, Prime);   // D2 �õ� fn+1^2
        Int64PolynomialGaloisMul(D2, D2, D3, Prime);   // D2 �õ� fn-2 * fn+1^2

        Int64PolynomialGaloisSub(D1, D1, D2, Prime);   // D1 �õ� fn+2 * fn-1^2 - fn-2 * fn+1^2

        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N, D2, Prime);    // D2 �õ� fn
        Int64PolynomialGaloisMul(OutDivisionPolynomial, D2, D1, Prime);     // ��˵õ� f2n
        MI := CnInt64ModularInverse(2, Prime);
        Int64PolynomialGaloisMulWord(OutDivisionPolynomial, MI, Prime);     // �ٳ��� 2
      end
      else // Degree ������
      begin
        Y4 := FLocalInt64PolynomialPool.Obtain;
        Y4.SetCoefficents([B, A, 0, 1]);
        Int64PolynomialGaloisMul(Y4, Y4, Y4, Prime);

        D1 := FLocalInt64PolynomialPool.Obtain;
        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N + 2, D1, Prime); // D1 �õ� fn+2

        D2 := FLocalInt64PolynomialPool.Obtain;
        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N, D2, Prime);
        Int64PolynomialGaloisPower(D2, D2, 3, Prime);                        // D2 �õ� fn^3

        D3 := FLocalInt64PolynomialPool.Obtain;
        Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N + 1, D3, Prime);
        Int64PolynomialGaloisPower(D3, D3, 3, Prime);                        // D3 �õ� fn+1^3

        if (N and 1) <> 0 then // N ������������ f2n+1 = fn+2 * fn^3 - fn-1 * fn+1^3 * (x^3 + Ax + B)^2
        begin
          Int64PolynomialGaloisMul(D1, D1, D2, Prime);  // D1 �õ� fn+2 * fn^3

          Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N - 1, D2, Prime);
          Int64PolynomialGaloisMul(D2, D2, Y4, Prime);  // D2 �õ� fn-1 * Y^4

          Int64PolynomialGaloisMul(D2, D2, D3, Prime);  // D2 �õ� fn+1^3 * fn-1 * Y^4
          Int64PolynomialGaloisSub(OutDivisionPolynomial, D1, D2, Prime);
        end
        else // N ��ż�������� (x^3 + Ax + B)^2 * fn+2 * fn^3 - fn-1 * fn+1^3
        begin
          Int64PolynomialGaloisMul(D1, D1, D2, Prime);
          Int64PolynomialGaloisMul(D1, D1, Y4, Prime);  // D1 �õ� Y^4 * fn+2 * fn^3

          Int64PolynomialGaloisCalcDivisionPolynomial(A, B, N - 1, D2, Prime);  // D2 �õ� fn-1

          Int64PolynomialGaloisMul(D2, D2, D3, Prime);  // D2 �õ� fn-1 * fn+1^3

          Int64PolynomialGaloisSub(OutDivisionPolynomial, D1, D2, Prime);
        end;
      end;
    finally
      FLocalInt64PolynomialPool.Recycle(D1);
      FLocalInt64PolynomialPool.Recycle(D2);
      FLocalInt64PolynomialPool.Recycle(D3);
      FLocalInt64PolynomialPool.Recycle(Y4);
    end;
    Result := True;
  end;
end;

procedure Int64PolynomialGaloisReduce2(P1, P2: TCnInt64Polynomial; Prime: Int64);
var
  D: TCnInt64Polynomial;
begin
  if P1 = P2 then
  begin
    P1.SetOne;
    Exit;
  end;

  D := FLocalInt64PolynomialPool.Obtain;
  try
    if not Int64PolynomialGaloisGreatestCommonDivisor(D, P1, P2, Prime) then
      Exit;

    if not D.IsOne then
    begin
      Int64PolynomialGaloisDiv(P1, nil, P1, D, Prime);
      Int64PolynomialGaloisDiv(P1, nil, P1, D, Prime);
    end;
  finally
    FLocalInt64PolynomialPool.Recycle(D);
  end;
end;

{ TCnInt64PolynomialPool }

function TCnInt64PolynomialPool.CreateObject: TObject;
begin
  Result := TCnInt64Polynomial.Create;
end;

function TCnInt64PolynomialPool.Obtain: TCnInt64Polynomial;
begin
  Result := TCnInt64Polynomial(inherited Obtain);
  Result.SetZero;
end;

procedure TCnInt64PolynomialPool.Recycle(Poly: TCnInt64Polynomial);
begin
  inherited Recycle(Poly);
end;

{ TCnInt64RationalPolynomial }

procedure TCnInt64RationalPolynomial.AssignTo(Dest: TPersistent);
begin
  if Dest is TCnInt64RationalPolynomial then
  begin
    Int64PolynomialCopy(TCnInt64RationalPolynomial(Dest).Nominator, FNominator);
    Int64PolynomialCopy(TCnInt64RationalPolynomial(Dest).Denominator, FDenominator);
  end
  else
    inherited;
end;

constructor TCnInt64RationalPolynomial.Create;
begin
  inherited;
  FNominator := TCnInt64Polynomial.Create([0]);
  FDenominator := TCnInt64Polynomial.Create([1]);
end;

destructor TCnInt64RationalPolynomial.Destroy;
begin
  FDenominator.Free;
  FNominator.Free;
  inherited;
end;

function TCnInt64RationalPolynomial.IsInt: Boolean;
begin
  Result := FDenominator.IsOne or FDenominator.IsNegOne;
end;

function TCnInt64RationalPolynomial.IsOne: Boolean;
begin
  Result := not FNominator.IsZero and Int64PolynomialEqual(FNominator, FDenominator);
end;

function TCnInt64RationalPolynomial.IsZero: Boolean;
begin
  Result := not FDenominator.IsZero and FNominator.IsZero;
end;

procedure TCnInt64RationalPolynomial.Neg;
begin
  FNominator.Negate;
end;

procedure TCnInt64RationalPolynomial.Reciprocal;
var
  T: TCnInt64Polynomial;
begin
  if FNominator.IsZero then
    raise EDivByZero.Create(SDivByZero);

  T := FLocalInt64PolynomialPool.Obtain;
  try
    Int64PolynomialCopy(T, FDenominator);
    Int64PolynomialCopy(FDenominator, FNominator);
    Int64PolynomialCopy(FNominator, T);
  finally
    FLocalInt64PolynomialPool.Recycle(T);
  end;
end;

procedure TCnInt64RationalPolynomial.Reduce;
begin
  Int64PolynomialReduce2(FNominator, FDenominator);
end;

procedure TCnInt64RationalPolynomial.SetOne;
begin
  FDenominator.SetOne;
  FNominator.SetOne;
end;

procedure TCnInt64RationalPolynomial.SetString(const Rational: string);
var
  P: Integer;
  N, D: string;
begin
  P := Pos('/', Rational);
  if P > 1 then
  begin
    N := Copy(Rational, 1, P - 1);
    D := Copy(Rational, P + 1, MaxInt);

    FNominator.SetString(Trim(N));
    FDenominator.SetString(Trim(D));
  end
  else
  begin
    FNominator.SetString(Rational);
    FDenominator.SetOne;
  end;
end;

procedure TCnInt64RationalPolynomial.SetZero;
begin
  FDenominator.SetOne;
  FNominator.SetZero;
end;

function TCnInt64RationalPolynomial.ToString: string;
begin
  if FDenominator.IsOne then
    Result := FNominator.ToString
  else if FNominator.IsZero then
    Result := '0'
  else
    Result := FNominator.ToString + ' / ' + FDenominator.ToString;
end;

// ============================= �����ʽ���� ==================================

function Int64RationalPolynomialEqual(R1, R2: TCnInt64RationalPolynomial): Boolean;
var
  T1, T2: TCnInt64Polynomial;
begin
  if R1 = R2 then
  begin
    Result := True;
    Exit;
  end;

  if R1.IsInt and R2.IsInt then
  begin
    Result := Int64PolynomialEqual(R1.Nominator, R2.Nominator);
    Exit;
  end;

  T1 := FLocalInt64PolynomialPool.Obtain;
  T2 := FLocalInt64PolynomialPool.Obtain;

  try
    // �жϷ��ӷ�ĸ����˵Ľ���Ƿ����
    Int64PolynomialMul(T1, R1.Nominator, R2.Denominator);
    Int64PolynomialMul(T2, R2.Nominator, R1.Denominator);
    Result := Int64PolynomialEqual(T1, T2);
  finally
    FLocalInt64PolynomialPool.Recycle(T2);
    FLocalInt64PolynomialPool.Recycle(T1);
  end;
end;

function Int64RationalPolynomialCopy(Dst: TCnInt64RationalPolynomial;
  Src: TCnInt64RationalPolynomial): TCnInt64RationalPolynomial;
begin
  Result := Dst;
  if Src <> Dst then
  begin
    Int64PolynomialCopy(Dst.Nominator, Src.Nominator);
    Int64PolynomialCopy(Dst.Denominator, Src.Denominator);
  end;
end;

procedure Int64RationalPolynomialAdd(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial);
var
  M, R, F1, F2, D1, D2: TCnInt64Polynomial;
begin
  if R1.IsInt and R2.IsInt then
  begin
    Int64PolynomialAdd(RationalResult.Nominator, R1.Nominator, R2.Nominator);
    RationalResult.Denominator.SetOne;
    Exit;
  end
  else if R1.IsZero then
  begin
    if R2 <> RationalResult then
      RationalResult.Assign(R2);
  end
  else if R2.IsZero then
  begin
    if R1 <> RationalResult then
      RationalResult.Assign(R1);
  end
  else
  begin
    M := nil;
    R := nil;
    F1 := nil;
    F2 := nil;
    D1 := nil;
    D2 := nil;

    try
      // ���ĸ����С������
      M := FLocalInt64PolynomialPool.Obtain;
      R := FLocalInt64PolynomialPool.Obtain;
      F1 := FLocalInt64PolynomialPool.Obtain;
      F2 := FLocalInt64PolynomialPool.Obtain;
      D1 := FLocalInt64PolynomialPool.Obtain;
      D2 := FLocalInt64PolynomialPool.Obtain;

      Int64PolynomialCopy(D1, R1.Denominator);
      Int64PolynomialCopy(D2, R2.Denominator);

      if not Int64PolynomialLeastCommonMultiple(M, D1, D2) then
        Int64PolynomialMul(M, D1, D2);   // �޷�����С����ʽ��ʾϵ���޷�������ֱ�����

      Int64PolynomialDiv(F1, R, M, D1);
      Int64PolynomialDiv(F2, R, M, D2);

      Int64PolynomialCopy(RationalResult.Denominator, M);
      Int64PolynomialMul(R, R1.Nominator, F1);
      Int64PolynomialMul(M, R2.Nominator, F2);
      Int64PolynomialAdd(RationalResult.Nominator, R, M);
    finally
      FLocalInt64PolynomialPool.Recycle(M);
      FLocalInt64PolynomialPool.Recycle(R);
      FLocalInt64PolynomialPool.Recycle(F1);
      FLocalInt64PolynomialPool.Recycle(F2);
      FLocalInt64PolynomialPool.Recycle(D1);
      FLocalInt64PolynomialPool.Recycle(D2);
    end;
  end;
end;

procedure Int64RationalPolynomialSub(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial);
begin
  R2.Nominator.Negate;
  Int64RationalPolynomialAdd(R1, R2, RationalResult);
  if RationalResult <> R2 then
    R2.Nominator.Negate;
end;

procedure Int64RationalPolynomialMul(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial);
begin
  Int64PolynomialMul(RationalResult.Nominator, R1.Nominator, R2.Nominator);
  Int64PolynomialMul(RationalResult.Denominator, R1.Denominator, R2.Denominator);
end;

procedure Int64RationalPolynomialDiv(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial);
var
  N: TCnInt64Polynomial;
begin
  if R2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  N := FLocalInt64PolynomialPool.Obtain; // ������ˣ��������м��������ֹ RationalResult �� Number1 �� Number 2
  try
    Int64PolynomialMul(N, R1.Nominator, R2.Denominator);
    Int64PolynomialMul(RationalResult.Denominator, R1.Denominator, R2.Nominator);
    Int64PolynomialCopy(RationalResult.Nominator, N);
  finally
    FLocalInt64PolynomialPool.Recycle(N);
  end;
end;

procedure Int64RationalPolynomialAddWord(R: TCnInt64RationalPolynomial; N: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialAdd(R, P, R);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialSubWord(R: TCnInt64RationalPolynomial; N: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialSub(R, P, R);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialMulWord(R: TCnInt64RationalPolynomial; N: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialMul(R, P, R);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialDivWord(R: TCnInt64RationalPolynomial; N: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialDiv(R, P, R);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialAdd(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial);
var
  T: TCnInt64RationalPolynomial;
begin
  if P1.IsZero then
  begin
    if R1 <> RationalResult then
    begin
      Int64RationalPolynomialCopy(RationalResult, R1);
      Exit;
    end;
  end;

  T := FLocalInt64RationalPolynomialPool.Obtain;
  try
    T.Denominator.SetOne;
    Int64PolynomialCopy(T.Nominator, P1);
    Int64RationalPolynomialAdd(R1, T, RationalResult);
  finally
    FLocalInt64RationalPolynomialPool.Recycle(T);
  end;
end;

procedure Int64RationalPolynomialSub(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial);
begin
  P1.Negate;
  try
    Int64RationalPolynomialAdd(R1, P1, RationalResult);
  finally
    P1.Negate;
  end;
end;

procedure Int64RationalPolynomialMul(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial);
begin
  if P1.IsZero then
    RationalResult.SetZero
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    Int64PolynomialMul(RationalResult.Nominator, R1.Nominator, P1);
    Int64PolynomialCopy(RationalResult.Denominator, R1.Denominator);
  end;
end;

procedure Int64RationalPolynomialDiv(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial);
begin
  if P1.IsZero then
    raise EDivByZero.Create(SDivByZero)
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    Int64PolynomialMul(RationalResult.Denominator, R1.Denominator, P1);
    Int64PolynomialCopy(RationalResult.Nominator, R1.Nominator);
  end;
end;

function Int64RationalPolynomialCompose(Res: TCnInt64RationalPolynomial;
  F, P: TCnInt64RationalPolynomial): Boolean;
var
  RN, RD: TCnInt64RationalPolynomial;
begin
  if P.IsInt then
    Result := Int64RationalPolynomialCompose(Res, F, P.Nominator)
  else
  begin
    RD := FLocalInt64RationalPolynomialPool.Obtain;
    RN := FLocalInt64RationalPolynomialPool.Obtain;

    try
      Int64RationalPolynomialCompose(RN, F.Nominator, P);
      Int64RationalPolynomialCompose(RD, F.Denominator, P);

      Int64PolynomialMul(Res.Nominator, RN.Nominator, RD.Denominator);
      Int64PolynomialMul(Res.Denominator, RN.Denominator, RD.Nominator);
      Result := True;
    finally
      FLocalInt64RationalPolynomialPool.Recycle(RN);
      FLocalInt64RationalPolynomialPool.Recycle(RD);
    end;
  end;
end;

function Int64RationalPolynomialCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64RationalPolynomial; P: TCnInt64Polynomial): Boolean;
begin
  Int64PolynomialCompose(Res.Nominator, F.Nominator, P);
  Int64PolynomialCompose(Res.Denominator, F.Denominator, P);
  Result := True;
end;

function Int64RationalPolynomialCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64Polynomial; P: TCnInt64RationalPolynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnInt64RationalPolynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    Res.Nominator[0] := F[0];
    Result := True;
    Exit;
  end;

  if Res = P then
    R := FLocalInt64RationalPolynomialPool.Obtain
  else
    R := Res;

  X := FLocalInt64RationalPolynomialPool.Obtain;
  T := FLocalInt64RationalPolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      Int64RationalPolynomialCopy(T, X);
      Int64RationalPolynomialMulWord(T, F[I]);
      Int64RationalPolynomialAdd(R, T, R);

      if I <> F.MaxDegree then
        Int64RationalPolynomialMul(X, P, X);
    end;

    if Res = P then
    begin
      Int64RationalPolynomialCopy(Res, R);
      FLocalInt64RationalPolynomialPool.Recycle(R);
    end;
  finally
    FLocalInt64RationalPolynomialPool.Recycle(X);
    FLocalInt64RationalPolynomialPool.Recycle(T);
  end;
  Result := True;
end;

procedure Int64RationalPolynomialGetValue(Res: TCnRationalNumber;
  F: TCnInt64RationalPolynomial; X: Int64);
begin
  Res.Nominator := Int64PolynomialGetValue(F.Nominator, X);
  Res.Denominator := Int64PolynomialGetValue(F.Denominator, X);
  Res.Reduce;
end;

// ====================== �����ʽ���������ϵ�ģ���� ===========================

function Int64RationalPolynomialGaloisEqual(R1, R2: TCnInt64RationalPolynomial;
  Prime: Int64; Primitive: TCnInt64Polynomial): Boolean;
var
  T1, T2: TCnInt64Polynomial;
begin
  if R1 = R2 then
  begin
    Result := True;
    Exit;
  end;

  T1 := FLocalInt64PolynomialPool.Obtain;
  T2 := FLocalInt64PolynomialPool.Obtain;

  try
    // �жϷ��ӷ�ĸ����˵Ľ���Ƿ����
    Int64PolynomialGaloisMul(T1, R1.Nominator, R2.Denominator, Prime, Primitive);
    Int64PolynomialGaloisMul(T2, R2.Nominator, R1.Denominator, Prime, Primitive);
    Result := Int64PolynomialGaloisEqual(T1, T2, Prime);
  finally
    FLocalInt64PolynomialPool.Recycle(T2);
    FLocalInt64PolynomialPool.Recycle(T1);
  end;
end;

procedure Int64RationalPolynomialGaloisNegate(P: TCnInt64RationalPolynomial;
  Prime: Int64);
begin
  Int64PolynomialGaloisNegate(P.Nominator, Prime);
end;

procedure Int64RationalPolynomialGaloisAdd(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial; Prime: Int64);
var
  M, R, F1, F2, D1, D2: TCnInt64Polynomial;
begin
  if R1.IsInt and R2.IsInt then
  begin
    Int64PolynomialGaloisAdd(RationalResult.Nominator, R1.Nominator,
      R2.Nominator, Prime);
    RationalResult.Denominator.SetOne;
    Exit;
  end
  else if R1.IsZero then
  begin
    if R2 <> RationalResult then
      RationalResult.Assign(R2);
  end
  else if R2.IsZero then
  begin
    if R1 <> RationalResult then
      RationalResult.Assign(R1);
  end
  else
  begin
    M := nil;
    R := nil;
    F1 := nil;
    F2 := nil;
    D1 := nil;
    D2 := nil;

    try
      // ���ĸ����С������
      M := FLocalInt64PolynomialPool.Obtain;
      R := FLocalInt64PolynomialPool.Obtain;
      F1 := FLocalInt64PolynomialPool.Obtain;
      F2 := FLocalInt64PolynomialPool.Obtain;
      D1 := FLocalInt64PolynomialPool.Obtain;
      D2 := FLocalInt64PolynomialPool.Obtain;

      Int64PolynomialCopy(D1, R1.Denominator);
      Int64PolynomialCopy(D2, R2.Denominator);

      if not Int64PolynomialGaloisLeastCommonMultiple(M, D1, D2, Prime) then
        Int64PolynomialGaloisMul(M, D1, D2, Prime);   // �޷�����С����ʽ��ʾϵ���޷�������ֱ�����

      Int64PolynomialGaloisDiv(F1, R, M, D1, Prime);  // ��С������ M div D1 ����� F1
      Int64PolynomialGaloisDiv(F2, R, M, D2, Prime);  // ��С������ M div D2 ����� F2

      Int64PolynomialCopy(RationalResult.Denominator, M);  // ����ķ�ĸ����С������
      Int64PolynomialGaloisMul(R, R1.Nominator, F1, Prime);
      Int64PolynomialGaloisMul(M, R2.Nominator, F2, Prime);
      Int64PolynomialGaloisAdd(RationalResult.Nominator, R, M, Prime);
    finally
      FLocalInt64PolynomialPool.Recycle(M);
      FLocalInt64PolynomialPool.Recycle(R);
      FLocalInt64PolynomialPool.Recycle(F1);
      FLocalInt64PolynomialPool.Recycle(F2);
      FLocalInt64PolynomialPool.Recycle(D1);
      FLocalInt64PolynomialPool.Recycle(D2);
    end;
  end;
end;

procedure Int64RationalPolynomialGaloisSub(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial; Prime: Int64);
begin
  R2.Nominator.Negate;
  Int64RationalPolynomialGaloisAdd(R1, R2, RationalResult, Prime);
  if RationalResult <> R2 then
    R2.Nominator.Negate;
end;

procedure Int64RationalPolynomialGaloisMul(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial; Prime: Int64);
begin
  Int64PolynomialGaloisMul(RationalResult.Nominator, R1.Nominator, R2.Nominator, Prime);
  Int64PolynomialGaloisMul(RationalResult.Denominator, R1.Denominator, R2.Denominator, Prime);
end;

procedure Int64RationalPolynomialGaloisDiv(R1, R2: TCnInt64RationalPolynomial;
  RationalResult: TCnInt64RationalPolynomial; Prime: Int64);
var
  N: TCnInt64Polynomial;
begin
  if R2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  N := FLocalInt64PolynomialPool.Obtain; // ������ˣ��������м��������ֹ RationalResult �� Number1 �� Number 2
  try
    Int64PolynomialGaloisMul(N, R1.Nominator, R2.Denominator, Prime);
    Int64PolynomialGaloisMul(RationalResult.Denominator, R1.Denominator, R2.Nominator, Prime);
    Int64PolynomialCopy(RationalResult.Nominator, N);
  finally
    FLocalInt64PolynomialPool.Recycle(N);
  end;
end;

procedure Int64RationalPolynomialGaloisAddWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialGaloisAdd(R, P, R, Prime);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialGaloisSubWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialGaloisSub(R, P, R, Prime);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialGaloisMulWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialGaloisMul(R, P, R, Prime);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialGaloisDivWord(R: TCnInt64RationalPolynomial;
  N: Int64; Prime: Int64);
var
  P: TCnInt64Polynomial;
begin
  P := FLocalInt64PolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    P[0] := N;
    Int64RationalPolynomialGaloisDiv(R, P, R, Prime);
  finally
    FLocalInt64PolynomialPool.Recycle(P);
  end;
end;

procedure Int64RationalPolynomialGaloisAdd(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
var
  T: TCnInt64RationalPolynomial;
begin
  if P1.IsZero then
  begin
    if R1 <> RationalResult then
    begin
      Int64RationalPolynomialCopy(RationalResult, R1);
      Exit;
    end;
  end;

  T := FLocalInt64RationalPolynomialPool.Obtain;
  try
    T.Denominator.SetOne;
    Int64PolynomialCopy(T.Nominator, P1);
    Int64RationalPolynomialGaloisAdd(R1, T, RationalResult, Prime);
  finally
    FLocalInt64RationalPolynomialPool.Recycle(T);
  end;
end;

procedure Int64RationalPolynomialGaloisSub(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
begin
  P1.Negate;
  try
    Int64RationalPolynomialGaloisAdd(R1, P1, RationalResult, Prime);
  finally
    P1.Negate;
  end;
end;

procedure Int64RationalPolynomialGaloisMul(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
begin
  if P1.IsZero then
    RationalResult.SetZero
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    Int64PolynomialGaloisMul(RationalResult.Nominator, R1.Nominator, P1, Prime);
    Int64PolynomialCopy(RationalResult.Denominator, R1.Denominator);
  end;
end;

procedure Int64RationalPolynomialGaloisDiv(R1: TCnInt64RationalPolynomial;
  P1: TCnInt64Polynomial; RationalResult: TCnInt64RationalPolynomial; Prime: Int64); overload;
begin
  if P1.IsZero then
    raise EDivByZero.Create(SDivByZero)
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    Int64PolynomialGaloisMul(RationalResult.Denominator, R1.Denominator, P1, Prime);
    Int64PolynomialCopy(RationalResult.Nominator, R1.Nominator);
  end;
end;

function Int64RationalPolynomialGaloisCompose(Res: TCnInt64RationalPolynomial;
  F, P: TCnInt64RationalPolynomial; Prime: Int64; Primitive: TCnInt64Polynomial): Boolean;
var
  RN, RD: TCnInt64RationalPolynomial;
begin
  if P.IsInt then
    Result := Int64RationalPolynomialGaloisCompose(Res, F, P.Nominator, Prime, Primitive)
  else
  begin
    RD := FLocalInt64RationalPolynomialPool.Obtain;
    RN := FLocalInt64RationalPolynomialPool.Obtain;

    try
      Int64RationalPolynomialGaloisCompose(RN, F.Nominator, P, Prime, Primitive);
      Int64RationalPolynomialGaloisCompose(RD, F.Denominator, P, Prime, Primitive);

      Int64PolynomialGaloisMul(Res.Nominator, RN.Nominator, RD.Denominator, Prime);
      Int64PolynomialGaloisMul(Res.Denominator, RN.Denominator, RD.Nominator, Prime);

      if Primitive <> nil then
      begin
        Int64PolynomialGaloisMod(Res.Nominator, Res.Nominator, Primitive, Prime);
        Int64PolynomialGaloisMod(Res.Denominator, Res.Denominator, Primitive, Prime);
      end;
      Result := True;
    finally
      FLocalInt64RationalPolynomialPool.Recycle(RN);
      FLocalInt64RationalPolynomialPool.Recycle(RD);
    end;
  end;
end;

function Int64RationalPolynomialGaloisCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64RationalPolynomial; P: TCnInt64Polynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial): Boolean;
begin
  Int64PolynomialGaloisCompose(Res.Nominator, F.Nominator, P, Prime, Primitive);
  Int64PolynomialGaloisCompose(Res.Denominator, F.Denominator, P, Prime, Primitive);
  Result := True;
end;

function Int64RationalPolynomialGaloisCompose(Res: TCnInt64RationalPolynomial;
  F: TCnInt64Polynomial; P: TCnInt64RationalPolynomial; Prime: Int64;
  Primitive: TCnInt64Polynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnInt64RationalPolynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    Res.Nominator[0] := Int64NonNegativeMod(F[0], Prime);
    Result := True;
    Exit;
  end;

  if Res = P then
    R := FLocalInt64RationalPolynomialPool.Obtain
  else
    R := Res;

  X := FLocalInt64RationalPolynomialPool.Obtain;
  T := FLocalInt64RationalPolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      Int64RationalPolynomialCopy(T, X);
      Int64RationalPolynomialGaloisMulWord(T, F[I], Prime);
      Int64RationalPolynomialGaloisAdd(R, T, R, Prime);

      if I <> F.MaxDegree then
        Int64RationalPolynomialGaloisMul(X, P, X, Prime);
    end;

    if Primitive <> nil then
    begin
      Int64PolynomialGaloisMod(R.Nominator, R.Nominator, Primitive, Prime);
      Int64PolynomialGaloisMod(R.Denominator, R.Denominator, Primitive, Prime);
    end;

    if Res = P then
    begin
      Int64RationalPolynomialCopy(Res, R);
      FLocalInt64RationalPolynomialPool.Recycle(R);
    end;
  finally
    FLocalInt64RationalPolynomialPool.Recycle(X);
    FLocalInt64RationalPolynomialPool.Recycle(T);
  end;
  Result := True;
end;

function Int64RationalPolynomialGaloisGetValue(F: TCnInt64RationalPolynomial;
  X: Int64; Prime: Int64): Int64;
var
  N, D: Int64;
begin
  D := Int64PolynomialGaloisGetValue(F.Denominator, X, Prime);
  if D = 0 then
    raise EDivByZero.Create(SDivByZero);

  N := Int64PolynomialGaloisGetValue(F.Nominator, X, Prime);
  Result := Int64NonNegativeMulMod(N, CnInt64ModularInverse2(D, Prime), Prime);
end;

{ TCnBigNumberPolynomial }

procedure TCnBigNumberPolynomial.CorrectTop;
begin
  while (MaxDegree > 0) and Items[MaxDegree].IsZero do
    Delete(MaxDegree);
end;

constructor TCnBigNumberPolynomial.Create;
begin
  inherited Create;
  Add.SetZero;   // ��ϵ����
end;

constructor TCnBigNumberPolynomial.Create(LowToHighCoefficients: array of const);
begin
  inherited Create;
  SetCoefficents(LowToHighCoefficients);
end;

destructor TCnBigNumberPolynomial.Destroy;
begin

  inherited;
end;

function TCnBigNumberPolynomial.GetMaxDegree: Integer;
begin
  if Count = 0 then
    Add.SetZero;
  Result := Count - 1;
end;

function TCnBigNumberPolynomial.IsMonic: Boolean;
begin
  Result := BigNumberPolynomialIsMonic(Self);
end;

function TCnBigNumberPolynomial.IsNegOne: Boolean;
begin
  Result := BigNumberPolynomialIsNegOne(Self);
end;

function TCnBigNumberPolynomial.IsOne: Boolean;
begin
  Result := BigNumberPolynomialIsOne(Self);
end;

function TCnBigNumberPolynomial.IsZero: Boolean;
begin
  Result := BigNumberPolynomialIsZero(Self);
end;

procedure TCnBigNumberPolynomial.Negate;
begin
  BigNumberPolynomialNegate(Self);
end;

procedure TCnBigNumberPolynomial.SetCoefficents(LowToHighCoefficients: array of const);
var
  I: Integer;
begin
  Clear;
  for I := Low(LowToHighCoefficients) to High(LowToHighCoefficients) do
  begin
    case LowToHighCoefficients[I].VType of
    vtInteger:
      begin
        Add.SetInteger(LowToHighCoefficients[I].VInteger);
      end;
    vtInt64:
      begin
        Add.SetInt64(LowToHighCoefficients[I].VInt64^);
      end;
    vtBoolean:
      begin
        if LowToHighCoefficients[I].VBoolean then
          Add.SetOne
        else
          Add.SetZero;
      end;
    vtString:
      begin
        Add.SetDec(LowToHighCoefficients[I].VString^);
      end;
    vtObject:
      begin
        // ���� TCnBigNumber �����и���ֵ
        if LowToHighCoefficients[I].VObject is TCnBigNumber then
          BigNumberCopy(Add, LowToHighCoefficients[I].VObject as TCnBigNumber);
      end;
    else
      raise ECnPolynomialException.CreateFmt(SInvalidInteger, ['Coefficients ' + IntToStr(I)]);
    end;
  end;

  if Count = 0 then
    Add.SetZero
  else
    CorrectTop;
end;

procedure TCnBigNumberPolynomial.SetMaxDegree(const Value: Integer);
var
  I, OC: Integer;
begin
  CheckDegree(Value);

  OC := Count;
  Count := Value + 1; // ֱ������ Count�����С�����Զ��ͷŶ���Ķ���

  if Count > OC then  // ���ӵĲ��ִ����¶���
  begin
    for I := OC to Count - 1 do
      Items[I] := TCnBigNumber.Create;
  end;
end;

procedure TCnBigNumberPolynomial.SetOne;
begin
  BigNumberPolynomialSetOne(Self);
end;

procedure TCnBigNumberPolynomial.SetString(const Poly: string);
begin
  BigNumberPolynomialSetString(Self, Poly);
end;

procedure TCnBigNumberPolynomial.SetZero;
begin
  BigNumberPolynomialSetZero(Self);
end;

function TCnBigNumberPolynomial.ToString: string;
begin
  Result := BigNumberPolynomialToString(Self);
end;

{ TCnBigNumberRationalPolynomial }

procedure TCnBigNumberRationalPolynomial.AssignTo(Dest: TPersistent);
begin
  if Dest is TCnBigNumberRationalPolynomial then
  begin
    BigNumberPolynomialCopy(TCnBigNumberRationalPolynomial(Dest).Nominator, FNominator);
    BigNumberPolynomialCopy(TCnBigNumberRationalPolynomial(Dest).Denominator, FDenominator);
  end
  else
    inherited;
end;

constructor TCnBigNumberRationalPolynomial.Create;
begin
  inherited;
  FNominator := TCnBigNumberPolynomial.Create([0]);
  FDenominator := TCnBigNumberPolynomial.Create([1]);
end;

destructor TCnBigNumberRationalPolynomial.Destroy;
begin
  FDenominator.Free;
  FNominator.Free;
  inherited;
end;

function TCnBigNumberRationalPolynomial.IsInt: Boolean;
begin
  Result := FDenominator.IsOne or FDenominator.IsNegOne;
end;

function TCnBigNumberRationalPolynomial.IsOne: Boolean;
begin
  Result := not FNominator.IsZero and BigNumberPolynomialEqual(FNominator, FDenominator);
end;

function TCnBigNumberRationalPolynomial.IsZero: Boolean;
begin
  Result := not FDenominator.IsZero and FNominator.IsZero;
end;

procedure TCnBigNumberRationalPolynomial.Neg;
begin
  FNominator.Negate;
end;

procedure TCnBigNumberRationalPolynomial.Reciprocal;
var
  T: TCnBigNumberPolynomial;
begin
  if FNominator.IsZero then
    raise EDivByZero.Create(SDivByZero);

  T := FLocalBigNumberPolynomialPool.Obtain;
  try
    BigNumberPolynomialCopy(T, FDenominator);
    BigNumberPolynomialCopy(FDenominator, FNominator);
    BigNumberPolynomialCopy(FNominator, T);
  finally
    FLocalBigNumberPolynomialPool.Recycle(T);
  end;
end;

procedure TCnBigNumberRationalPolynomial.Reduce;
begin
  BigNumberPolynomialReduce2(FNominator, FDenominator);
end;

procedure TCnBigNumberRationalPolynomial.SetOne;
begin
  FDenominator.SetOne;
  FNominator.SetOne;
end;

procedure TCnBigNumberRationalPolynomial.SetString(const Rational: string);
var
  P: Integer;
  N, D: string;
begin
  P := Pos('/', Rational);
  if P > 1 then
  begin
    N := Copy(Rational, 1, P - 1);
    D := Copy(Rational, P + 1, MaxInt);

    FNominator.SetString(Trim(N));
    FDenominator.SetString(Trim(D));
  end
  else
  begin
    FNominator.SetString(Rational);
    FDenominator.SetOne;
  end;
end;

procedure TCnBigNumberRationalPolynomial.SetZero;
begin
  FDenominator.SetOne;
  FNominator.SetZero;
end;

function TCnBigNumberRationalPolynomial.ToString: string;
begin
  if FDenominator.IsOne then
    Result := FNominator.ToString
  else if FNominator.IsZero then
    Result := '0'
  else
    Result := FNominator.ToString + ' / ' + FDenominator.ToString;
end;

{ TCnBigNumberPolynomialPool }

function TCnBigNumberPolynomialPool.CreateObject: TObject;
begin
  Result := TCnBigNumberPolynomial.Create;
end;

function TCnBigNumberPolynomialPool.Obtain: TCnBigNumberPolynomial;
begin
  Result := TCnBigNumberPolynomial(inherited Obtain);
  Result.SetZero;
end;

procedure TCnBigNumberPolynomialPool.Recycle(Poly: TCnBigNumberPolynomial);
begin
  inherited Recycle(Poly);
end;

{ TCnInt64RationalPolynomialPool }

function TCnInt64RationalPolynomialPool.CreateObject: TObject;
begin
  Result := TCnInt64RationalPolynomial.Create;
end;

function TCnInt64RationalPolynomialPool.Obtain: TCnInt64RationalPolynomial;
begin
  Result := TCnInt64RationalPolynomial(inherited Obtain);
  Result.SetZero;
end;

procedure TCnInt64RationalPolynomialPool.Recycle(Poly: TCnInt64RationalPolynomial);
begin
  inherited Recycle(Poly);
end;

function BigNumberPolynomialNew: TCnBigNumberPolynomial;
begin
  Result := TCnBigNumberPolynomial.Create;
end;

procedure BigNumberPolynomialFree(P: TCnBigNumberPolynomial);
begin
  P.Free;
end;

function BigNumberPolynomialDuplicate(P: TCnBigNumberPolynomial): TCnBigNumberPolynomial;
begin
  if P = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := BigNumberPolynomialNew;
  if Result <> nil then
    BigNumberPolynomialCopy(Result, P);
end;

function BigNumberPolynomialCopy(Dst: TCnBigNumberPolynomial;
  Src: TCnBigNumberPolynomial): TCnBigNumberPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  if Src <> Dst then
  begin
    Dst.MaxDegree := Src.MaxDegree;
    for I := 0 to Src.Count - 1 do
      BigNumberCopy(Dst[I], Src[I]);
    Dst.CorrectTop;
  end;
end;

function BigNumberPolynomialToString(P: TCnBigNumberPolynomial;
  const VarName: string): string;
var
  I: Integer;
begin
  Result := '';
  if BigNumberPolynomialIsZero(P) then
  begin
    Result := '0';
    Exit;
  end;

  for I := P.MaxDegree downto 0 do
  begin
    if VarItemFactor(Result, (I = 0), P[I].ToDec) then
      Result := Result + VarPower(VarName, I);
  end;
end;

{$WARNINGS OFF}

function BigNumberPolynomialSetString(P: TCnBigNumberPolynomial;
  const Str: string; const VarName: string): Boolean;
var
  C, Ptr: PChar;
  Num, ES: string;
  MDFlag, E: Integer;
  IsNeg: Boolean;
begin
  Result := False;
  if Str = '' then
    Exit;

  MDFlag := -1;
  C := @Str[1];

  while C^ <> #0 do
  begin
    if not (C^ in ['+', '-', '0'..'9']) and (C^ <> VarName) then
    begin
      Inc(C);
      Continue;
    end;

    IsNeg := False;
    if C^ = '+' then
      Inc(C)
    else if C^ = '-' then
    begin
      IsNeg := True;
      Inc(C);
    end;

    Num := '1';
    if C^ in ['0'..'9'] then // ��ϵ��
    begin
      Ptr := C;
      while C^ in ['0'..'9'] do
        Inc(C);

      // Ptr �� C ֮�������֣�����һ��ϵ��
      SetString(Num, Ptr, C - Ptr);
      if IsNeg then
        Num := '-' + Num;
    end
    else if IsNeg then
      Num := '-' + Num;

    if C^ = VarName then
    begin
      E := 1;
      Inc(C);
      if C^ = '^' then // ��ָ��
      begin
        Inc(C);
        if C^ in ['0'..'9'] then
        begin
          Ptr := C;
          while C^ in ['0'..'9'] do
            Inc(C);

          // Ptr �� C ֮�������֣�����һ��ָ��
          SetString(ES, Ptr, C - Ptr);
          E := StrToInt64(ES);
        end;
      end;
    end
    else
      E := 0;

    // ָ�������ˣ���
    if MDFlag = -1 then // ��һ��ָ���� MaxDegree
    begin
      P.MaxDegree := E;
      MDFlag := 0;
    end;

    P[E].SetDec(AnsiString(Num));
  end;
end;

{$WARNINGS ON}

function BigNumberPolynomialIsZero(P: TCnBigNumberPolynomial): Boolean;
begin
  Result := (P.MaxDegree = 0) and P[0].IsZero;
end;

procedure BigNumberPolynomialSetZero(P: TCnBigNumberPolynomial);
begin
  P.Clear;
  P.Add.SetZero;
end;

function BigNumberPolynomialIsOne(P: TCnBigNumberPolynomial): Boolean;
begin
  Result := (P.MaxDegree = 0) and P[0].IsOne;
end;

procedure BigNumberPolynomialSetOne(P: TCnBigNumberPolynomial);
begin
  P.Clear;
  P.Add.SetOne;
end;

function BigNumberPolynomialIsNegOne(P: TCnBigNumberPolynomial): Boolean;
begin
  Result := (P.MaxDegree = 0) and P[0].IsNegOne;
end;

procedure BigNumberPolynomialNegate(P: TCnBigNumberPolynomial);
var
  I: Integer;
begin
  for I := 0 to P.MaxDegree do
    P[I].Negate;
end;

function BigNumberPolynomialIsMonic(P: TCnBigNumberPolynomial): Boolean;
begin
  Result := P[P.MaxDegree].IsOne;
end;

procedure BigNumberPolynomialShiftLeft(P: TCnBigNumberPolynomial; N: Integer);
var
  I: Integer;
begin
  if N = 0 then
    Exit
  else if N < 0 then
    BigNumberPolynomialShiftRight(P, -N)
  else
    for I := 1 to N do
      P.Insert(0, TCnBigNumber.Create);
end;

procedure BigNumberPolynomialShiftRight(P: TCnBigNumberPolynomial; N: Integer);
var
  I: Integer;
begin
  if N = 0 then
    Exit
  else if N < 0 then
    BigNumberPolynomialShiftLeft(P, -N)
  else
  begin
    for I := 1 to N do
      P.Delete(0);

    if P.Count = 0 then
      P.Add.SetZero;
  end;
end;

function BigNumberPolynomialEqual(A, B: TCnBigNumberPolynomial): Boolean;
var
  I: Integer;
begin
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  Result := A.MaxDegree = B.MaxDegree;
  if Result then
  begin
    for I := A.MaxDegree downto 0 do
    begin
      if BigNumberCompare(A[I], B[I]) <> 0 then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

// ======================== һԪ����ϵ������ʽ��ͨ���� =============================

procedure BigNumberPolynomialAddWord(P: TCnBigNumberPolynomial; N: Cardinal);
begin
  if N <> 0 then
    BigNumberAddWord(P[0], N);
end;

procedure BigNumberPolynomialSubWord(P: TCnBigNumberPolynomial; N: Cardinal);
begin
  if N <> 0 then
    BigNumberSubWord(P[0], N);
end;

procedure BigNumberPolynomialMulWord(P: TCnBigNumberPolynomial; N: Cardinal);
var
  I: Integer;
begin
  if N = 0 then
    BigNumberPolynomialSetZero(P)
  else if N <> 1 then
  begin
    for I := 0 to P.MaxDegree do
      BigNumberMulWord(P[I], N);
  end;
end;

procedure BigNumberPolynomialDivWord(P: TCnBigNumberPolynomial; N: Cardinal);
var
  I: Integer;
begin
  if N = 0 then
    raise ECnPolynomialException.Create(SZeroDivide)
  else if N <> 1 then
    for I := 0 to P.MaxDegree do
      BigNumberDivWord(P[I], N);
end;

procedure BigNumberPolynomialNonNegativeModWord(P: TCnBigNumberPolynomial; N: Cardinal);
var
  I: Integer;
begin
  if N = 0 then
    raise ECnPolynomialException.Create(SZeroDivide);

  for I := 0 to P.MaxDegree do
  begin
    BigNumberModWord(P[I], N);
    if P[I].IsNegative then
      BigNumberAddWord(P[I], N);
  end;
end;

procedure BigNumberPolynomialAddBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
begin
  BigNumberAdd(P[0], P[0], N);
end;

procedure BigNumberPolynomialSubBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
begin
  BigNumberSub(P[0], P[0], N);
end;

procedure BigNumberPolynomialMulBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
var
  I: Integer;
begin
  if N.IsZero then
    BigNumberPolynomialSetZero(P)
  else if not N.IsOne then
  begin
    for I := 0 to P.MaxDegree do
      BigNumberMul(P[I], P[I], N);
  end;
end;

procedure BigNumberPolynomialDivBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
var
  I: Integer;
  T: TCnBigNumber;
begin
  if N.IsZero then
    BigNumberPolynomialSetZero(P)
  else if not N.IsOne then
  begin
    T := FLocalBigNumberPool.Obtain;
    try
      for I := 0 to P.MaxDegree do
        BigNumberDiv(P[I], T, P[I], N);
    finally
      FLocalBigNumberPool.Recycle(T);
    end;
  end;
end;

procedure BigNumberPolynomialNonNegativeModBigNumber(P: TCnBigNumberPolynomial; N: TCnBigNumber);
var
  I: Integer;
begin
  if N.IsZero then
    raise ECnPolynomialException.Create(SZeroDivide);

  for I := 0 to P.MaxDegree do
    BigNumberNonNegativeMod(P[I], P[I], N);
end;

function BigNumberPolynomialAdd(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial): Boolean;
var
  I, D1, D2: Integer;
  PBig: TCnBigNumberPolynomial;
begin
  D1 := Max(P1.MaxDegree, P2.MaxDegree);
  D2 := Min(P1.MaxDegree, P2.MaxDegree);

  if D1 > D2 then
  begin
    if P1.MaxDegree > P2.MaxDegree then
      PBig := P1
    else
      PBig := P2;

    Res.MaxDegree := D1; // ���ǵ� Res ������ P1 �� P2�����Ը� Res �� MaxDegree ��ֵ�÷�����ıȽ�֮��
    for I := D1 downto D2 + 1 do
      BigNumberCopy(Res[I], PBig[I]);
  end
  else // D1 = D2 ˵������ʽͬ��
    Res.MaxDegree := D1;

  for I := D2 downto 0 do
    BigNumberAdd(Res[I], P1[I], P2[I]);

  Res.CorrectTop;
  Result := True;
end;

function BigNumberPolynomialSub(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial): Boolean;
var
  I, D1, D2: Integer;
begin
  D1 := Max(P1.MaxDegree, P2.MaxDegree);
  D2 := Min(P1.MaxDegree, P2.MaxDegree);

  Res.MaxDegree := D1;
  if D1 > D2 then
  begin
    if P1.MaxDegree > P2.MaxDegree then // ����ʽ��
    begin
      for I := D1 downto D2 + 1 do
        BigNumberCopy(Res[I], P1[I]);
    end
    else  // ��ʽ��
    begin
      for I := D1 downto D2 + 1 do
      begin
        BigNumberCopy(Res[I], P2[I]);
        Res[I].Negate;
      end;
    end;
  end;

  for I := D2 downto 0 do
    BigNumberSub(Res[I], P1[I], P2[I]);

  Res.CorrectTop;
  Result := True;
end;

function BigNumberPolynomialMul(Res: TCnBigNumberPolynomial; P1: TCnBigNumberPolynomial;
  P2: TCnBigNumberPolynomial): Boolean;
var
  R: TCnBigNumberPolynomial;
  T: TCnBigNumber;
  I, J: Integer;
begin
  if BigNumberPolynomialIsZero(P1) or BigNumberPolynomialIsZero(P2) then
  begin
    BigNumberPolynomialSetZero(Res);
    Result := True;
    Exit;
  end;

  T := FLocalBigNumberPool.Obtain;
  if (Res = P1) or (Res = P2) then
    R := FLocalBigNumberPolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxDegree := P1.MaxDegree + P2.MaxDegree;

  for I := 0 to P1.MaxDegree do
  begin
    // �ѵ� I �η������ֳ��� P2 ��ÿһ�����֣��ӵ������ I ��ͷ�Ĳ���
    for J := 0 to P2.MaxDegree do
    begin
      BigNumberMul(T, P1[I], P2[J]);
      BigNumberAdd(R[I + J], R[I + J], T);
    end;
  end;

  R.CorrectTop;
  if (Res = P1) or (Res = P2) then
  begin
    BigNumberPolynomialCopy(Res, R);
    FLocalBigNumberPolynomialPool.Recycle(R);
  end;
  FLocalBigNumberPool.Recycle(T);
  Result := True;
end;

function BigNumberPolynomialDiv(Res: TCnBigNumberPolynomial; Remain: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Divisor: TCnBigNumberPolynomial; ErrMulFactor: TCnBigNumber): Boolean;
var
  SubRes: TCnBigNumberPolynomial; // ���ɵݼ���
  MulRes: TCnBigNumberPolynomial; // ���ɳ����˻�
  DivRes: TCnBigNumberPolynomial; // ������ʱ��
  I, D: Integer;
  T, R: TCnBigNumber;
begin
  if BigNumberPolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxDegree > P.MaxDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      BigNumberPolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      BigNumberPolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;
  T := nil;
  R := nil;

  try
    T := FLocalBigNumberPool.Obtain;
    R := FLocalBigNumberPool.Obtain;

    SubRes := FLocalBigNumberPolynomialPool.Obtain;
    BigNumberPolynomialCopy(SubRes, P);

    D := P.MaxDegree - Divisor.MaxDegree;
    DivRes := FLocalBigNumberPolynomialPool.Obtain;
    DivRes.MaxDegree := D;
    MulRes := FLocalBigNumberPolynomialPool.Obtain;

    Result := False;
    for I := 0 to D do
    begin
      if P.MaxDegree - I > SubRes.MaxDegree then                 // �м���������λ
        Continue;

      // �ж� Divisor[Divisor.MaxDegree] �Ƿ������� SubRes[P.MaxDegree - I] ������˵�����������Ͷ���ʽ��Χ���޷�֧�֣�ֻ�ܳ���
      if not BigNumberMod(T, SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]) then
        Exit;

      if not T.IsZero then
      begin
        if ErrMulFactor <> nil then
        begin
          // Divisor[Divisor.MaxDegree] �������ߵ����Լ��
          if BigNumberGcd(T, SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]) then
            BigNumberMul(ErrMulFactor, Divisor[Divisor.MaxDegree], T);
        end;
        Exit;
      end;

      BigNumberPolynomialCopy(MulRes, Divisor);
      BigNumberPolynomialShiftLeft(MulRes, D - I);                 // ���뵽 SubRes ����ߴ�
      BigNumberDiv(T, R, SubRes[P.MaxDegree - I], MulRes[MulRes.MaxDegree]);

      BigNumberPolynomialMulBigNumber(MulRes, T); // ��ʽ�˵���ߴ�ϵ����ͬ
      BigNumberCopy(DivRes[D - I], T);            // �̷ŵ� DivRes λ��

      BigNumberPolynomialSub(SubRes, SubRes, MulRes);              // ���������·Ż� SubRes
    end;

    if Remain <> nil then
      BigNumberPolynomialCopy(Remain, SubRes);
    if Res <> nil then
      BigNumberPolynomialCopy(Res, DivRes);
  finally
    FLocalBigNumberPolynomialPool.Recycle(SubRes);
    FLocalBigNumberPolynomialPool.Recycle(MulRes);
    FLocalBigNumberPolynomialPool.Recycle(DivRes);
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(R);
  end;
  Result := True;
end;

function BigNumberPolynomialMod(Res: TCnBigNumberPolynomial; P: TCnBigNumberPolynomial;
  Divisor: TCnBigNumberPolynomial; ErrMulFactor: TCnBigNumber): Boolean;
begin
  Result := BigNumberPolynomialDiv(nil, Res, P, Divisor, ErrMulFactor);
end;

function BigNumberPolynomialPower(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Exponent: TCnBigNumber): Boolean;
var
  T: TCnBigNumberPolynomial;
  E: TCnBigNumber;
begin
  if Exponent.IsZero then
  begin
    Res.SetOne;
    Result := True;
    Exit;
  end
  else if Exponent.IsOne then
  begin
    if Res <> P then
      BigNumberPolynomialCopy(Res, P);
    Result := True;
    Exit;
  end
  else if Exponent.IsNegative then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidExponent, [Exponent.ToDec]);

  T := FLocalBigNumberPolynomialPool.Obtain;
  BigNumberPolynomialCopy(T, P);
  E := FLocalBigNumberPool.Obtain;
  BigNumberCopy(E, Exponent);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetOne;
    while not E.IsZero do // E ���� 0 �����ж�
    begin
      if BigNumberIsBitSet(E, 0) then
        BigNumberPolynomialMul(Res, Res, T);

      BigNumberShiftRightOne(E, E);
      if not E.IsZero then // ���һ���������
        BigNumberPolynomialMul(T, T, T);
    end;
    Result := True;
  finally
    FLocalBigNumberPool.Recycle(E);
    FLocalBigNumberPolynomialPool.Recycle(T);
  end;
end;

procedure BigNumberPolynomialReduce(P: TCnBigNumberPolynomial);
var
  I: Integer;
  D: TCnBigNumber;
begin
  if P.MaxDegree = 0 then
  begin
    if not P[P.MaxDegree].IsZero then
      P[P.MaxDegree].SetOne;
  end
  else
  begin
    D := FLocalBigNumberPool.Obtain;
    BigNumberCopy(D, P[0]);

    for I := 0 to P.MaxDegree - 1 do
    begin
      BigNumberGcd(D, D, P[I + 1]);
      if D.IsOne then
        Break;
    end;

    if not D.IsOne then
      BigNumberPolynomialDivBigNumber(P, D);
  end;
end;

procedure BigNumberPolynomialCentralize(P: TCnBigNumberPolynomial; Modulus: TCnBigNumber);
var
  I: Integer;
  K: TCnBigNumber;
begin
  K := FLocalBigNumberPool.Obtain;
  try
    BigNumberShiftRightOne(K, Modulus);
    for I := 0 to P.MaxDegree do
      if BigNumberCompare(P[I], K) > 0 then
        BigNumberSub(P[I], P[I], Modulus);
  finally
    FLocalBigNumberPool.Recycle(K);
  end;
end;

function BigNumberPolynomialGreatestCommonDivisor(Res: TCnBigNumberPolynomial;
  P1, P2: TCnBigNumberPolynomial): Boolean;
var
  A, B, C: TCnBigNumberPolynomial;
  MF: TCnBigNumber;
begin
  A := nil;
  B := nil;
  C := nil;
  MF := nil;

  try
    A := FLocalBigNumberPolynomialPool.Obtain;
    B := FLocalBigNumberPolynomialPool.Obtain;
    MF := FLocalBigNumberPool.Obtain;

    if P1.MaxDegree >= P2.MaxDegree then
    begin
      BigNumberPolynomialCopy(A, P1);
      BigNumberPolynomialCopy(B, P2);
    end
    else
    begin
      BigNumberPolynomialCopy(A, P2);
      BigNumberPolynomialCopy(B, P1);
    end;

    C := FLocalBigNumberPolynomialPool.Obtain;
    while not B.IsZero do
    begin
      BigNumberPolynomialCopy(C, B);        // ���� B
      while not BigNumberPolynomialMod(B, A, B, MF) do   // A mod B �� B
        BigNumberPolynomialMulBigNumber(A, MF);

      // B Ҫϵ��Լ�ֻ���
      BigNumberPolynomialReduce(B);
      BigNumberPolynomialCopy(A, C);        // ԭʼ B �� A
    end;

    BigNumberPolynomialCopy(Res, A);
    Result := True;
  finally
    FLocalBigNumberPool.Recycle(MF);
    FLocalBigNumberPolynomialPool.Recycle(C);
    FLocalBigNumberPolynomialPool.Recycle(B);
    FLocalBigNumberPolynomialPool.Recycle(A);
  end;
end;

function BigNumberPolynomialLeastCommonMultiple(Res: TCnBigNumberPolynomial;
  P1, P2: TCnBigNumberPolynomial): Boolean;
var
  G, M, R: TCnBigNumberPolynomial;
begin
  Result := False;
  if BigNumberPolynomialEqual(P1, P2) then
  begin
    BigNumberPolynomialCopy(Res, P1);
    Result := True;
    Exit;
  end;

  G := nil;
  M := nil;
  R := nil;

  try
    G := FLocalBigNumberPolynomialPool.Obtain;
    M := FLocalBigNumberPolynomialPool.Obtain;
    R := FLocalBigNumberPolynomialPool.Obtain;

    if not BigNumberPolynomialMul(M, P1, P2) then
      Exit;

    if not BigNumberPolynomialGreatestCommonDivisor(G, P1, P2) then
      Exit;

    if not BigNumberPolynomialDiv(Res, R, M, G) then
      Exit;

    Result := True;
  finally
    FLocalBigNumberPolynomialPool.Recycle(R);
    FLocalBigNumberPolynomialPool.Recycle(M);
    FLocalBigNumberPolynomialPool.Recycle(G);
  end;
end;

function BigNumberPolynomialCompose(Res: TCnBigNumberPolynomial;
  F, P: TCnBigNumberPolynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnBigNumberPolynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    BigNumberCopy(Res[0], F[0]);
    Result := True;
    Exit;
  end;

  if (Res = F) or (Res = P) then
    R := FLocalBigNumberPolynomialPool.Obtain
  else
    R := Res;

  X := FLocalBigNumberPolynomialPool.Obtain;
  T := FLocalBigNumberPolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      BigNumberPolynomialCopy(T, X);
      BigNumberPolynomialMulBigNumber(T, F[I]);
      BigNumberPolynomialAdd(R, R, T);

      if I <> F.MaxDegree then
        BigNumberPolynomialMul(X, X, P);
    end;

    if (Res = F) or (Res = P) then
    begin
      BigNumberPolynomialCopy(Res, R);
      FLocalBigNumberPolynomialPool.Recycle(R);
    end;
  finally
    FLocalBigNumberPolynomialPool.Recycle(X);
    FLocalBigNumberPolynomialPool.Recycle(T);
  end;
  Result := True;
end;

procedure BigNumberPolynomialGetValue(Res: TCnBigNumber; F: TCnBigNumberPolynomial;
  X: TCnBigNumber);
var
  I: Integer;
  T, M: TCnBigNumber;
begin
  BigNumberCopy(Res, F[0]);
  if X.IsZero or (F.MaxDegree = 0) then    // ֻ�г����������£��ó�����
    Exit;

  T := FLocalBigNumberPool.Obtain;
  M := FLocalBigNumberPool.Obtain;

  try
    BigNumberCopy(T, X);

    // �� F �е�ÿ��ϵ������ X �Ķ�Ӧ������ˣ�������
    for I := 1 to F.MaxDegree do
    begin
      BigNumberMul(M, F[I], T);
      BigNumberAdd(Res, Res, M);

      if I <> F.MaxDegree then
        BigNumberMul(T, T, X);
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(M);
  end;
end;

procedure BigNumberPolynomialReduce2(P1, P2: TCnBigNumberPolynomial);
var
  D: TCnBigNumberPolynomial;
begin
  if P1 = P2 then
  begin
    P1.SetOne;
    Exit;
  end;

  D := FLocalBigNumberPolynomialPool.Obtain;
  try
    if not BigNumberPolynomialGreatestCommonDivisor(D, P1, P2) then
      Exit;

    if not D.IsOne then
    begin
      BigNumberPolynomialDiv(P1, nil, P1, D);
      BigNumberPolynomialDiv(P1, nil, P1, D);
    end;
  finally
    FLocalBigNumberPolynomialPool.Recycle(D);
  end;
end;

// ===================== ���������µ���ϵ������ʽģ���� ========================

function BigNumberPolynomialGaloisEqual(A, B: TCnBigNumberPolynomial;
  Prime: TCnBigNumber): Boolean;
var
  I: Integer;
  T1, T2: TCnBigNumber;
begin
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  Result := A.MaxDegree = B.MaxDegree;
  if Result then
  begin
    T1 := FLocalBigNumberPool.Obtain;
    T2 := FLocalBigNumberPool.Obtain;

    try
      for I := A.MaxDegree downto 0 do
      begin
        if BigNumberEqual(A[I], B[I]) then
          Continue;

        // ��������ж�����
        BigNumberNonNegativeMod(T1, A[I], Prime);
        BigNumberNonNegativeMod(T2, B[I], Prime);

        if not BigNumberEqual(T1, T2) then
        begin
          Result := False;
          Exit;
        end;
      end;
    finally
      FLocalBigNumberPool.Recycle(T2);
      FLocalBigNumberPool.Recycle(T1);
    end;
  end;
end;

procedure BigNumberPolynomialGaloisNegate(P: TCnBigNumberPolynomial;
  Prime: TCnBigNumber);
var
  I: Integer;
begin
  for I := 0 to P.MaxDegree do
  begin
    P[I].Negate;
    BigNumberNonNegativeMod(P[I], P[I], Prime);
  end;
end;

function BigNumberPolynomialGaloisAdd(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
begin
  Result := BigNumberPolynomialAdd(Res, P1, P2);
  if Result then
  begin
    BigNumberPolynomialNonNegativeModBigNumber(Res, Prime);
    if Primitive <> nil then
      BigNumberPolynomialGaloisMod(Res, Res, Primitive, Prime);
  end;
end;

function BigNumberPolynomialGaloisSub(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
begin
  Result := BigNumberPolynomialSub(Res, P1, P2);
  if Result then
  begin
    BigNumberPolynomialNonNegativeModBigNumber(Res, Prime);
    if Primitive <> nil then
      BigNumberPolynomialGaloisMod(Res, Res, Primitive, Prime);
  end;
end;

function BigNumberPolynomialGaloisMul(Res: TCnBigNumberPolynomial;
  P1: TCnBigNumberPolynomial; P2: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
var
  R: TCnBigNumberPolynomial;
  T: TCnBigNumber;
  I, J: Integer;
begin
  if BigNumberPolynomialIsZero(P1) or BigNumberPolynomialIsZero(P2) then
  begin
    BigNumberPolynomialSetZero(Res);
    Result := True;
    Exit;
  end;

  T := FLocalBigNumberPool.Obtain;
  if (Res = P1) or (Res = P2) then
    R := FLocalBigNumberPolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxDegree := P1.MaxDegree + P2.MaxDegree;

  for I := 0 to P1.MaxDegree do
  begin
    // �ѵ� I �η������ֳ��� P2 ��ÿһ�����֣��ӵ������ I ��ͷ�Ĳ���
    for J := 0 to P2.MaxDegree do
    begin
      BigNumberMul(T, P1[I], P2[J]);
      BigNumberAdd(R[I + J], R[I + J], T);
      BigNumberNonNegativeMod(R[I + J], R[I + J], Prime);
    end;
  end;

  R.CorrectTop;

  // �ٶԱ�ԭ����ʽȡģ��ע�����ﴫ��ı�ԭ����ʽ�� mod �����ĳ��������Ǳ�ԭ����ʽ����
  if Primitive <> nil then
    BigNumberPolynomialGaloisMod(R, R, Primitive, Prime);

  if (Res = P1) or (Res = P2) then
  begin
    BigNumberPolynomialCopy(Res, R);
    FLocalBigNumberPolynomialPool.Recycle(R);
  end;
  FLocalBigNumberPool.Recycle(T);
  Result := True;
end;

function BigNumberPolynomialGaloisDiv(Res: TCnBigNumberPolynomial;
  Remain: TCnBigNumberPolynomial; P: TCnBigNumberPolynomial;
  Divisor: TCnBigNumberPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial; ErrMulFactor: TCnBigNumber): Boolean;
var
  SubRes: TCnBigNumberPolynomial; // ���ɵݼ���
  MulRes: TCnBigNumberPolynomial; // ���ɳ����˻�
  DivRes: TCnBigNumberPolynomial; // ������ʱ��
  I, D: Integer;
  K, T: TCnBigNumber;
  Co: Boolean;
begin
  Result := False;
  if BigNumberPolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxDegree > P.MaxDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      BigNumberPolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      BigNumberPolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;
  T := nil;
  K := nil;

  try
    T := FLocalBigNumberPool.Obtain;
    SubRes := FLocalBigNumberPolynomialPool.Obtain;
    BigNumberPolynomialCopy(SubRes, P);

    D := P.MaxDegree - Divisor.MaxDegree;
    DivRes := FLocalBigNumberPolynomialPool.Obtain;
    DivRes.MaxDegree := D;
    MulRes := FLocalBigNumberPolynomialPool.Obtain;

    Co := True;
    K := FLocalBigNumberPool.Obtain;
    if Divisor[Divisor.MaxDegree].IsOne then
      K.SetOne
    else
      Co := BigNumberModularInverse(K, Divisor[Divisor.MaxDegree], Prime, True);
      // Ҫ�� CheckGcd Ϊ True ���ڲ�����ʱ���� Co Ϊ False

    for I := 0 to D do
    begin
      if P.MaxDegree - I > SubRes.MaxDegree then               // �м���������λ
        Continue;
      BigNumberPolynomialCopy(MulRes, Divisor);
      BigNumberPolynomialShiftLeft(MulRes, D - I);             // ���뵽 SubRes ����ߴ�

      if Co then // ������ģ��Ԫ
      begin
        // ��ʽҪ��һ������������� SubRes ���λ���Գ�ʽ���λ�õ��Ľ����Ҳ�� SubRes ���λ���Գ�ʽ���λ����Ԫ�� mod Prime
        BigNumberDirectMulMod(T, SubRes[P.MaxDegree - I], K, Prime);
        BigNumberPolynomialGaloisMulBigNumber(MulRes, T, Prime);          // ��ʽ�˵���ߴ�ϵ����ͬ
      end
      else // Prime �ͳ�ʽ���λ������ʱģ��Ԫ K �����ڣ�Ҫ�������Ͳ������������
      begin
        BigNumberMod(T, SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]);
        if not T.IsZero then // ��������û��ģ��Ԫ��������ζ�û������ֻ�ܳ����˳�
        begin
          if ErrMulFactor <> nil then
          begin
            // Divisor[Divisor.MaxDegree] �������ߵ����Լ��
            if BigNumberGcd(T, SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]) then
              BigNumberMul(ErrMulFactor, Divisor[Divisor.MaxDegree], T);
          end;
          Exit;
        end
        else
        begin
          BigNumberDiv(T, nil, SubRes[P.MaxDegree - I], Divisor[Divisor.MaxDegree]);
          BigNumberPolynomialGaloisMulBigNumber(MulRes, T, Prime); // ��ʽ�˵���ߴ�ϵ����ͬ
        end;
      end;

      BigNumberCopy(DivRes[D - I], T);                             // ��Ӧλ���̷ŵ� DivRes λ��
      BigNumberPolynomialGaloisSub(SubRes, SubRes, MulRes, Prime); // ����ģ�������·Ż� SubRes
    end;

    // ������ʽ����Ҫ��ģ��ԭ����ʽ
    if Primitive <> nil then
    begin
      BigNumberPolynomialGaloisMod(SubRes, SubRes, Primitive, Prime);
      BigNumberPolynomialGaloisMod(DivRes, DivRes, Primitive, Prime);
    end;

    if Remain <> nil then
      BigNumberPolynomialCopy(Remain, SubRes);
    if Res <> nil then
      BigNumberPolynomialCopy(Res, DivRes);
    Result := True;
  finally
    FLocalBigNumberPolynomialPool.Recycle(SubRes);
    FLocalBigNumberPolynomialPool.Recycle(MulRes);
    FLocalBigNumberPolynomialPool.Recycle(DivRes);
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(K);
  end;
end;

function BigNumberPolynomialGaloisMod(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Divisor: TCnBigNumberPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial; ErrMulFactor: TCnBigNumber): Boolean;
begin
  Result := BigNumberPolynomialGaloisDiv(nil, Res, P, Divisor, Prime, Primitive, ErrMulFactor);
end;

function BigNumberPolynomialGaloisPower(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Exponent: TCnBigNumber;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial): Boolean;
var
  T: TCnBigNumberPolynomial;
  E: TCnBigNumber;
begin
  if Exponent.IsZero then
  begin
    Res.SetOne;
    Result := True;
    Exit;
  end
  else if Exponent.IsOne then
  begin
    if Res <> P then
      BigNumberPolynomialCopy(Res, P);
    Result := True;
    Exit;
  end
  else if Exponent.IsNegative then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidExponent, [Exponent]);

  T := FLocalBigNumberPolynomialPool.Obtain;
  BigNumberPolynomialCopy(T, P);
  E := FLocalBigNumberPool.Obtain;
  BigNumberCopy(E, Exponent);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetOne;
    while not E.IsZero do
    begin
      if BigNumberIsBitSet(E, 0) then
        BigNumberPolynomialGaloisMul(Res, Res, T, Prime, Primitive);

      BigNumberShiftRightOne(E, E);
      if not E.IsZero then
        BigNumberPolynomialGaloisMul(T, T, T, Prime, Primitive);
    end;
    Result := True;
  finally
    FLocalBigNumberPool.Recycle(E);
    FLocalBigNumberPolynomialPool.Recycle(T);
  end;
end;

function BigNumberPolynomialGaloisPower(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberPolynomial; Exponent: Cardinal; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial): Boolean; overload;
var
  T: TCnBigNumber;
begin
  T := FLocalBigNumberPool.Obtain;
  try
    T.SetWord(Exponent);
    Result := BigNumberPolynomialGaloisPower(Res, P, T, Prime, Primitive);
  finally
    FLocalBigNumberPool.Recycle(T);
  end;
end;

function BigNumberPolynomialGaloisAddWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
begin
  if N <> 0 then
  begin
    BigNumberAddWord(P[0], N);
    BigNumberNonNegativeMod(P[0], P[0], Prime);
  end;
  Result := True;
end;

function BigNumberPolynomialGaloisSubWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
begin
  if N <> 0 then
  begin
    BigNumberSubWord(P[0], N);
    BigNumberNonNegativeMod(P[0], P[0], Prime);
  end;
  Result := True;
end;

function BigNumberPolynomialGaloisMulWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
var
  I: Integer;
begin
  if N = 0 then
  begin
    BigNumberPolynomialSetZero(P);
  end
  else if N <> 1 then
  begin
    for I := 0 to P.MaxDegree do
    begin
      BigNumberMulWord(P[I], N);
      BigNumberNonNegativeMod(P[I], P[I], Prime);
    end;
  end;
  Result := True;
end;

function BigNumberPolynomialGaloisDivWord(P: TCnBigNumberPolynomial;
  N: Cardinal; Prime: TCnBigNumber): Boolean;
var
  I: Integer;
  K, T: TCnBigNumber;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero);

  K := nil;
  T := nil;

  try
    K := FLocalBigNumberPool.Obtain;
    T := FLocalBigNumberPool.Obtain;
    T.SetWord(N);

    BigNumberModularInverse(K, T, Prime);
    for I := 0 to P.MaxDegree do
    begin
      BigNumberMul(P[I], P[I], T);
      BigNumberNonNegativeMod(P[I], P[I], Prime);
    end;
  finally
    FLocalBigNumberPool.Recycle(K);
    FLocalBigNumberPool.Recycle(T);
  end;
  Result := True;
end;

procedure BigNumberPolynomialGaloisAddBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
begin
  BigNumberAdd(P[0], P[0], N);
  BigNumberNonNegativeMod(P[0], P[0], Prime);
end;

procedure BigNumberPolynomialGaloisSubBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
begin
  BigNumberSub(P[0], P[0], N);
  BigNumberNonNegativeMod(P[0], P[0], Prime);
end;

procedure BigNumberPolynomialGaloisMulBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
var
  I: Integer;
begin
  if N.IsZero then
    BigNumberPolynomialSetZero(P)
  else if not N.IsOne then
  begin
    for I := 0 to P.MaxDegree do
    begin
      BigNumberMul(P[I], P[I], N);
      BigNumberNonNegativeMod(P[I], P[I], Prime);
    end;
  end;
end;

procedure BigNumberPolynomialGaloisDivBigNumber(P: TCnBigNumberPolynomial;
  N: TCnBigNumber; Prime: TCnBigNumber);
var
  I: Integer;
  K: TCnBigNumber;
  B: Boolean;
begin
  if N.IsZero then
    raise EDivByZero.Create(SDivByZero);

  B := N.IsNegative;
  if B then
    N.Negate;

  K := FLocalBigNumberPool.Obtain;
  try
    BigNumberModularInverse(K, N, Prime);

    for I := 0 to P.MaxDegree do
    begin
      BigNumberMul(P[I], P[I], K);
      BigNumberNonNegativeMod(P[I], P[I], Prime);

      if B then
        BigNumberSub(P[I], Prime, P[I]);
    end;
  finally
    FLocalBigNumberPool.Recycle(K);
    if B then
      N.Negate;
  end;
end;

procedure BigNumberPolynomialGaloisMonic(P: TCnBigNumberPolynomial; Prime: TCnBigNumber);
begin
  if not P[P.MaxDegree].IsZero and not P[P.MaxDegree].IsOne then
    BigNumberPolynomialGaloisDivBigNumber(P, P[P.MaxDegree], Prime);
end;

function BigNumberPolynomialGaloisGreatestCommonDivisor(Res: TCnBigNumberPolynomial;
  P1, P2: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean;
var
  A, B, C: TCnBigNumberPolynomial;
begin
  A := nil;
  B := nil;
  C := nil;

  try
    A := FLocalBigNumberPolynomialPool.Obtain;
    B := FLocalBigNumberPolynomialPool.Obtain;

    if P1.MaxDegree >= P2.MaxDegree then
    begin
      BigNumberPolynomialCopy(A, P1);
      BigNumberPolynomialCopy(B, P2);
    end
    else
    begin
      BigNumberPolynomialCopy(A, P2);
      BigNumberPolynomialCopy(B, P1);
    end;

    C := FLocalBigNumberPolynomialPool.Obtain;
    while not B.IsZero do
    begin
      BigNumberPolynomialCopy(C, B);          // ���� B
      BigNumberPolynomialGaloisMod(B, A, B, Prime);  // A mod B �� B

      if B.MaxDegree = 0 then  // ����ǳ��������Ϊ 1
      begin
        if not B[0].IsZero then
          B[0].SetOne;
      end;

      BigNumberPolynomialCopy(A, C);          // ԭʼ B �� A
    end;

    BigNumberPolynomialCopy(Res, A);
    BigNumberPolynomialGaloisMonic(Res, Prime);      // ���Ϊһ
    Result := True;
  finally
    FLocalBigNumberPolynomialPool.Recycle(A);
    FLocalBigNumberPolynomialPool.Recycle(B);
    FLocalBigNumberPolynomialPool.Recycle(C);
  end;
end;

function BigNumberPolynomialGaloisLeastCommonMultiple(Res: TCnBigNumberPolynomial;
  P1, P2: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean;
var
  G, M, R: TCnBigNumberPolynomial;
begin
  Result := False;
  if BigNumberPolynomialEqual(P1, P2) then
  begin
    BigNumberPolynomialCopy(Res, P1);
    Result := True;
    Exit;
  end;

  G := nil;
  M := nil;
  R := nil;

  try
    G := FLocalBigNumberPolynomialPool.Obtain;
    M := FLocalBigNumberPolynomialPool.Obtain;
    R := FLocalBigNumberPolynomialPool.Obtain;

    if not BigNumberPolynomialGaloisMul(M, P1, P2, Prime) then
      Exit;

    if not BigNumberPolynomialGaloisGreatestCommonDivisor(G, P1, P2, Prime) then
      Exit;

    if not BigNumberPolynomialGaloisDiv(Res, R, M, G, Prime) then
      Exit;

    Result := True;
  finally
    FLocalBigNumberPolynomialPool.Recycle(R);
    FLocalBigNumberPolynomialPool.Recycle(M);
    FLocalBigNumberPolynomialPool.Recycle(G);
  end;
end;

procedure BigNumberPolynomialGaloisExtendedEuclideanGcd(A, B: TCnBigNumberPolynomial;
  X, Y: TCnBigNumberPolynomial; Prime: TCnBigNumber);
var
  T, P, M: TCnBigNumberPolynomial;
begin
  if B.IsZero then
  begin
    X.SetZero;
    BigNumberModularInverse(X[0], A[0], Prime);
    // X ���� A ���� P ��ģ��Ԫ��������������շת����������� 1
    // ��Ϊ A �����ǲ����� 1 ������
    Y.SetZero;
  end
  else
  begin
    T := nil;
    P := nil;
    M := nil;

    try
      T := FLocalBigNumberPolynomialPool.Obtain;
      P := FLocalBigNumberPolynomialPool.Obtain;
      M := FLocalBigNumberPolynomialPool.Obtain;

      BigNumberPolynomialGaloisMod(P, A, B, Prime);

      BigNumberPolynomialGaloisExtendedEuclideanGcd(B, P, Y, X, Prime);

      // Y := Y - (A div B) * X;
      BigNumberPolynomialGaloisDiv(P, M, A, B, Prime);
      BigNumberPolynomialGaloisMul(P, P, X, Prime);
      BigNumberPolynomialGaloisSub(Y, Y, P, Prime);
    finally
      FLocalBigNumberPolynomialPool.Recycle(M);
      FLocalBigNumberPolynomialPool.Recycle(P);
      FLocalBigNumberPolynomialPool.Recycle(T);
    end;
  end;
end;

procedure BigNumberPolynomialGaloisModularInverse(Res: TCnBigNumberPolynomial;
  X, Modulus: TCnBigNumberPolynomial; Prime: TCnBigNumber; CheckGcd: Boolean = False);
var
  X1, Y, G: TCnBigNumberPolynomial;
begin
  X1 := nil;
  Y := nil;
  G := nil;

  try
    if CheckGcd then
    begin
      G := FLocalBigNumberPolynomialPool.Obtain;
      BigNumberPolynomialGaloisGreatestCommonDivisor(G, X, Modulus, Prime);
      if not G.IsOne then
        raise ECnPolynomialException.Create(SCnErrorPolynomialGCDMustOne);
    end;

    X1 := FLocalBigNumberPolynomialPool.Obtain;
    Y := FLocalBigNumberPolynomialPool.Obtain;

    BigNumberPolynomialCopy(X1, X);

    // ��չŷ�����շת��������Ԫһ�β�����ϵ������ʽ���� A * X - B * Y = 1 ��������
    BigNumberPolynomialGaloisExtendedEuclideanGcd(X1, Modulus, Res, Y, Prime);
  finally
    FLocalBigNumberPolynomialPool.Recycle(X1);
    FLocalBigNumberPolynomialPool.Recycle(Y);
    FLocalBigNumberPolynomialPool.Recycle(G);
  end;
end;

function BigNumberPolynomialGaloisPrimePowerModularInverse(Res: TCnBigNumberPolynomial;
  X, Modulus: TCnBigNumberPolynomial; PrimeRoot: TCnBigNumber; Exponent: Integer): Boolean;
var
  F, G, T: TCnBigNumberPolynomial;
  N: Integer;
  P: TCnBigNumber;
begin
  // ԭʼ X �� Modulus ��ģ PrimeRoot^Exponent �µģ���ϵ���� PrimeRoot ��ģ�õ� F �� G ������ʽ

  if Exponent < 2 then
    raise ECnPolynomialException.Create(SCnErrorPolynomialInvalidExponent);

  F := nil;
  G := nil;
  T := nil;
  P := nil;

  try
    F := FLocalBigNumberPolynomialPool.Obtain;
    G := FLocalBigNumberPolynomialPool.Obtain;

    BigNumberPolynomialCopy(F, X);
    BigNumberPolynomialCopy(G, Modulus);

    BigNumberPolynomialNonNegativeModBigNumber(F, PrimeRoot);
    BigNumberPolynomialNonNegativeModBigNumber(G, PrimeRoot);

    T := FLocalBigNumberPolynomialPool.Obtain;
    BigNumberPolynomialGaloisGreatestCommonDivisor(T, F, G, PrimeRoot);

    Result := T.IsOne;  // F G �ͷ��˿��Ը���
    if not Result then  // �� PrimeRoot �»��� PrimeRoot^Exponent �²�����Ԫ
      Exit;

    BigNumberPolynomialGaloisModularInverse(T, F, G, PrimeRoot); // �� PrimeRoot ģ�µ������ʽ

    N := 2;
    P := FLocalBigNumberPool.Obtain;
    while N <= Exponent do
    begin
      // T := (p * T - X * T^2) in Ring(p^n, M)

      BigNumberPower(P, PrimeRoot, Cardinal(N));

      BigNumberPolynomialGaloisMul(F, T, T, P);
      BigNumberPolynomialGaloisMul(F, F, X, P);

      BigNumberPolynomialGaloisMulBigNumber(T, PrimeRoot, P);
      BigNumberPolynomialGaloisSub(T, T, F, P, Modulus);

      N := N + 1;
    end;

    // Result := T in Ring(p^e, M)
    BigNumberPower(P, PrimeRoot, Cardinal(Exponent));
    Result := BigNumberPolynomialGaloisMod(Res, T, Modulus, P);
  finally
    FLocalBigNumberPool.Recycle(P);
    FLocalBigNumberPolynomialPool.Recycle(T);
    FLocalBigNumberPolynomialPool.Recycle(G);
    FLocalBigNumberPolynomialPool.Recycle(F);
  end;
end;

function BigNumberPolynomialGaloisCompose(Res: TCnBigNumberPolynomial;
  F, P: TCnBigNumberPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
var
  I: Integer;
  R, X, T: TCnBigNumberPolynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    BigNumberNonNegativeMod(Res[0], F[0], Prime);
    Result := True;
    Exit;
  end;

  if (Res = F) or (Res = P) then
    R := FLocalBigNumberPolynomialPool.Obtain
  else
    R := Res;

  X := FLocalBigNumberPolynomialPool.Obtain;
  T := FLocalBigNumberPolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      BigNumberPolynomialCopy(T, X);
      BigNumberPolynomialGaloisMulBigNumber(T, F[I], Prime);
      BigNumberPolynomialGaloisAdd(R, R, T, Prime);

      if I <> F.MaxDegree then
        BigNumberPolynomialGaloisMul(X, X, P, Prime);
    end;

    if Primitive <> nil then
      BigNumberPolynomialGaloisMod(R, R, Primitive, Prime);

    if (Res = F) or (Res = P) then
    begin
      BigNumberPolynomialCopy(Res, R);
      FLocalBigNumberPolynomialPool.Recycle(R);
    end;
  finally
    FLocalBigNumberPolynomialPool.Recycle(X);
    FLocalBigNumberPolynomialPool.Recycle(T);
  end;
  Result := True;
end;

function BigNumberPolynomialGaloisGetValue(Res: TCnBigNumber;
  F: TCnBigNumberPolynomial; X, Prime: TCnBigNumber): Boolean;
var
  I: Integer;
  T, M: TCnBigNumber;
begin
  Result := True;
  BigNumberNonNegativeMod(Res, F[0], Prime);
  if X.IsZero or (F.MaxDegree = 0) then    // ֻ�г����������£��ó�����
    Exit;

  T := nil;
  M := nil;

  try
    T := FLocalBigNumberPool.Obtain;
    BigNumberCopy(T, X);
    M := FLocalBigNumberPool.Obtain;

    // �� F �е�ÿ��ϵ������ X �Ķ�Ӧ������ˣ�������
    for I := 1 to F.MaxDegree do
    begin
      BigNumberDirectMulMod(M, F[I], T, Prime);
      BigNumberAdd(Res, Res, M);
      BigNumberNonNegativeMod(Res, Res, Prime);

      if I <> F.MaxDegree then
        BigNumberDirectMulMod(T, T, X, Prime);
    end;
    BigNumberNonNegativeMod(Res, Res, Prime);
  finally
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(M);
  end;
end;

function BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B: Integer; Degree: Integer;
  OutDivisionPolynomial: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean; overload;
var
  NA, NB: TCnBigNumber;
begin
  NA := FLocalBigNumberPool.Obtain;
  NB := FLocalBigNumberPool.Obtain;

  try
    NA.SetInteger(A);
    NB.SetInteger(B);
    Result := BigNumberPolynomialGaloisCalcDivisionPolynomial(NA, NB, Degree,
      OutDivisionPolynomial, Prime);
  finally
    FLocalBigNumberPool.Recycle(NB);
    FLocalBigNumberPool.Recycle(NA);
  end;
end;

function BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B: TCnBigNumber; Degree: Integer;
  OutDivisionPolynomial: TCnBigNumberPolynomial; Prime: TCnBigNumber): Boolean;
var
  N: Integer;
  T, MI: TCnBigNumber;
  D1, D2, D3, Y4: TCnBigNumberPolynomial;
begin
  if Degree < 0 then
    raise ECnPolynomialException.Create('Galois Division Polynomial Invalid Degree')
  else if Degree = 0 then
  begin
    OutDivisionPolynomial.SetCoefficents([0]);  // f0(X) = 0
    Result := True;
  end
  else if Degree = 1 then
  begin
    OutDivisionPolynomial.SetCoefficents([1]);  // f1(X) = 1
    Result := True;
  end
  else if Degree = 2 then
  begin
    OutDivisionPolynomial.SetCoefficents([2]);  // f2(X) = 2
    Result := True;
  end
  else if Degree = 3 then   // f3(X) = 3 X4 + 6 a X2 + 12 b X - a^2
  begin
    OutDivisionPolynomial.MaxDegree := 4;
    OutDivisionPolynomial[4].SetWord(3);
    OutDivisionPolynomial[3].SetWord(0);
    BigNumberMulWordNonNegativeMod(OutDivisionPolynomial[2], A, 6, Prime);
    BigNumberMulWordNonNegativeMod(OutDivisionPolynomial[1], B, 12, Prime);

    T := FLocalBigNumberPool.Obtain;
    try
      BigNumberCopy(T, A);
      T.Negate;
      BigNumberDirectMulMod(OutDivisionPolynomial[0], T, A, Prime);
    finally
      FLocalBigNumberPool.Recycle(T);
    end;
    Result := True;
  end
  else if Degree = 4 then // f4(X) = 4 X6 + 20 a X4 + 80 b X3 - 20 a2X2 - 16 a b X - 4 a3 - 32 b^2
  begin
    OutDivisionPolynomial.MaxDegree := 6;
    OutDivisionPolynomial[6].SetWord(4);
    OutDivisionPolynomial[5].SetWord(0);
    BigNumberMulWordNonNegativeMod(OutDivisionPolynomial[4], A, 20, Prime);
    BigNumberMulWordNonNegativeMod(OutDivisionPolynomial[3], B, 80, Prime);

    T := FLocalBigNumberPool.Obtain;
    try
      BigNumberMulWordNonNegativeMod(T, A, -20, Prime);
      BigNumberDirectMulMod(OutDivisionPolynomial[2], T, A, Prime);
      BigNumberMulWordNonNegativeMod(T, A, -16, Prime);
      BigNumberDirectMulMod(OutDivisionPolynomial[1], T, B, Prime);

      BigNumberMulWordNonNegativeMod(T, A, -4, Prime);
      BigNumberDirectMulMod(T, T, A, Prime);
      BigNumberDirectMulMod(OutDivisionPolynomial[0], T, A, Prime);

      BigNumberMulWordNonNegativeMod(T, B, -32, Prime);
      BigNumberDirectMulMod(T, T, B, Prime);
      BigNumberAdd(OutDivisionPolynomial[0], OutDivisionPolynomial[0], T);
      BigNumberNonNegativeMod(OutDivisionPolynomial[0], OutDivisionPolynomial[0], Prime);
    finally
      FLocalBigNumberPool.Recycle(T);
    end;
    Result := True;
  end
  else
  begin
    D1 := nil;
    D2 := nil;
    D3 := nil;
    Y4 := nil;
    MI := nil;

    try
      // ��ʼ�ݹ����
      N := Degree shr 1;
      if (Degree and 1) = 0 then // Degree ��ż�������� fn * (fn+2 * fn-1 ^ 2 - fn-2 * fn+1 ^ 2) / 2
      begin
        D1 := FLocalBigNumberPolynomialPool.Obtain;
        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N + 2, D1, Prime);

        D2 := FLocalBigNumberPolynomialPool.Obtain;        // D1 �õ� fn+2
        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N - 1, D2, Prime);
        BigNumberPolynomialGaloisMul(D2, D2, D2, Prime);   // D2 �õ� fn-1 ^2

        BigNumberPolynomialGaloisMul(D1, D1, D2, Prime);   // D1 �õ� fn+2 * fn-1 ^ 2

        D3 := FLocalBigNumberPolynomialPool.Obtain;
        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N - 2, D3, Prime);  // D3 �õ� fn-2

        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N + 1, D2, Prime);
        BigNumberPolynomialGaloisMul(D2, D2, D2, Prime);   // D2 �õ� fn+1^2
        BigNumberPolynomialGaloisMul(D2, D2, D3, Prime);   // D2 �õ� fn-2 * fn+1^2

        BigNumberPolynomialGaloisSub(D1, D1, D2, Prime);   // D1 �õ� fn+2 * fn-1^2 - fn-2 * fn+1^2

        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N, D2, Prime);    // D2 �õ� fn
        BigNumberPolynomialGaloisMul(OutDivisionPolynomial, D2, D1, Prime);     // ��˵õ� f2n

        MI := FLocalBigNumberPool.Obtain;
        BigNumberModularInverseWord(MI, 2, Prime);
        BigNumberPolynomialGaloisMulBigNumber(OutDivisionPolynomial, MI, Prime);     // �ٳ��� 2
      end
      else // Degree ������
      begin
        Y4 := FLocalBigNumberPolynomialPool.Obtain;
        Y4.MaxDegree := 3;
        BigNumberCopy(Y4[0], B);
        BigNumberCopy(Y4[1], A);
        Y4[2].SetZero;
        Y4[3].SetOne;

        BigNumberPolynomialGaloisMul(Y4, Y4, Y4, Prime);

        D1 := FLocalBigNumberPolynomialPool.Obtain;
        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N + 2, D1, Prime); // D1 �õ� fn+2

        D2 := FLocalBigNumberPolynomialPool.Obtain;
        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N, D2, Prime);
        BigNumberPolynomialGaloisPower(D2, D2, 3, Prime);                        // D2 �õ� fn^3

        D3 := FLocalBigNumberPolynomialPool.Obtain;
        BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N + 1, D3, Prime);
        BigNumberPolynomialGaloisPower(D3, D3, 3, Prime);                        // D3 �õ� fn+1^3

        if (N and 1) <> 0 then // N ������������ f2n+1 = fn+2 * fn^3 - fn-1 * fn+1^3 * (x^3 + Ax + B)^2
        begin
          BigNumberPolynomialGaloisMul(D1, D1, D2, Prime);  // D1 �õ� fn+2 * fn^3

          BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N - 1, D2, Prime);
          BigNumberPolynomialGaloisMul(D2, D2, Y4, Prime);     // D2 �õ� fn-1 * Y^4

          BigNumberPolynomialGaloisMul(D2, D2, D3, Prime);     // D2 �õ� fn+1^3 * fn-1 * Y^4
          BigNumberPolynomialGaloisSub(OutDivisionPolynomial, D1, D2, Prime);
        end
        else // N ��ż�������� (x^3 + Ax + B)^2 * fn+2 * fn^3 - fn-1 * fn+1^3
        begin
          BigNumberPolynomialGaloisMul(D1, D1, D2, Prime);
          BigNumberPolynomialGaloisMul(D1, D1, Y4, Prime);   // D1 �õ� Y^4 * fn+2 * fn^3

          BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, N - 1, D2, Prime);  // D2 �õ� fn-1

          BigNumberPolynomialGaloisMul(D2, D2, D3, Prime);  // D2 �õ� fn-1 * fn+1^3

          BigNumberPolynomialGaloisSub(OutDivisionPolynomial, D1, D2, Prime);
        end;
      end;
    finally
      FLocalBigNumberPolynomialPool.Recycle(D1);
      FLocalBigNumberPolynomialPool.Recycle(D2);
      FLocalBigNumberPolynomialPool.Recycle(D3);
      FLocalBigNumberPolynomialPool.Recycle(Y4);
      FLocalBigNumberPool.Recycle(MI);
    end;
    Result := True;
  end;
end;

procedure BigNumberPolynomialGaloisReduce2(P1, P2: TCnBigNumberPolynomial; Prime: TCnBigNumber);
var
  D: TCnBigNumberPolynomial;
begin
  if P1 = P2 then
  begin
    P1.SetOne;
    Exit;
  end;

  D := FLocalBigNumberPolynomialPool.Obtain;
  try
    if not BigNumberPolynomialGaloisGreatestCommonDivisor(D, P1, P2, Prime) then
      Exit;

    if not D.IsOne then
    begin
      BigNumberPolynomialGaloisDiv(P1, nil, P1, D, Prime);
      BigNumberPolynomialGaloisDiv(P1, nil, P1, D, Prime);
    end;
  finally
    FLocalBigNumberPolynomialPool.Recycle(D);
  end;
end;

{ TCnBigNumberRationalPolynomialPool }

function TCnBigNumberRationalPolynomialPool.CreateObject: TObject;
begin
  Result := TCnBigNumberRationalPolynomial.Create;
end;

function TCnBigNumberRationalPolynomialPool.Obtain: TCnBigNumberRationalPolynomial;
begin
  Result := TCnBigNumberRationalPolynomial(inherited Obtain);
  Result.SetZero;
end;

procedure TCnBigNumberRationalPolynomialPool.Recycle(
  Poly: TCnBigNumberRationalPolynomial);
begin
  inherited Recycle(Poly);
end;

// ======================= һԪ����ϵ�������ʽ�������� ============================

function BigNumberRationalPolynomialEqual(R1, R2: TCnBigNumberRationalPolynomial): Boolean;
var
  T1, T2: TCnBigNumberPolynomial;
begin
  if R1 = R2 then
  begin
    Result := True;
    Exit;
  end;

  if R1.IsInt and R2.IsInt then
  begin
    Result := BigNumberPolynomialEqual(R1.Nominator, R2.Nominator);
    Exit;
  end;

  T1 := FLocalBigNumberPolynomialPool.Obtain;
  T2 := FLocalBigNumberPolynomialPool.Obtain;

  try
    // �жϷ��ӷ�ĸ����˵Ľ���Ƿ����
    BigNumberPolynomialMul(T1, R1.Nominator, R2.Denominator);
    BigNumberPolynomialMul(T2, R2.Nominator, R1.Denominator);
    Result := BigNumberPolynomialEqual(T1, T2);
  finally
    FLocalBigNumberPolynomialPool.Recycle(T2);
    FLocalBigNumberPolynomialPool.Recycle(T1);
  end;
end;

function BigNumberRationalPolynomialCopy(Dst: TCnBigNumberRationalPolynomial;
  Src: TCnBigNumberRationalPolynomial): TCnBigNumberRationalPolynomial;
begin
  Result := Dst;
  if Src <> Dst then
  begin
    BigNumberPolynomialCopy(Dst.Nominator, Src.Nominator);
    BigNumberPolynomialCopy(Dst.Denominator, Src.Denominator);
  end;
end;

procedure BigNumberRationalPolynomialAdd(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial); overload;
var
  M, R, F1, F2, D1, D2: TCnBigNumberPolynomial;
begin
  if R1.IsInt and R2.IsInt then
  begin
    BigNumberPolynomialAdd(RationalResult.Nominator, R1.Nominator, R2.Nominator);
    RationalResult.Denominator.SetOne;
    Exit;
  end
  else if R1.IsZero then
  begin
    if R2 <> RationalResult then
      RationalResult.Assign(R2);
  end
  else if R2.IsZero then
  begin
    if R1 <> RationalResult then
      RationalResult.Assign(R1);
  end
  else
  begin
    M := nil;
    R := nil;
    F1 := nil;
    F2 := nil;
    D1 := nil;
    D2 := nil;

    try
      // ���ĸ����С������
      M := FLocalBigNumberPolynomialPool.Obtain;
      R := FLocalBigNumberPolynomialPool.Obtain;
      F1 := FLocalBigNumberPolynomialPool.Obtain;
      F2 := FLocalBigNumberPolynomialPool.Obtain;
      D1 := FLocalBigNumberPolynomialPool.Obtain;
      D2 := FLocalBigNumberPolynomialPool.Obtain;

      BigNumberPolynomialCopy(D1, R1.Denominator);
      BigNumberPolynomialCopy(D2, R2.Denominator);

      if not BigNumberPolynomialLeastCommonMultiple(M, D1, D2) then
        BigNumberPolynomialMul(M, D1, D2);   // �޷�����С����ʽ��ʾϵ���޷�������ֱ�����

      BigNumberPolynomialDiv(F1, R, M, D1);
      BigNumberPolynomialDiv(F2, R, M, D2);

      BigNumberPolynomialCopy(RationalResult.Denominator, M);
      BigNumberPolynomialMul(R, R1.Nominator, F1);
      BigNumberPolynomialMul(M, R2.Nominator, F2);
      BigNumberPolynomialAdd(RationalResult.Nominator, R, M);
    finally
      FLocalBigNumberPolynomialPool.Recycle(M);
      FLocalBigNumberPolynomialPool.Recycle(R);
      FLocalBigNumberPolynomialPool.Recycle(F1);
      FLocalBigNumberPolynomialPool.Recycle(F2);
      FLocalBigNumberPolynomialPool.Recycle(D1);
      FLocalBigNumberPolynomialPool.Recycle(D2);
    end;
  end;
end;

procedure BigNumberRationalPolynomialSub(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial); overload;
begin
  R2.Nominator.Negate;
  BigNumberRationalPolynomialAdd(R1, R2, RationalResult);
  if RationalResult <> R2 then
    R2.Nominator.Negate;
end;

procedure BigNumberRationalPolynomialMul(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial); overload;
begin
  BigNumberPolynomialMul(RationalResult.Nominator, R1.Nominator, R2.Nominator);
  BigNumberPolynomialMul(RationalResult.Denominator, R1.Denominator, R2.Denominator);
end;

procedure BigNumberRationalPolynomialDiv(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial); overload;
var
  N: TCnBigNumberPolynomial;
begin
  if R2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  N := FLocalBigNumberPolynomialPool.Obtain; // ������ˣ��������м��������ֹ RationalResult �� Number1 �� Number 2
  try
    BigNumberPolynomialMul(N, R1.Nominator, R2.Denominator);
    BigNumberPolynomialMul(RationalResult.Denominator, R1.Denominator, R2.Nominator);
    BigNumberPolynomialCopy(RationalResult.Nominator, N);
  finally
    FLocalBigNumberPolynomialPool.Recycle(N);
  end;
end;

procedure BigNumberRationalPolynomialAddBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialAdd(R, P, R);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialSubBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialSub(R, P, R);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialMulBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialMul(R, P, R);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialDivBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialDiv(R, P, R);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialAdd(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
var
  T: TCnBigNumberRationalPolynomial;
begin
  if P1.IsZero then
  begin
    if R1 <> RationalResult then
    begin
      BigNumberRationalPolynomialCopy(RationalResult, R1);
      Exit;
    end;
  end;

  T := FLocalBigNumberRationalPolynomialPool.Obtain;
  try
    T.Denominator.SetOne;
    BigNumberPolynomialCopy(T.Nominator, P1);
    BigNumberRationalPolynomialAdd(R1, T, RationalResult);
  finally
    FLocalBigNumberRationalPolynomialPool.Recycle(T);
  end;
end;

procedure BigNumberRationalPolynomialSub(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
begin
  P1.Negate;
  try
    BigNumberRationalPolynomialAdd(R1, P1, RationalResult);
  finally
    P1.Negate;
  end;
end;

procedure BigNumberRationalPolynomialMul(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
begin
  if P1.IsZero then
    RationalResult.SetZero
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    BigNumberPolynomialMul(RationalResult.Nominator, R1.Nominator, P1);
    BigNumberPolynomialCopy(RationalResult.Denominator, R1.Denominator);
  end;
end;

procedure BigNumberRationalPolynomialDiv(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial); overload;
begin
  if P1.IsZero then
    raise EDivByZero.Create(SDivByZero)
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    BigNumberPolynomialMul(RationalResult.Denominator, R1.Denominator, P1);
    BigNumberPolynomialCopy(RationalResult.Nominator, R1.Nominator);
  end;
end;

function BigNumberRationalPolynomialCompose(Res: TCnBigNumberRationalPolynomial;
  F, P: TCnBigNumberRationalPolynomial): Boolean;
var
  RN, RD: TCnBigNumberRationalPolynomial;
begin
  if P.IsInt then
    Result := BigNumberRationalPolynomialCompose(Res, F, P.Nominator)
  else
  begin
    RD := FLocalBigNumberRationalPolynomialPool.Obtain;
    RN := FLocalBigNumberRationalPolynomialPool.Obtain;

    try
      BigNumberRationalPolynomialCompose(RN, F.Nominator, P);
      BigNumberRationalPolynomialCompose(RD, F.Denominator, P);

      BigNumberPolynomialMul(Res.Nominator, RN.Nominator, RD.Denominator);
      BigNumberPolynomialMul(Res.Denominator, RN.Denominator, RD.Nominator);
      Result := True;
    finally
      FLocalBigNumberRationalPolynomialPool.Recycle(RN);
      FLocalBigNumberRationalPolynomialPool.Recycle(RD);
    end;
  end;
end;

function BigNumberRationalPolynomialCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberRationalPolynomial; P: TCnBigNumberPolynomial): Boolean;
begin
  BigNumberPolynomialCompose(Res.Nominator, F.Nominator, P);
  BigNumberPolynomialCompose(Res.Denominator, F.Denominator, P);
  Result := True;
end;

function BigNumberRationalPolynomialCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberPolynomial; P: TCnBigNumberRationalPolynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnBigNumberRationalPolynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    Res.Nominator[0] := F[0];
    Result := True;
    Exit;
  end;

  if Res = P then
    R := FLocalBigNumberRationalPolynomialPool.Obtain
  else
    R := Res;

  X := FLocalBigNumberRationalPolynomialPool.Obtain;
  T := FLocalBigNumberRationalPolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      BigNumberRationalPolynomialCopy(T, X);
      BigNumberRationalPolynomialMulBigNumber(T, F[I]);
      BigNumberRationalPolynomialAdd(R, T, R);

      if I <> F.MaxDegree then
        BigNumberRationalPolynomialMul(X, P, X);
    end;

    if Res = P then
    begin
      BigNumberRationalPolynomialCopy(Res, R);
      FLocalBigNumberRationalPolynomialPool.Recycle(R);
    end;
  finally
    FLocalBigNumberRationalPolynomialPool.Recycle(X);
    FLocalBigNumberRationalPolynomialPool.Recycle(T);
  end;
  Result := True;
end;

procedure BigNumberRationalPolynomialGetValue(Res: TCnBigRational;
  F: TCnBigNumberRationalPolynomial; X: TCnBigNumber);
begin
  BigNumberPolynomialGetValue(Res.Nominator, F.Nominator, X);
  BigNumberPolynomialGetValue(Res.Denominator, F.Denominator, X);
  Res.Reduce;
end;

// ================== һԪ����ϵ�������ʽ���������ϵ�ģ���� ===================

function BigNumberRationalPolynomialGaloisEqual(R1, R2: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial = nil): Boolean;
var
  T1, T2: TCnBigNumberPolynomial;
begin
  if R1 = R2 then
  begin
    Result := True;
    Exit;
  end;

  T1 := FLocalBigNumberPolynomialPool.Obtain;
  T2 := FLocalBigNumberPolynomialPool.Obtain;

  try
    // �жϷ��ӷ�ĸ����˵Ľ���Ƿ����
    BigNumberPolynomialGaloisMul(T1, R1.Nominator, R2.Denominator, Prime, Primitive);
    BigNumberPolynomialGaloisMul(T2, R2.Nominator, R1.Denominator, Prime, Primitive);
    Result := BigNumberPolynomialGaloisEqual(T1, T2, Prime);
  finally
    FLocalBigNumberPolynomialPool.Recycle(T2);
    FLocalBigNumberPolynomialPool.Recycle(T1);
  end;
end;

procedure BigNumberRationalPolynomialGaloisNegate(P: TCnBigNumberRationalPolynomial;
  Prime: TCnBigNumber);
begin
  BigNumberPolynomialGaloisNegate(P.Nominator, Prime);
end;

procedure BigNumberRationalPolynomialGaloisAdd(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
var
  M, R, F1, F2, D1, D2: TCnBigNumberPolynomial;
begin
  if R1.IsInt and R2.IsInt then
  begin
    BigNumberPolynomialGaloisAdd(RationalResult.Nominator, R1.Nominator,
      R2.Nominator, Prime);
    RationalResult.Denominator.SetOne;
    Exit;
  end
  else if R1.IsZero then
  begin
    if R2 <> RationalResult then
      RationalResult.Assign(R2);
  end
  else if R2.IsZero then
  begin
    if R1 <> RationalResult then
      RationalResult.Assign(R1);
  end
  else
  begin
    M := nil;
    R := nil;
    F1 := nil;
    F2 := nil;
    D1 := nil;
    D2 := nil;

    try
      // ���ĸ����С������
      M := FLocalBigNumberPolynomialPool.Obtain;
      R := FLocalBigNumberPolynomialPool.Obtain;
      F1 := FLocalBigNumberPolynomialPool.Obtain;
      F2 := FLocalBigNumberPolynomialPool.Obtain;
      D1 := FLocalBigNumberPolynomialPool.Obtain;
      D2 := FLocalBigNumberPolynomialPool.Obtain;

      BigNumberPolynomialCopy(D1, R1.Denominator);
      BigNumberPolynomialCopy(D2, R2.Denominator);

      if not BigNumberPolynomialGaloisLeastCommonMultiple(M, D1, D2, Prime) then
        BigNumberPolynomialGaloisMul(M, D1, D2, Prime);   // �޷�����С����ʽ��ʾϵ���޷�������ֱ�����

      BigNumberPolynomialGaloisDiv(F1, R, M, D1, Prime);  // ��С������ M div D1 ����� F1
      BigNumberPolynomialGaloisDiv(F2, R, M, D2, Prime);  // ��С������ M div D2 ����� F2

      BigNumberPolynomialCopy(RationalResult.Denominator, M);  // ����ķ�ĸ����С������
      BigNumberPolynomialGaloisMul(R, R1.Nominator, F1, Prime);
      BigNumberPolynomialGaloisMul(M, R2.Nominator, F2, Prime);
      BigNumberPolynomialGaloisAdd(RationalResult.Nominator, R, M, Prime);
    finally
      FLocalBigNumberPolynomialPool.Recycle(M);
      FLocalBigNumberPolynomialPool.Recycle(R);
      FLocalBigNumberPolynomialPool.Recycle(F1);
      FLocalBigNumberPolynomialPool.Recycle(F2);
      FLocalBigNumberPolynomialPool.Recycle(D1);
      FLocalBigNumberPolynomialPool.Recycle(D2);
    end;
  end;
end;

procedure BigNumberRationalPolynomialGaloisSub(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
begin
  R2.Nominator.Negate;
  BignumberRationalPolynomialGaloisAdd(R1, R2, RationalResult, Prime);
  if RationalResult <> R2 then
    R2.Nominator.Negate;
end;

procedure BigNumberRationalPolynomialGaloisMul(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
begin
  BigNumberPolynomialGaloisMul(RationalResult.Nominator, R1.Nominator, R2.Nominator, Prime);
  BigNumberPolynomialGaloisMul(RationalResult.Denominator, R1.Denominator, R2.Denominator, Prime);
end;

procedure BigNumberRationalPolynomialGaloisDiv(R1, R2: TCnBigNumberRationalPolynomial;
  RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
var
  N: TCnBigNumberPolynomial;
begin
  if R2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  N := FLocalBigNumberPolynomialPool.Obtain; // ������ˣ��������м��������ֹ RationalResult �� Number1 �� Number 2
  try
    BigNumberPolynomialGaloisMul(N, R1.Nominator, R2.Denominator, Prime);
    BigNumberPolynomialGaloisMul(RationalResult.Denominator, R1.Denominator, R2.Nominator, Prime);
    BigNumberPolynomialCopy(RationalResult.Nominator, N);
  finally
    FLocalBigNumberPolynomialPool.Recycle(N);
  end;
end;

procedure BigNumberRationalPolynomialGaloisAddBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialGaloisAdd(R, P, R, Prime);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialGaloisSubBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialGaloisSub(R, P, R, Prime);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialGaloisMulBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialGaloisMul(R, P, R, Prime);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialGaloisDivBigNumber(R: TCnBigNumberRationalPolynomial;
  Num: TCnBigNumber; Prime: TCnBigNumber);
var
  P: TCnBigNumberPolynomial;
begin
  P := FLocalBigNumberPolynomialPool.Obtain;
  try
    P.MaxDegree := 0;
    BigNumberCopy(P[0], Num);
    BigNumberRationalPolynomialGaloisDiv(R, P, R, Prime);
  finally
    FLocalBigNumberPolynomialPool.Recycle(P);
  end;
end;

procedure BigNumberRationalPolynomialGaloisAdd(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
var
  T: TCnBigNumberRationalPolynomial;
begin
  if P1.IsZero then
  begin
    if R1 <> RationalResult then
    begin
      BigNumberRationalPolynomialCopy(RationalResult, R1);
      Exit;
    end;
  end;

  T := FLocalBigNumberRationalPolynomialPool.Obtain;
  try
    T.Denominator.SetOne;
    BigNumberPolynomialCopy(T.Nominator, P1);
    BigNumberRationalPolynomialGaloisAdd(R1, T, RationalResult, Prime);
  finally
    FLocalBigNumberRationalPolynomialPool.Recycle(T);
  end;
end;

procedure BigNumberRationalPolynomialGaloisSub(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
begin
  P1.Negate;
  try
    BigNumberRationalPolynomialGaloisAdd(R1, P1, RationalResult, Prime);
  finally
    P1.Negate;
  end;
end;

procedure BigNumberRationalPolynomialGaloisMul(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
begin
  if P1.IsZero then
    RationalResult.SetZero
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    BigNumberPolynomialGaloisMul(RationalResult.Nominator, R1.Nominator, P1, Prime);
    BigNumberPolynomialCopy(RationalResult.Denominator, R1.Denominator);
  end;
end;

procedure BigNumberRationalPolynomialGaloisDiv(R1: TCnBigNumberRationalPolynomial;
  P1: TCnBigNumberPolynomial; RationalResult: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber); overload;
begin
  if P1.IsZero then
    raise EDivByZero.Create(SDivByZero)
  else if P1.IsOne then
    RationalResult.Assign(R1)
  else
  begin
    BigNumberPolynomialGaloisMul(RationalResult.Denominator, R1.Denominator, P1, Prime);
    BigNumberPolynomialCopy(RationalResult.Nominator, R1.Nominator);
  end;
end;

function BigNumberRationalPolynomialGaloisCompose(Res: TCnBigNumberRationalPolynomial;
  F, P: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberPolynomial): Boolean;
var
  RN, RD: TCnBigNumberRationalPolynomial;
begin
  if P.IsInt then
    Result := BigNumberRationalPolynomialGaloisCompose(Res, F, P.Nominator, Prime, Primitive)
  else
  begin
    RD := FLocalBigNumberRationalPolynomialPool.Obtain;
    RN := FLocalBigNumberRationalPolynomialPool.Obtain;

    try
      BigNumberRationalPolynomialGaloisCompose(RN, F.Nominator, P, Prime, Primitive);
      BigNumberRationalPolynomialGaloisCompose(RD, F.Denominator, P, Prime, Primitive);

      BigNumberPolynomialGaloisMul(Res.Nominator, RN.Nominator, RD.Denominator, Prime);
      BigNumberPolynomialGaloisMul(Res.Denominator, RN.Denominator, RD.Nominator, Prime);

      if Primitive <> nil then
      begin
        BigNumberPolynomialGaloisMod(Res.Nominator, Res.Nominator, Primitive, Prime);
        BigNumberPolynomialGaloisMod(Res.Denominator, Res.Denominator, Primitive, Prime);
      end;
      Result := True;
    finally
      FLocalBigNumberRationalPolynomialPool.Recycle(RN);
      FLocalBigNumberRationalPolynomialPool.Recycle(RD);
    end;
  end;
end;

function BigNumberRationalPolynomialGaloisCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberRationalPolynomial; P: TCnBigNumberPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial): Boolean;
begin
  BigNumberPolynomialGaloisCompose(Res.Nominator, F.Nominator, P, Prime, Primitive);
  BigNumberPolynomialGaloisCompose(Res.Denominator, F.Denominator, P, Prime, Primitive);
  Result := True;
end;

function BigNumberRationalPolynomialGaloisCompose(Res: TCnBigNumberRationalPolynomial;
  F: TCnBigNumberPolynomial; P: TCnBigNumberRationalPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberPolynomial): Boolean;
var
  I: Integer;
  R, X, T: TCnBigNumberRationalPolynomial;
begin
  if P.IsZero or (F.MaxDegree = 0) then    // 0 ���룬��ֻ�г����������£��ó�����
  begin
    Res.SetOne;
    BigNumberNonNegativeMod(Res.Nominator[0], F[0], Prime);
    Result := True;
    Exit;
  end;

  if Res = P then
    R := FLocalBigNumberRationalPolynomialPool.Obtain
  else
    R := Res;

  X := FLocalBigNumberRationalPolynomialPool.Obtain;
  T := FLocalBigNumberRationalPolynomialPool.Obtain;

  try
    X.SetOne;
    R.SetZero;

    // �� F �е�ÿ��ϵ������ P �Ķ�Ӧ������ˣ�������
    for I := 0 to F.MaxDegree do
    begin
      BigNumberRationalPolynomialCopy(T, X);
      BigNumberRationalPolynomialGaloisMulBigNumber(T, F[I], Prime);
      BigNumberRationalPolynomialGaloisAdd(R, T, R, Prime);

      if I <> F.MaxDegree then
        BigNumberRationalPolynomialGaloisMul(X, P, X, Prime);
    end;

    if Primitive <> nil then
    begin
      BigNumberPolynomialGaloisMod(R.Nominator, R.Nominator, Primitive, Prime);
      BigNumberPolynomialGaloisMod(R.Denominator, R.Denominator, Primitive, Prime);
    end;

    if Res = P then
    begin
      BigNumberRationalPolynomialCopy(Res, R);
      FLocalBigNumberRationalPolynomialPool.Recycle(R);
    end;
  finally
    FLocalBigNumberRationalPolynomialPool.Recycle(X);
    FLocalBigNumberRationalPolynomialPool.Recycle(T);
  end;
  Result := True;
end;

procedure BigNumberRationalPolynomialGaloisGetValue(Res: TCnBigNumber;
  F: TCnBigNumberRationalPolynomial; X: TCnBigNumber; Prime: TCnBigNumber);
var
  N, D, T: TCnBigNumber;
begin
  D := nil;
  N := nil;
  T := nil;

  try
    D := FLocalBigNumberPool.Obtain;
    BigNumberPolynomialGaloisGetValue(D, F.Denominator, X, Prime);
    if D.IsZero then
      raise EDivByZero.Create(SDivByZero);

    N := FLocalBigNumberPool.Obtain;
    BigNumberPolynomialGaloisGetValue(N, F.Nominator, X, Prime);

    T := FLocalBigNumberPool.Obtain;
    BigNumberModularInverse(T, D, Prime);
    BigNumberMul(N, T, N);
    BigNumberNonNegativeMod(Res, N, Prime);
  finally
    FLocalBigNumberPool.Recycle(D);
    FLocalBigNumberPool.Recycle(N);
    FLocalBigNumberPool.Recycle(T);
  end;
end;

{ TCnInt64BiPolynomial }

procedure TCnInt64BiPolynomial.CorrectTop;
var
  I: Integer;
  Compact, MeetNonEmpty: Boolean;
  YL: TCnInt64List;
begin
  MeetNonEmpty := False;
  for I := FXs.Count - 1 downto 0 do
  begin
    YL := TCnInt64List(FXs[I]);
    Compact := CompactYDegree(YL);

    if not Compact then     // ����ѹ���� 0
      MeetNonEmpty := True;

    if Compact and not MeetNonEmpty then // ��ߵ�һ·����ѹ������ȫ 0 ��Ҫɾ��
    begin
      FXs.Delete(I);
      YL.Free;
    end;
  end;
end;

function TCnInt64BiPolynomial.CompactYDegree(YList: TCnInt64List): Boolean;
var
  I: Integer;
begin
  for I := YList.Count - 1 downto 0 do
  begin
    if YList[I] = 0 then
      YList.Delete(I)
    else
      Break;
  end;

  Result := YList.Count = 0;
end;

constructor TCnInt64BiPolynomial.Create(XDegree, YDegree: Integer);
begin
  FXs := TObjectList.Create(False);
  EnsureDegrees(XDegree, YDegree);
end;

destructor TCnInt64BiPolynomial.Destroy;
var
  I: Integer;
begin
  for I := FXs.Count - 1 downto 0 do
    FXs[I].Free;
  FXs.Free;
  inherited;
end;

procedure TCnInt64BiPolynomial.EnsureDegrees(XDegree, YDegree: Integer);
var
  I, OldCount: Integer;
begin
  CheckDegree(XDegree);
  CheckDegree(YDegree);

  OldCount := FXs.Count;
  if (XDegree + 1) > FXs.Count then
  begin
    for I := FXs.Count + 1 to XDegree + 1 do
    begin
      FXs.Add(TCnInt64List.Create);
      TCnInt64List(FXs[FXs.Count - 1]).Count := YDegree + 1;
    end;
  end;

  for I:= OldCount - 1 downto 0 do
    if TCnInt64List(FXs[I]).Count < YDegree + 1 then
      TCnInt64List(FXs[I]).Count := YDegree + 1;
end;

function TCnInt64BiPolynomial.GetMaxXDegree: Integer;
begin
  Result := FXs.Count - 1;
end;

function TCnInt64BiPolynomial.GetMaxYDegree: Integer;
var
  I: Integer;
begin
  Result := 0;
  for I := FXs.Count - 1 downto 0 do
    if YFactorsList[I].Count - 1 > Result then
      Result := YFactorsList[I].Count - 1;
end;

function TCnInt64BiPolynomial.GetYFactorsList(
  Index: Integer): TCnInt64List;
begin
  if (Index < 0) or (Index >= FXs.Count) then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidDegree, [Index]);

  Result := TCnInt64List(FXs[Index]);
end;

function TCnInt64BiPolynomial.IsZero: Boolean;
begin
  Result := Int64BiPolynomialIsZero(Self);
end;

procedure TCnInt64BiPolynomial.Negate;
begin
  Int64BiPolynomialNegate(Self);
end;

procedure TCnInt64BiPolynomial.SetMaxXDegree(const Value: Integer);
var
  I: Integer;
begin
  CheckDegree(Value);

  if Value + 1 > FXs.Count then
  begin
    for I := FXs.Count + 1 to Value + 1 do
      FXs.Add(TCnInt64List.Create);
  end
  else if Value + 1 < FXs.Count then
  begin
    for I := FXs.Count - 1 downto Value + 1 do
    begin
      FXs[I].Free;
      FXs.Delete(I);
    end;
  end;
end;

procedure TCnInt64BiPolynomial.SetMaxYDegree(const Value: Integer);
var
  I: Integer;
begin
  CheckDegree(Value);

  for I := FXs.Count - 1 downto 0 do
    TCnInt64List(FXs[I]).Count := Value + 1;
end;

procedure TCnInt64BiPolynomial.SetString(const Poly: string);
begin
  Int64BiPolynomialSetString(Self, Poly);
end;

procedure TCnInt64BiPolynomial.SetZero;
begin
  Int64BiPolynomialSetZero(Self);
end;

function TCnInt64BiPolynomial.ToString: string;
begin
  Result := Int64BiPolynomialToString(Self);
end;

function Int64BiPolynomialNew: TCnInt64BiPolynomial;
begin
  Result := TCnInt64BiPolynomial.Create;
end;

procedure Int64BiPolynomialFree(P: TCnInt64BiPolynomial);
begin
  P.Free;
end;

function Int64BiPolynomialDuplicate(P: TCnInt64BiPolynomial): TCnInt64BiPolynomial;
begin
  if P = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := Int64BiPolynomialNew;
  if Result <> nil then
    Int64BiPolynomialCopy(Result, P);
end;

function Int64BiPolynomialCopy(Dst: TCnInt64BiPolynomial;
  Src: TCnInt64BiPolynomial): TCnInt64BiPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  if Src <> Dst then
  begin
    if Src.MaxXDegree >= 0 then
    begin
      Dst.MaxXDegree := Src.MaxXDegree;
      for I := 0 to Src.MaxXDegree do
        CnInt64ListCopy(Dst.YFactorsList[I], Src.YFactorsList[I]);
    end
    else
      Dst.SetZero; // ��� Src δ��ʼ������ Dst Ҳ����
  end;
end;

function Int64BiPolynomialCopyFromX(Dst: TCnInt64BiPolynomial;
  SrcX: TCnInt64Polynomial): TCnInt64BiPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  Dst.Clear;

  Dst.MaxXDegree := SrcX.MaxDegree;
  for I := 0 to SrcX.MaxDegree do
    Dst.SafeValue[I, 0] := SrcX[I]; // ��ÿһ�� YList ����Ԫ����ֵ
end;

function Int64BiPolynomialCopyFromY(Dst: TCnInt64BiPolynomial;
  SrcY: TCnInt64Polynomial): TCnInt64BiPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  Dst.Clear;

  for I := 0 to SrcY.MaxDegree do
    Dst.YFactorsList[0].Add(SrcY[I]); // �����һ�� YList ������Ԫ����ֵ
end;

function Int64BiPolynomialToString(P: TCnInt64BiPolynomial;
  const Var1Name: string; const Var2Name: string): string;
var
  I, J: Integer;
  YL: TCnInt64List;
begin
  Result := '';
  for I := P.FXs.Count - 1 downto 0 do
  begin
    YL := TCnInt64List(P.FXs[I]);
    for J := YL.Count - 1 downto 0 do
    begin
      if VarItemFactor(Result, (J = 0) and (I = 0), IntToStr(YL[J])) then
        Result := Result + VarPower2(Var1Name, Var2Name, I, J);
    end;
  end;

  if Result = '' then
    Result := '0';
end;

{$WARNINGS OFF}

function Int64BiPolynomialSetString(P: TCnInt64BiPolynomial;
  const Str: string; const Var1Name: string; const Var2Name: string): Boolean;
var
  C, Ptr: PChar;
  Num: string;
  E1, E2: Integer;
  F: Int64;
  IsNeg: Boolean;
begin
  // ��Ԫ����ʽ�ַ��������е���
  Result := False;
  if (P = nil) or (Str = '') then
    Exit;

  P.SetZero;
  C := @Str[1];

  while C^ <> #0 do
  begin
    if not (C^ in ['+', '-', '0'..'9']) and (C^ <> Var1Name) and (C^ <> Var2Name) then
    begin
      Inc(C);
      Continue;
    end;

    IsNeg := False;
    if C^ = '+' then
      Inc(C)
    else if C^ = '-' then
    begin
      IsNeg := True;
      Inc(C);
    end;

    F := 1;
    if C^ in ['0'..'9'] then // ��ϵ��
    begin
      Ptr := C;
      while C^ in ['0'..'9'] do
        Inc(C);

      // Ptr �� C ֮�������֣�����һ��ϵ��
      SetString(Num, Ptr, C - Ptr);
      F := StrToInt64(Num);
      if IsNeg then
        F := -F;
    end
    else if IsNeg then
      F := -F;

    E1 := 0;
    if C^ = Var1Name then
    begin
      E1 := 1;
      Inc(C);
      if C^ = '^' then // ��ָ��
      begin
        Inc(C);
        if C^ in ['0'..'9'] then
        begin
          Ptr := C;
          while C^ in ['0'..'9'] do
            Inc(C);

          // Ptr �� C ֮�������֣�����һ��ָ��
          SetString(Num, Ptr, C - Ptr);
          E1 := StrToInt64(Num);
        end;
      end;
    end;

    E2 := 0;
    if C^ = Var2Name then
    begin
      E2 := 1;
      Inc(C);
      if C^ = '^' then // ��ָ��
      begin
        Inc(C);
        if C^ in ['0'..'9'] then
        begin
          Ptr := C;
          while C^ in ['0'..'9'] do
            Inc(C);

          // Ptr �� C ֮�������֣�����һ��ָ��
          SetString(Num, Ptr, C - Ptr);
          E2 := StrToInt64(Num);
        end;
      end;
    end;

    // ��ָ�������ˣ���
    P.SafeValue[E1, E2] := F;
  end;

  Result := True;
end;

{$WARNINGS ON}

function Int64BiPolynomialIsZero(P: TCnInt64BiPolynomial): Boolean;
begin
  Result := (P.FXs.Count = 1) and (TCnInt64List(P.FXs[0]).Count = 1)
    and (TCnInt64List(P.FXs[0])[0] = 0);
end;

procedure Int64BiPolynomialSetZero(P: TCnInt64BiPolynomial);
var
  I: Integer;
begin
  if P.FXs.Count <= 0 then
    P.FXs.Add(TCnInt64List.Create)
  else
    for I := P.FXs.Count - 1 downto 1 do
    begin
      P.FXs[I].Free;
      P.FXs.Delete(I);
    end;

  if P.YFactorsList[0].Count <= 0 then
    P.YFactorsList[0].Add(0)
  else
  begin
    for I := P.YFactorsList[0].Count - 1 downto 1 do
      P.YFactorsList[0].Delete(I);

    P.YFactorsList[0][0] := 0;
  end;
end;

procedure Int64BiPolynomialSetOne(P: TCnInt64BiPolynomial);
var
  I: Integer;
begin
  if P.FXs.Count <= 0 then
    P.FXs.Add(TCnInt64List.Create)
  else
    for I := P.FXs.Count - 1 downto 1 do
    begin
      P.FXs[I].Free;
      P.FXs.Delete(I);
    end;

  if P.YFactorsList[0].Count <= 0 then
    P.YFactorsList[0].Add(1)
  else
  begin
    for I := P.YFactorsList[0].Count - 1 downto 1 do
      P.YFactorsList[0].Delete(I);

    P.YFactorsList[0][0] := 1;
  end;
end;

procedure Int64BiPolynomialNegate(P: TCnInt64BiPolynomial);
var
  I, J: Integer;
  YL: TCnInt64List;
begin
  for I := P.FXs.Count - 1 downto 0 do
  begin
    YL := TCnInt64List(P.FXs[I]);
    for J := YL.Count - 1 downto 0 do
      YL[J] := - YL[J];
  end;
end;

function Int64BiPolynomialIsMonicX(P: TCnInt64BiPolynomial): Boolean;
begin
  Result := False;
  if P.MaxXDegree >= 0 then
    Result := (P.YFactorsList[P.MaxXDegree].Count = 1) and (P.YFactorsList[P.MaxXDegree][0] = 1);
end;

procedure Int64BiPolynomialShiftLeftX(P: TCnInt64BiPolynomial; N: Integer);
var
  I: Integer;
begin
  if N = 0 then
    Exit
  else if N < 0 then
    Int64BiPolynomialShiftRightX(P, -N)
  else
    for I := 0 to N - 1 do
      P.FXs.Insert(0, TCnInt64List.Create);
end;

procedure Int64BiPolynomialShiftRightX(P: TCnInt64BiPolynomial; N: Integer);
var
  I: Integer;
begin
  if N = 0 then
    Exit
  else if N < 0 then
    Int64BiPolynomialShiftLeftX(P, -N)
  else
  begin
    if N > P.FXs.Count then
      N := P.FXs.Count;

    for I := 0 to N - 1 do
    begin
      P.FXs[0].Free;
      P.FXs.Delete(0);
    end;
  end;
end;

function Int64BiPolynomialEqual(A, B: TCnInt64BiPolynomial): Boolean;
var
  I, J: Integer;
begin
  Result := False;
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  if (A = nil) or (B = nil) then
    Exit;

  if A.MaxXDegree <> B.MaxXDegree then
    Exit;

  for I := A.FXs.Count - 1 downto 0 do
  begin
    if A.YFactorsList[I].Count <> B.YFactorsList[I].Count then
      Exit;

    for J := A.YFactorsList[I].Count - 1 downto 0 do
      if A.YFactorsList[I][J] <> B.YFactorsList[I][J] then
        Exit;
  end;
  Result := True;
end;

procedure Int64BiPolynomialAddWord(P: TCnInt64BiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  for I := P.FXs.Count - 1 downto 0 do
    for J := P.YFactorsList[I].Count - 1 downto 0 do
      P.YFactorsList[I][J] := P.YFactorsList[I][J] + N;
end;

procedure Int64BiPolynomialSubWord(P: TCnInt64BiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  for I := P.FXs.Count - 1 downto 0 do
    for J := P.YFactorsList[I].Count - 1 downto 0 do
      P.YFactorsList[I][J] := P.YFactorsList[I][J] - N;
end;

procedure Int64BiPolynomialMulWord(P: TCnInt64BiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    P.SetZero
  else if N <> 1 then
    for I := P.FXs.Count - 1 downto 0 do
      for J := P.YFactorsList[I].Count - 1 downto 0 do
        P.YFactorsList[I][J] := P.YFactorsList[I][J] * N;
end;

procedure Int64BiPolynomialDivWord(P: TCnInt64BiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero)
  else if N <> 1 then
    for I := P.FXs.Count - 1 downto 0 do
      for J := P.YFactorsList[I].Count - 1 downto 0 do
        P.YFactorsList[I][J] := P.YFactorsList[I][J] div N;
end;

procedure Int64BiPolynomialNonNegativeModWord(P: TCnInt64BiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero);

  for I := P.FXs.Count - 1 downto 0 do
    for J := P.YFactorsList[I].Count - 1 downto 0 do
      P.YFactorsList[I][J] := Int64NonNegativeMod(P.YFactorsList[I][J], N);
end;

function Int64BiPolynomialAdd(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial): Boolean;
var
  I, J, MaxX, MaxY: Integer;
begin
  MaxX := Max(P1.MaxXDegree, P2.MaxXDegree);
  MaxY := Max(P1.MaxYDegree, P2.MaxYDegree);
  Res.MaxXDegree := MaxX;
  Res.MaxYDegree := MaxY;

  for I := MaxX downto 0 do
  begin
    for J := MaxY downto 0 do
    begin
      Res.YFactorsList[I][J] := P1.SafeValue[I, J] + P2.SafeValue[I, J];
    end;
  end;

  Res.CorrectTop;
  Result := True;
end;

function Int64BiPolynomialSub(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial): Boolean;
var
  I, J, MaxX, MaxY: Integer;
begin
  MaxX := Max(P1.MaxXDegree, P2.MaxXDegree);
  MaxY := Max(P1.MaxYDegree, P2.MaxYDegree);
  Res.MaxXDegree := MaxX;
  Res.MaxYDegree := MaxY;

  for I := MaxX downto 0 do
  begin
    for J := MaxY downto 0 do
    begin
      Res.YFactorsList[I][J] := P1.SafeValue[I, J] - P2.SafeValue[I, J];
    end;
  end;

  Res.CorrectTop;
  Result := True;
end;

function Int64BiPolynomialMul(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial): Boolean;
var
  I, J, K, L: Integer;
  R: TCnInt64BiPolynomial;
begin
  if P1.IsZero or P2.IsZero then
  begin
    Res.SetZero;
    Result := True;
    Exit;
  end;

  if (Res = P1) or (Res = P2) then
    R := FLocalInt64BiPolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxXDegree := P1.MaxXDegree + P2.MaxXDegree;
  R.MaxYDegree := P1.MaxYDegree + P2.MaxYDegree;

  for I := P1.FXs.Count - 1 downto 0 do
  begin
    for J := P1.YFactorsList[I].Count - 1 downto 0 do
    begin
      // �õ� P1.SafeValue[I, J]��Ҫ������� P2 ��ÿһ��
      for K := P2.FXs.Count - 1 downto 0 do
      begin
        for L := P2.YFactorsList[K].Count - 1 downto 0 do
        begin
          R.SafeValue[I + K, J + L] := R.SafeValue[I + K, J + L] + P1.SafeValue[I, J] * P2.SafeValue[K, L];
        end;
      end;
    end;
  end;

  R.CorrectTop;
  if (Res = P1) or (Res = P2) then
  begin
    Int64BiPolynomialCopy(Res, R);
    FLocalInt64BiPolynomialPool.Recycle(R);
  end;
  Result := True;
end;

function Int64BiPolynomialMulX(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PX: TCnInt64Polynomial): Boolean;
var
  P: TCnInt64BiPolynomial;
begin
  P := FLocalInt64BiPolynomialPool.Obtain;
  try
    Int64BiPolynomialCopyFromX(P, PX);
    Result := Int64BiPolynomialMul(Res, P1, P);
  finally
    FLocalInt64BiPolynomialPool.Recycle(P);
  end;
end;

function Int64BiPolynomialMulY(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PY: TCnInt64Polynomial): Boolean;
var
  P: TCnInt64BiPolynomial;
begin
  P := FLocalInt64BiPolynomialPool.Obtain;
  try
    Int64BiPolynomialCopyFromY(P, PY);
    Result := Int64BiPolynomialMul(Res, P1, P);
  finally
    FLocalInt64BiPolynomialPool.Recycle(P);
  end;
end;

function Int64BiPolynomialDivX(Res: TCnInt64BiPolynomial; Remain: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Divisor: TCnInt64BiPolynomial): Boolean;
var
  SubRes: TCnInt64BiPolynomial; // ���ɵݼ���
  MulRes: TCnInt64BiPolynomial; // ���ɳ����˻�
  DivRes: TCnInt64BiPolynomial; // ������ʱ��
  I, D: Integer;
  TY: TCnInt64Polynomial;        // ������һ����ʽ��Ҫ�˵� Y ����ʽ
begin
  Result := False;
  if Int64BiPolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxXDegree > P.MaxXDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      Int64BiPolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      Int64BiPolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  if not Divisor.IsMonicX then // ֻ֧�� X ����һ����ʽ
    Exit;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;
  TY := nil;

  try
    SubRes := FLocalInt64BiPolynomialPool.Obtain;
    Int64BiPolynomialCopy(SubRes, P);

    D := P.MaxXDegree - Divisor.MaxXDegree;
    DivRes := FLocalInt64BiPolynomialPool.Obtain;
    DivRes.MaxXDegree := D;
    MulRes := FLocalInt64BiPolynomialPool.Obtain;

    TY := FLocalInt64PolynomialPool.Obtain;

    for I := 0 to D do
    begin
      if P.MaxXDegree - I > SubRes.MaxXDegree then                 // �м���������λ
        Continue;

      Int64BiPolynomialCopy(MulRes, Divisor);
      Int64BiPolynomialShiftLeftX(MulRes, D - I);                 // ���뵽 SubRes ����ߴ�

      Int64BiPolynomialExtractYByX(TY, SubRes, P.MaxXDegree - I);
      Int64BiPolynomialMulY(MulRes, MulRes, TY);                  // ��ʽ�˵���ߴ�ϵ����ͬ

      DivRes.SetYCoefficentsFromPolynomial(D - I, TY);            // �̷ŵ� DivRes λ��
      Int64BiPolynomialSub(SubRes, SubRes, MulRes);               // ���������·Ż� SubRes
    end;

    if Remain <> nil then
      Int64BiPolynomialCopy(Remain, SubRes);
    if Res <> nil then
      Int64BiPolynomialCopy(Res, DivRes);
  finally
    FLocalInt64BiPolynomialPool.Recycle(SubRes);
    FLocalInt64BiPolynomialPool.Recycle(MulRes);
    FLocalInt64BiPolynomialPool.Recycle(DivRes);
    FLocalInt64PolynomialPool.Recycle(TY);
  end;
  Result := True;
end;

function Int64BiPolynomialModX(Res: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Divisor: TCnInt64BiPolynomial): Boolean;
begin
  Result := Int64BiPolynomialDivX(nil, Res, P, Divisor);
end;

function Int64BiPolynomialPower(Res: TCnInt64BiPolynomial;
  P: TCnInt64BiPolynomial; Exponent: Int64): Boolean;
var
  T: TCnInt64BiPolynomial;
begin
  if Exponent = 0 then
  begin
    Res.SetOne;
    Result := True;
    Exit;
  end
  else if Exponent = 1 then
  begin
    if Res <> P then
      Int64BiPolynomialCopy(Res, P);
    Result := True;
    Exit;
  end
  else if Exponent < 0 then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidExponent, [Exponent]);

  T := FLocalInt64BiPolynomialPool.Obtain;
  Int64BiPolynomialCopy(T, P);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetOne;
    while Exponent > 0 do
    begin
      if (Exponent and 1) <> 0 then
        Int64BiPolynomialMul(Res, Res, T);

      Exponent := Exponent shr 1;
      if Exponent > 0 then
        Int64BiPolynomialMul(T, T, T);
    end;
    Result := True;
  finally
    FLocalInt64BiPolynomialPool.Recycle(T);
  end;
end;

function Int64BiPolynomialEvaluateByY(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; YValue: Int64): Boolean;
var
  I, J: Integer;
  Sum, TY: Int64;
  YL: TCnInt64List;
begin
  // ���ÿһ�� FXs[I] �� List������������ Y ���η�ֵ�ۼӣ���Ϊ X ��ϵ��
  Res.Clear;
  for I := 0 to P.FXs.Count - 1 do
  begin
    Sum := 0;
    TY := 1;
    YL := TCnInt64List(P.FXs[I]);

    for J := 0 to YL.Count - 1 do
    begin
      Sum := Sum + TY * YL[J];
      TY := TY * YValue;
    end;
    Res.Add(Sum);
  end;
  Result := True;
end;

function Int64BiPolynomialEvaluateByX(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; XValue: Int64): Boolean;
var
  I, J: Integer;
  Sum, TX: Int64;
begin
  // ���ÿһ�� Y ���������� FXs[I] �� List �еĸô���Ԫ�أ�����ۼӣ���Ϊ Y ��ϵ��
  Res.Clear;
  for I := 0 to P.MaxYDegree do
  begin
    Sum := 0;
    TX := 1;

    for J := 0 to P.FXs.Count - 1 do
    begin
      Sum := Sum + TX * P.SafeValue[J, I];
      TX := TX * XValue;
    end;
    Res.Add(Sum);
  end;
  Result := True;
end;

procedure Int64BiPolynomialTranspose(Dst, Src: TCnInt64BiPolynomial);
var
  I, J: Integer;
  T: TCnInt64BiPolynomial;
begin
  if Src = Dst then
    T := FLocalInt64BiPolynomialPool.Obtain
  else
    T := Dst;

  // �� Src ת������ T ��
  T.SetZero;
  T.MaxXDegree := Src.MaxYDegree;
  T.MaxYDegree := Src.MaxXDegree;

  for I := Src.FXs.Count - 1 downto 0 do
    for J := Src.YFactorsList[I].Count - 1 downto 0 do
      T.SafeValue[J, I] := Src.SafeValue[I, J];

  if Src = Dst then
  begin
    Int64BiPolynomialCopy(Dst, T);
    FLocalInt64BiPolynomialPool.Recycle(T);
  end;
end;

procedure Int64BiPolynomialExtractYByX(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; XDegree: Int64);
begin
  CheckDegree(XDegree);
  if XDegree < P.FXs.Count then
    CnInt64ListCopy(Res, TCnInt64List(P.FXs[XDegree]))
  else
    Res.SetZero;
end;

procedure Int64BiPolynomialExtractXByY(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; YDegree: Int64);
var
  I: Integer;
begin
  CheckDegree(YDegree);
  Res.Clear;
  for I := 0 to P.FXs.Count - 1 do
    Res.Add(P.SafeValue[I, YDegree]);

  Res.CorrectTop;
end;

function Int64BiPolynomialGaloisEqual(A, B: TCnInt64BiPolynomial; Prime: Int64): Boolean;
var
  I, J: Integer;
begin
  Result := False;
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  if (A = nil) or (B = nil) then
    Exit;

  if A.MaxXDegree <> B.MaxXDegree then
    Exit;

  for I := A.FXs.Count - 1 downto 0 do
  begin
    if A.YFactorsList[I].Count <> B.YFactorsList[I].Count then
      Exit;

    for J := A.YFactorsList[I].Count - 1 downto 0 do
      if (A.YFactorsList[I][J] <> B.YFactorsList[I][J]) and
        (Int64NonNegativeMod(A.YFactorsList[I][J], Prime) <> Int64NonNegativeMod(A.YFactorsList[I][J], Prime)) then
        Exit;
  end;
  Result := True;
end;

procedure Int64BiPolynomialGaloisNegate(P: TCnInt64BiPolynomial; Prime: Int64);
var
  I, J: Integer;
  YL: TCnInt64List;
begin
  for I := P.FXs.Count - 1 downto 0 do
  begin
    YL := TCnInt64List(P.FXs[I]);
    for J := YL.Count - 1 downto 0 do
      YL[J] := Int64NonNegativeMod(-YL[J], Prime);
  end;
end;

function Int64BiPolynomialGaloisAdd(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
begin
  Result := Int64BiPolynomialAdd(Res, P1, P2);
  if Result then
  begin
    Int64BiPolynomialNonNegativeModWord(Res, Prime);
    if Primitive <> nil then
      Int64BiPolynomialGaloisModX(Res, Res, Primitive, Prime);
  end;
end;

function Int64BiPolynomialGaloisSub(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
begin
  Result := Int64BiPolynomialSub(Res, P1, P2);
  if Result then
  begin
    Int64BiPolynomialNonNegativeModWord(Res, Prime);
    if Primitive <> nil then
      Int64BiPolynomialGaloisModX(Res, Res, Primitive, Prime);
  end;
end;

function Int64BiPolynomialGaloisMul(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  P2: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
var
  I, J, K, L: Integer;
  R: TCnInt64BiPolynomial;
  T: Int64;
begin
  if P1.IsZero or P2.IsZero then
  begin
    Res.SetZero;
    Result := True;
    Exit;
  end;

  if (Res = P1) or (Res = P2) then
    R := FLocalInt64BiPolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxXDegree := P1.MaxXDegree + P2.MaxXDegree;
  R.MaxYDegree := P1.MaxYDegree + P2.MaxYDegree;

  for I := P1.FXs.Count - 1 downto 0 do
  begin
    for J := P1.YFactorsList[I].Count - 1 downto 0 do
    begin
      // �õ� P1.SafeValue[I, J]��Ҫ������� P2 ��ÿһ��
      for K := P2.FXs.Count - 1 downto 0 do
      begin
        for L := P2.YFactorsList[K].Count - 1 downto 0 do
        begin
          // �������������ֱ�����
          T := Int64NonNegativeMulMod(P1.SafeValue[I, J], P2.SafeValue[K, L], Prime);
          R.SafeValue[I + K, J + L] := Int64NonNegativeMod(R.SafeValue[I + K, J + L] + Int64NonNegativeMod(T, Prime), Prime);
          // TODO: ��δ����ӷ���������
        end;
      end;
    end;
  end;

  R.CorrectTop;

  // �ٶԱ�ԭ����ʽȡģ��ע�����ﴫ��ı�ԭ����ʽ�� mod �����ĳ��������Ǳ�ԭ����ʽ����
  if Primitive <> nil then
    Int64BiPolynomialGaloisModX(R, R, Primitive, Prime);

  if (Res = P1) or (Res = P2) then
  begin
    Int64BiPolynomialCopy(Res, R);
    FLocalInt64BiPolynomialPool.Recycle(R);
  end;
  Result := True;
end;

function Int64BiPolynomialGaloisMulX(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PX: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
var
  P: TCnInt64BiPolynomial;
begin
  P := FLocalInt64BiPolynomialPool.Obtain;
  try
    Int64BiPolynomialCopyFromX(P, PX);
    Result := Int64BiPolynomialGaloisMul(Res, P1, P, Prime, Primitive);
  finally
    FLocalInt64BiPolynomialPool.Recycle(P);
  end;
end;

function Int64BiPolynomialGaloisMulY(Res: TCnInt64BiPolynomial; P1: TCnInt64BiPolynomial;
  PY: TCnInt64Polynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
var
  P: TCnInt64BiPolynomial;
begin
  P := FLocalInt64BiPolynomialPool.Obtain;
  try
    Int64BiPolynomialCopyFromY(P, PY);
    Result := Int64BiPolynomialGaloisMul(Res, P1, P, Prime, Primitive);
  finally
    FLocalInt64BiPolynomialPool.Recycle(P);
  end;
end;

function Int64BiPolynomialGaloisDivX(Res: TCnInt64BiPolynomial;
  Remain: TCnInt64BiPolynomial; P: TCnInt64BiPolynomial;
  Divisor: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
var
  SubRes: TCnInt64BiPolynomial; // ���ɵݼ���
  MulRes: TCnInt64BiPolynomial; // ���ɳ����˻�
  DivRes: TCnInt64BiPolynomial; // ������ʱ��
  I, D: Integer;
  TY: TCnInt64Polynomial;        // ������һ����ʽ��Ҫ�˵� Y ����ʽ
begin
  Result := False;
  if Int64BiPolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxXDegree > P.MaxXDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      Int64BiPolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      Int64BiPolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  if not Divisor.IsMonicX then // ֻ֧�� X ����һ����ʽ
    Exit;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;
  TY := nil;

  try
    SubRes := FLocalInt64BiPolynomialPool.Obtain;
    Int64BiPolynomialCopy(SubRes, P);

    D := P.MaxXDegree - Divisor.MaxXDegree;
    DivRes := FLocalInt64BiPolynomialPool.Obtain;
    DivRes.MaxXDegree := D;
    MulRes := FLocalInt64BiPolynomialPool.Obtain;

    TY := FLocalInt64PolynomialPool.Obtain;

    for I := 0 to D do
    begin
      if P.MaxXDegree - I > SubRes.MaxXDegree then                 // �м���������λ
        Continue;

      Int64BiPolynomialCopy(MulRes, Divisor);
      Int64BiPolynomialShiftLeftX(MulRes, D - I);                 // ���뵽 SubRes ����ߴ�

      Int64BiPolynomialExtractYByX(TY, SubRes, P.MaxXDegree - I);
      Int64BiPolynomialGaloisMulY(MulRes, MulRes, TY, Prime, Primitive);     // ��ʽ�˵���ߴ�ϵ����ͬ

      DivRes.SetYCoefficentsFromPolynomial(D - I, TY);            // �̷ŵ� DivRes λ��
      Int64BiPolynomialGaloisSub(SubRes, SubRes, MulRes, Prime, Primitive);  // ���������·Ż� SubRes
    end;

    // ������ʽ����Ҫ��ģ��ԭ����ʽ
    if Primitive <> nil then
    begin
      Int64BiPolynomialGaloisModX(SubRes, SubRes, Primitive, Prime);
      Int64BiPolynomialGaloisModX(DivRes, DivRes, Primitive, Prime);
    end;

    if Remain <> nil then
      Int64BiPolynomialCopy(Remain, SubRes);
    if Res <> nil then
      Int64BiPolynomialCopy(Res, DivRes);
  finally
    FLocalInt64BiPolynomialPool.Recycle(SubRes);
    FLocalInt64BiPolynomialPool.Recycle(MulRes);
    FLocalInt64BiPolynomialPool.Recycle(DivRes);
    FLocalInt64PolynomialPool.Recycle(TY);
  end;
  Result := True;
end;

function Int64BiPolynomialGaloisModX(Res: TCnInt64BiPolynomial; P: TCnInt64BiPolynomial;
  Divisor: TCnInt64BiPolynomial; Prime: Int64; Primitive: TCnInt64BiPolynomial): Boolean;
begin
  Result := Int64BiPolynomialGaloisDivX(nil, Res, P, Divisor, Prime, Primitive);
end;

function Int64BiPolynomialGaloisPower(Res, P: TCnInt64BiPolynomial;
  Exponent: Int64; Prime: Int64; Primitive: TCnInt64BiPolynomial;
  ExponentHi: Int64): Boolean;
var
  T: TCnInt64BiPolynomial;
begin
  if Exponent128IsZero(Exponent, ExponentHi) then
  begin
    Res.SetOne;
    Result := True;
    Exit;
  end
  else if Exponent128IsOne(Exponent, ExponentHi) then
  begin
    if Res <> P then
      Int64BiPolynomialCopy(Res, P);
    Result := True;
    Exit;
  end;

  T := FLocalInt64BiPolynomialPool.Obtain;
  Int64BiPolynomialCopy(T, P);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetOne;
    while not Exponent128IsZero(Exponent, ExponentHi) do
    begin
      if (Exponent and 1) <> 0 then
        Int64BiPolynomialGaloisMul(Res, Res, T, Prime, Primitive);

      ExponentShiftRightOne(Exponent, ExponentHi);
      if not Exponent128IsZero(Exponent, ExponentHi) then
        Int64BiPolynomialGaloisMul(T, T, T, Prime, Primitive);
    end;
    Result := True;
  finally
    FLocalInt64BiPolynomialPool.Recycle(T);
  end;
end;

function Int64BiPolynomialGaloisEvaluateByY(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; YValue, Prime: Int64): Boolean;
var
  I, J: Integer;
  Sum, TY: Int64;
  YL: TCnInt64List;
begin
  // ���ÿһ�� FXs[I] �� List������������ Y ���η�ֵ�ۼӣ���Ϊ X ��ϵ��
  Res.Clear;
  for I := 0 to P.FXs.Count - 1 do
  begin
    Sum := 0;
    TY := 1;
    YL := TCnInt64List(P.FXs[I]);

    for J := 0 to YL.Count - 1 do
    begin
      // TODO: �ݲ����������������
      Sum := Int64NonNegativeMod(Sum + Int64NonNegativeMulMod(TY, YL[J], Prime), Prime);
      TY := Int64NonNegativeMulMod(TY, YValue, Prime);
    end;
    Res.Add(Sum);
  end;
  Result := True;
end;

function Int64BiPolynomialGaloisEvaluateByX(Res: TCnInt64Polynomial;
  P: TCnInt64BiPolynomial; XValue, Prime: Int64): Boolean;
var
  I, J: Integer;
  Sum, TX: Int64;
begin
  // ���ÿһ�� Y ���������� FXs[I] �� List �еĸô���Ԫ�أ�����ۼӣ���Ϊ Y ��ϵ��
  Res.Clear;
  for I := 0 to P.MaxYDegree do
  begin
    Sum := 0;
    TX := 1;

    for J := 0 to P.FXs.Count - 1 do
    begin
      // TODO: �ݲ����������������
      Sum := Int64NonNegativeMod(Sum + Int64NonNegativeMulMod(TX, P.SafeValue[J, I], Prime), Prime);
      TX := Int64NonNegativeMulMod(TX, XValue, Prime);
    end;
    Res.Add(Sum);
  end;
  Result := True;
end;

procedure Int64BiPolynomialGaloisAddWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
var
  I, J: Integer;
begin
  for I := P.FXs.Count - 1 downto 0 do
    for J := P.YFactorsList[I].Count - 1 downto 0 do
      P.YFactorsList[I][J] := Int64NonNegativeMod(P.YFactorsList[I][J] + N, Prime);
end;

procedure Int64BiPolynomialGaloisSubWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
var
  I, J: Integer;
begin
  for I := P.FXs.Count - 1 downto 0 do
    for J := P.YFactorsList[I].Count - 1 downto 0 do
      P.YFactorsList[I][J] := Int64NonNegativeMod(P.YFactorsList[I][J] - N, Prime);
end;

procedure Int64BiPolynomialGaloisMulWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    P.SetZero
  else // �� Prime ��Ҫ Mod�����ж��Ƿ��� 1 ��
    for I := P.FXs.Count - 1 downto 0 do
      for J := P.YFactorsList[I].Count - 1 downto 0 do
        P.YFactorsList[I][J] := Int64NonNegativeMulMod(P.YFactorsList[I][J], N, Prime);
end;

procedure Int64BiPolynomialGaloisDivWord(P: TCnInt64BiPolynomial; N: Int64; Prime: Int64);
var
  I, J: Integer;
  K: Int64;
  B: Boolean;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero);

  B := N < 0;
  if B then
    N := -N;

  K := CnInt64ModularInverse2(N, Prime);
  for I := P.FXs.Count - 1 downto 0 do
  begin
    for J := P.YFactorsList[I].Count - 1 downto 0 do
    begin
      P.YFactorsList[I][J] := Int64NonNegativeMulMod(P.YFactorsList[I][J], K, Prime);
      if B then
        P.YFactorsList[I][J] := Prime - P.YFactorsList[I][J];
    end;
  end;
end;

procedure TCnInt64BiPolynomial.SetXCoefficents(YDegree: Integer;
  LowToHighXCoefficients: array of const);
var
  I: Integer;
begin
  CheckDegree(YDegree);

  MaxXDegree := High(LowToHighXCoefficients);

  if YDegree > MaxYDegree then
    MaxYDegree := YDegree;

  for I := Low(LowToHighXCoefficients) to High(LowToHighXCoefficients) do
    SafeValue[I, YDegree] := ExtractInt64FromArrayConstElement(LowToHighXCoefficients[I]);
end;

procedure TCnInt64BiPolynomial.SetYCoefficents(XDegree: Integer;
  LowToHighYCoefficients: array of const);
var
  I: Integer;
begin
  CheckDegree(XDegree);

  if XDegree > MaxXDegree then
    MaxXDegree := XDegree;

  YFactorsList[XDegree].Clear;
  for I := Low(LowToHighYCoefficients) to High(LowToHighYCoefficients) do
    YFactorsList[XDegree].Add(ExtractInt64FromArrayConstElement(LowToHighYCoefficients[I]));
end;

procedure TCnInt64BiPolynomial.SetXYCoefficent(XDegree, YDegree: Integer;
  ACoefficient: Int64);
begin
  CheckDegree(XDegree);
  CheckDegree(YDegree);

  if MaxXDegree < XDegree then
    MaxXDegree := XDegree;

  if YFactorsList[XDegree].Count - 1 < YDegree then
    YFactorsList[XDegree].Count := YDegree + 1;

  YFactorsList[XDegree][YDegree] := ACoefficient;
end;

function TCnInt64BiPolynomial.GetSafeValue(XDegree, YDegree: Integer): Int64;
var
  YL: TCnInt64List;
begin
  Result := 0;
  if (XDegree >= 0) and (XDegree < FXs.Count) then
  begin
    YL := TCnInt64List(FXs[XDegree]);
    if (YDegree >= 0) and (YDegree < YL.Count) then
      Result := YL[YDegree];
  end;
end;

procedure TCnInt64BiPolynomial.SetSafeValue(XDegree, YDegree: Integer;
  const Value: Int64);
begin
  SetXYCoefficent(XDegree, YDegree, Value);
end;

procedure TCnInt64BiPolynomial.SetOne;
begin
  Int64BiPolynomialSetOne(Self);
end;

procedure TCnInt64BiPolynomial.Transpose;
begin
  Int64BiPolynomialTranspose(Self, Self);
end;

function TCnInt64BiPolynomial.IsMonicX: Boolean;
begin
  Result := Int64BiPolynomialIsMonicX(Self);
end;

procedure TCnInt64BiPolynomial.SetYCoefficentsFromPolynomial(
  XDegree: Integer; PY: TCnInt64Polynomial);
var
  I: Integer;
begin
  CheckDegree(XDegree);

  if XDegree > MaxXDegree then   // ȷ�� X ����� List ����
    MaxXDegree := XDegree;

  YFactorsList[XDegree].Clear;
  for I := 0 to PY.MaxDegree do
    YFactorsList[XDegree].Add(PY[I]); // ���ض��� YList ������Ԫ����ֵ
end;

procedure TCnInt64BiPolynomial.Clear;
var
  I: Integer;
begin
  if FXs.Count <= 0 then
    FXs.Add(TCnInt64List.Create)
  else
    for I := FXs.Count - 1 downto 1 do
    begin
      FXs[I].Free;
      FXs.Delete(I);
    end;

  YFactorsList[0].Clear;
end;

{ TCnInt64BiPolynomialPool }

function TCnInt64BiPolynomialPool.CreateObject: TObject;
begin
  Result := TCnInt64BiPolynomial.Create;
end;

function TCnInt64BiPolynomialPool.Obtain: TCnInt64BiPolynomial;
begin
  Result := TCnInt64BiPolynomial(inherited Obtain);
  Result.SetZero;
end;

procedure TCnInt64BiPolynomialPool.Recycle(Poly: TCnInt64BiPolynomial);
begin
  inherited Recycle(Poly);
end;

// ========================== ��Ԫ����ϵ������ʽ ===============================

function BigNumberBiPolynomialNew: TCnBigNumberBiPolynomial;
begin
  Result := TCnBigNumberBiPolynomial.Create;
end;

procedure BigNumberBiPolynomialFree(P: TCnBigNumberBiPolynomial);
begin
  P.Free;
end;

function BigNumberBiPolynomialDuplicate(P: TCnBigNumberBiPolynomial): TCnBigNumberBiPolynomial;
begin
  if P = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := BigNumberBiPolynomialNew;
  if Result <> nil then
    BigNumberBiPolynomialCopy(Result, P);
end;

function BigNumberBiPolynomialCopy(Dst: TCnBigNumberBiPolynomial;
  Src: TCnBigNumberBiPolynomial): TCnBigNumberBiPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  if Src <> Dst then
  begin
    if Src.MaxXDegree >= 0 then
    begin
      Dst.MaxXDegree := Src.MaxXDegree;
      for I := 0 to Src.MaxXDegree do
      begin
        if Src.FXs[I] = nil then
        begin
          Dst.FXs[I].Free;
          Dst.FXs[I] := nil;
        end
        else
          Src.YFactorsList[I].AssignTo(Dst.YFactorsList[I]);
      end;
    end
    else
      Dst.SetZero; // ��� Src δ��ʼ������ Dst Ҳ����
  end;
end;

function BigNumberBiPolynomialCopyFromX(Dst: TCnBigNumberBiPolynomial;
  SrcX: TCnBigNumberPolynomial): TCnBigNumberBiPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  Dst.Clear;

  Dst.MaxXDegree := SrcX.MaxDegree;
  for I := 0 to SrcX.MaxDegree do
    if SrcX[I].IsZero then
    begin
      Dst.FXs[I].Free;
      Dst.FXs[I] := nil;
    end
    else
      Dst.SafeValue[I, 0] := SrcX[I]; // ��ÿһ�� YList ����Ԫ����ֵ��0 ����� FXs ��Ӧ��
end;

function BigNumberBiPolynomialCopyFromY(Dst: TCnBigNumberBiPolynomial;
  SrcY: TCnBigNumberPolynomial): TCnBigNumberBiPolynomial;
var
  I: Integer;
begin
  Result := Dst;
  Dst.Clear;

  if not SrcY.IsZero then
    for I := 0 to SrcY.MaxDegree do
      Dst.YFactorsList[0].AddPair(I, SrcY[I]); // �����һ�� YList ������Ԫ����ֵ
end;

function BigNumberBiPolynomialToString(P: TCnBigNumberBiPolynomial;
  const Var1Name: string; const Var2Name: string): string;
var
  I, J: Integer;
  YL: TCnSparseBigNumberList;
begin
  Result := '';
  for I := P.FXs.Count - 1 downto 0 do
  begin
    YL := TCnSparseBigNumberList(P.FXs[I]);  // ֻ������ڵ���������� 0 ��
    if YL <> nil then
      for J := YL.Count - 1 downto 0 do
      begin
        if VarItemFactor(Result, (YL[J].Exponent = 0) and (I = 0), YL[J].Value.ToDec) then
          Result := Result + VarPower2(Var1Name, Var2Name, I, YL[J].Exponent);
      end;
  end;

  if Result = '' then
    Result := '0';
end;

{$WARNINGS OFF}

function BigNumberBiPolynomialSetString(P: TCnBigNumberBiPolynomial;
  const Str: string; const Var1Name: string; const Var2Name: string): Boolean;
var
  C, Ptr: PChar;
  Num, ES: string;
  E1, E2: Integer;
  IsNeg: Boolean;
begin
  // ��Ԫ����ʽ�ַ��������е���
  Result := False;
  if (P = nil) or (Str = '') then
    Exit;

  P.SetZero;
  C := @Str[1];

  while C^ <> #0 do
  begin
    if not (C^ in ['+', '-', '0'..'9']) and (C^ <> Var1Name) and (C^ <> Var2Name) then
    begin
      Inc(C);
      Continue;
    end;

    IsNeg := False;
    if C^ = '+' then
      Inc(C)
    else if C^ = '-' then
    begin
      IsNeg := True;
      Inc(C);
    end;

    Num := '1';
    if C^ in ['0'..'9'] then // ��ϵ��
    begin
      Ptr := C;
      while C^ in ['0'..'9'] do
        Inc(C);

      // Ptr �� C ֮�������֣�����һ��ϵ��
      SetString(Num, Ptr, C - Ptr);
      if IsNeg then
        Num := '-' + Num;
    end
    else if IsNeg then
      Num := '-' + Num;

    E1 := 0;
    if C^ = Var1Name then
    begin
      E1 := 1;
      Inc(C);
      if C^ = '^' then // ��ָ��
      begin
        Inc(C);
        if C^ in ['0'..'9'] then
        begin
          Ptr := C;
          while C^ in ['0'..'9'] do
            Inc(C);

          // Ptr �� C ֮�������֣�����һ��ָ��
          SetString(ES, Ptr, C - Ptr);
          E1 := StrToInt64(ES);
        end;
      end;
    end;

    E2 := 0;
    if C^ = Var2Name then
    begin
      E2 := 1;
      Inc(C);
      if C^ = '^' then // ��ָ��
      begin
        Inc(C);
        if C^ in ['0'..'9'] then
        begin
          Ptr := C;
          while C^ in ['0'..'9'] do
            Inc(C);

          // Ptr �� C ֮�������֣�����һ��ָ��
          SetString(ES, Ptr, C - Ptr);
          E2 := StrToInt64(ES);
        end;
      end;
    end;

    // ��ָ�������ˣ���
    P.SafeValue[E1, E2].SetDec(AnsiString(Num));
  end;

  Result := True;
end;

{$WARNINGS ON}

function BigNumberBiPolynomialIsZero(P: TCnBigNumberBiPolynomial): Boolean;
begin
  Result := True;
  if P.FXs.Count = 0 then
    Exit;

  if (P.FXs.Count = 1) and ((P.FXs[0] = nil) or (TCnSparseBigNumberList(P.FXs[0]).Count = 0)) then
    Exit;

  if (P.FXs.Count = 1) and (P.FXs[0] <> nil) and (TCnSparseBigNumberList(P.FXs[0]).Count = 1)
    and (TCnSparseBigNumberList(P.FXs[0])[0].Exponent = 0) and TCnSparseBigNumberList(P.FXs[0])[0].Value.IsZero then
    Exit;

  Result := False;
end;

procedure BigNumberBiPolynomialSetZero(P: TCnBigNumberBiPolynomial);
begin
  P.FXs.Clear;
end;

procedure BigNumberBiPolynomialSetOne(P: TCnBigNumberBiPolynomial);
var
  I: Integer;
begin
  if P.FXs.Count <= 0 then
    P.FXs.Add(TCnSparseBigNumberList.Create)
  else
    for I := P.FXs.Count - 1 downto 1 do
    begin
      P.FXs[I].Free;
      P.FXs.Delete(I);
    end;

  if P.YFactorsList[0].Count <= 0 then
    P.YFactorsList[0].Add(TCnExponentBigNumberPair.Create)
  else
  begin
    for I := P.YFactorsList[0].Count - 1 downto 1 do
      P.YFactorsList[0].Delete(I);
  end;

  P.YFactorsList[0][0].Exponent := 0;
  P.YFactorsList[0][0].Value.SetOne;
end;

procedure BigNumberBiPolynomialNegate(P: TCnBigNumberBiPolynomial);
var
  I, J: Integer;
  YL: TCnSparseBigNumberList;
begin
  for I := P.FXs.Count - 1 downto 0 do
  begin
    YL := TCnSparseBigNumberList(P.FXs[I]); // �粻���ڣ����贴��
    if YL <> nil then
      for J := YL.Count - 1 downto 0 do
        YL[I].Value.Negate;
  end;
end;

function BigNumberBiPolynomialIsMonicX(P: TCnBigNumberBiPolynomial): Boolean;
begin
  Result := False;
  if P.MaxXDegree >= 0 then
    Result := (P.YFactorsList[P.MaxXDegree].Count = 1) and (P.YFactorsList[P.MaxXDegree][0].Exponent = 0)
      and (P.YFactorsList[P.MaxXDegree][0].Value.IsOne);
end;

procedure BigNumberBiPolynomialShiftLeftX(P: TCnBigNumberBiPolynomial; N: Integer);
var
  I: Integer;
begin
  if N = 0 then
    Exit
  else if N < 0 then
    BigNumberBiPolynomialShiftRightX(P, -N)
  else
    for I := 0 to N - 1 do
      P.FXs.InsertBatch(0, N);
end;

procedure BigNumberBiPolynomialShiftRightX(P: TCnBigNumberBiPolynomial; N: Integer);
var
  I: Integer;
begin
  if N = 0 then
    Exit
  else if N < 0 then
    BigNumberBiPolynomialShiftLeftX(P, -N)
  else
  begin
    if N > P.FXs.Count then
      N := P.FXs.Count;

    for I := N - 1 downto 0 do
      P.FXs[I].Free;

    P.FXs.DeleteLow(N);
  end;
end;

function BigNumberBiPolynomialEqual(A, B: TCnBigNumberBiPolynomial): Boolean;
var
  I: Integer;
begin
  Result := False;
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  if (A = nil) or (B = nil) then
    Exit;

  if A.MaxXDegree <> B.MaxXDegree then
    Exit;

  for I := A.FXs.Count - 1 downto 0 do
  begin
    if not SparseBigNumberListEqual(TCnSparseBigNumberList(A.FXs[I]), TCnSparseBigNumberList(B.FXs[I])) then
      Exit;

//    if (A.FXs[I] = nil) and (B.FXs[I] = nil) then
//      Continue;
//
//    if A.YFactorsList[I].Count <> B.YFactorsList[I].Count then
//      Exit;
//
//    for J := A.YFactorsList[I].Count - 1 downto 0 do
//      if (A.YFactorsList[I][J].Exponent <> B.YFactorsList[I][J].Exponent) or
//        not BigNumberEqual(A.YFactorsList[I][J].Value, B.YFactorsList[I][J].Value) then
//        Exit;
  end;
  Result := True;
end;

// ===================== ��Ԫ����ϵ������ʽ��ͨ���� ============================

procedure BigNumberBiPolynomialMulWord(P: TCnBigNumberBiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    P.SetZero
  else if N <> 1 then
    for I := P.FXs.Count - 1 downto 0 do
      if P.FXs[I] <> nil then
        for J := P.YFactorsList[I].Count - 1 downto 0 do
          P.YFactorsList[I][J].Value.MulWord(N);
end;

procedure BigNumberBiPolynomialDivWord(P: TCnBigNumberBiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero)
  else if N <> 1 then
    for I := P.FXs.Count - 1 downto 0 do
      if P.FXs[I] <> nil then
        for J := P.YFactorsList[I].Count - 1 downto 0 do
          P.YFactorsList[I][J].Value.DivWord(N);
end;

procedure BigNumberBiPolynomialNonNegativeModWord(P: TCnBigNumberBiPolynomial; N: Int64);
var
  I, J: Integer;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero);

  for I := P.FXs.Count - 1 downto 0 do
    if P.FXs[I] <> nil then
      for J := P.YFactorsList[I].Count - 1 downto 0 do
        P.YFactorsList[I][J].Value.ModWord(N); // ���� NonNegativeMod ������
end;

procedure BigNumberBiPolynomialMulBigNumber(P: TCnBigNumberBiPolynomial; N: TCnBigNumber);
var
  I, J: Integer;
begin
  if N.IsZero then
    P.SetZero
  else if not N.IsOne then
    for I := P.FXs.Count - 1 downto 0 do
      if P.FXs[I] <> nil then
        for J := P.YFactorsList[I].Count - 1 downto 0 do
          BigNumberMul(P.YFactorsList[I][J].Value, P.YFactorsList[I][J].Value, N);
end;

procedure BigNumberBiPolynomialDivBigNumber(P: TCnBigNumberBiPolynomial; N: TCnBigNumber);
var
  I, J: Integer;
begin
  if N.IsZero then
    raise EDivByZero.Create(SDivByZero)
  else if not N.IsOne then
    for I := P.FXs.Count - 1 downto 0 do
      if P.FXs[I] <> nil then
        for J := P.YFactorsList[I].Count - 1 downto 0 do
          BigNumberDiv(P.YFactorsList[I][J].Value, nil, P.YFactorsList[I][J].Value, N);
end;

procedure BigNumberBiPolynomialNonNegativeModBigNumber(P: TCnBigNumberBiPolynomial; N: TCnBigNumber);
var
  I, J: Integer;
begin
  if N.IsZero then
    raise EDivByZero.Create(SDivByZero);

  for I := P.FXs.Count - 1 downto 0 do
    if P.FXs[I] <> nil then
      for J := P.YFactorsList[I].Count - 1 downto 0 do
        BigNumberNonNegativeMod(P.YFactorsList[I][J].Value, P.YFactorsList[I][J].Value, N);
end;

function BigNumberBiPolynomialAdd(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial): Boolean;
var
  I, M: Integer;
  S1, S2: TCnSparseBigNumberList;
begin
  M := Max(P1.MaxXDegree, P2.MaxXDegree);
  Res.SetMaxXDegree(M);

  for I := M downto 0 do
  begin
    if I >= P1.FXs.Count then
      S1 := nil
    else
      S1 := TCnSparseBigNumberList(P1.FXs[I]);

    if I >= P2.FXs.Count then
      S2 := nil
    else
      S2 := TCnSparseBigNumberList(P2.FXs[I]);

    if (S1 = nil) and (S2 = nil) then
    begin
      Res.FXs[I].Free;
      Res.FXs[I] := nil;
    end
    else
      SparseBigNumberListMerge(Res.YFactorsList[I], S1, S2, True); // ��ѭ��ȷ������ÿһ�� Res.YFactorsList[I]
  end;
  Res.CorrectTop;
  Result := True;
end;

function BigNumberBiPolynomialSub(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial): Boolean;
var
  I, M: Integer;
  S1, S2: TCnSparseBigNumberList;
begin
  M := Max(P1.MaxXDegree, P2.MaxXDegree);
  Res.SetMaxXDegree(M);

  for I := M downto 0 do
  begin
    if I >= P1.FXs.Count then
      S1 := nil
    else
      S1 := TCnSparseBigNumberList(P1.FXs[I]);

    if I >= P2.FXs.Count then
      S2 := nil
    else
      S2 := TCnSparseBigNumberList(P2.FXs[I]);

    if (S1 = nil) and (S2 = nil) then
    begin
      Res.FXs[I].Free;
      Res.FXs[I] := nil;
    end
    else
      SparseBigNumberListMerge(Res.YFactorsList[I], S1, S2, False);
  end;
  Res.CorrectTop;
  Result := True;
end;

function BigNumberBiPolynomialMul(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial): Boolean;
var
  I, J, K, L: Integer;
  R: TCnBigNumberBiPolynomial;
  T: TCnBigNumber;
  Pair1, Pair2: TCnExponentBigNumberPair;
begin
  if P1.IsZero or P2.IsZero then
  begin
    Res.SetZero;
    Result := True;
    Exit;
  end;

  if (Res = P1) or (Res = P2) then
    R := FLocalBigNumberBiPolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxXDegree := P1.MaxXDegree + P2.MaxXDegree;
  R.MaxYDegree := P1.MaxYDegree + P2.MaxYDegree;

  T := FLocalBigNumberPool.Obtain;
  try
    for I := P1.FXs.Count - 1 downto 0 do
    begin
      if P1.FXs[I] = nil then
        Continue;

      for J := P1.YFactorsList[I].Count - 1 downto 0 do
      begin
        Pair1 := P1.YFactorsList[I][J];
        // �õ� P1.SafeValue[I, J]��Ҫ������� P2 ��ÿһ��
        for K := P2.FXs.Count - 1 downto 0 do
        begin
          if P2.FXs[K] = nil then
            Continue;

          for L := P2.YFactorsList[K].Count - 1 downto 0 do
          begin
            Pair2 := P2.YFactorsList[K][L];
            BigNumberMul(T, Pair1.Value, Pair2.Value);
            BigNumberAdd(R.SafeValue[I + K, Pair1.Exponent + Pair2.Exponent],
              R.SafeValue[I + K, Pair1.Exponent + Pair2.Exponent], T);
          end;
        end;
      end;
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
  end;

  R.CorrectTop;
  if (Res = P1) or (Res = P2) then
  begin
    BigNumberBiPolynomialCopy(Res, R);
    FLocalBigNumberBiPolynomialPool.Recycle(R);
  end;
  Result := True;
end;

function BigNumberBiPolynomialMulX(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PX: TCnBigNumberPolynomial): Boolean;
var
  P: TCnBigNumberBiPolynomial;
begin
  P := FLocalBigNumberBiPolynomialPool.Obtain;
  try
    BigNumberBiPolynomialCopyFromX(P, PX);
    Result := BigNumberBiPolynomialMul(Res, P1, P);
  finally
    FLocalBigNumberBiPolynomialPool.Recycle(P);
  end;
end;

function BigNumberBiPolynomialMulY(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PY: TCnBigNumberPolynomial): Boolean;
var
  P: TCnBigNumberBiPolynomial;
begin
  P := FLocalBigNumberBiPolynomialPool.Obtain;
  try
    BigNumberBiPolynomialCopyFromY(P, PY);
    Result := BigNumberBiPolynomialMul(Res, P1, P);
  finally
    FLocalBigNumberBiPolynomialPool.Recycle(P);
  end;
end;

function BigNumberBiPolynomialDivX(Res: TCnBigNumberBiPolynomial;
  Remain: TCnBigNumberBiPolynomial; P: TCnBigNumberBiPolynomial;
  Divisor: TCnBigNumberBiPolynomial): Boolean;
var
  SubRes: TCnBigNumberBiPolynomial; // ���ɵݼ���
  MulRes: TCnBigNumberBiPolynomial; // ���ɳ����˻�
  DivRes: TCnBigNumberBiPolynomial; // ������ʱ��
  I, D: Integer;
  TY: TCnBigNumberPolynomial;       // ������һ����ʽ��Ҫ�˵� Y ����ʽ
begin
  Result := False;
  if BigNumberBiPolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxXDegree > P.MaxXDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      BigNumberBiPolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      BigNumberBiPolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  if not Divisor.IsMonicX then // ֻ֧�� X ����һ����ʽ
    Exit;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;
  TY := nil;

  try
    SubRes := FLocalBigNumberBiPolynomialPool.Obtain;
    BigNumberBiPolynomialCopy(SubRes, P);

    D := P.MaxXDegree - Divisor.MaxXDegree;
    DivRes := FLocalBigNumberBiPolynomialPool.Obtain;
    DivRes.MaxXDegree := D;
    MulRes := FLocalBigNumberBiPolynomialPool.Obtain;

    TY := FLocalBigNumberPolynomialPool.Obtain;

    for I := 0 to D do
    begin
      if P.MaxXDegree - I > SubRes.MaxXDegree then                 // �м���������λ
        Continue;

      BigNumberBiPolynomialCopy(MulRes, Divisor);
      BigNumberBiPolynomialShiftLeftX(MulRes, D - I);              // ���뵽 SubRes ����ߴ�

      BigNumberBiPolynomialExtractYByX(TY, SubRes, P.MaxXDegree - I);
      BigNumberBiPolynomialMulY(MulRes, MulRes, TY);               // ��ʽ�˵���ߴ�ϵ����ͬ

      DivRes.SetYCoefficentsFromPolynomial(D - I, TY);             // �̷ŵ� DivRes λ��
      BigNumberBiPolynomialSub(SubRes, SubRes, MulRes);            // ���������·Ż� SubRes
    end;

    if Remain <> nil then
      BigNumberBiPolynomialCopy(Remain, SubRes);
    if Res <> nil then
      BigNumberBiPolynomialCopy(Res, DivRes);
  finally
    FLocalBigNumberBiPolynomialPool.Recycle(SubRes);
    FLocalBigNumberBiPolynomialPool.Recycle(MulRes);
    FLocalBigNumberBiPolynomialPool.Recycle(DivRes);
    FLocalBigNumberPolynomialPool.Recycle(TY);
  end;
  Result := True;
end;

function BigNumberBiPolynomialModX(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Divisor: TCnBigNumberBiPolynomial): Boolean;
begin
  Result := BigNumberBiPolynomialDivX(nil, Res, P, Divisor);
end;

function BigNumberBiPolynomialPower(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Exponent: TCnBigNumber): Boolean;
var
  T: TCnBigNumberBiPolynomial;
  E: TCnBigNumber;
begin
  if Exponent.IsZero then
  begin
    Res.SetOne;
    Result := True;
    Exit;
  end
  else if Exponent.IsOne then
  begin
    if Res <> P then
      BigNumberBiPolynomialCopy(Res, P);
    Result := True;
    Exit;
  end
  else if Exponent.IsNegative then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidExponent, [Exponent.ToDec]);

  T := FLocalBigNumberBiPolynomialPool.Obtain;
  BigNumberBiPolynomialCopy(T, P);
  E := FLocalBigNumberPool.Obtain;
  BigNumberCopy(E, Exponent);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetOne;
    while not E.IsZero do
    begin
      if BigNumberIsBitSet(E, 0) then
        BigNumberBiPolynomialMul(Res, Res, T);

      BigNumberShiftRightOne(E, E);
      if not E.IsZero then // ���һ�β��ó���
        BigNumberBiPolynomialMul(T, T, T);
    end;
    Result := True;
  finally
    FLocalBigNumberPool.Recycle(E);
    FLocalBigNumberBiPolynomialPool.Recycle(T);
  end;
end;

function BigNumberBiPolynomialEvaluateByY(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; YValue: TCnBigNumber): Boolean;
var
  I, J: Integer;
  Sum, TY, T: TCnBigNumber;
  YL: TCnSparseBigNumberList;
  Pair: TCnExponentBigNumberPair;
begin
  // ���ÿһ�� FXs[I] �� List������������ Y ���η�ֵ�ۼӣ���Ϊ X ��ϵ��
  Res.Clear;
  Sum := nil;
  TY := nil;
  T := nil;

  try
    Sum := FLocalBigNumberPool.Obtain;
    TY := FLocalBigNumberPool.Obtain;
    T := FLocalBigNumberPool.Obtain;

    for I := 0 to P.FXs.Count - 1 do
    begin
      if P.FXs[I] = nil then
        Continue;

      Sum.SetZero;
      YL := P.YFactorsList[I];

      if YL.Count > 0 then
      begin
        if YL.Bottom.Exponent = 0 then
          TY.SetOne
        else
          BigNumberPower(TY, YValue, YL.Bottom.Exponent);

        for J := 0 to YL.Count - 1 do
        begin
          Pair := YL[J];

          // Sum := Sum + TY * YL[J];
          BigNumberMul(T, TY, Pair.Value);
          BigNumberAdd(Sum, Sum, T);

          // TY := TY * Power(YValue, YL[J+1].Exponent - YL[J].Exponent);
          if J < YL.Count - 1 then
          begin
            BigNumberPower(T, YValue, YL[J + 1].Exponent - YL[J].Exponent);
            BigNumberMul(TY, TY, T);
          end;
        end;
      end;
      BigNumberCopy(Res.Add, Sum);
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(TY);
    FLocalBigNumberPool.Recycle(Sum);
  end;
  Result := True;
end;

function BigNumberBiPolynomialEvaluateByX(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; XValue: TCnBigNumber): Boolean;
var
  I, J: Integer;
  Sum, TX, T: TCnBigNumber;
begin
  // ���ÿһ�� Y ���������� FXs[I] �� List �еĸô���Ԫ�أ�����ۼӣ���Ϊ Y ��ϵ��
  Res.Clear;
  Sum := nil;
  TX := nil;
  T := nil;

  try
    Sum := FLocalBigNumberPool.Obtain;
    TX := FLocalBigNumberPool.Obtain;
    T := FLocalBigNumberPool.Obtain;

    for I := 0 to P.MaxYDegree do
    begin
      Sum.SetZero;
      TX.SetOne;

      for J := 0 to P.FXs.Count - 1 do
      begin
        //Sum := Sum + TX * P.SafeValue[J, I];
        BigNumberMul(T, TX, P.ReadonlyValue[J, I]);
        BigNumberAdd(Sum, Sum, T);

        //TX := TX * XValue;
        BigNumberMul(TX, TX, XValue);
      end;
      BigNumberCopy(Res.Add, Sum);
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(TX);
    FLocalBigNumberPool.Recycle(Sum);
  end;
  Result := True;
end;

procedure BigNumberBiPolynomialTranspose(Dst, Src: TCnBigNumberBiPolynomial);
var
  I, J: Integer;
  T: TCnBigNumberBiPolynomial;
  Pair: TCnExponentBigNumberPair;
begin
  if Src = Dst then
    T := FLocalBigNumberBiPolynomialPool.Obtain
  else
    T := Dst;

  // �� Src ת������ T ��
  T.SetZero;
  T.MaxXDegree := Src.MaxYDegree;
  T.MaxYDegree := Src.MaxXDegree;

  for I := Src.FXs.Count - 1 downto 0 do
  begin
    if Src.FXs[I] <> nil then
      for J := Src.YFactorsList[I].Count - 1 downto 0 do
      begin
        Pair := Src.YFactorsList[I][J];
        T.SafeValue[Pair.Exponent, I] := Pair.Value; // �ڲ�����
      end;
  end;

  if Src = Dst then
  begin
    BigNumberBiPolynomialCopy(Dst, T);
    FLocalBigNumberBiPolynomialPool.Recycle(T);
  end;
end;

procedure BigNumberBiPolynomialExtractYByX(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; XDegree: Integer);
var
  I: Integer;
  Pair: TCnExponentBigNumberPair;
begin
  CheckDegree(XDegree);
  Res.SetZero;

  if XDegree < P.FXs.Count then
  begin
    if P.FXs[XDegree] <> nil then
    begin
      Pair := P.YFactorsList[XDegree].Top;
      Res.MaxDegree := Pair.Exponent;

      for I := 0 to P.YFactorsList[XDegree].Count - 1 do
      begin
        Pair := P.YFactorsList[XDegree][I];
        if Res[Pair.Exponent] = nil then
          Res[Pair.Exponent] := TCnBigNumber.Create;

        BigNumberCopy(Res[Pair.Exponent], Pair.Value);
      end;
    end;
  end;
end;

procedure BigNumberBiPolynomialExtractXByY(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; YDegree: Integer);
var
  I: Integer;
begin
  CheckDegree(YDegree);
  Res.Clear;
  for I := 0 to P.FXs.Count - 1 do
    BigNumberCopy(Res.Add, P.ReadonlyValue[I, YDegree]);

  Res.CorrectTop;
end;

// ================== ��Ԫ����ϵ������ʽʽ���������ϵ�ģ���� ===================

function BigNumberBiPolynomialGaloisEqual(A, B: TCnBigNumberBiPolynomial; Prime: TCnBigNumber): Boolean;
var
  I, J: Integer;
  T1, T2: TCnBigNumber;
begin
  Result := False;
  if A = B then
  begin
    Result := True;
    Exit;
  end;

  if (A = nil) or (B = nil) then
    Exit;

  if A.MaxXDegree <> B.MaxXDegree then
    Exit;

  T1 := nil;
  T2 := nil;

  try
    T1 := FLocalBigNumberPool.Obtain;
    T2 := FLocalBigNumberPool.Obtain;

    for I := A.FXs.Count - 1 downto 0 do
    begin
      // TODO: δ���� A[I] �� B[I] һ���� nil����һ������ mod ������� 0 ������
      if (A.FXs[I] = nil) and (B.FXs[I] = nil) then
        Continue
      else if A.FXs[I] = nil then // �ж� B �Ƿ�Ϊ 0
      begin
        if not SparseBigNumberListIsZero(TCnSparseBigNumberList(B.FXs[I])) then
          Exit;
      end
      else if B.FXs[I] = nil then // �ж� A �Ƿ�Ϊ 0
      begin
        if not SparseBigNumberListIsZero(TCnSparseBigNumberList(A.FXs[I])) then
          Exit;
      end;

      if A.YFactorsList[I].Count <> B.YFactorsList[I].Count then
        Exit;

      for J := A.YFactorsList[I].Count - 1 downto 0 do
      begin
        if (A.YFactorsList[I][J].Exponent <> B.YFactorsList[I][J].Exponent) or
          not BigNumberEqual(A.YFactorsList[I][J].Value, B.YFactorsList[I][J].Value) then
        begin
          BigNumberNonNegativeMod(T1, A.YFactorsList[I][J].Value, Prime);
          BigNumberNonNegativeMod(T2, B.YFactorsList[I][J].Value, Prime);
          if not BigNumberEqual(T1, T2) then
            Exit;
        end;
      end;
    end;
  finally
    FLocalBigNumberPool.Recycle(T1);
    FLocalBigNumberPool.Recycle(T2);
  end;
  Result := True;
end;

procedure BigNumberBiPolynomialGaloisNegate(P: TCnBigNumberBiPolynomial; Prime: TCnBigNumber);
var
  I, J: Integer;
  YL: TCnSparseBigNumberList;
begin
  for I := P.FXs.Count - 1 downto 0 do
  begin
    YL := TCnSparseBigNumberList(P.FXs[I]);
    if YL <> nil then
      for J := YL.Count - 1 downto 0 do
      begin
        YL[J].Value.Negate;
        BigNumberNonNegativeMod(YL[J].Value, YL[J].Value, Prime);
      end;
  end;
end;

function BigNumberBiPolynomialGaloisAdd(Res: TCnBigNumberBiPolynomial;
  P1: TCnBigNumberBiPolynomial; P2: TCnBigNumberBiPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
begin
  Result := BigNumberBiPolynomialAdd(Res, P1, P2);
  if Result then
  begin
    BigNumberBiPolynomialNonNegativeModBigNumber(Res, Prime);
    if Primitive <> nil then
      BigNumberBiPolynomialGaloisModX(Res, Res, Primitive, Prime);
  end;
end;

function BigNumberBiPolynomialGaloisSub(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
begin
  Result := BigNumberBiPolynomialSub(Res, P1, P2);
  if Result then
  begin
    BigNumberBiPolynomialNonNegativeModBigNumber(Res, Prime);
    if Primitive <> nil then
      BigNumberBiPolynomialGaloisModX(Res, Res, Primitive, Prime);
  end;
end;

function BigNumberBiPolynomialGaloisMul(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  P2: TCnBigNumberBiPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
var
  I, J, K, L: Integer;
  R: TCnBigNumberBiPolynomial;
  T: TCnBigNumber;
  Pair1, Pair2: TCnExponentBigNumberPair;
begin
  if P1.IsZero or P2.IsZero then
  begin
    Res.SetZero;
    Result := True;
    Exit;
  end;

  if (Res = P1) or (Res = P2) then
    R := FLocalBigNumberBiPolynomialPool.Obtain
  else
    R := Res;

  R.Clear;
  R.MaxXDegree := P1.MaxXDegree + P2.MaxXDegree;
  R.MaxYDegree := P1.MaxYDegree + P2.MaxYDegree;

  T := FLocalBigNumberPool.Obtain;
  try
    for I := P1.FXs.Count - 1 downto 0 do
    begin
      if P1.FXs[I] = nil then
        Continue;

      for J := P1.YFactorsList[I].Count - 1 downto 0 do
      begin
        Pair1 := P1.YFactorsList[I][J];
        // �õ� P1.SafeValue[I, J] ��ķ� 0 �Ҫ������� P2 ��ÿһ���� 0 ��
        for K := P2.FXs.Count - 1 downto 0 do
        begin
          if P2.FXs[K] = nil then
            Continue;

          for L := P2.YFactorsList[K].Count - 1 downto 0 do
          begin
            Pair2 := P2.YFactorsList[K][L];
            BigNumberMul(T, Pair1.Value, Pair2.Value);
            BigNumberAdd(R.SafeValue[I + K, Pair1.Exponent + Pair2.Exponent],
              R.SafeValue[I + K, Pair1.Exponent + Pair2.Exponent], T);
            BigNumberNonNegativeMod(R.SafeValue[I + K, Pair1.Exponent + Pair2.Exponent],
              R.SafeValue[I + K, Pair1.Exponent + Pair2.Exponent], Prime);
          end;
        end;
      end;
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
  end;

  R.CorrectTop;
  if Primitive <> nil then
    BigNumberBiPolynomialGaloisModX(R, R, Primitive, Prime);

  if (Res = P1) or (Res = P2) then
  begin
    BigNumberBiPolynomialCopy(Res, R);
    FLocalBigNumberBiPolynomialPool.Recycle(R);
  end;
  Result := True;
end;

function BigNumberBiPolynomialGaloisMulX(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PX: TCnBigNumberPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
var
  P: TCnBigNumberBiPolynomial;
begin
  P := FLocalBigNumberBiPolynomialPool.Obtain;
  try
    BigNumberBiPolynomialCopyFromX(P, PX);
    Result := BigNumberBiPolynomialGaloisMul(Res, P1, P, Prime, Primitive);
  finally
    FLocalBigNumberBiPolynomialPool.Recycle(P);
  end;
end;

function BigNumberBiPolynomialGaloisMulY(Res: TCnBigNumberBiPolynomial; P1: TCnBigNumberBiPolynomial;
  PY: TCnBigNumberPolynomial; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
var
  P: TCnBigNumberBiPolynomial;
begin
  P := FLocalBigNumberBiPolynomialPool.Obtain;
  try
    BigNumberBiPolynomialCopyFromY(P, PY);
    Result := BigNumberBiPolynomialGaloisMul(Res, P1, P, Prime, Primitive);
  finally
    FLocalBigNumberBiPolynomialPool.Recycle(P);
  end;
end;

function BigNumberBiPolynomialGaloisDivX(Res: TCnBigNumberBiPolynomial;
  Remain: TCnBigNumberBiPolynomial; P: TCnBigNumberBiPolynomial;
  Divisor: TCnBigNumberBiPolynomial; Prime: TCnBigNumber;
  Primitive: TCnBigNumberBiPolynomial): Boolean;
var
  SubRes: TCnBigNumberBiPolynomial; // ���ɵݼ���
  MulRes: TCnBigNumberBiPolynomial; // ���ɳ����˻�
  DivRes: TCnBigNumberBiPolynomial; // ������ʱ��
  I, D: Integer;
  TY: TCnBigNumberPolynomial;       // ������һ����ʽ��Ҫ�˵� Y ����ʽ
begin
  Result := False;
  if BigNumberBiPolynomialIsZero(Divisor) then
    raise EDivByZero.Create(SDivByZero);

  if Divisor.MaxXDegree > P.MaxXDegree then // ��ʽ�����߲�������ֱ�ӱ������
  begin
    if Res <> nil then
      BigNumberBiPolynomialSetZero(Res);
    if (Remain <> nil) and (P <> Remain) then
      BigNumberBiPolynomialCopy(Remain, P);
    Result := True;
    Exit;
  end;

  if not Divisor.IsMonicX then // ֻ֧�� X ����һ����ʽ
    Exit;

  // ������ѭ��
  SubRes := nil;
  MulRes := nil;
  DivRes := nil;
  TY := nil;

  try
    SubRes := FLocalBigNumberBiPolynomialPool.Obtain;
    BigNumberBiPolynomialCopy(SubRes, P);

    D := P.MaxXDegree - Divisor.MaxXDegree;
    DivRes := FLocalBigNumberBiPolynomialPool.Obtain;
    DivRes.MaxXDegree := D;
    MulRes := FLocalBigNumberBiPolynomialPool.Obtain;

    TY := FLocalBigNumberPolynomialPool.Obtain;

    for I := 0 to D do
    begin
      if P.MaxXDegree - I > SubRes.MaxXDegree then                 // �м���������λ
        Continue;

      BigNumberBiPolynomialCopy(MulRes, Divisor);
      BigNumberBiPolynomialShiftLeftX(MulRes, D - I);              // ���뵽 SubRes ����ߴ�

      BigNumberBiPolynomialExtractYByX(TY, SubRes, P.MaxXDegree - I);
      BigNumberBiPolynomialGaloisMulY(MulRes, MulRes, TY, Prime, Primitive);               // ��ʽ�˵���ߴ�ϵ����ͬ

      DivRes.SetYCoefficentsFromPolynomial(D - I, TY);             // �̷ŵ� DivRes λ��
      BigNumberBiPolynomialGaloisSub(SubRes, SubRes, MulRes, Prime, Primitive);            // ���������·Ż� SubRes
    end;

    // ������ʽ����Ҫ��ģ��ԭ����ʽ
    if Primitive <> nil then
    begin
      BigNumberBiPolynomialGaloisModX(SubRes, SubRes, Primitive, Prime);
      BigNumberBiPolynomialGaloisModX(DivRes, DivRes, Primitive, Prime);
    end;

    if Remain <> nil then
      BigNumberBiPolynomialCopy(Remain, SubRes);
    if Res <> nil then
      BigNumberBiPolynomialCopy(Res, DivRes);
  finally
    FLocalBigNumberBiPolynomialPool.Recycle(SubRes);
    FLocalBigNumberBiPolynomialPool.Recycle(MulRes);
    FLocalBigNumberBiPolynomialPool.Recycle(DivRes);
    FLocalBigNumberPolynomialPool.Recycle(TY);
  end;
  Result := True;
end;

function BigNumberBiPolynomialGaloisModX(Res: TCnBigNumberBiPolynomial;
  P: TCnBigNumberBiPolynomial; Divisor: TCnBigNumberBiPolynomial;
  Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
begin
  Result := BigNumberBiPolynomialGaloisDivX(nil, Res, P, Divisor, Prime, Primitive);
end;

function BigNumberBiPolynomialGaloisPower(Res, P: TCnBigNumberBiPolynomial;
  Exponent: TCnBigNumber; Prime: TCnBigNumber; Primitive: TCnBigNumberBiPolynomial): Boolean;
var
  T: TCnBigNumberBiPolynomial;
  E: TCnBigNumber;
begin
  if Exponent.IsZero then
  begin
    Res.SetOne;
    Result := True;
    Exit;
  end
  else if Exponent.IsOne then
  begin
    if Res <> P then
      BigNumberBiPolynomialCopy(Res, P);
    Result := True;
    Exit;
  end
  else if Exponent.IsNegative then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidExponent, [Exponent.ToDec]);

  T := FLocalBigNumberBiPolynomialPool.Obtain;
  BigNumberBiPolynomialCopy(T, P);
  E := FLocalBigNumberPool.Obtain;
  BigNumberCopy(E, Exponent);

  try
    // ��������ʽ���ټ��� T �Ĵη���ֵ�� Res
    Res.SetOne;
    while not E.IsZero do
    begin
      if BigNumberIsBitSet(E, 0) then
        BigNumberBiPolynomialGaloisMul(Res, Res, T, Prime, Primitive);

      BigNumberShiftRightOne(E, E);
      if not E.IsZero then
        BigNumberBiPolynomialGaloisMul(T, T, T, Prime, Primitive);
    end;
    Result := True;
  finally
    FLocalBigNumberPool.Recycle(E);
    FLocalBigNumberBiPolynomialPool.Recycle(T);
  end;
end;

function BigNumberBiPolynomialGaloisEvaluateByY(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; YValue, Prime: TCnBigNumber): Boolean;
var
  I, J: Integer;
  Sum, TY, T, TE: TCnBigNumber;
  YL: TCnSparseBigNumberList;
  Pair: TCnExponentBigNumberPair;
begin
  // ���ÿһ�� FXs[I] �� List������������ Y ���η�ֵ�ۼӣ���Ϊ X ��ϵ��
  Res.Clear;
  Sum := nil;
  TY := nil;
  TE := nil;
  T := nil;

  try
    Sum := FLocalBigNumberPool.Obtain;
    TY := FLocalBigNumberPool.Obtain;
    TE := FLocalBigNumberPool.Obtain;
    T := FLocalBigNumberPool.Obtain;

    for I := 0 to P.FXs.Count - 1 do
    begin
      if P.FXs[I] = nil then
        Continue;

      Sum.SetZero;
      YL := P.YFactorsList[I];

      if YL.Count > 0 then
      begin
        if YL.Bottom.Exponent = 0 then
          TY.SetOne
        else if YL.Bottom.Exponent = 1 then
          BigNumberCopy(TY, YValue)
        else if YL.Bottom.Exponent = 2 then
          BigNumberDirectMulMod(TY, YValue, YValue, Prime)
        else
        begin
          T.SetWord(YL.Bottom.Exponent);
          BigNumberPowerMod(TY, YValue, T, Prime);
        end;

        for J := 0 to YL.Count - 1 do
        begin
          Pair := YL[J];

          // Sum := Sum + TY * YL[J];
          BigNumberMul(T, TY, Pair.Value);
          BigNumberAdd(Sum, Sum, T);
          BigNumberNonNegativeMod(Sum, Sum, Prime);

          // TY := TY * Power(YValue, YL[J+1].Exponent - YL[J].Exponent);
          if J < YL.Count - 1 then
          begin
            TE.SetWord(YL[J + 1].Exponent - YL[J].Exponent);
            BigNumberPowerMod(T, YValue, TE, Prime);
            BigNumberDirectMulMod(TY, TY, T, Prime);
          end;
        end;
      end;
      BigNumberCopy(Res.Add, Sum);
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(TY);
    FLocalBigNumberPool.Recycle(TE);
    FLocalBigNumberPool.Recycle(Sum);
  end;
  Result := True;
end;

function BigNumberBiPolynomialGaloisEvaluateByX(Res: TCnBigNumberPolynomial;
  P: TCnBigNumberBiPolynomial; XValue, Prime: TCnBigNumber): Boolean;
var
  I, J: Integer;
  Sum, TX, T: TCnBigNumber;
begin
  // ���ÿһ�� Y ���������� FXs[I] �� List �еĸô���Ԫ�أ�����ۼӣ���Ϊ Y ��ϵ��
  Res.Clear;
  Sum := nil;
  TX := nil;
  T := nil;

  try
    Sum := FLocalBigNumberPool.Obtain;
    TX := FLocalBigNumberPool.Obtain;
    T := FLocalBigNumberPool.Obtain;

    for I := 0 to P.MaxYDegree do
    begin
      Sum.SetZero;
      TX.SetOne;

      for J := 0 to P.FXs.Count - 1 do
      begin
        if P.FXs[J] <> nil then
        begin
          //Sum := Sum + TX * P.SafeValue[J, I];
          BigNumberMul(T, TX, P.ReadonlyValue[J, I]);
          BigNumberAdd(Sum, Sum, T);
          BigNumberNonNegativeMod(Sum, Sum, Prime);
        end;

        //TX := TX * XValue;
        BigNumberMul(TX, TX, XValue);
        BigNumberNonNegativeMod(TX, TX, Prime);
      end;
      BigNumberCopy(Res.Add, Sum);
    end;
  finally
    FLocalBigNumberPool.Recycle(T);
    FLocalBigNumberPool.Recycle(TX);
    FLocalBigNumberPool.Recycle(Sum);
  end;
  Result := True;
end;

procedure BigNumberBiPolynomialGaloisMulWord(P: TCnBigNumberBiPolynomial;
  N: Int64; Prime: TCnBigNumber);
var
  I, J: Integer;
begin
  if N = 0 then
    P.SetZero
  else // �� Prime ��Ҫ Mod�����ж��Ƿ��� 1 ��
    for I := P.FXs.Count - 1 downto 0 do
    begin
      if P.FXs[I] <> nil then
        for J := P.YFactorsList[I].Count - 1 downto 0 do
        begin
          P.YFactorsList[I][J].Value.MulWord(N);
          BigNumberNonNegativeMod(P.YFactorsList[I][J].Value, P.YFactorsList[I][J].Value, Prime);
        end;
    end;
end;

procedure BigNumberBiPolynomialGaloisDivWord(P: TCnBigNumberBiPolynomial;
  N: Int64; Prime: TCnBigNumber);
var
  I, J: Integer;
  B: Boolean;
  K, T: TCnBigNumber;
begin
  if N = 0 then
    raise EDivByZero.Create(SDivByZero);

  B := N < 0;
  if B then
    N := -N;

  K := nil;
  T := nil;

  try
    K := FLocalBigNumberPool.Obtain;
    T := FLocalBigNumberPool.Obtain;
    T.SetWord(N);

    BigNumberModularInverse(K, T, Prime);

    for I := P.FXs.Count - 1 downto 0 do
    begin
      if P.FXs[I] <> nil then
        for J := P.YFactorsList[I].Count - 1 downto 0 do
        begin
          BigNumberDirectMulMod(P.YFactorsList[I][J].Value, P.YFactorsList[I][J].Value, K, Prime);
          if B then
            BigNumberSub(P.YFactorsList[I][J].Value, Prime, P.YFactorsList[I][J].Value);
        end;
    end;
  finally
    FLocalBigNumberPool.Recycle(K);
    FLocalBigNumberPool.Recycle(T);
  end;
end;

procedure Int64PolynomialToBigNumberPolynomial(Dst: TCnBigNumberPolynomial;
  Src: TCnInt64Polynomial);
var
  I: Integer;
begin
  Dst.MaxDegree := Src.MaxDegree;
  for I := 0 to Src.MaxDegree do
    Dst[I].SetInt64(Src[I]);
end;
{ TCnBigNumberBiPolynomial }

procedure TCnBigNumberBiPolynomial.Clear;
var
  I: Integer;
begin
//  if FXs.Count <= 0 then
//    FXs.Add(TCnSparseBigNumberList.Create)
//  else
    for I := FXs.Count - 1 downto 0 do
    begin
      FXs[I].Free;
      FXs.Delete(I);
    end;

//  YFactorsList[0].Clear;
end;

function TCnBigNumberBiPolynomial.CompactYDegree(
  YList: TCnSparseBigNumberList): Boolean;
begin
  if YList = nil then
    Result := True
  else
  begin
    YList.Compact;
    Result := YList.Count = 0;
  end;
end;

procedure TCnBigNumberBiPolynomial.CorrectTop;
var
  I: Integer;
  Compact, MeetNonEmpty: Boolean;
  YL: TCnSparseBigNumberList;
begin
  MeetNonEmpty := False;
  for I := FXs.Count - 1 downto 0 do
  begin
    YL := TCnSparseBigNumberList(FXs[I]);
    if YL = nil then
      Compact := True
    else
      Compact := CompactYDegree(YL);

    if not Compact then     // ����ѹ���� 0
      MeetNonEmpty := True;

    if Compact and not MeetNonEmpty then // ��ߵ�һ·����ѹ������ȫ 0 ��Ҫɾ��
    begin
      FXs.Delete(I);
      YL.Free;
    end
    else if Compact then // ��ͨ��ѹ����ȫ 0 �ģ���Ҫ�ͷ� SparseBigNumberList���� FXs �ﻹ��ռλ
    begin
      FXs[I] := nil;
      YL.Free;
    end;
  end;
end;

constructor TCnBigNumberBiPolynomial.Create(XDegree, YDegree: Integer);
begin
  FXs := TCnRefObjectList.Create;
  EnsureDegrees(XDegree, YDegree);
end;

destructor TCnBigNumberBiPolynomial.Destroy;
var
  I: Integer;
begin
  for I := FXs.Count - 1 downto 0 do
    FXs[I].Free;
  FXs.Free;
  inherited;
end;

procedure TCnBigNumberBiPolynomial.EnsureDegrees(XDegree,
  YDegree: Integer);
var
  I: Integer;
begin
  CheckDegree(XDegree);
  CheckDegree(YDegree);

  // OldCount := FXs.Count;
  if (XDegree + 1) > FXs.Count then
  begin
    for I := FXs.Count + 1 to XDegree + 1 do
    begin
      FXs.Add(nil);
      // TCnSparseBigNumberList(FXs[FXs.Count - 1]).Count := YDegree + 1;
    end;
  end;

//  for I:= OldCount - 1 downto 0 do
//    if TCnSparseBigNumberList(FXs[I]).Count < YDegree + 1 then
//      TCnSparseBigNumberList(FXs[I]).Count := YDegree + 1;
end;

function TCnBigNumberBiPolynomial.GetMaxXDegree: Integer;
begin
  Result := FXs.Count - 1;
end;

function TCnBigNumberBiPolynomial.GetMaxYDegree: Integer;
var
  I: Integer;
  Pair: TCnExponentBigNumberPair;
begin
  Result := 0;
  for I := FXs.Count - 1 downto 0 do
  begin
    if FXs[I] <> nil then
      if YFactorsList[I].Count > 0 then
      begin
        Pair := YFactorsList[I].Top;
        if Pair <> nil then
        begin
          if Pair.Exponent > Result then
          Result := Pair.Exponent;
        end;
      end;
  end;
end;

function TCnBigNumberBiPolynomial.GetReadonlyValue(XDegree,
  YDegree: Integer): TCnBigNumber;
var
  YL: TCnSparseBigNumberList;
begin
  Result := CnBigNumberZero;
  if (XDegree >= 0) and (XDegree < FXs.Count) then
  begin
    YL := TCnSparseBigNumberList(FXs[XDegree]);
    if YL <> nil then
      if (YDegree >= 0) and (YDegree < YL.Count) then
        Result := YL.ReadonlyValue[YDegree];
  end;
end;

function TCnBigNumberBiPolynomial.GetSafeValue(XDegree,
  YDegree: Integer): TCnBigNumber;
var
  YL: TCnSparseBigNumberList;
begin
  if XDegree > MaxXDegree then  
    MaxXDegree := XDegree;

  YL := YFactorsList[XDegree];  // ȷ�� XDegree ����
  Result := YL.SafeValue[YDegree];
end;

function TCnBigNumberBiPolynomial.GetYFactorsList(
  Index: Integer): TCnSparseBigNumberList;
begin
  if Index < 0 then
    raise ECnPolynomialException.CreateFmt(SCnErrorPolynomialInvalidDegree, [Index]);

  if Index >= FXs.Count then
    FXs.Count := Index + 1;

  Result := TCnSparseBigNumberList(FXs[Index]);
  if Result = nil then
  begin
    Result := TCnSparseBigNumberList.Create;
    FXs[Index] := Result;
  end;
end;

function TCnBigNumberBiPolynomial.IsMonicX: Boolean;
begin
  Result := BigNumberBiPolynomialIsMonicX(Self);
end;

function TCnBigNumberBiPolynomial.IsZero: Boolean;
begin
  Result := BigNumberBiPolynomialIsZero(Self);
end;

procedure TCnBigNumberBiPolynomial.Negate;
begin
  BignumberBiPolynomialNegate(Self);
end;

procedure TCnBigNumberBiPolynomial.SetMaxXDegree(const Value: Integer);
var
  I: Integer;
begin
  CheckDegree(Value);

  if Value + 1 > FXs.Count then
  begin
    FXs.Count := Value + 1; // ��Ԥ�ȴ���
//    for I := FXs.Count + 1 to Value + 1 do
//      FXs.Add(TCnSparseBigNumberList.Create);
  end
  else if Value + 1 < FXs.Count then
  begin
    for I := FXs.Count - 1 downto Value + 1 do
    begin
      FXs[I].Free;
      FXs.Delete(I);
    end;
  end;
end;

procedure TCnBigNumberBiPolynomial.SetMaxYDegree(const Value: Integer);
begin
  // Not Needed
end;

procedure TCnBigNumberBiPolynomial.SetOne;
begin
  BigNumberBiPolynomialSetOne(Self);
end;

procedure TCnBigNumberBiPolynomial.SetSafeValue(XDegree, YDegree: Integer;
  const Value: TCnBigNumber);
var
  YL: TCnSparseBigNumberList;
begin
  if XDegree > MaxXDegree then  
    MaxXDegree := XDegree;

  YL := YFactorsList[XDegree];    // ȷ�� XDegree ����
  YL.SafeValue[YDegree] := Value; // �ڲ� Copy ����
end;

procedure TCnBigNumberBiPolynomial.SetString(const Poly: string);
begin
  BigNumberBiPolynomialSetString(Self, Poly);
end;

procedure TCnBigNumberBiPolynomial.SetXCoefficents(YDegree: Integer;
  LowToHighXCoefficients: array of const);
var
  I: Integer;
  S: string;
begin
  CheckDegree(YDegree);

  MaxXDegree := High(LowToHighXCoefficients);

  if YDegree > MaxYDegree then
    MaxYDegree := YDegree;

  for I := Low(LowToHighXCoefficients) to High(LowToHighXCoefficients) do
  begin
    S := ExtractBigNumberFromArrayConstElement(LowToHighXCoefficients[I]);
    if S <> '' then
      SafeValue[I, YDegree].SetDec(AnsiString(ExtractBigNumberFromArrayConstElement(LowToHighXCoefficients[I])));
  end;
end;

procedure TCnBigNumberBiPolynomial.SetXYCoefficent(XDegree,
  YDegree: Integer; ACoefficient: TCnBigNumber);
begin
  CheckDegree(XDegree);
  CheckDegree(YDegree);

  if MaxXDegree < XDegree then
    MaxXDegree := XDegree;

  YFactorsList[XDegree].SafeValue[YDegree] := ACoefficient; // �ڲ��� BigNumberCopy ֵ
end;

procedure TCnBigNumberBiPolynomial.SetYCoefficents(XDegree: Integer;
  LowToHighYCoefficients: array of const);
var
  I: Integer;
begin
  CheckDegree(XDegree);

  if XDegree > MaxXDegree then
    MaxXDegree := XDegree;

  YFactorsList[XDegree].Clear;
  for I := Low(LowToHighYCoefficients) to High(LowToHighYCoefficients) do
    YFactorsList[XDegree].SafeValue[I].SetDec(AnsiString(ExtractBigNumberFromArrayConstElement(LowToHighYCoefficients[I])));
end;

procedure TCnBigNumberBiPolynomial.SetYCoefficentsFromPolynomial(
  XDegree: Integer; PY: TCnInt64Polynomial);
var
  I: Integer;
begin
  CheckDegree(XDegree);

  if XDegree > MaxXDegree then   
    MaxXDegree := XDegree;

  if PY.IsZero then
  begin
    FXs[XDegree].Free;
    FXs[XDegree] := nil;
  end
  else
  begin
    YFactorsList[XDegree].Clear; // ȷ�� X ����� List ����
    for I := 0 to PY.MaxDegree do
      YFactorsList[XDegree].SafeValue[I].SetInt64(PY[I]);
  end;
end;

procedure TCnBigNumberBiPolynomial.SetYCoefficentsFromPolynomial(
  XDegree: Integer; PY: TCnBigNumberPolynomial);
var
  I: Integer;
begin
  CheckDegree(XDegree);

  if XDegree > MaxXDegree then   
    MaxXDegree := XDegree;

  if PY.IsZero then
  begin
    FXs[XDegree].Free;
    FXs[XDegree] := nil;
  end
  else
  begin
    YFactorsList[XDegree].Clear;   // ȷ�� X ����� List ����
    for I := 0 to PY.MaxDegree do
      YFactorsList[XDegree].SafeValue[I] := PY[I];
  end;
end;

procedure TCnBigNumberBiPolynomial.SetZero;
begin
  BigNumberBiPolynomialSetZero(Self);
end;

function TCnBigNumberBiPolynomial.ToString: string;
begin
  Result := BigNumberBiPolynomialToString(Self);
end;

procedure TCnBigNumberBiPolynomial.Transpose;
begin
  BigNumberBiPolynomialTranspose(Self, Self);
end;

{ TCnBigNumberBiPolynomialPool }

function TCnBigNumberBiPolynomialPool.CreateObject: TObject;
begin
  Result := TCnBigNumberBiPolynomial.Create;
end;

function TCnBigNumberBiPolynomialPool.Obtain: TCnBigNumberBiPolynomial;
begin
  Result := TCnBigNumberBiPolynomial(inherited Obtain);
  Result.SetZero;
end;

procedure TCnBigNumberBiPolynomialPool.Recycle(
  Poly: TCnBigNumberBiPolynomial);
begin
  inherited Recycle(Poly);
end;

initialization
  FLocalInt64PolynomialPool := TCnInt64PolynomialPool.Create;
  FLocalInt64RationalPolynomialPool := TCnInt64RationalPolynomialPool.Create;
  FLocalBigNumberPolynomialPool := TCnBigNumberPolynomialPool.Create;
  FLocalBigNumberRationalPolynomialPool := TCnBigNumberRationalPolynomialPool.Create;
  FLocalBigNumberPool := TCnBigNumberPool.Create;
  FLocalInt64BiPolynomialPool := TCnInt64BiPolynomialPool.Create;
  FLocalBigNumberBiPolynomialPool := TCnBigNumberBiPolynomialPool.Create;

  CnInt64PolynomialOne := TCnInt64Polynomial.Create([1]);
  CnInt64PolynomialZero := TCnInt64Polynomial.Create([0]);

  CnBigNumberPolynomialOne := TCnBigNumberPolynomial.Create([1]);
  CnBigNumberPolynomialZero := TCnBigNumberPolynomial.Create([0]);

finalization
  // CnInt64PolynomialOne.ToString; // �ֹ����÷�ֹ������������

  CnBigNumberPolynomialOne.Free;
  CnBigNumberPolynomialZero.Free;

  CnInt64PolynomialOne.Free;
  CnInt64PolynomialZero.Free;

  FLocalBigNumberBiPolynomialPool.Free;
  FLocalInt64BiPolynomialPool.Free;
  FLocalInt64PolynomialPool.Free;
  FLocalInt64RationalPolynomialPool.Free;
  FLocalBigNumberPolynomialPool.Free;
  FLocalBigNumberRationalPolynomialPool.Free;
  FLocalBigNumberPool.Free;

end.
