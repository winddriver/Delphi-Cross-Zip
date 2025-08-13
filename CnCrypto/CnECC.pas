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

unit CnECC;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�κ��˹����˹��Weierstrass����Բ�����㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���� Int64 ��Χ���Լ���������ʽ������ y^2 = x^3 + Ax + B mod p
*           ����κ��˹����˹��Weierstrass����Բ���ߵļ��㣬���ˡ�ǩ���ȣ�x �� y ������������
*           ��ʵ���˽�������Բ��������㷨 Schoof��
*           ��Բ���ߵĹ�˽Կ����� PEM ������Ƶȸ�ʽ���ļ������м��ر��档
*
*           �����Բ���ߵĽ��������ϵ��ܵ������ƺ�����������Զ�㣩
*           ����Ľ��ǻ�������˶��ٵ�������Զ�㡣�����Ǳ���������ϵ��������ȡ�
*
* ����ƽ̨��WinXP + Delphi 5.0
* ���ݲ��ԣ���δ���У�ע�ⲿ�ָ�������ȱ���̶����ȴ������������� ASN.1 ��װ������ָ���̶�����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2024.04.14 V2.6
*               ����һ�� 384 ��һ�� 512 ����
*           2024.02.07 V2.5
*               ASN1 ���ǩ��ʱ����ָ���̶��ֽڳ��ȣ��ɱ��ⲻͬ��ǩ�����Ȳ�ͬ
*           2023.12.16 V2.4
*               ���� PKCS1 ��ʽ�� ECC PEM ��ʽ�������⣬PKCS8 �ݲ�֧��
*           2023.06.24 V2.3
*               ���������� Fast Schoof ʵ�ֵ���֤δͨ��������ʹ��
*           2023.05.28 V2.2
*               �ܹ����� Int64 ����Բ���ߵ��б�ʽ�� j ������
*           2022.11.01 V2.1
*               ����У�鹫˽Կ�Ƿ���Եĺ���
*           2022.06.10 V2.0
*               ��˸�ΪĬ��ʹ�÷��������Լ��٣���Ӳ���
*           2021.12.22 V1.9
*               ���� In64 �������Χ�ڷ����������ſɱ�����ļӼ�����˷�
*           2021.12.07 V1.8
*               ���� SM9 �� WAPI ���������߶���
*           2020.11.13 V1.7
*               ʵ�ִ�����Χ�ڵĻ��� Schoof �㷨������С��Χ����ͨ����
*               ֧�� Unicode ���������֧�� Win64������Χ�޴���֤
*           2020.10.25 V1.6
*               ʵ�� Int64 ��Χ�ڵĻ��� Schoof �㷨����������ͨ��
*           2020.04.06 V1.5
*               ʵ�� ECC ǩ����ǩ�������� openssl �Ĺ���
*               openssl dgst -sha256 -sign ec.pem -out hello.sig hello
*               openssl dgst -sha256 -verify ecpub.pem -signature hello.sig hello
*               ע�� Ecc ��ǩ��ֻ�����Ϣ Hash������в��� Hash �㷨�������û���Ϣ��
*               �� SM2 �淶��ͬ���� RSA �� Hash �� Hash �����ٶ���� BER ����Ҳ��ͬ
*           2020.03.28 V1.4
*               ʵ�� ECC ��˽Կ PEM �ļ����������д�������� openssl �Ĺ���
*               openssl ecparam -name secp256k1 -genkey -out ec_pkcs1.pem
*                    // PKCS#1 ��ʽ�Ĺ�˽Կ
*               openssl pkcs8 -topk8 -inform PEM -in ec_pkcs1.pem -outform PEM -nocrypt -out ec_pkcs8.pem
*                    // PKCS#8 ��ʽ�Ĺ�˽Կ
*               openssl ec -in ec.pem -pubout -out ecpub_pkcs1.pem
*                    // PKCS#1 ��ʽ�Ĺ�Կ
*               openssl ec -in ec_pkcs8.pem -outform PEM -pubout -out ecpub_pkcs8.pem
*                    // PKCS#8 ��ʽ�Ĺ�Կ
*           2018.09.29 V1.3
*               ʵ�ִ�����Բ���߸��� X �� Y �������㷨����Ĭ�����ٶȸ���� Lucas
*           2018.09.13 V1.2
*               ����ʵ�ִ�����Բ���ߵļӽ��ܹ��ܣ�֧�� SM2 �Լ� Secp256k1 ������
*           2018.09.10 V1.1
*               �ܹ�����ϵ����С����Բ���߲���
*           2018.09.05 V1.0
*               ������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

{$DEFINE USE_LUCAS}
// ��������������Ҳ���Ǹ��� X ������Բ���߷��̵� Y ֵʱʹ�� Lucas �����㷨������
// �粻���壬��ʹ�� Tonelli-Shanks �㷨���㡣Tonelli-Shanks �ٶȽ�����������Χ��
// ���� Lucas ������ 10 �����ϡ�

uses
  SysUtils, Classes, Contnrs, {$IFDEF MSWINDOWS} Windows, {$ENDIF}
  CnNative, CnPrime, CnBigNumber, CnMatrix,
  CnPolynomial, CnPemUtils, CnBerUtils, CnMD5, CnSHA1, CnSHA2, CnSM3;

const

  CN_OID_EC_PUBLIC_KEY: array [0..6] of Byte = (               // 1.2.840.10045.2.1
    $2A, $86, $48, $CE, $3D, $02, $01
  );
  {* ecPublicKey �� OID}

type
  TCnEccSignDigestType = (esdtMD5, esdtSHA1, esdtSHA256, esdtSM3);
  {* ECC ǩ����֧�ֵ�����ժҪ�㷨����֧����ժҪ�ķ�ʽ}

  ECnEccException = class(Exception);
  {* ��Բ��������쳣}

  TCnInt64EccPoint = packed record
  {* Int64 ��Χ�ڵ���Բ�����ϵ�����������ṹ}
    X: Int64;
    Y: Int64;
  end;

  TCnInt64Ecc3Point = packed record
  {* Int64 ��Χ�ڵ���Ӱ/����/�ſɱ������������ṹ�������ڲ��������١�Z = 0 ʱ��ʾ����Զ��Ҳ���� 0 ��}
    X: Int64;
    Y: Int64;
    Z: Int64;
  end;

  TCnInt64PublicKey = TCnInt64EccPoint;
  {* Int64 ��Χ�ڵ���Բ���ߵĹ�Կ��G ����� k �κ�������}

  TCnInt64PrivateKey = Int64;
  {* Int64 ��Χ�ڵ���Բ���ߵ�˽Կ��������� k ��}

  TCnInt64Ecc = class
  {* ����һ�������� p Ҳ���� 0 �� p - 1 �ϵ���Բ���� y^2 = x^3 + Ax + B mod p���������� Int64 ��Χ��}
  private
    FGenerator: TCnInt64EccPoint;
    FCoefficientA: Int64;
    FCoefficientB: Int64;
    FFiniteFieldSize: Int64;
    FOrder: Int64;
    FSizeUFactor: Int64;
    FSizePrimeType: TCnPrimeType;
    F2Inverse: Int64;               // 2 ��� FFiniteFieldSize ��ģ��Ԫ�����ſɱ��������
    function GetJInvariance: Int64;
    function GetDelta: Int64;
  protected
    function TonelliShanks(X: Int64; P: Int64; out Y: Int64): Boolean;
    {* Tonelli-Shanks ģ��������ʣ����⣬���� False ��ʾʧ�ܣ������������б�֤ P Ϊ����}

    function Lucas(X: Int64; P: Int64; out Y: Int64): Boolean;
    {* Lucas ����ģ��������ʣ����⣬���� False ��ʾʧ�ܣ�ֻ��� P Ϊ 8*u + 1 ����ʽ}
  public
    constructor Create(A: Int64; B: Int64; FieldPrime: Int64; GX: Int64; GY: Int64; Order: Int64);
    {* ���캯�������뷽�̵� A, B �������������Ͻ� p��G �����ꡢG ��Ľ�����

       ������
         A: Int64                         - κ��˹����˹��Բ���߷��̵� a ����
         B: Int64                         - κ��˹����˹��Բ���߷��̵� b ����
         FieldPrime: Int64                - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         GX: Int64                        - κ��˹����˹��Բ���߷��̵� G ��� X ����
         GY: Int64                        - κ��˹����˹��Բ���߷��̵� G ��� Y ����
         Order: Int64                     - κ��˹����˹��Բ���߷��̵� G ��Ľ�

       ����ֵ��TCnInt64Ecc                - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure AffinePointAddPoint(var P: TCnInt64Ecc3Point;
      var Q: TCnInt64Ecc3Point; var Sum: TCnInt64Ecc3Point);
    {* ʹ�÷�������ϵ���е�ӣ�����ȡģ��Ԫ���µĿ�����

       ������
         var P: TCnInt64Ecc3Point         - ��һ�������ĵ�����
         var Q: TCnInt64Ecc3Point         - �ڶ��������ĵ�����
         var Sum: TCnInt64Ecc3Point       - ����ĺ͵ĵ�����

       ����ֵ�����ޣ�
    }

    procedure JacobianPointAddPoint(var P: TCnInt64Ecc3Point;
      var Q: TCnInt64Ecc3Point; var Sum: TCnInt64Ecc3Point);
    {* ʹ���ſɱ�����ϵ���е�ӣ�����ȡģ��Ԫ���µĿ�����

       ������
         var P: TCnInt64Ecc3Point         - ��һ�������ĵ�����
         var Q: TCnInt64Ecc3Point         - �ڶ��������ĵ�����
         var Sum: TCnInt64Ecc3Point       - ����ĺ͵ĵ�����

       ����ֵ�����ޣ�
    }

    procedure AffineMultiplePoint(K: Int64; var Point: TCnInt64Ecc3Point);
    {* ʹ�÷�������ϵ���е�ˣ�����ȡģ���µĿ�����

       ������
         K: Int64                         - ����
         var Point: TCnInt64Ecc3Point     - ���˵������

       ����ֵ�����ޣ�
    }

    procedure JacobianMultiplePoint(K: Int64; var Point: TCnInt64Ecc3Point);
    {* ʹ���ſɱ�����ϵ���е�ˣ�����ȡģ���µĿ�����

       ������
         K: Int64                         - ����
         var Point: TCnInt64Ecc3Point     - ���˵������

       ����ֵ�����ޣ�
    }

    procedure MultiplePoint(K: Int64; var Point: TCnInt64EccPoint);
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P��

       ������
         K: Int64                         - ����
         var Point: TCnInt64EccPoint      - ���˵������

       ����ֵ�����ޣ�
    }

    procedure PointAddPoint(var P: TCnInt64EccPoint; var Q: TCnInt64EccPoint; var Sum: TCnInt64EccPoint);
    {* ���� P + Q��ֵ���� Sum �У�Sum ������ P��Q ֮һ��P��Q ������ͬ��

       ������
         var P: TCnInt64EccPoint          - ��һ�������ĵ�����
         var Q: TCnInt64EccPoint          - �ڶ��������ĵ�����
         var Sum: TCnInt64EccPoint        - ����ĺ͵ĵ�����

       ����ֵ�����ޣ�
    }

    procedure PointSubPoint(var P: TCnInt64EccPoint; var Q: TCnInt64EccPoint; var Diff: TCnInt64EccPoint);
    {* ���� P - Q��ֵ���� Diff �У�Diff ������ P��Q ֮һ��P��Q ������ͬ��

       ������
         var P: TCnInt64EccPoint          - �������ĵ�����
         var Q: TCnInt64EccPoint          - �����ĵ�����
         var Diff: TCnInt64EccPoint       - ����Ĳ�ĵ�����

       ����ֵ�����ޣ�
    }

    procedure PointInverse(var P: TCnInt64EccPoint);
    {* ���� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         var P: TCnInt64EccPoint          - ��ȡ��Ԫ�������

       ����ֵ�����ޣ�
    }

    procedure AffinePointInverse(var P: TCnInt64Ecc3Point);
    {* �����Է��������ʾ�� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         var P: TCnInt64Ecc3Point         - ��ȡ��Ԫ�������

       ����ֵ�����ޣ�
    }

    procedure JacobianPointInverse(var P: TCnInt64Ecc3Point);
    {* �������ſɱ������ʾ�� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         var P: TCnInt64Ecc3Point         - ��ȡ��Ԫ�������

       ����ֵ�����ޣ�
    }

    function IsPointOnCurve(var P: TCnInt64EccPoint): Boolean;
    {* �ж� P ���Ƿ��ڱ������ϡ�

       ������
         var P: TCnInt64EccPoint          - ���жϵ������

       ����ֵ��Boolean                    - �����Ƿ���������
    }

    function DivisionPolynomial(Degree: Integer; outDivisionPolynomial: TCnInt64Polynomial): Boolean;
    {* �ݹ����� Degree ���ɳ�����ʽ�����ؼ����Ƿ�ɹ���

       ������
         Degree: Integer                                  - �ɳ�����ʽ�����
         outDivisionPolynomial: TCnInt64Polynomial        - ���صĿɳ�����ʽ

       ����ֵ��Boolean                                    - ���ؼ����Ƿ�ɹ�
    }

    function PlainToPoint(Plain: Int64; var OutPoint: TCnInt64EccPoint): Boolean;
    {* ��Ҫ���ܵ�������ֵ��װ��һ�������ܵĵ㣬Ҳ����������Ϊ X �󷽳̵� Y��
       ע�� Plain Ϊ 0 ʱֱ�Ӷ�Ӧ����㣬��ʹ��Բ�������У�0, ���� Y����ʽ�ĺϷ�����ڡ�

       ������
         Plain: Int64                     - �����ܵ�������
         var OutPoint: TCnInt64EccPoint   - ��������������

       ����ֵ��Boolean                    - ��������Ƿ�ɹ�
    }

    function PointToPlain(var Point: TCnInt64EccPoint): Int64;
    {* �����ܳ������ĵ�⿪��һ��������ֵ��Ҳ���ǽ���� X ֵȡ����

       ������
         Point: TCnInt64EccPoint          - ���⿪�����������

       ����ֵ��Int64                      - ����������ֵ
    }

    procedure GenerateKeys(out PrivateKey: TCnInt64PrivateKey; out PublicKey: TCnInt64PublicKey);
    {* ����һ�Ը���Բ���ߵĹ�˽Կ��˽Կ��������� k����Կ�ǻ��� G ���� k �γ˷���õ��ĵ����� K��

       ������
         out PrivateKey: TCnInt64PrivateKey               - ���ɵ���Բ���ߵ�˽Կ
         out PublicKey: TCnInt64PublicKey                 - ���ɵ���Բ���ߵĹ�Կ

       ����ֵ�����ޣ�
    }

    procedure Encrypt(var PlainPoint: TCnInt64EccPoint; PublicKey: TCnInt64PublicKey;
      var OutDataPoint1: TCnInt64EccPoint; var OutDataPoint2: TCnInt64EccPoint; RandomKey: Int64 = 0);
    {* ��Կ�������ĵ� M���õ��������������ģ��ڲ����������ֵ r��Ҳ���� C1 = M + rK; C2 = r * G��
       �������� RandomKey �� 0�����ڲ�������ɡ�

       ������
         var PlainPoint: TCnInt64EccPoint                 - �����ܵ����������
         PublicKey: TCnInt64PublicKey                     - ���ڼ��ܵ���Բ���߹�Կ
         var OutDataPoint1: TCnInt64EccPoint              - ������������һ
         var OutDataPoint2: TCnInt64EccPoint              - �������������
         RandomKey: Int64                                 - �����

       ����ֵ�����ޣ�
    }

    procedure Decrypt(var DataPoint1: TCnInt64EccPoint; var DataPoint2: TCnInt64EccPoint;
      PrivateKey: TCnInt64PrivateKey; var OutPlainPoint: TCnInt64EccPoint);
    {* ˽Կ�������ĵ㣬Ҳ���Ǽ��� C1 - k * C2 �͵õ���ԭ�ĵ� M��

       ������
         var DataPoint1: TCnInt64EccPoint                 - �����ܵ����������һ
         var DataPoint2: TCnInt64EccPoint                 - �����ܵ�����������
         PrivateKey: TCnInt64PrivateKey                   - ���ڽ��ܵ���Բ����˽Կ
         var OutPlainPoint: TCnInt64EccPoint              - ������������

       ����ֵ�����ޣ�
    }

    property Generator: TCnInt64EccPoint read FGenerator;
    {* �������� G}
    property CoefficientA: Int64 read FCoefficientA;
    {* ����ϵ�� A}
    property CoefficientB: Int64 read FCoefficientB;
    {* ����ϵ�� B}
    property FiniteFieldSize: Int64 read FFiniteFieldSize;
    {* ��������Ͻ磬���� p}
    property Order: Int64 read FOrder;
    {* ����Ľ���}

    property Delta: Int64 read GetDelta;
    {* �б�ʽ}
    property JInvariance: Int64 read GetJInvariance;
    {* j ������}
  end;

  TCnEcc = class;

  TCnEccPoint = class(TPersistent)
  {* ���������ϵ���Բ�����ϵĵ�������}
  private
    FY: TCnBigNumber;
    FX: TCnBigNumber;
    procedure SetX(const Value: TCnBigNumber);
    procedure SetY(const Value: TCnBigNumber);
  public
    constructor Create; overload;
    {* ���캯��}
    constructor Create(const XDec: AnsiString; const YDec: AnsiString); overload;
    {* ���캯��

       ������
         const XDec: AnsiString           - X �����ʮ�����ַ���
         const YDec: AnsiString           - Y �����ʮ�����ַ���

       ����ֵ��TCnEccPoint                - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent              - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ����Զ��Ҳ�� 0 �㡣

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�����Զ��
    }

    procedure SetZero;
    {* ��Ϊ����Զ��Ҳ�� 0 ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����������ö��ŷָ���ʮ������ X �� Y ����ֵ��

       ������
         ���ޣ�

       ����ֵ��string                     - ����ʮ�������ַ���
    }

    procedure SetHex(const Buf: AnsiString; Ecc: TCnEcc = nil);
    {* ��ʮ�������ַ����м��ص����꣬�ڲ��� 02 03 04 ǰ׺�Ĵ���
       ����� 02 03 04 ǰ׺��԰������ֱ�ֵ�� X �� Y��
       ���ǰ׺�� 02 �� 03��˵������ֻ�� X ���꣬��ʱ�贫����Բ����ʵ�������� Y ���ꡣ

       ������
         const Buf: AnsiString            - �����ص�ʮ�������ַ���
         Ecc: TCnEcc                      - ����� Y ����ʱ�������Բ����ʵ��

       ����ֵ�����ޣ�
    }

    function ToHex(FixedLen: Integer = 0): string;
    {* ����ɴ� 03 �� 04 ǰ׺��ʮ�������ַ��������ֻ�� X ֵ��ʹ�� 03 ǰ׺

       ������
         FixedLen: Integer                - ָ�����ݵĹ̶��ֽڳ��ȣ��������λ�� 0

       ����ֵ��string                     - ����
    }

    procedure SetBase64(const Buf: AnsiString; Ecc: TCnEcc = nil);
    {* �� Base64 �ַ����м��ص����꣬�ڲ��� 02 03 04 ǰ׺�Ĵ���
       ����� 02 03 04 ǰ׺��԰������ֱ�ֵ�� X �� Y��
       ���ǰ׺�� 02 �� 03��˵������ֻ�� X ���꣬��ʱ�贫�� Ecc ����ʵ�������� Y ���ꡣ

       ������
         const Buf: AnsiString            - �����ص� Base64 �ַ���
         Ecc: TCnEcc                      - ����� Y ����ʱ�������Բ����ʵ��

       ����ֵ�����ޣ�
    }

    function ToBase64(FixedLen: Integer = 0): string;
    {* ����ɴ� 03 �� 04 ǰ׺�� Base64 �ַ��������ֻ�� X ֵ��ʹ�� 03 ǰ׺��

       ������
         FixedLen: Integer                - ָ�����ݵĹ̶��ֽڳ��ȣ��������λ�� 0

       ����ֵ��string                     - ���� Base64 �ַ���
    }

    property X: TCnBigNumber read FX write SetX;
    {* ��Բ���ߵ�� X ����}
    property Y: TCnBigNumber read FY write SetY;
    {* ��Բ���ߵ�� Y ����}
  end;

  TCnEcc3Point = class(TPersistent)
  {* ��Ӱ/����/�ſɱ�����㣬�����ڲ���������}
  private
    FX: TCnBigNumber;
    FY: TCnBigNumber;
    FZ: TCnBigNumber;
    procedure SetX(const Value: TCnBigNumber);
    procedure SetY(const Value: TCnBigNumber);
    procedure SetZ(const Value: TCnBigNumber);
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent              - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ����Զ��Ҳ�� 0 �㡣

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�����Զ��
    }

    procedure SetZero;
    {* ��Ϊ����Զ��Ҳ�� 0 ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ELSE} virtual; {$ENDIF}
    {* ת��Ϊ�ַ�����������ö��ŷָ���ʮ������ X��Y��Z ����ֵ��

       ������
         ���ޣ�

       ����ֵ��string                     - ����ʮ�������ַ���
    }

    property X: TCnBigNumber read FX write SetX;
    {* X ����}
    property Y: TCnBigNumber read FY write SetY;
    {* Y ����}
    property Z: TCnBigNumber read FZ write SetZ;
    {* Z ���ꡣ���Ϊ 0 ���ʾ������Զ��}
  end;

  TCnEccPublicKey = class(TCnEccPoint);
  {* ��Բ���ߵĹ�Կ��G ����� k �κ�ĵ�����}

  TCnEccPrivateKey = class(TCnBigNumber);
  {* ��Բ���ߵ�˽Կ��������� k ��}

  TCnEccSignature = class(TPersistent)
  {* ��Բ���ߵ�ǩ������������ R S}
  private
    FR: TCnBigNumber;
    FS: TCnBigNumber;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent              - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    function ToHex(FixedLen: Integer = 0): string;
    {* ת��Ϊʮ�������ַ������ڲ� R S ��ƴ�ӣ�ע����Ҫ��ʮ�������лָ�ʱ
       ��ָ�� FixedLen Ϊ��Ӧ��Բ���ߵ� BytesCount���������ǰ�� 0 �ֽڶ�����


       ������
         FixedLen: Integer                - ָ�����ݵĹ̶��ֽڳ��ȣ��������λ�� 0

       ����ֵ��string                     - ����ʮ�������ַ���
    }

    procedure SetHex(const Buf: AnsiString);
    {* ��ʮ�������ַ����м��أ��ڲ��԰��֡�

       ������
         const Buf: AnsiString            - �����ص�ʮ�������ַ���

       ����ֵ�����ޣ�
    }

    function ToBase64(FixedLen: Integer = 0): string;
    {* ת��Ϊ Base64 �ַ������ڲ� R S ��ƴ�Ӻ�ת����
       ��ָ�� FixedLen Ϊ��Ӧ��Բ���ߵ� BytesCount���������ǰ�� 0 �ֽڶ�����

       ������
         FixedLen: Integer                - ָ�����ݵĹ̶��ֽڳ��ȣ��������λ�� 0

       ����ֵ��string                     -
    }

    function SetBase64(const Buf: AnsiString): Boolean;
    {* �� Base64 �ַ����м��أ��ڲ��԰��֡����ؼ����Ƿ�ɹ���

       ������
         const Buf: AnsiString            - �����ص� Base64 �ַ���

       ����ֵ��Boolean                    - ���ؼ����Ƿ�ɹ�
    }

    function ToAsn1Hex(FixedLen: Integer = 0): string;
    {* �� R S ƴ�Ӱ�װΪ ASN1 �� BER/DER ��ʽ��ʮ�������ַ�����
       ��ָ�� FixedLen Ϊ��Ӧ��Բ���ߵ� BytesCount���������ǰ�� 0 �ֽڶ�����

       ������
         FixedLen: Integer                - ָ�����ݵĹ̶��ֽڳ��ȣ��������λ�� 0

       ����ֵ��string                     - ����ʮ�������ַ���
    }

    function SetAsn1Hex(const Buf: AnsiString): Boolean;
    {* �� ASN1 �� BER/DER ��ʽ��ʮ�������ַ����м��� R S�����ؼ����Ƿ�ɹ���

       ������
         const Buf: AnsiString            - �����ص� ASN1 ��ʮ�������ַ���

       ����ֵ��Boolean                    - ���ؼ����Ƿ�ɹ�
    }

    function ToAsn1Base64: string;
    {* �� R S ƴ�Ӱ�װΪ ASN1 �� BER/DER ��ʽ�����ݺ��� Base64 ���롣

       ������
         ���ޣ�

       ����ֵ��string                     - ���� ASN1 ��ʽ�� Base64 �ַ���
    }

    function SetAsn1Base64(const Buf: AnsiString): Boolean;
    {* �� ASN1 �� BER/DER ��ʽ�� Base64 �ַ����м��� R S�����ؼ����Ƿ�ɹ���

       ������
         const Buf: AnsiString            - �����ص� ASN1 ��ʽ�� Base64 �ַ���

       ����ֵ��Boolean                    - ���ؼ����Ƿ�ɹ�
    }

    property R: TCnBigNumber read FR;
    {* ǩ�� R ֵ}
    property S: TCnBigNumber read FS;
    {* ǩ�� S ֵ}
  end;

  TCnEccCurveType = (ctCustomized, ctSM2, ctSM2Example192, ctSM2Example256,
    ctRfc4754ECDSAExample256, ctSecp224r1, ctSecp224k1, ctSecp256k1, ctPrime256v1,
    ctWapiPrime192v1, ctSM9Bn256v1, ctSecp384r1, ctSecp521r1);
  {* ����Ԫ֧�ֵ���Բ��������}

  TCnEcc = class
  {* ����һ�������� p Ҳ���� 0 �� p - 1 �ϵ���Բ���� y^2 = x^3 + Ax + B mod p}
  private
    FCoefficientB: TCnBigNumber;
    FCoefficientA: TCnBigNumber;
    FOrder: TCnBigNumber;
    FFiniteFieldSize: TCnBigNumber;
    FGenerator: TCnEccPoint;
    FSizeUFactor: TCnBigNumber;
    FSizePrimeType: TCnPrimeType;
    FCoFactor: Integer;
    F2Inverse: TCnBigNumber;
    function GetBitsCount: Integer;
    function GetBytesCount: Integer;
  protected
    procedure CalcX3AddAXAddB(X: TCnBigNumber); // ���� X^3 + A*X + B��������� X
  public
    constructor Create; overload; virtual;
    {* ���캯��}
    constructor Create(Predefined: TCnEccCurveType); overload;
    {* ���캯����

       ������
         Predefined: TCnEccCurveType      - �����ص���Բ���߲�������

       ����ֵ��TCnEcc                     - ���ش����Ķ���ʵ��
    }

    constructor Create(const A: AnsiString; const B: AnsiString; const FieldPrime: AnsiString;
      const GX: AnsiString; const GY: AnsiString; const Order: AnsiString; H: Integer = 1); overload;
    {* ���캯�������뷽�̵� A, B �������������Ͻ� p��G �����ꡢG ��Ľ����ȣ���������������Ҫʮ�������ַ�����

       ������
         const A: AnsiString              - κ��˹����˹��Բ���߷��̵� a ����
         const B: AnsiString              - κ��˹����˹��Բ���߷��̵� b ����
         const FieldPrime: AnsiString     - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         const GX: AnsiString             - κ��˹����˹��Բ���߷��̵� G ��� X ����
         const GY: AnsiString             - κ��˹����˹��Բ���߷��̵� G ��� Y ����
         const Order: AnsiString          - κ��˹����˹��Բ���߷��̵� G ��Ľ�
         H: Integer                       - κ��˹����˹��Բ���߷��̵ĸ�������

       ����ֵ��TCnEcc                     - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure Load(Predefined: TCnEccCurveType); overload; virtual;
    {* ������Բ���߲�����

       ������
         Predefined: TCnEccCurveType      - �����ص���Բ���߲�������

       ����ֵ�����ޣ�
    }

    procedure Load(const A: AnsiString; const B: AnsiString; const FieldPrime: AnsiString;
      const GX: AnsiString; const GY: AnsiString; const Order: AnsiString; H: Integer = 1); overload; virtual;
    {* ������Բ���߲��������뷽�̵� A, B �������������Ͻ� p��G �����ꡢG ��Ľ����ȣ����������������Ҫʮ�������ַ�����

       ������
         const A: AnsiString              - κ��˹����˹��Բ���߷��̵� a ����
         const B: AnsiString              - κ��˹����˹��Բ���߷��̵� b ����
         const FieldPrime: AnsiString     - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         const GX: AnsiString             - κ��˹����˹��Բ���߷��̵� G ��� X ����
         const GY: AnsiString             - κ��˹����˹��Բ���߷��̵� G ��� Y ����
         const Order: AnsiString          - κ��˹����˹��Բ���߷��̵Ľ�
         H: Integer                       - κ��˹����˹��Բ���߷��̵ĸ�������

       ����ֵ�����ޣ�
    }

    procedure AffinePointAddPoint(P: TCnEcc3Point; Q: TCnEcc3Point; Sum: TCnEcc3Point);
    {* ʹ�÷�������ϵ���е�ӣ�����ȡģ��Ԫ���µĿ�����

       ������
         P: TCnEcc3Point                  - ��һ�������ĵ�����
         Q: TCnEcc3Point                  - �ڶ��������ĵ�����
         Sum: TCnEcc3Point                - ����ĺ͵ĵ�����

       ����ֵ�����ޣ�
    }
    procedure AffinePointSubPoint(P: TCnEcc3Point; Q: TCnEcc3Point; Diff: TCnEcc3Point);
    {* ʹ�÷�������ϵ���е��������ȡģ��Ԫ���µĿ�����

       ������
         P: TCnEcc3Point                  - �������ĵ�����
         Q: TCnEcc3Point                  - �����ĵ�����
         Diff: TCnEcc3Point               - ����Ĳ�ĵ�����

       ����ֵ�����ޣ�
    }

    procedure JacobianPointAddPoint(P: TCnEcc3Point; Q: TCnEcc3Point; Sum: TCnEcc3Point);
    {* ʹ���ſɱ�����ϵ���е�ӣ�����ȡģ��Ԫ���µĿ���

       ������
         P: TCnEcc3Point                  - ��һ�������ĵ�����
         Q: TCnEcc3Point                  - �ڶ��������ĵ�����
         Sum: TCnEcc3Point                - ����ĺ͵ĵ�����

       ����ֵ�����ޣ�
    }

    procedure JacobianPointSubPoint(P: TCnEcc3Point; Q: TCnEcc3Point; Diff: TCnEcc3Point);
    {* ʹ���ſɱ�����ϵ���е��������ȡģ��Ԫ���µĿ���

       ������
         P: TCnEcc3Point                  - �������ĵ�����
         Q: TCnEcc3Point                  - �����ĵ�����
         Diff: TCnEcc3Point               - ����Ĳ�ĵ�����

       ����ֵ�����ޣ�
    }

    procedure AffineMultiplePoint(K: TCnBigNumber; Point: TCnEcc3Point); virtual;
    {* ʹ�÷�������ϵ���е�ˣ�����ȡģ��Ԫ���µĿ�����

       ������
         K: TCnBigNumber                  - ��������ʽΪ����
         Point: TCnEcc3Point              - ���˵������

       ����ֵ�����ޣ�
    }
    procedure JacobianMultiplePoint(K: TCnBigNumber; Point: TCnEcc3Point); virtual;
    {* ʹ���ſɱ�����ϵ���е�ˣ�����ȡģ��Ԫ���µĿ�����

       ������
         K: TCnBigNumber                  - ��������ʽΪ����
         Point: TCnEcc3Point              - ���˵������

       ����ֵ�����ޣ�
    }

    procedure MultiplePoint(K: Int64; Point: TCnEccPoint); overload;
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P��

       ������
         K: Int64                         - ����
         Point: TCnEccPoint               - ���˵������

       ����ֵ�����ޣ�
    }
    procedure MultiplePoint(K: TCnBigNumber; Point: TCnEccPoint); overload;
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P���ڲ��÷��������˽��м��١�

       ������
         K: TCnBigNumber                  - ��������ʽΪ����
         Point: TCnEccPoint               - ���˵������

       ����ֵ�����ޣ�
    }

    procedure NormalMultiplePoint(K: TCnBigNumber; Point: TCnEccPoint);
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P��

       ������
         K: TCnBigNumber                  - ��������ʽΪ����
         Point: TCnEccPoint               - ���˵������

       ����ֵ�����ޣ�
    }

    procedure PointAddPoint(P: TCnEccPoint; Q: TCnEccPoint; Sum: TCnEccPoint);
    {* ���� P + Q��ֵ���� Sum �У�Sum ������ P��Q ֮һ��P��Q ������ͬ���ڲ���ͨʵ��

       ������
         P: TCnEccPoint                   - ��һ�������ĵ�����
         Q: TCnEccPoint                   - �ڶ��������ĵ�����
         Sum: TCnEccPoint                 - ����ĺ͵ĵ�����

       ����ֵ�����ޣ�
    }

    procedure PointSubPoint(P: TCnEccPoint; Q: TCnEccPoint; Diff: TCnEccPoint);
    {* ���� P - Q��ֵ���� Diff �У�Diff ������ P��Q ֮һ��P��Q ������ͬ

       ������
         P: TCnEccPoint                   - �������ĵ�����
         Q: TCnEccPoint                   - �����ĵ�����
         Diff: TCnEccPoint                - ����Ĳ�ĵ�����

       ����ֵ�����ޣ�
    }

    procedure PointInverse(P: TCnEccPoint);
    {* ���� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         P: TCnEccPoint                   - ��ȡ��Ԫ�������

       ����ֵ�����ޣ�
    }

    procedure AffinePointInverse(P: TCnEcc3Point);
    {* �����Է��������ʾ�� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         P: TCnEcc3Point                  - ��ȡ��Ԫ�������

       ����ֵ�����ޣ�
    }

    procedure JacobianPointInverse(P: TCnEcc3Point);
    {* �������ſɱ������ʾ�� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         P: TCnEcc3Point                  - ��ȡ��Ԫ�Ķ���ʽ�����

       ����ֵ�����ޣ�
    }
    function IsPointOnCurve(P: TCnEccPoint): Boolean;
    {* �ж� P ���Ƿ��ڱ������ϡ�

       ������
         P: TCnEccPoint                   - ���жϵ������

       ����ֵ��Boolean                    - �����Ƿ���������
    }

    function PlainToPoint(Plain: TCnBigNumber; OutPoint: TCnEccPoint): Boolean;
    {* ��Ҫ���ܵ�������ֵ��װ��һ�������ܵĵ㣬Ҳ����������Ϊ X �󷽳̵� Y��
       ע�� Plain Ϊ 0 ʱֱ�Ӷ�Ӧ����㣬��ʹ��Բ�������У�0, ���� Y����ʽ�ĺϷ�����ڡ�

       ������
         Plain: TCnBigNumber              - �����ܵ�������
         OutPoint: TCnEccPoint            - ��������������

       ����ֵ��Boolean                    - ��������Ƿ�ɹ�
    }

    function PointToPlain(Point: TCnEccPoint; OutPlain: TCnBigNumber): Boolean;
    {* �����ܳ������ĵ�⿪��һ��������ֵ��Ҳ���ǽ���� X ֵȡ����

       ������
         Point: TCnEccPoint               - ���⿪�����������
         OutPlain: TCnBigNumber           - ����������ֵ

       ����ֵ��Boolean                    - ���ؽ⿪�Ƿ�ɹ�
    }

    procedure GenerateKeys(PrivateKey: TCnEccPrivateKey; PublicKey: TCnEccPublicKey);
    {* ����һ�Ը���Բ���ߵĹ�˽Կ��˽Կ��������� k����Կ�ǻ��� G ���� k �γ˷���õ��ĵ����� K��

       ������
         PrivateKey: TCnEccPrivateKey     - ���ɵ���Բ���ߵ�˽Կ
         PublicKey: TCnEccPublicKey       - ���ɵ���Բ���ߵĹ�Կ

       ����ֵ�����ޣ�
    }

    procedure Encrypt(PlainPoint: TCnEccPoint; PublicKey: TCnEccPublicKey;
      OutDataPoint1: TCnEccPoint; OutDataPoint2: TCnEccPoint);
    {* ��Կ�������ĵ� M���õ��������������ģ��ڲ����������ֵ r��Ҳ���� C1 = M + rK; C2 = r * G��

       ������
         PlainPoint: TCnEccPoint          - �����ܵ����������
         PublicKey: TCnEccPublicKey       - ���ڼ��ܵ���Բ���߹�Կ
         OutDataPoint1: TCnEccPoint       - ������������һ
         OutDataPoint2: TCnEccPoint       - �������������

       ����ֵ�����ޣ�
    }

    procedure Decrypt(DataPoint1: TCnEccPoint; DataPoint2: TCnEccPoint;
      PrivateKey: TCnEccPrivateKey; OutPlainPoint: TCnEccPoint);
    {* ˽Կ�������ĵ㣬Ҳ���Ǽ��� C1 - k * C2 �͵õ���ԭ�ĵ� M��

       ������
         DataPoint1: TCnEccPoint          - �����ܵ����������һ
         DataPoint2: TCnEccPoint          - �����ܵ�����������
         PrivateKey: TCnEccPrivateKey     - ���ڽ��ܵ���Բ����˽Կ
         OutPlainPoint: TCnEccPoint       - ������������

       ����ֵ�����ޣ�
    }

    property Generator: TCnEccPoint read FGenerator;
    {* �������� G}
    property CoefficientA: TCnBigNumber read FCoefficientA;
    {* ����ϵ�� A}
    property CoefficientB: TCnBigNumber read FCoefficientB;
    {* ����ϵ�� B}
    property FiniteFieldSize: TCnBigNumber read FFiniteFieldSize;
    {* ��������Ͻ磬���� p}
    property Order: TCnBigNumber read FOrder;
    {* ����Ľ��� N��ע����ֻ�� H Ϊ 1 ʱ�ŵ��ڱ����ߵ��ܵ���}
    property CoFactor: Integer read FCoFactor;
    {* �������� H��Ҳ�����ܵ��� = N * H������ Integer ��ʾ��һ�㶼�� 1}
    property BitsCount: Integer read GetBitsCount;
    {* ����Բ���ߵ�������λ��}
    property BytesCount: Integer read GetBytesCount;
    {* ����Բ���ߵ��������ֽ���}
  end;

  TCnEccKeyType = (cktPKCS1, cktPKCS8);
  {* ECC ��Կ�ļ���ʽ��ע������ CnRSA �е� TCnRSAKeyType �����ظ���ʹ��ʱҪע��}

  TCnEcc2Matrix = class(TCn2DObjectList)
  {* ���� TCnEccPoint �Ķ�ά�������}
  private
    function GetValueObject(Row: Integer; Col: Integer): TCnEccPoint;
    procedure SetValueObject(Row: Integer; Col: Integer; const Value: TCnEccPoint);
  protected

  public
    constructor Create(ARow: Integer; ACol: Integer); override;
    {* ���캯����

       ������
         ARow: Integer                    - ����
         ACol: Integer                    - ����

       ����ֵ��TCnEcc2Matrix              - ���ش����Ķ���ʵ��
    }

    property ValueObject[Row, Col: Integer]: TCnEccPoint read GetValueObject write SetValueObject; default;
    {* ��ά����ֵ}
  end;

  TCnEcc3Matrix = class(TCn2DObjectList)
  {* ���� TCnEcc3Point �Ķ�ά�������}
  private
    function GetValueObject(Row: Integer; Col: Integer): TCnEcc3Point;
    procedure SetValueObject(Row: Integer; Col: Integer; const Value: TCnEcc3Point);
  protected

  public
    constructor Create(ARow: Integer; ACol: Integer); override;
    {* ���캯����

       ������
         ARow: Integer                    - ����
         ACol: Integer                    - ����

       ����ֵ��TCnEcc3Matrix              - ���ش����Ķ���ʵ��
    }

    property ValueObject[Row, Col: Integer]: TCnEcc3Point read GetValueObject write SetValueObject; default;
    {* ��ά����ֵ}
  end;

  TCnInt64PolynomialEccPoint = class(TPersistent)
  {* ���������ϵ���Բ�����ϵĶ���ʽ��������}
  private
    FY: TCnInt64Polynomial;
    FX: TCnInt64Polynomial;
    procedure SetX(const Value: TCnInt64Polynomial);
    procedure SetY(const Value: TCnInt64Polynomial);
  public
    constructor Create; overload;
    {* ���캯��}

    constructor Create(const XLowToHighCoefficients: array of const;
      const YLowToHighCoefficients: array of const); overload;
    {* ���캯����

       ������
         const XLowToHighCoefficients: array of const     - X ϵ�����飬�ӵʹε��ߴ�
         const YLowToHighCoefficients: array of const     - Y ϵ�����飬�ӵʹε��ߴ�

       ����ֵ��TCnInt64PolynomialEccPoint                 - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent              - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ����Զ��Ҳ�� 0 �㡣

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�����Զ��
    }

    procedure SetZero;
    {* ��Ϊ����Զ��Ҳ�� 0 ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ʽת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property X: TCnInt64Polynomial read FX write SetX;
    {* X �������ʽ}
    property Y: TCnInt64Polynomial read FY write SetY;
    {* Y �������ʽ}
  end;

  TCnInt64PolynomialEcc = class
  {* ����һ�������� p Ҳ���� 0 �� p - 1 �� n �η��ڵĶ���ʽ��Բ���� y^2 = x^3 + Ax + B mod p���������� Int64 ��Χ��}
  private
    FGenerator: TCnInt64PolynomialEccPoint;
    FCoefficientA: Int64;
    FCoefficientB: Int64;
    FFiniteFieldSize: Int64;
    FOrder: Int64;
    FExtension: Integer;
    FPrimitive: TCnInt64Polynomial;
    procedure SetPrimitive(const Value: TCnInt64Polynomial);
  protected

  public
    constructor Create(A: Int64; B: Int64; FieldPrime: Int64; Ext: Integer; GX: array of const;
      GY: array of const; Order: Int64; PrimitivePolynomial: array of const);
    {* ���캯�������뷽�̵� A, B �������������Ͻ� p�����������G ���������ʽ��G ��Ľ�������ԭ����ʽ

       ������
         A: Int64                                         - κ��˹����˹��Բ���߷��̵� a ����
         B: Int64                                         - κ��˹����˹��Բ���߷��̵� b ����
         FieldPrime: Int64                                - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         Ext: Integer                                     - ��������������
         GX: array of const                               - κ��˹����˹��Բ���߷��̵� G ��� X ����ϵ��
         GY: array of const                               - κ��˹����˹��Բ���߷��̵� G ��� Y ����ϵ��
         Order: Int64                                     - κ��˹����˹��Բ���߷��̵� G ��Ľ�
         const PrimitivePolynomial: array of const        - ��ԭ����ʽϵ��

       ����ֵ��TCnInt64PolynomialEcc                      - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure MultiplePoint(K: Int64; Point: TCnInt64PolynomialEccPoint);
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P��

       ������
         K: Int64                                         - ����
         Point: TCnInt64PolynomialEccPoint                - ���˵Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    procedure PointAddPoint(P: TCnInt64PolynomialEccPoint; Q: TCnInt64PolynomialEccPoint;
      Sum: TCnInt64PolynomialEccPoint);
    {* ���� P + Q��ֵ���� Sum �У�Sum ������ P��Q ֮һ��P��Q ������ͬ��

       ������
         P: TCnInt64PolynomialEccPoint    - ��һ�������Ķ���ʽ�����
         Q: TCnInt64PolynomialEccPoint    - �ڶ��������Ķ���ʽ�����
         Sum: TCnInt64PolynomialEccPoint  - ����ĺ͵Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    procedure PointSubPoint(P: TCnInt64PolynomialEccPoint; Q: TCnInt64PolynomialEccPoint;
      Diff: TCnInt64PolynomialEccPoint);
    {* ���� P - Q��ֵ���� Diff �У�Diff ������ P��Q ֮һ��P��Q ������ͬ��

       ������
         P: TCnInt64PolynomialEccPoint    - �������Ķ���ʽ�����
         Q: TCnInt64PolynomialEccPoint    - �����Ķ���ʽ�����
         Diff: TCnInt64PolynomialEccPoint - ����Ĳ�Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    procedure PointInverse(P: TCnInt64PolynomialEccPoint);
    {* ���� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         P: TCnInt64PolynomialEccPoint    - ��ȡ��Ԫ�Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    function IsPointOnCurve(P: TCnInt64PolynomialEccPoint): Boolean;
    {* �ж� P ���Ƿ��ڱ������ϡ�

       ������
         P: TCnInt64PolynomialEccPoint    - ���жϵĶ���ʽ�����

       ����ֵ��Boolean                    - �����Ƿ���������
    }

    function DivisionPolynomial(Degree: Integer; outDivisionPolynomial: TCnInt64Polynomial): Boolean;
    {* �ݹ����� Degree ���ɳ�����ʽ�����ؼ����Ƿ�ɹ���ע�����һ�����������

       ������
         Degree: Integer                                  - �ɳ�����ʽ�����
         outDivisionPolynomial: TCnInt64Polynomial        - ���صĿɳ�����ʽ

       ����ֵ��Boolean                                    - ���ؼ����Ƿ�ɹ�
    }

    class function IsPointOnCurve2(PX: TCnInt64Polynomial; PY: TCnInt64Polynomial;
      A: Int64; B: Int64; APrime: Int64; APrimitive: TCnInt64Polynomial): Boolean;
    {* �����ֱ�ӵ��õ��жϣ�PX, PY�����Ƿ��ڱ������ϣ�
       ��Բ���߲���ֱ��ָ�� A��B�������Ͻ��뱾ԭ����ʽ���������ͽ��Լ����������

       ������
         PX: TCnInt64Polynomial           - ���жϵĶ���ʽ������ X �������ʽ
         PY: TCnInt64Polynomial           - ���жϵĶ���ʽ������ Y �������ʽ
         A: Int64                         - κ��˹����˹��Բ���߷��̵� a ����
         B: Int64                         - κ��˹����˹��Բ���߷��̵� b ����
         APrime: Int64                    - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnInt64Polynomial   - ��ԭ����ʽ

       ����ֵ��Boolean                    - ���ؼ����Ƿ�ɹ�
    }

    class procedure RationalPointAddPoint(PX: TCnInt64RationalPolynomial;
      PY: TCnInt64RationalPolynomial; QX: TCnInt64RationalPolynomial;
      QY: TCnInt64RationalPolynomial; SX: TCnInt64RationalPolynomial;
      SY: TCnInt64RationalPolynomial; A: Int64; B: Int64; APrime: Int64;
      APrimitive: TCnInt64Polynomial = nil);
    {* �����ֱ�ӵ��õĵ�ӷ��������㣨PX, PY * y) �͵㣨QX, QY * y����ӣ�����ŵ���SX, SY * y�����С�
       ע�Ȿ�����в����ѳ���ת��Ϊ�˷����������ݰ���б�ʵ�������Ҫ�÷�ʽ��ʾ�����Ҳ�Է�ʽ��ʽ�����
       PX��PY��QX��QY��SX��SY ��Ϊ���ӷ�ĸΪ�� x ����ʽ�ķ�ʽ��SX��SY ������ PX��PY��QX��QY��
       ����÷���һ�㲻���ڼ������������ֵ��ֵ����Ϊ����ʱ�޷�ֱ���ж�ֵ�Ƿ���ȵ���б�ʼ�����ʵ��ֵ��ƫ�
       Schoof �㷨�У���ԭ����ʽΪָ�������Ŀɳ�����ʽ���Թ������ʽ�����������������������֤ͨ����

       ������
         PX: TCnInt64RationalPolynomial   - �����ʽ��������һ�� X ���������ʽ
         PY: TCnInt64RationalPolynomial   - �����ʽ��������һ�� Y ���������ʽ
         QX: TCnInt64RationalPolynomial   - �����ʽ������������ X ���������ʽ
         QY: TCnInt64RationalPolynomial   - �����ʽ������������ Y ���������ʽ
         SX: TCnInt64RationalPolynomial   - �͵�����ֶ���ʽ������ X ���������ʽ
         SY: TCnInt64RationalPolynomial   - �͵�����ֶ���ʽ������ Y ���������ʽ
         A: Int64                         - κ��˹����˹��Բ���߷��̵� a ����
         B: Int64                         - κ��˹����˹��Բ���߷��̵� b ����
         APrime: Int64                    - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnInt64Polynomial   - ��ԭ����ʽ

       ����ֵ�����ޣ�
    }

    class procedure RationalMultiplePoint(K: Integer; MX: TCnInt64RationalPolynomial; MY: TCnInt64RationalPolynomial;
      A: Int64; B: Int64; APrime: Int64; APrimitive: TCnInt64Polynomial = nil);
    {* �����ֱ�ӵ��õĶ౶�㷽����ʹ�ÿɳ�����ʽֱ�Ӽ���㣨x, 1 * y) �� k * P ֵ��ֵ���� MX, MY * y��
       ע�Ȿ�����в����ѳ���ת��Ϊ�˷����������ݰ���б�ʵ�������Ҫ�÷�ʽ��ʾ�����Ҳ�Է�ʽ��ʽ�����
       ��� MX �� MY ��Ϊ nil ��ʾ������ X �� Y��ֻ���㲻Ϊ nil �ġ�
       ����÷���һ�㲻���ڼ������������ֵ��ֵ����Ϊ����ʱ�޷�ֱ���ж�ֵ�Ƿ���ȵ���б�ʼ�����ʵ��ֵ��ƫ�
       Schoof �㷨�У���ԭ����ʽΪָ�������Ŀɳ�����ʽ���Թ������ʽ�����������������

       ������
         K: Integer                       - ����
         MX: TCnInt64RationalPolynomial   - �����ʽ���������� X ���������ʽ
         MY: TCnInt64RationalPolynomial   - �����ʽ���������� Y ���������ʽ
         A: Int64                         - κ��˹����˹��Բ���߷��̵� a ����
         B: Int64                         - κ��˹����˹��Բ���߷��̵� b ����
         APrime: Int64                    - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnInt64Polynomial   - ��ԭ����ʽ

       ����ֵ�����ޣ�
    }

    class function IsRationalPointOnCurve(PX: TCnInt64RationalPolynomial; PY: TCnInt64RationalPolynomial;
      A: Int64; B: Int64; APrime: Int64; APrimitive: TCnInt64Polynomial = nil): Boolean;
    {* �����ֱ�ӵ��õ��ޱ�ԭ����ʽ���жϣ�PX, PY * y�����Ƿ��ڱ������ϣ�
       ��Բ���߲���ֱ��ָ�� A��B�������Ͻ��룬���豾ԭ����ʽ������ͽ��Լ����������
       ע���������ݰ���б�ʵ����ݾ��÷�ʽ��ʾ����ʹ�б�ԭ����ʽ���ڣ�����Ҳ��ת��Ϊ�˷���

       ������
         PX: TCnInt64RationalPolynomial   - ���жϵ������ʽ������ X ���������ʽ
         PY: TCnInt64RationalPolynomial   - ���жϵ������ʽ������ Y ���������ʽ
         A: Int64                         - κ��˹����˹��Բ���߷��̵� a ����
         B: Int64                         - κ��˹����˹��Բ���߷��̵� b ����
         APrime: Int64                    - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnInt64Polynomial   - ��ԭ����ʽ

       ����ֵ��Boolean                    - �����Ƿ���������
    }

    property Generator: TCnInt64PolynomialEccPoint read FGenerator;
    {* �������� G}
    property CoefficientA: Int64 read FCoefficientA;
    {* ����ϵ�� A}
    property CoefficientB: Int64 read FCoefficientB;
    {* ����ϵ�� B}
    property FiniteFieldSize: Int64 read FFiniteFieldSize;
    {* ����������Ͻ磬���� p}
    property Extension: Integer read FExtension write FExtension;
    {* ��������Ĵ�����Ҳ������ p ��ָ��}
    property Order: Int64 read FOrder;
    {* ����Ľ���}
    property Primitive: TCnInt64Polynomial read FPrimitive write SetPrimitive;
    {* ��ԭ����ʽ}
  end;

  TCnPolynomialEccPoint = class(TPersistent)
  {* ���������ϵ���Բ�����ϵĶ���ʽ��������}
  private
    FY: TCnBigNumberPolynomial;
    FX: TCnBigNumberPolynomial;
    procedure SetX(const Value: TCnBigNumberPolynomial);
    procedure SetY(const Value: TCnBigNumberPolynomial);
  public
    constructor Create; overload;
    {* ���캯��}
    constructor Create(const XLowToHighCoefficients: array of const;
      const YLowToHighCoefficients: array of const); overload;
    {* ���캯��

       ������
         const XLowToHighCoefficients: array of const     - X ϵ�����飬�ӵʹε��ߴ�
         const YLowToHighCoefficients: array of const     - Y ϵ�����飬�ӵʹε��ߴ�

       ����ֵ��TCnPolynomialEccPoint                      - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure Assign(Source: TPersistent); override;
    {* ����������ֵ������

       ������
         Source: TPersistent              - ����֮��ֵ��Դ����

       ����ֵ�����ޣ�
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ����Զ��Ҳ�� 0 �㡣

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�����Զ��
    }

    procedure SetZero;
    {* ��Ϊ����Զ��Ҳ�� 0 ��}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ������ʽת���ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property X: TCnBigNumberPolynomial read FX write SetX;
    {* X �������ʽ}
    property Y: TCnBigNumberPolynomial read FY write SetY;
    {* Y �������ʽ}
  end;

  TCnPolynomialEcc = class
  {* ����һ�������� p Ҳ���� 0 �� p - 1 �� n �η��ڵĶ���ʽ��Բ���� y^2 = x^3 + Ax + B mod p���������Դ�����ʾ}
  private
    FGenerator: TCnPolynomialEccPoint;
    FCoefficientA: TCnBigNumber;
    FCoefficientB: TCnBigNumber;
    FFiniteFieldSize: TCnBigNumber;
    FOrder: TCnBigNumber;
    FExtension: Integer;
    FPrimitive: TCnBigNumberPolynomial;
    procedure SetPrimitive(const Value: TCnBigNumberPolynomial);
  protected

  public
    constructor Create(const A: AnsiString; const B: AnsiString; const FieldPrime: AnsiString;
      Ext: Integer; GX: TCnBigNumberPolynomial; GY: TCnBigNumberPolynomial;
      const Order: AnsiString; PrimitivePolynomial: TCnBigNumberPolynomial); overload;
    {* ���캯�������뷽�̵� A, B �������������Ͻ� p�����������G ���������ʽ��G ��Ľ�������ԭ����ʽ
       ��������������������ڲ��������в����Ķ������á��ַ�����������ʮ�������ַ�����

       ������
         const A: AnsiString                              - κ��˹����˹��Բ���߷��̵� a ����
         const B: AnsiString                              - κ��˹����˹��Բ���߷��̵� b ����
         const FieldPrime: AnsiString                     - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         Ext: Integer                                     - ��������������
         GX: TCnBigNumberPolynomial                       - κ��˹����˹��Բ���߷��̵� G ��� X ����
         GY: TCnBigNumberPolynomial                       - κ��˹����˹��Բ���߷��̵� G ��� Y ����
         const Order: AnsiString                          - κ��˹����˹��Բ���߷��̵� G ��Ľ�
         PrimitivePolynomial: TCnBigNumberPolynomial      - ��ԭ����ʽ

       ����ֵ��TCnPolynomialEcc                           - ���ش����Ķ���ʵ��
    }

    constructor Create(A: TCnBigNumber; B: TCnBigNumber; FieldPrime: TCnBigNumber;
      Ext: Integer; GX: TCnBigNumberPolynomial; GY: TCnBigNumberPolynomial;
      AnOrder: TCnBigNumber; PrimitivePolynomial: TCnBigNumberPolynomial); overload;
    {* ���캯�������뷽�̵� A, B �������������Ͻ� p�����������G ���������ʽ��G ��Ľ�������ԭ����ʽ
       ��������������������ڲ��������в����Ķ������á�

       ������
         A: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� a ����
         B: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� b ����
         FieldPrime: TCnBigNumber                         - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         Ext: Integer                                     - ��������������
         GX: TCnBigNumberPolynomial                       - κ��˹����˹��Բ���߷��̵� G ��� X ����
         GY: TCnBigNumberPolynomial                       - κ��˹����˹��Բ���߷��̵� G ��� Y ����
         AnOrder: TCnBigNumber                            - κ��˹����˹��Բ���߷��̵� G ��Ľ�
         PrimitivePolynomial: TCnBigNumberPolynomial      - ��ԭ����ʽ

       ����ֵ��TCnPolynomialEcc                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure MultiplePoint(K: Int64; Point: TCnPolynomialEccPoint); overload;
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P��

       ������
         K: Int64                         - ����
         Point: TCnPolynomialEccPoint     - ���˵������

       ����ֵ�����ޣ�
    }

    procedure MultiplePoint(K: TCnBigNumber; Point: TCnPolynomialEccPoint); overload;
    {* ����ĳ�� P �� k * P ֵ��ֵ���·��� P

       ������
         K: TCnBigNumber                  - ��������ʽΪ����
         Point: TCnPolynomialEccPoint     - ���˵������

       ����ֵ�����ޣ�
    }

    procedure PointAddPoint(P: TCnPolynomialEccPoint; Q: TCnPolynomialEccPoint;
      Sum: TCnPolynomialEccPoint);
    {* ���� P + Q��ֵ���� Sum �У�Sum ������ P��Q ֮һ��P��Q ������ͬ��

       ������
         P: TCnPolynomialEccPoint         - ��һ�������Ķ���ʽ�����
         Q: TCnPolynomialEccPoint         - �ڶ��������Ķ���ʽ�����
         Sum: TCnPolynomialEccPoint       - ����ĺ͵Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    procedure PointSubPoint(P: TCnPolynomialEccPoint; Q: TCnPolynomialEccPoint;
      Diff: TCnPolynomialEccPoint);
    {* ���� P - Q��ֵ���� Diff �У�Diff ������ P��Q ֮һ��P��Q ������ͬ

       ������
         P: TCnPolynomialEccPoint         - �������Ķ���ʽ�����
         Q: TCnPolynomialEccPoint         - �����Ķ���ʽ�����
         Diff: TCnPolynomialEccPoint      - ����Ĳ�Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    procedure PointInverse(P: TCnPolynomialEccPoint);
    {* ���� P ��ļӷ���Ԫ -P��ֵ���·��� P��

       ������
         P: TCnPolynomialEccPoint         - ��ȡ��Ԫ�Ķ���ʽ�����

       ����ֵ�����ޣ�
    }

    function IsPointOnCurve(P: TCnPolynomialEccPoint): Boolean;
    {* �ж� P ���Ƿ��ڱ������ϡ�

       ������
         P: TCnPolynomialEccPoint         - ���жϵĶ���ʽ�����

       ����ֵ��Boolean                    - �����Ƿ���������
    }

    function DivisionPolynomial(Degree: Integer; outDivisionPolynomial: TCnBigNumberPolynomial): Boolean;
    {* �ݹ����� Degree ���ɳ�����ʽ�����ؼ����Ƿ�ɹ���ע�����һ�����������

       ������
         Degree: Integer                                  - �ɳ�����ʽ�����
         outDivisionPolynomial: TCnBigNumberPolynomial    - ���صĿɳ�����ʽ

       ����ֵ��Boolean                                    - ���ؼ����Ƿ�ɹ�
    }

    class function IsPointOnCurve2(PX: TCnBigNumberPolynomial; PY: TCnBigNumberPolynomial;
      A: TCnBigNumber; B: TCnBigNumber; APrime: TCnBigNumber; APrimitive: TCnBigNumberPolynomial): Boolean;
    {* �����ֱ�ӵ��õ��жϣ�PX, PY�����Ƿ��ڱ������ϣ�
       ��Բ���߲���ֱ��ָ�� A��B�������Ͻ��뱾ԭ����ʽ���������ͽ��Լ����������

       ������
         PX: TCnBigNumberPolynomial                       - ���жϵĶ���ʽ������ X �������ʽ
         PY: TCnBigNumberPolynomial                       - ���жϵĶ���ʽ������ Y �������ʽ
         A: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� a ����
         B: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� b ����
         APrime: TCnBigNumber                             - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnBigNumberPolynomial               - ��ԭ����ʽ

       ����ֵ��Boolean                                    - ���ؼ����Ƿ�ɹ�
    }

    class procedure RationalPointAddPoint(PX: TCnBigNumberRationalPolynomial;
      PY: TCnBigNumberRationalPolynomial; QX: TCnBigNumberRationalPolynomial;
      QY: TCnBigNumberRationalPolynomial; SX: TCnBigNumberRationalPolynomial;
      SY: TCnBigNumberRationalPolynomial; A: TCnBigNumber; B: TCnBigNumber;
      APrime: TCnBigNumber; APrimitive: TCnBigNumberPolynomial = nil);
    {* �����ֱ�ӵ��õĵ�ӷ��������㣨PX, PY * y) �͵㣨QX, QY * y����ӣ�����ŵ���SX, SY * y�����С�
       ע�Ȿ�����в����ѳ���ת��Ϊ�˷����������ݰ���б�ʵ�������Ҫ�÷�ʽ��ʾ�����Ҳ�Է�ʽ��ʽ�����
       PX��PY��QX��QY��SX��SY��Ϊ���ӷ�ĸΪ�� x ����ʽ�ķ�ʽ��SX��SY ������ PX��PY��QX��QY��
       ����÷���һ�㲻���ڼ������������ֵ��ֵ����Ϊ����ʱ�޷�ֱ���ж�ֵ�Ƿ���ȵ���б�ʼ�����ʵ��ֵ��ƫ�
       Schoof �㷨�У���ԭ����ʽΪָ�������Ŀɳ�����ʽ���Թ������ʽ�����������������������֤ͨ����

       ������
         PX: TCnBigNumberRationalPolynomial               - �����ʽ��������һ�� X ���������ʽ
         PY: TCnBigNumberRationalPolynomial               - �����ʽ��������һ�� Y ���������ʽ
         QX: TCnBigNumberRationalPolynomial               - �����ʽ������������ X ���������ʽ
         QY: TCnBigNumberRationalPolynomial               - �����ʽ������������ Y ���������ʽ
         SX: TCnBigNumberRationalPolynomial               - �͵�����ֶ���ʽ������ X ���������ʽ
         SY: TCnBigNumberRationalPolynomial               - �͵�����ֶ���ʽ������ Y ���������ʽ
         A: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� a ����
         B: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� b ����
         APrime: TCnBigNumber                             - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnBigNumberPolynomial               - ��ԭ����ʽ

       ����ֵ�����ޣ�
    }

    class procedure RationalMultiplePoint(K: Integer; MX: TCnBigNumberRationalPolynomial;
      MY: TCnBigNumberRationalPolynomial; A: TCnBigNumber; B: TCnBigNumber; APrime: TCnBigNumber;
      APrimitive: TCnBigNumberPolynomial = nil); overload;
    {* �����ֱ�ӵ��õĶ౶�㷽����ʹ�ÿɳ�����ʽֱ�Ӽ���㣨x, 1 * y) �� k * P ֵ��ֵ���� MX, MY * y
       ע�Ȿ�����в����ѳ���ת��Ϊ�˷����������ݰ���б�ʵ�������Ҫ�÷�ʽ��ʾ�����Ҳ�Է�ʽ��ʽ�����
       PX��PY��QX��QY��SX��SY��Ϊ���ӷ�ĸΪ�� x ����ʽ�ķ�ʽ����SX��SY ������ PX��PY��QX��QY��
       ����÷���һ�㲻���ڼ������������ֵ��ֵ����Ϊ����ʱ�޷�ֱ���ж�ֵ�Ƿ���ȵ���б�ʼ�����ʵ��ֵ��ƫ�
       Schoof �㷨�У���ԭ����ʽΪָ�������Ŀɳ�����ʽ���Թ������ʽ�����������������

       ������
         K: Integer                                       - ����
         MX: TCnBigNumberRationalPolynomial               - �����ʽ���������� X ���������ʽ
         MY: TCnBigNumberRationalPolynomial               - �����ʽ���������� Y ���������ʽ
         A: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� a ����
         B: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� b ����
         APrime: TCnBigNumber                             - κ��˹����˹��Բ���߷������ڵ��������Ͻ�
         APrimitive: TCnBigNumberPolynomial               - ��ԭ����ʽ

       ����ֵ�����ޣ�
    }

    class function IsRationalPointOnCurve(PX: TCnBigNumberRationalPolynomial;
      PY: TCnBigNumberRationalPolynomial; A: TCnBigNumber; B: TCnBigNumber; APrime: TCnBigNumber): Boolean;
    {* �����ֱ�ӵ��õ��ޱ�ԭ����ʽ���жϣ�PX, PY * y�����Ƿ��ڱ������ϣ�
       ��Բ���߲���ֱ��ָ�� A��B�������Ͻ��룬���豾ԭ����ʽ������ͽ��Լ����������
       ע�����ޱ�ԭ����ʽ������£������޷�ת��Ϊ�˷����������ݰ���б�ʵ�������Ҫ�÷�ʽ��ʾ��

       ������
         PX: TCnBigNumberRationalPolynomial               - ���жϵ������ʽ������ X ���������ʽ
         PY: TCnBigNumberRationalPolynomial               - ���жϵ������ʽ������ Y ���������ʽ
         A: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� a ����
         B: TCnBigNumber                                  - κ��˹����˹��Բ���߷��̵� b ����
         APrime: TCnBigNumber                             - κ��˹����˹��Բ���߷������ڵ��������Ͻ�

       ����ֵ��Boolean                                    - �����Ƿ���������
    }

    property Generator: TCnPolynomialEccPoint read FGenerator;
    {* �������� G}
    property CoefficientA: TCnBigNumber read FCoefficientA;
    {* ����ϵ�� A}
    property CoefficientB: TCnBigNumber read FCoefficientB;
    {* ����ϵ�� B}
    property FiniteFieldSize: TCnBigNumber read FFiniteFieldSize;
    {* ����������Ͻ磬���� p}
    property Extension: Integer read FExtension write FExtension;
    {* ��������Ĵ�����Ҳ������ p ��ָ��}
    property Order: TCnBigNumber read FOrder;
    {* ����Ľ���}
    property Primitive: TCnBigNumberPolynomial read FPrimitive write SetPrimitive;
    {* ��ԭ����ʽ}
  end;

function CnInt64EccPointToString(var P: TCnInt64EccPoint): string;
{* ��һ�� TCnInt64EccPoint �����ת��Ϊ�ַ�����

   ������
     var P: TCnInt64EccPoint              - ��ת���������

   ����ֵ��string                         - �����ַ���
}

function CnInt64EccSchoof(A: Int64; B: Int64; Q: Int64): Int64;
{* �� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�������
   Q ���֧�� Sqrt(2 * Max UInt64)���Դ��� Max UInt32��
   Schoof �㷨�������汾��˼��һ������������̲�ͬ��
   һ�������õ�Ķ����ʽ���������Լ����ڿɳ�����ʽ���Ͻ�������ѭ�����㣬�Ƚ�����
   һ�����ж�ʱ���ø��ַ��ӵ������ʽ�Լ�����������

   ������
     A: Int64                             - κ��˹����˹��Բ���߷��̵� a ����
     B: Int64                             - κ��˹����˹��Բ���߷��̵� b ����
     Q: Int64                             - κ��˹����˹��Բ���߷������ڵ��������Ͻ�

   ����ֵ��Int64                          - ���ص�����
}

function CnEccPointToString(P: TCnEccPoint): string;
{* ��һ�� TCnEccPoint ������ת��Ϊʮ�����ַ�����

   ������
     P: TCnEccPoint                       - ��ת���������

   ����ֵ��string                         - ����ʮ�����ַ���
}

function CnEccPointToHex(P: TCnEccPoint): string;
{* ��һ�� TCnEccPoint ������ת��Ϊʮ�������ַ�����

   ������
     P: TCnEccPoint                       - ��ת���������

   ����ֵ��string                         - ����ʮ�������ַ���
}

function CnInt64Ecc3PointToString(var P: TCnInt64Ecc3Point): string;
{* ��һ�� TCnInt64Ecc3Point ������ת��Ϊ�ַ�����

   ������
     var P: TCnInt64Ecc3Point             - ��ת���������

   ����ֵ��string                         - �����ַ���
}

function CnEcc3PointToString(P: TCnEcc3Point): string;
{* ��һ�� TCnEcc3Point ������ת��Ϊʮ�����ַ�����

   ������
     P: TCnEcc3Point                      - ��ת���������

   ����ֵ��string                         - ����ʮ�����ַ���
}

function CnEcc3PointToHex(P: TCnEcc3Point): string;
{* ��һ�� TCnEcc3Point ������ת��Ϊʮ�������ַ�����

   ������
     P: TCnEcc3Point                      - ��ת���������

   ����ֵ��string                         - ����ʮ�������ַ���
}

function CnAffineEcc3PointEqual(P1: TCnEcc3Point; P2: TCnEcc3Point; Prime: TCnBigNumber = nil): Boolean;
{* �ж����� TCnEcc3Point ���Ƿ���ȣ��� Prime Ϊ nil ��ֻ�ж�ֵ������ Z �ĳ�����
   ���������Ӱ���������жϡ�

   ������
     P1: TCnEcc3Point                     - ���Ƚϵ������һ
     P2: TCnEcc3Point                     - ���Ƚϵ�������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ����
}

function CnEccSchoof(Res: TCnBigNumber; A: TCnBigNumber; B: TCnBigNumber; Q: TCnBigNumber): Boolean;
{* �� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�����������֧�ִ�����

   ������
     Res: TCnBigNumber                    - ���ص�����
     A: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� b ����
     Q: TCnBigNumber                      - κ��˹����˹��Բ���߷������ڵ��������Ͻ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnEccSchoof2(Res: TCnBigNumber; A: TCnBigNumber; B: TCnBigNumber; Q: TCnBigNumber): Boolean;
{* �� Wikipedia �ϵĸĽ��� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�����������֧�ִ�����
   �����ٶȽ������ԭʼ�汾������������

   ������
     Res: TCnBigNumber                    - ���ص�����
     A: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� b ����
     Q: TCnBigNumber                      - κ��˹����˹��Բ���߷������ڵ��������Ͻ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnEccFastSchoof(Res: TCnBigNumber; A: TCnBigNumber; B: TCnBigNumber;
  Q: TCnBigNumber): Boolean; {$IFDEF SUPPORT_DEPRECATED} deprecated; {$ENDIF}
{* ����ǿ�� GCD �� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�����������֧�ִ�����
   TODO: P16 �������ͨ����P19X, P19Y ������֤δͨ��������Ͷ��ʵ��ʹ�á�

   ������
     Res: TCnBigNumber                    - ���ص�����
     A: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� b ����
     Q: TCnBigNumber                      - κ��˹����˹��Բ���߷������ڵ��������Ͻ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnInt64EccGenerateParams(out FiniteFieldSize: Int64; out CoefficientA: Int64;
  out CoefficientB: Int64; out GX: Int64; out GY: Int64; out Order: Int64): Boolean;
{* ������Բ���� y^2 = x^3 + Ax + B mod p �ĸ�����������������ʵ�֣�ֻ��������ϵ����С�ġ�

   ������
     out FiniteFieldSize: Int64           - ���ɵ�κ��˹����˹��Բ���߷��̵��������Ͻ�
     out CoefficientA: Int64              - ���ɵ�κ��˹����˹��Բ���߷��̵� a ����
     out CoefficientB: Int64              - ���ɵ�κ��˹����˹��Բ���߷��̵� a ����
     out GX: Int64                        - ���ɵ�κ��˹����˹��Բ���߷��̵� G ��� X ����
     out GY: Int64                        - ���ɵ�κ��˹����˹��Բ���߷��̵� G ��� Y ����
     out Order: Int64                     - ���ɵ�κ��˹����˹��Բ���߷��̵� G ��Ľ�

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnInt64EccDiffieHellmanGenerateOutKey(Ecc: TCnInt64Ecc; SelfPrivateKey: TCnInt64PrivateKey;
  out PublicKey: TCnInt64PublicKey): Boolean;
{* ��������ѡ�������� PrivateKey ���� ECDH ��ԿЭ�̵������Կ����㣬˫��������á�
   ���� OutPublicKey = SelfPrivateKey * G��

   ������
     Ecc: TCnInt64Ecc                     - ��ԿЭ���������Բ����ʵ��
     SelfPrivateKey: TCnInt64PrivateKey   - �������Բ����˽Կ
     out PublicKey: TCnInt64PublicKey     - �������Բ���߹�Կ����㣬�贫�����Է�

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnInt64EccDiffieHellmanComputeKey(Ecc: TCnInt64Ecc; SelfPrivateKey: TCnInt64PrivateKey;
  var OtherPublicKey: TCnInt64PublicKey; var SharedSecretKey: TCnInt64PublicKey): Boolean;
{* ���ݶԷ����͵� ECDH ��ԿЭ�̵������Կ�������ɹ�����Կ����㣬˫��������á�
   ���� SecretKey = SelfPrivateKey * OtherPublicKey��

   ������
     Ecc: TCnInt64Ecc                                     - ��ԿЭ���������Բ����ʵ��
     SelfPrivateKey: TCnInt64PrivateKey                   - �������Բ����˽Կ
     var OtherPublicKey: TCnInt64PublicKey                - �ɶԷ����ɲ������������Բ���߹�Կ
     var SharedSecretKey: TCnInt64PublicKey               - Э������Ĺ�����Կ�����

   ����ֵ��Boolean                                        - ����Э���Ƿ�ɹ�
}

function CnInt64EccPointsEqual(var P1: TCnInt64EccPoint; var P2: TCnInt64EccPoint): Boolean;
{* �ж����� TCnInt64EccPoint ���Ƿ���ȡ�

   ������
     var P1: TCnInt64EccPoint             - ���Ƚϵ������һ
     var P2: TCnInt64EccPoint             - ���Ƚϵ�������

   ����ֵ��Boolean                        - �����Ƿ����
}

function CnEccPointsEqual(P1: TCnEccPoint; P2: TCnEccPoint): Boolean;
{* �ж����� TCnEccPoint ���Ƿ���ȡ�

   ������
     P1: TCnEccPoint                      - ���Ƚϵ������һ
     P2: TCnEccPoint                      - ���Ƚϵ�������

   ����ֵ��Boolean                        - �����Ƿ����
}

function CnPolynomialEccPointToString(P: TCnPolynomialEccPoint): string;
{* ��һ�� TCnPolynomialEccPoint ����ʽ�����ת��Ϊ�ַ�����

   ������
     P: TCnPolynomialEccPoint             - ��ת���Ķ���ʽ�����

   ����ֵ��string                         - �����ַ���
}

function CnPolynomialEccPointsEqual(P1: TCnPolynomialEccPoint; P2: TCnPolynomialEccPoint): Boolean;
{* �ж����� TCnPolynomialEccPoint ����ʽ������Ƿ���ȡ�

   ������
     P1: TCnPolynomialEccPoint            - ���ȽϵĶ���ʽ�����һ
     P2: TCnPolynomialEccPoint            - ���ȽϵĶ���ʽ������

   ����ֵ��Boolean                        - �����Ƿ����
}

function CnEccDiffieHellmanGenerateOutKey(Ecc: TCnEcc; SelfPrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey): Boolean;
{* ��������ѡ�������� PrivateKey ���� ECDH ��ԿЭ�̵������Կ����㣬˫��������á�
   ���� PublicKey = SelfPrivateKey * G��

   ������
     Ecc: TCnEcc                          - ��ԿЭ���������Բ����ʵ��
     SelfPrivateKey: TCnEccPrivateKey     - �������Բ����˽Կ
     PublicKey: TCnEccPublicKey           - �������Բ���߹�Կ����㣬�贫�����Է�

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnEccDiffieHellmanComputeKey(Ecc: TCnEcc; SelfPrivateKey: TCnEccPrivateKey;
  OtherPublicKey: TCnEccPublicKey; SharedSecretKey: TCnEccPublicKey): Boolean;
{* ���ݶԷ����͵� ECDH ��ԿЭ�̵������Կ�������ɹ�����Կ����㣬һ���õ�� X ����������Կ��˫��������á�
   ���� SecretKey = SelfPrivateKey * OtherPublicKey

   ������
     Ecc: TCnEcc                          - ��ԿЭ���������Բ����ʵ��
     SelfPrivateKey: TCnEccPrivateKey     - �������Բ����˽Կ
     OtherPublicKey: TCnEccPublicKey      - �ɶԷ����ɲ������������Բ���߹�Կ
     SharedSecretKey: TCnEccPublicKey     - Э������Ĺ�����Կ�����

   ����ֵ��Boolean                        - ����Э���Ƿ�ɹ�
}

function CnInt64EccPointToEcc3Point(var P: TCnInt64EccPoint; var P3: TCnInt64Ecc3Point): Boolean;
{* Int64 ��Χ�ڵ���ͨ����㵽������ſɱ�������ת������ͬ�� CnInt64EccPointToAffinePoint �� CnInt64EccPointToJacobianPoint��

   ������
     var P: TCnInt64EccPoint              - ��ת������ͨ�����
     var P3: TCnInt64Ecc3Point            - ����ķ����������ſɱ������

   ����ֵ��Boolean                        - ����ת���Ƿ�ɹ�
}

function CnInt64AffinePointToEccPoint(var P3: TCnInt64Ecc3Point;
  var P: TCnInt64EccPoint; Prime: Int64): Boolean;
{* Int64 ��Χ�ڵķ�������㵽��ͨ������ת����

   ������
     var P3: TCnInt64Ecc3Point            - ��ת���ķ��������
     var P: TCnInt64EccPoint              - �������ͨ�����
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Boolean                        - ����ת���Ƿ�ɹ�
}

function CnInt64JacobianPointToEccPoint(var P3: TCnInt64Ecc3Point;
  var P: TCnInt64EccPoint; Prime: Int64): Boolean;
{* Int64 ��Χ�ڵ��ſɱ�����㵽��ͨ������ת����

   ������
     var P3: TCnInt64Ecc3Point            - ��ת�����ſɱ������
     var P: TCnInt64EccPoint              - �������ͨ�����
     Prime: Int64                         - �������Ͻ�

   ����ֵ��Boolean                        - ����ת���Ƿ�ɹ�
}

function CnEccPointToEcc3Point(P: TCnEccPoint; P3: TCnEcc3Point): Boolean;
{* ������Χ�ڵ���ͨ����㵽������ſɱ�������ת������ͬ�� CnEccPointToAffinePoint �� CnEccPointToJacobianPoint��

   ������
     P: TCnEccPoint                       - ��ת������ͨ�����
     P3: TCnEcc3Point                     - ����ķ����������ſɱ������

   ����ֵ��Boolean                        - ����ת���Ƿ�ɹ�
}

function CnAffinePointToEccPoint(P3: TCnEcc3Point; P: TCnEccPoint; Prime: TCnBigNumber): Boolean;
{* ������Χ�ڵķ�������㵽��ͨ������ת����

   ������
     P3: TCnEcc3Point                     - ��ת���ķ��������
     P: TCnEccPoint                       - �������ͨ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - ����ת���Ƿ�ɹ�
}

function CnJacobianPointToEccPoint(P3: TCnEcc3Point; P: TCnEccPoint; Prime: TCnBigNumber): Boolean;
{* ������Χ�ڵ��ſɱ�����㵽��ͨ������ת����

   ������
     P3: TCnEcc3Point                     - ��ת�����ſɱ������
     P: TCnEccPoint                       - �������ͨ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - ����ת���Ƿ�ɹ�
}

function CnEccPointToStream(P: TCnEccPoint; Stream: TStream; FixedLen: Integer = 0): Integer;
{* ��һ��Բ��������������д����������д�볤�ȡ�
   FixedLen ��ʾ��Բ���ߵ��ڴ������ݲ��� FixedLen �ֽڳ���ʱ��λ���� 0��
   �Ա�֤ Stream ������̶� FixedLen �ĳ��ȣ��ڲ��������ȳ��� FixedLen ʱ������ʵ�ʳ���д��

   ������
     P: TCnEccPoint                       - ��д�����Բ���������
     Stream: TStream                      - ��д�����
     FixedLen: Integer                    - ָ�����ݵĹ̶��ֽڳ��ȣ��������λ�� 0

   ����ֵ��Integer                        - ����д���ʵ���ֽ���
}

function CnEccVerifyKeys(Ecc: TCnEcc; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey): Boolean; overload;
{* У��ĳ��Բ���ߵĹ�˽Կ�Ƿ���ԡ�

   ������
     Ecc: TCnEcc                          - ����У�����Բ����ʵ��
     PrivateKey: TCnEccPrivateKey         - ��У�����Բ����˽Կ
     PublicKey: TCnEccPublicKey           - ��У�����Բ���߹�Կ

   ����ֵ��Boolean                        - ����У���Ƿ�ɹ�
}

function CnEccVerifyKeys(CurveType: TCnEccCurveType; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey): Boolean; overload;
{* У��ĳ��Բ���ߵĹ�˽Կ�Ƿ���ԡ�

   ������
     CurveType: TCnEccCurveType           - ��У�����Բ��������
     PrivateKey: TCnEccPrivateKey         - ��У�����Բ����˽Կ
     PublicKey: TCnEccPublicKey           - ��У�����Բ���߹�Կ

   ����ֵ��Boolean                        - ����У���Ƿ�ɹ�
}

// ======================= ��Բ������Կ PEM ��дʵ�� ===========================

function CnEccLoadKeysFromPem(const PemFileName: string; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* �� PEM ��ʽ���ļ��м��ع�˽Կ���ݣ���ĳԿ����Ϊ�������롣

   ������
     const PemFileName: string            - �����ص� PEM �ļ���
     PrivateKey: TCnEccPrivateKey         - ���غ�����ݴ������Բ����˽Կ
     PublicKey: TCnEccPublicKey           - ���غ�����ݴ������Բ���߹�Կ
     out CurveType: TCnEccCurveType       - ���غ����Բ��������
     KeyHashMethod: TCnKeyHashMethod      - PEM �ļ�����ܣ��˴�Ӧ����Ӧ�ļ����Ӵ��㷨��Ĭ�� MD5���޷����� PEM �����Զ��ж�
     const Password: string               - PEM �ļ�����ܣ��˴�Ӧ����Ӧ������

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnEccLoadKeysFromPem(PemStream: TStream; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* �� PEM ��ʽ�����м��ع�˽Կ���ݣ���ĳԿ����Ϊ�������롣

   ������
     PemStream: TStream                   - �����ص� PEM ��ʽ����
     PrivateKey: TCnEccPrivateKey         - ���غ�����ݴ������Բ����˽Կ
     PublicKey: TCnEccPublicKey           - ���غ�����ݴ������Բ���߹�Կ
     out CurveType: TCnEccCurveType       - ���غ����Բ��������
     KeyHashMethod: TCnKeyHashMethod      - PEM ������ܣ��˴�Ӧ����Ӧ�ļ����Ӵ��㷨��Ĭ�� MD5���޷����� PEM �����Զ��ж�
     const Password: string               - PEM ������ܣ��˴�Ӧ����Ӧ������

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnEccSaveKeysToPem(const PemFileName: string; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType; KeyType: TCnEccKeyType = cktPKCS1;
  KeyEncryptMethod: TCnKeyEncryptMethod = ckeNone;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* ����˽Կд�� PEM ��ʽ���ļ��У������Ƿ�ɹ���

   ������
     const PemFileName: string                            - ������� PEM �ļ���
     PrivateKey: TCnEccPrivateKey                         - ���������Բ����˽Կ
     PublicKey: TCnEccPublicKey                           - ���������Բ���߹�Կ
     CurveType: TCnEccCurveType                           - ���������Բ��������
     KeyType: TCnEccKeyType                               - ����� PEM ��ʽ���ͣ�Ĭ�� PKCS1
     KeyEncryptMethod: TCnKeyEncryptMethod                - ����� PEM �ļ��ļ���ģʽ��Ĭ�ϲ����ܣ������Ժ���Ĳ���
     KeyHashMethod: TCnKeyHashMethod                      - ����� PEM �ļ����Ӵ�ģʽ��Ĭ�� MD5
     const Password: string                               - ����� PEM �ļ�������ܣ��˴�Ӧ���������룬�粻���������贫

   ����ֵ��Boolean                                        - ���ر����Ƿ�ɹ�
}

function CnEccSaveKeysToPem(PemStream: TStream; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType; KeyType: TCnEccKeyType = cktPKCS1;
  KeyEncryptMethod: TCnKeyEncryptMethod = ckeNone;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* ����˽Կд�� PEM ��ʽ�����У������Ƿ�ɹ���

   ������
     PemStream: TStream                                   - ������� PEM ��ʽ����
     PrivateKey: TCnEccPrivateKey                         - ���������Բ����˽Կ
     PublicKey: TCnEccPublicKey                           - ���������Բ���߹�Կ
     CurveType: TCnEccCurveType                           - ���������Բ��������
     KeyType: TCnEccKeyType                               - ����� PEM ��ʽ���ͣ�Ĭ�� PKCS1
     KeyEncryptMethod: TCnKeyEncryptMethod                - ����� PEM ���ļ���ģʽ��Ĭ�ϲ����ܣ������Ժ���Ĳ���
     KeyHashMethod: TCnKeyHashMethod                      - ����� PEM �����Ӵ�ģʽ��Ĭ�� MD5
     const Password: string                               - ����� PEM ��������ܣ��˴�Ӧ���������룬�粻���������贫

   ����ֵ��Boolean                                        - ���ر����Ƿ�ɹ�
}

function CnEccLoadPublicKeyFromPem(const PemFileName: string;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* �� PEM ��ʽ���ļ��м��ع�Կ���ݣ������Ƿ�ɹ���

   ������
     const PemFileName: string            - �����ص� PEM �ļ���
     PublicKey: TCnEccPublicKey           - ���غ�����ݴ������Բ���߹�Կ
     out CurveType: TCnEccCurveType       - ���غ����Բ��������
     KeyHashMethod: TCnKeyHashMethod      - PEM �ļ�����ܣ��˴�Ӧ����Ӧ�ļ����Ӵ��㷨��Ĭ�� MD5���޷����� PEM �����Զ��ж�
     const Password: string               - PEM �ļ�����ܣ��˴�Ӧ����Ӧ������

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnEccLoadPublicKeyFromPem(PemStream: TStream;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* �� PEM ��ʽ�����м��ع�Կ���ݣ������Ƿ�ɹ���

   ������
     PemStream: TStream                   - �����ص� PEM ��ʽ����
     PublicKey: TCnEccPublicKey           - ���غ�����ݴ������Բ���߹�Կ
     out CurveType: TCnEccCurveType       - ���غ����Բ��������
     KeyHashMethod: TCnKeyHashMethod      - PEM ������ܣ��˴�Ӧ����Ӧ�ļ����Ӵ��㷨��Ĭ�� MD5���޷����� PEM �����Զ��ж�
     const Password: string               - PEM ������ܣ��˴�Ӧ����Ӧ������

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CnEccSavePublicKeyToPem(const PemFileName: string;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType;
  KeyType: TCnEccKeyType = cktPKCS1; KeyEncryptMethod: TCnKeyEncryptMethod = ckeNone;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* ����Կд�� PEM ��ʽ���ļ��У������Ƿ�ɹ���

   ������
     const PemFileName: string                            - ������� PEM �ļ���
     PublicKey: TCnEccPublicKey                           - ���������Բ���߹�Կ
     CurveType: TCnEccCurveType                           - ���������Բ��������
     KeyType: TCnEccKeyType                               - ����� PEM ��ʽ���ͣ�Ĭ�� PKCS1
     KeyEncryptMethod: TCnKeyEncryptMethod                - ����� PEM �ļ��ļ���ģʽ��Ĭ�ϲ����ܣ������Ժ���Ĳ���
     KeyHashMethod: TCnKeyHashMethod                      - ����� PEM �ļ����Ӵ�ģʽ��Ĭ�� MD5
     const Password: string                               - ����� PEM �ļ�������ܣ��˴�Ӧ���������룬�粻���������贫

   ����ֵ��Boolean                                        - ���ر����Ƿ�ɹ�
}

function CnEccSavePublicKeyToPem(PemStream: TStream;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType;
  KeyType: TCnEccKeyType = cktPKCS1; KeyEncryptMethod: TCnKeyEncryptMethod = ckeNone;
  KeyHashMethod: TCnKeyHashMethod = ckhMd5; const Password: string = ''): Boolean; overload;
{* ����Կд�� PEM ��ʽ�����У������Ƿ�ɹ���

   ������
     PemStream: TStream                                   - ������� PEM ��ʽ����
     PublicKey: TCnEccPublicKey                           - ���������Բ���߹�Կ
     CurveType: TCnEccCurveType                           - ���������Բ��������
     KeyType: TCnEccKeyType                               - ����� PEM ��ʽ���ͣ�Ĭ�� PKCS1
     KeyEncryptMethod: TCnKeyEncryptMethod                - ����� PEM ���ļ���ģʽ��Ĭ�ϲ����ܣ������Ժ���Ĳ���
     KeyHashMethod: TCnKeyHashMethod                      - ����� PEM �����Ӵ�ģʽ��Ĭ�� MD5
     const Password: string                               - ����� PEM ��������ܣ��˴�Ӧ���������룬�粻���������贫

   ����ֵ��Boolean                                        - ���ر����Ƿ�ɹ�
}

// ========================= ECC �ļ�ǩ������֤ʵ�� ============================
//
// �����ļ��ֿ�ʵ������Ϊ�����ļ�ժҪʱ֧�ִ��ļ����� FileStream �Ͱ汾��֧��
// ע�� ECC ǩ����֤�������� RSA �������ܺ�ȶԼ��ܽ�ȥ���Ӵ�ֵ
// ���Ǳȶ��м����Ĵ�����ECC ǩ�����ݲ���������ǩ��ʱ��ԭԭʼ�Ӵ�ֵ
//
// =============================================================================

function CnEccSignFile(const InFileName: string; const OutSignFileName: string; Ecc: TCnEcc;
  PrivateKey: TCnEccPrivateKey; SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��˽Կǩ��ָ���ļ���Ecc ����ҪԤ��ָ�����ߡ�
   ʹ��ָ������ժҪ�㷨���ļ����м���õ��Ӵ�ֵ���ٽ�ԭʼ�Ķ������Ӵ�ֵ���� BER ������ PKCS1 ���룬����˽Կ���ܡ�

   ������
     const InFileName: string             - ��ǩ�����ļ���
     const OutSignFileName: string        - ǩ�����ݱ��������ļ���
     Ecc: TCnEcc                          - ����ǩ������Բ����ʵ��
     PrivateKey: TCnEccPrivateKey         - ����ǩ������Բ����˽Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ�����

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnEccSignFile(const InFileName: string; const OutSignFileName: string; CurveType: TCnEccCurveType;
  PrivateKey: TCnEccPrivateKey; SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��˽Կǩ��ָ���ļ���ʹ��Ԥ�������ߡ�
   ʹ��ָ������ժҪ�㷨���ļ����м���õ��Ӵ�ֵ���ٽ�ԭʼ�Ķ������Ӵ�ֵ���� BER ������ PKCS1 ���룬����˽Կ���ܡ�

   ������
     const InFileName: string             - ��ǩ�����ļ���
     const OutSignFileName: string        - ǩ�����ݱ��������ļ���
     CurveType: TCnEccCurveType           - ����ǩ������Բ��������
     PrivateKey: TCnEccPrivateKey         - ����ǩ������Բ����˽Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ�����

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnEccVerifyFile(const InFileName: string; const InSignFileName: string; Ecc: TCnEcc;
  PublicKey: TCnEccPublicKey; SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* �ù�Կ��ǩ��ֵ��ָ֤���ļ���Ҳ����ָ������ժҪ�㷨���ļ����м���õ��Ӵ�ֵ��
   ���ù�Կ����ǩ�����ݲ��⿪ PKCS1 �����ٽ⿪ BER ����õ��Ӵ��㷨���Ӵ�ֵ��
   ���ȶ������������Ӵ�ֵ�Ƿ���ͬ��������֤�Ƿ�ͨ����
   Ecc ����ҪԤ��ָ�����ߡ�

   ������
     const InFileName: string             - ����֤���ļ���
     const InSignFileName: string         - ����֤��ǩ���ļ�
     Ecc: TCnEcc                          - ������֤����Բ����ʵ��
     PublicKey: TCnEccPublicKey           - ������֤����Բ���߹�Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ���ļ�����һ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnEccVerifyFile(const InFileName: string; const InSignFileName: string; CurveType: TCnEccCurveType;
  PublicKey: TCnEccPublicKey; SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��Ԥ���������빫Կ��ǩ��ֵ��ָ֤���ļ���Ҳ����ָ������ժҪ�㷨���ļ����м���õ��Ӵ�ֵ��
   ���ù�Կ����ǩ�����ݲ��⿪ PKCS1 �����ٽ⿪ BER ����õ��Ӵ��㷨���Ӵ�ֵ��
   ���ȶ������������Ӵ�ֵ�Ƿ���ͬ��������֤�Ƿ�ͨ��

   ������
     const InFileName: string             - ����֤���ļ���
     const InSignFileName: string         - ����֤��ǩ���ļ�
     CurveType: TCnEccCurveType           - ������֤����Բ��������
     PublicKey: TCnEccPublicKey           - ������֤����Բ���߹�Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ���ļ�����һ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnEccRecoverPublicKeyFromFile(const InFileName: string; const InSignFileName: string;
  Ecc: TCnEcc; OutPublicKey1: TCnEccPublicKey; OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��ָ���ļ�����ǩ���ļ��л�ԭ��Բ���߹�Կֵ����һ��һż������Ecc ����ҪԤ��ָ�����ߡ�

   ������
     const InFileName: string             - ��ǩ���������ļ���
     const InSignFileName: string         - ǩ���ļ�
     Ecc: TCnEcc                          - ���ڻ�ԭ����Բ����ʵ��
     OutPublicKey1: TCnEccPublicKey       - ��ԭ����Բ���߹�Կһ
     OutPublicKey2: TCnEccPublicKey       - ��ԭ����Բ���߹�Կ��
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ���ļ�����һ��

   ����ֵ��Boolean                        - ���ػ�ԭ�Ƿ�ɹ�
}

function CnEccRecoverPublicKeyFromFile(const InFileName: string; const InSignFileName: string;
  CurveType: TCnEccCurveType; OutPublicKey1: TCnEccPublicKey; OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��Ԥ�������ߴ�ָ���ļ�����ǩ���ļ��л�ԭ��Բ���߹�Կֵ����һ��һż������

   ������
     const InFileName: string             - ��ǩ���������ļ���
     const InSignFileName: string         - ǩ���ļ�
     CurveType: TCnEccCurveType           - ���ڻ�ԭ����Բ��������
     OutPublicKey1: TCnEccPublicKey       - ��ԭ����Բ���߹�Կһ
     OutPublicKey2: TCnEccPublicKey       - ��ԭ����Բ���߹�Կ��
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ���ļ�����һ��

   ����ֵ��Boolean                        - ���ػ�ԭ�Ƿ�ɹ�
}

function CnEccSignStream(InStream: TMemoryStream; OutSignStream: TMemoryStream;
  Ecc: TCnEcc; PrivateKey: TCnEccPrivateKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��˽Կǩ��ָ���ڴ�����Ecc ����ҪԤ��ָ�����ߣ�ǩ����ʽ�� ASN1/BER ��װ�� R S��

   ������
     InStream: TMemoryStream              - ��ǩ�����ڴ���
     OutSignStream: TMemoryStream         - �����ǩ�������ڴ���
     Ecc: TCnEcc                          - ����ǩ������Բ����ʵ��
     PrivateKey: TCnEccPrivateKey         - ����ǩ������Բ����˽Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ�����

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnEccSignStream(InStream: TMemoryStream; OutSignStream: TMemoryStream;
  CurveType: TCnEccCurveType; PrivateKey: TCnEccPrivateKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��Ԥ����������˽Կǩ��ָ���ڴ�����ǩ����ʽ�� ASN1/BER ��װ�� R S��

   ������
     InStream: TMemoryStream              - ��ǩ�����ڴ���
     OutSignStream: TMemoryStream         - �����ǩ�������ڴ���
     CurveType: TCnEccCurveType           - ����ǩ������Բ��������
     PrivateKey: TCnEccPrivateKey         - ����ǩ������Բ����˽Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ�����

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnEccVerifyStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  Ecc: TCnEcc; PublicKey: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* �ù�Կ��ǩ��ֵ��ָ֤���ڴ�����Ecc ����ҪԤ��ָ�����ߡ�

   ������
     InStream: TMemoryStream              - ����֤���ڴ���
     InSignStream: TMemoryStream          - ǩ�������ڴ���
     Ecc: TCnEcc                          - ������֤����Բ����ʵ��
     PublicKey: TCnEccPublicKey           - ������֤����Բ���߹�Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ�����ݱ���һ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnEccVerifyStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  CurveType: TCnEccCurveType; PublicKey: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��Ԥ���������빫Կ��ǩ��ֵ��ָ֤���ڴ�����

   ������
     InStream: TMemoryStream              - ����֤���ڴ���
     InSignStream: TMemoryStream          - ǩ�������ڴ���
     CurveType: TCnEccCurveType           - ������֤����Բ��������
     PublicKey: TCnEccPublicKey           - ������֤����Բ���߹�Կ
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ�����ݱ���һ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnEccRecoverPublicKeyFromStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  Ecc: TCnEcc; OutPublicKey1: TCnEccPublicKey; OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��ָ���ڴ��������ڴ���ǩ���л�ԭ��Բ���߹�Կֵ����һ��һż������
   Ecc ����ҪԤ��ָ�����ߡ�

   ������
     InStream: TMemoryStream              - ��ǩ����������
     InSignStream: TMemoryStream          - ǩ����
     Ecc: TCnEcc                          - ���ڻ�ԭ����Բ����ʵ��
     OutPublicKey1: TCnEccPublicKey       - ��ԭ����Բ���߹�Կһ
     OutPublicKey2: TCnEccPublicKey       - ��ԭ����Բ���߹�Կ��
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ�����ݱ���һ��

   ����ֵ��Boolean                        - ���ػ�ԭ�Ƿ�ɹ�
}

function CnEccRecoverPublicKeyFromStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  CurveType: TCnEccCurveType; OutPublicKey1: TCnEccPublicKey; OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean; overload;
{* ��Ԥ�������ߴ�ָ���ڴ��������ڴ���ǩ���л�ԭ��Բ���߹�Կֵ����һ��һż������
   Ecc ����ҪԤ��ָ�����ߡ�

   ������
     InStream: TMemoryStream              - ��ǩ����������
     InSignStream: TMemoryStream          - ǩ��������
     CurveType: TCnEccCurveType           - ���ڻ�ԭ����Բ��������
     OutPublicKey1: TCnEccPublicKey       - ��ԭ����Բ���߹�Կһ
     OutPublicKey2: TCnEccPublicKey       - ��ԭ����Բ���߹�Կ��
     SignType: TCnEccSignDigestType       - ǩ�����Ӵ����ͣ����ǩ�����ݱ���һ��

   ����ֵ��Boolean                        - ���ػ�ԭ�Ƿ�ɹ�
}

// ===================== ������������Ķ���ʽ��Բ�������� ======================

function CnInt64PolynomialEccPointToString(P: TCnInt64PolynomialEccPoint): string;
{* ��һ�� Int64 ����ʽ�����ת��Ϊ����ʽ�ַ�����

   ������
     const P: TCnInt64PolynomialEccPoint  - ��ת���Ķ���ʽ�����

   ����ֵ��string                         - �����ַ���
}

function CnInt64PolynomialEccPointsEqual(P1: TCnInt64PolynomialEccPoint;
  P2: TCnInt64PolynomialEccPoint): Boolean;
{* �ж����� Int64 ����ʽ������Ƿ���ȡ�

   ������
     P1: TCnInt64PolynomialEccPoint       - ���ȽϵĶ���ʽ�����һ
     P2: TCnInt64PolynomialEccPoint       - ���ȽϵĶ���ʽ������

   ����ֵ��Boolean                        - �����Ƿ����
}

// ============================= ������������ ==================================

function CheckEccPublicKey(Ecc: TCnEcc; PublicKey: TCnEccPublicKey): Boolean;
{* ����������ߵ� PublicKey �Ƿ�Ϸ���

   ������
     Ecc: TCnEcc                          - ����У�����Բ����ʵ��
     PublicKey: TCnEccPublicKey           - ��У�����Բ���߹�Կ

   ����ֵ��Boolean                        - ����У���Ƿ�ɹ�
}

function GetCurveTypeFromOID(Data: PAnsiChar; DataByteLen: Cardinal): TCnEccCurveType;
{* ͨ�� BER �е�ԭʼ OID ���ݣ�����ͷ����ȡ��Ӧ����Բ�������͡�

   ������
     Data: PAnsiChar                      - ԭʼ OID ���ݿ��ַ
     DataByteLen: Cardinal                - ԭʼ OID ���ݿ��ֽڳ���

   ����ֵ��TCnEccCurveType                - ������Բ��������
}

function GetOIDFromCurveType(Curve: TCnEccCurveType; out OIDAddr: Pointer): Integer;
{* ������Բ�������ͷ����� OID ��ַ�볤�ȣ����ʹ�ú������ͷš�

   ������
     Curve: TCnEccCurveType               - ��Բ��������
     out OIDAddr: Pointer                 - ���ص� OID ���ݿ��ַ�������򷵻� nil

   ����ֵ��Integer                        - ���ص� OID ���ݿ��ֽڳ��ȣ������򷵻� 0
}

function ReadEccPublicKeyFromBitStringNode(BitStringNode: TCnBerReadNode;
  PublicKey: TCnEccPublicKey): Boolean;
{* ��ȡ BER �ڵ� BITSTRING �е� ECC ��Կ�������Ƿ�ɹ���

   ������
     BitStringNode: TCnBerReadNode        - ����ȡ�� BER �ڵ�
     PublicKey: TCnEccPublicKey           - ��������Բ���߹�Կ

   ����ֵ��Boolean                        - ���ض�ȡ�Ƿ�ɹ�
}

function WriteEccPublicKeyToBitStringNode(Writer: TCnBerWriter;
  ParentNode: TCnBerWriteNode; PublicKey: TCnEccPublicKey): Boolean;
{* �� ECC ��Կд�� BER �е� BITSTRING �ڵ㡣

   ������
     Writer: TCnBerWriter                 - BER д�����ʵ��
     ParentNode: TCnBerWriteNode          - ��д��� BER ���ڵ�
     PublicKey: TCnEccPublicKey           - ��д�����Բ���߹�Կ

   ����ֵ��Boolean                        - ����д���Ƿ�ɹ�
}

function GetEccDigestNameFromSignDigestType(Digest: TCnEccSignDigestType): string;
{* ��ǩ���Ӵ��㷨���͵�ö��ֵ��ȡ�����ơ�

   ������
     Digest: TCnEccSignDigestType         - ǩ���Ӵ��㷨����

   ����ֵ��string                         - ����ǩ���Ӵ��㷨����
}

procedure CnInt64GenerateGaloisDivisionPolynomials(A: Int64; B: Int64; APrime: Int64;
  MaxDegree: Integer; PolynomialList: TObjectList);
{* �������� 0 �� MaxDegree �׵Ŀɳ�����ʽ��Ҫȷ���� Int64PolynomialGaloisCalcDivisionPolynomial
   �ĵݹ�ʵ����ȫ��ͬ��

   ������
     A: Int64                             - κ��˹����˹��Բ���߷��̵� a ����
     B: Int64                             - κ��˹����˹��Բ���߷��̵� b ����
     APrime: Int64                        - κ��˹����˹��Բ���߷��̵��������Ͻ�
     MaxDegree: Integer                   - ������Ŀɳ�����ʽ����߽���
     PolynomialList: TObjectList          - ���ɿɳ�����ʽ������б�

   ����ֵ�����ޣ�
}

procedure Int64RationalMultiplePointX(Res: TCnInt64RationalPolynomial; PX: TCnInt64RationalPolynomial;
  K: Integer; A: Int64; B: Int64; APrime: Int64; DivisionPolynomialList: TObjectList;
  APrimitive: TCnInt64Polynomial = nil);
{* �ÿɳ�����ʽֱ���㵽 K �α���������� X ���꣬��Χ�� Int64��
   DivisionPolynomialList ������ CnInt64GenerateGaloisDivisionPolynomials ���ɵ���ͬ A��B��Prime �Ŀɳ�����ʽ�б�

   ����ԭ�����£�
   (x, y) * K �ÿɳ�����ʽ������Ľ������д�� (F(x), G(x) * y)��
   ��ô (f(x), g(x) * y) * K �ÿɳ�����ʽ������Ľ�����Դ���д��(F(f(x))��G(f(x)) * g(x) * y)��
   ���������� F(f(x))��

   ������
     Res: TCnInt64RationalPolynomial      - ���������ʽ������ K ����� X ���������ʽ������
     PX: TCnInt64RationalPolynomial       - ������������ʽ������ X ���������ʽ
     K: Integer                           - ����
     A: Int64                             - κ��˹����˹��Բ���߷��̵� a ����
     B: Int64                             - κ��˹����˹��Բ���߷��̵� a ����
     APrime: Int64                        - κ��˹����˹��Բ���߷��̵��������Ͻ�
     DivisionPolynomialList: TObjectList  - Ԥ�����ɵĿɳ�����ʽ������б�
     APrimitive: TCnInt64Polynomial       - ��ԭ����ʽ

   ����ֵ�����ޣ�
}

procedure Int64RationalMultiplePointY(Res: TCnInt64RationalPolynomial; PX: TCnInt64RationalPolynomial;
  PY: TCnInt64RationalPolynomial; K: Integer; A: Int64; B: Int64; APrime: Int64;
  DivisionPolynomialList: TObjectList; APrimitive: TCnInt64Polynomial = nil);
{* �ÿɳ�����ʽֱ���㵽 K �α���������� Y ���꣬��Χ�� Int64��
   DivisionPolynomialList ������ CnInt64GenerateGaloisDivisionPolynomials ���ɵ���ͬ A��B��Prime �Ŀɳ�����ʽ�б�

   ����ԭ�����£�
   (x, y) * K �ÿɳ�����ʽ������Ľ������д�� (F(x), G(x) * y)��
   ��ô (f(x), g(x) * y) * K �ÿɳ�����ʽ������Ľ�����Դ���д��(F(f(x))��G(f(x)) * g(x) * y)��
   ���������� G(f(x)) * g(x)��

   ������
     Res: TCnInt64RationalPolynomial      - ���������ʽ������ K ����� Y ���������ʽ������
     PX: TCnInt64RationalPolynomial       - ������������ʽ������ X ���������ʽ
     PY: TCnInt64RationalPolynomial       - ������������ʽ������ Y ���������ʽ
     K: Integer                           - ����
     A: Int64                             - κ��˹����˹��Բ���߷��̵� a ����
     B: Int64                             - κ��˹����˹��Բ���߷��̵� b ����
     APrime: Int64                        - κ��˹����˹��Բ���߷��̵��������Ͻ�
     DivisionPolynomialList: TObjectList  - Ԥ�����ɵĿɳ�����ʽ������б�
     APrimitive: TCnInt64Polynomial       - ��ԭ����ʽ

   ����ֵ�����ޣ�
}

procedure CnGenerateGaloisDivisionPolynomials(A: TCnBigNumber; B: TCnBigNumber; APrime: TCnBigNumber;
  MaxDegree: Integer; PolynomialList: TObjectList);
{* �������� 0 �� MaxDegree �׵Ŀɳ�����ʽ��Ҫȷ���� BigNumberPolynomialGaloisCalcDivisionPolynomial
   �ĵݹ�ʵ����ȫ��ͬ

   ������
     A: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� b ����
     APrime: TCnBigNumber                 - κ��˹����˹��Բ���߷��̵��������Ͻ�
     MaxDegree: Integer                   - ������Ŀɳ�����ʽ����߽���
     PolynomialList: TObjectList          - ���ɿɳ�����ʽ������б�

   ����ֵ�����ޣ�
}

procedure RationalMultiplePointX(Res: TCnBigNumberRationalPolynomial; PX: TCnBigNumberRationalPolynomial;
  K: Integer; A: TCnBigNumber; B: TCnBigNumber; APrime: TCnBigNumber;
  DivisionPolynomialList: TObjectList; APrimitive: TCnBigNumberPolynomial = nil);
{* �ÿɳ�����ʽֱ�Ӽ��� K �α���������� X ���꣬��Χ�Ǵ�������
   DivisionPolynomialList ������ CnGenerateGaloisDivisionPolynomials ���ɵ���ͬ A��B��Prime �Ŀɳ�����ʽ�б�

   ����ԭ�����£�
   (x, y) * K �ÿɳ�����ʽ������Ľ������д�� (F(x), G(x) * y)��
   ��ô (f(x), g(x) * y) * K �ÿɳ�����ʽ������Ľ�����Դ���д��(F(f(x))��G(f(x)) * g(x) * y)��
   ���������� F(f(x))��

   ������
     Res: TCnBigNumberRationalPolynomial  - ���������ʽ������ K ����� X ���������ʽ������
     PX: TCnBigNumberRationalPolynomial   - ������������ʽ������ X ���������ʽ
     K: Integer                           - ����
     A: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� b ����
     APrime: TCnBigNumber                 - κ��˹����˹��Բ���߷��̵��������Ͻ�
     DivisionPolynomialList: TObjectList  - Ԥ�����ɵĿɳ�����ʽ������б�
     APrimitive: TCnBigNumberPolynomial   - ��ԭ����ʽ

   ����ֵ�����ޣ�
}

procedure RationalMultiplePointY(Res: TCnBigNumberRationalPolynomial; PX: TCnBigNumberRationalPolynomial;
  PY: TCnBigNumberRationalPolynomial; K: Integer; A: TCnBigNumber; B: TCnBigNumber; APrime: TCnBigNumber;
  DivisionPolynomialList: TObjectList; APrimitive: TCnBigNumberPolynomial = nil);
{* �ÿɳ�����ʽֱ�Ӽ��� K �α���������� Y ���꣬��Χ�Ǵ�������
   DivisionPolynomialList ������ CnGenerateGaloisDivisionPolynomials ���ɵ���ͬ A��B��Prime �Ŀɳ�����ʽ�б�

   ����ԭ�����£�
   (x, y) * K �ÿɳ�����ʽ������Ľ������д�� (F(x), G(x) * y)��
   ��ô (f(x), g(x) * y) * K �ÿɳ�����ʽ������Ľ�����Դ���д��(F(f(x))��G(f(x)) * g(x) * y)��
   ���������� G(f(x)) * g(x)

   ������
     Res: TCnBigNumberRationalPolynomial  - ���������ʽ������ K ����� X ���������ʽ������
     PX: TCnBigNumberRationalPolynomial   - ������������ʽ������ X ���������ʽ
     PY: TCnBigNumberRationalPolynomial   - ������������ʽ������ Y ���������ʽ
     K: Integer                           - ����
     A: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� a ����
     B: TCnBigNumber                      - κ��˹����˹��Բ���߷��̵� b ����
     APrime: TCnBigNumber                 - κ��˹����˹��Բ���߷��̵��������Ͻ�
     DivisionPolynomialList: TObjectList  - Ԥ�����ɵĿɳ�����ʽ������б�
     APrimitive: TCnBigNumberPolynomial   - ��ԭ����ʽ

   ����ֵ�����ޣ�
}

implementation

uses
  CnContainers, CnRandom, CnBase64;

resourcestring
  SCnErrorEccCurveType = 'Invalid Curve Type.';
  SCnErrorEccKeyData = 'Invalid Key or Data.';

type
  TCnEccPredefinedHexParams = packed record
    P: AnsiString;
    A: AnsiString;
    B: AnsiString;
    X: AnsiString;
    Y: AnsiString;
    N: AnsiString;
    H: AnsiString;
  end;

const
  ECC_PRE_DEFINED_PARAMS: array[TCnEccCurveType] of TCnEccPredefinedHexParams = (
    (P: ''; A: ''; B: ''; X: ''; Y: ''; N: ''; H: ''),
    ( // SM2 = SM2 Prime 256 v1
      P: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF';
      A: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC';
      B: '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93';
      X: '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
      Y: 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
      N: 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123';
      H: '01'
    ),
    ( // SM2 Example 192
      P: 'BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F';
      A: 'BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985';
      B: '1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1';
      X: '4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640';
      Y: '02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2';
      N: 'BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677';
      H: '01'
    ),
    ( // SM2 Example 256
      P: '8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3';
      A: '787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498';
      B: '63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A';
      X: '421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D';
      Y: '0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2';
      N: '8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7';
      H: '01'
    ),
    ( // RFC 4754 ECDSA Example 256
      P: 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF';
      A: '-03';
      B: '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B';
      X: '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296';
      Y: '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5';
      N: 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';
      H: '01'
    ),
    ( // ctSecp224r1
      P: '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001';
      A: '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE';
      B: '00B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4';
      X: 'B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21';
      Y: 'BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34';
      N: '00FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D';
      H: '01'
    ),
    ( // ctSecp224k1
      P: '00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D';
      A: '00';
      B: '05';
      X: 'A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C';
      Y: '7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5';
      N: '010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7';
      H: '01'
    ),
    ( // ctSecp256k1
      P: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
      A: '00';
      B: '07';
      X: '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
      Y: '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
      N: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
      H: '01'
    ),
    ( // ctPrime256v1
      P: 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF';
      A: 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC';
      B: '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B';
      X: '6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296';
      Y: '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5';
      N: 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';
      H: '01'
    ),
    ( // ctWapiPrime192v1
      P: 'BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F';
      A: 'BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985';
      B: '1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1';
      X: '4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640';
      Y: '02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2';
      N: 'BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677';
      H: '01'
    ),
    ( // ctSM9Bn256v1
      P: 'B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D';
      A: '0000000000000000000000000000000000000000000000000000000000000000';
      B: '0000000000000000000000000000000000000000000000000000000000000005';
      X: '93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD';
      Y: '21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616';
      N: 'B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25';
      H: '01'
    ),
    ( // ctSecp384r1
      P: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF';
      A: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC';
      B: 'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF';
      X: 'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7';
      Y: '3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F';
      N: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973';
      H: '01'
    ),
    ( // ctSecp521r1
      P: '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
      A: '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC';
      B: '0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00';
      X: '00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66';
      Y: '011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650';
      N: '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409';
      H: '01'
    )
  );

  // PKCS#1
  PEM_EC_PARAM_HEAD = '-----BEGIN EC PARAMETERS-----';
  PEM_EC_PARAM_TAIL = '-----END EC PARAMETERS-----';

  PEM_EC_PRIVATE_HEAD = '-----BEGIN EC PRIVATE KEY-----';
  PEM_EC_PRIVATE_TAIL = '-----END EC PRIVATE KEY-----';

  PEM_EC_PUBLIC_HEAD = '-----BEGIN PUBLIC KEY-----';
  PEM_EC_PUBLIC_TAIL = '-----END PUBLIC KEY-----';

  // PKCS#8
  PEM_PRIVATE_HEAD = '-----BEGIN PRIVATE KEY-----';
  PEM_PRIVATE_TAIL = '-----END PRIVATE KEY-----';

  // ECC ˽Կ�ļ��������ڵ�� BER Tag Ҫ������� TypeMask
  ECC_PRIVATEKEY_TYPE_MASK  = $80;

  // ��Կ�Ĵ洢��ʽ
  EC_PUBLICKEY_COMPRESSED_EVEN  = 02; // ʡ���� Y������ Y ��ż��
  EC_PUBLICKEY_COMPRESSED_ODD   = 03; // ʡ���� Y������ Y ������
  EC_PUBLICKEY_UNCOMPRESSED     = 04; // X Y ����

  // Ԥ�������Բ�������͵� OID ������󳤶�
  EC_CURVE_TYPE_OID_MAX_LENGTH = 8;

  OID_ECPARAM_CURVE_TYPE_SECP256K1: array[0..4] of Byte = ( // 1.3.132.0.10
    $2B, $81, $04, $00, $0A
  );

  OID_ECPARAM_CURVE_TYPE_SM2: array[0..7] of Byte = (       // 1.2.156.10197.301
    $2A, $81, $1C, $CF, $55, $01, $82, $2D
  );

  OID_ECPARAM_CURVE_TYPE_PRIME256V1: array[0..7] of Byte = (  // 1.2.840.10045.3.1.7
    $2A, $86, $48, $CE, $3D, $03, $01, $07
  );

var
  FEccBigNumberPool: TCnBigNumberPool = nil;
  FEccInt64PolynomialPool: TCnInt64PolynomialPool = nil;
  FEccPolynomialPool: TCnBigNumberPolynomialPool = nil;
  FEccInt64RationalPolynomialPool: TCnInt64RationalPolynomialPool = nil;
  FEccRationalPolynomialPool: TCnBigNumberRationalPolynomialPool = nil;

function Min(A, B: Integer): Integer;
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

{* ȡ X ����߸� W λ������ W �� N �� BitsCount���ú�������ǩ����ǩ
   ע������ SM2 �е�ͬ���������ܲ�ͬ}
procedure BuildShortXValue(X: TCnBigNumber; Order: TCnBigNumber);
var
  W: Integer;
begin
  W := X.GetBitsCount - Order.GetBitsCount;
  if W > 0 then
    BigNumberShiftRight(X, X, W);
end;

// ��һ�� TCnInt64EccPoint ������ת��Ϊ�ַ���
function CnInt64EccPointToString(var P: TCnInt64EccPoint): string;
begin
  Result := Format('%d,%d', [P.X, P.Y]);
end;

// ��һ�� TCnEccPoint ������ת��Ϊʮ�����ַ���
function CnEccPointToString(P: TCnEccPoint): string;
begin
  Result := Format('%s,%s', [P.X.ToDec, P.Y.ToDec]);
end;

// ��һ�� TCnEccPoint ������ת��Ϊʮ�������ַ���
function CnEccPointToHex(P: TCnEccPoint): string;
begin
  Result := Format('%s,%s', [P.X.ToHex, P.Y.ToHex]);
end;

// ��һ�� TCnInt64Ecc3Point ������ת��Ϊ�ַ���}
function CnInt64Ecc3PointToString(var P: TCnInt64Ecc3Point): string;
begin
  Result := Format('%d,%d,%d', [P.X, P.Y, P.Z]);
end;

// ��һ�� TCnEcc3Point ������ת��Ϊʮ�����ַ���
function CnEcc3PointToString(P: TCnEcc3Point): string;
begin
  Result := Format('%s,%s,%s', [P.X.ToDec, P.Y.ToDec, P.Z.ToDec]);
end;

// ��һ�� TCnEcc3Point ������ת��Ϊʮ�������ַ���}
function CnEcc3PointToHex(P: TCnEcc3Point): string;
begin
  Result := Format('%s,%s,%s', [P.X.ToHex, P.Y.ToHex, P.Z.ToHex]);
end;

// �ж����� TCnEcc3Point ���Ƿ���ȣ���ʱֻ�ж�ֵ������ Z �ĳ���
function CnAffineEcc3PointEqual(P1, P2: TCnEcc3Point; Prime: TCnBigNumber): Boolean;
var
  T1, T2, Z1, Z2: TCnBigNumber;
begin
  if P1 = P2 then
    Result := True
  else
  begin
    Result := (BigNumberCompare(P1.X, P2.X) = 0) and (BigNumberCompare(P1.Y, P2.Y) = 0)
      and (BigNumberCompare(P1.Z, P2.Z) = 0);
    if Result or (Prime = nil) then
      Exit;

    // �� X/Z �� Y/Z �Ƿ����
    Z1 := nil;
    Z2 := nil;
    T1 := nil;
    T2 := nil;

    try
      Z1 := FEccBigNumberPool.Obtain;
      Z2 := FEccBigNumberPool.Obtain;

      BigNumberModularInverse(Z1, P1.Z, Prime);
      BigNumberModularInverse(Z2, P2.Z, Prime);

      T1 := FEccBigNumberPool.Obtain;
      T2 := FEccBigNumberPool.Obtain;

      BigNumberDirectMulMod(T1, P1.X, Z1, Prime);
      BigNumberDirectMulMod(T2, P2.X, Z2, Prime);

      if not BigNumberEqual(T1, T2) then // X ����
        Exit;

      BigNumberDirectMulMod(T1, P1.Y, Z1, Prime);
      BigNumberDirectMulMod(T2, P2.Y, Z2, Prime);

      if not BigNumberEqual(T1, T2) then // Y ����
        Exit;

      Result := True;
    finally
      FEccBigNumberPool.Recycle(T2);
      FEccBigNumberPool.Recycle(T1);
      FEccBigNumberPool.Recycle(Z2);
      FEccBigNumberPool.Recycle(Z1);
    end;
  end;
end;

// ��һ�� TCnPolynomialEccPoint ������ת��Ϊ�ַ���
function CnPolynomialEccPointToString(P: TCnPolynomialEccPoint): string;
begin
  Result := Format('%s,%s', [P.X.ToString, P.Y.ToString]);
end;

// �ж����� TCnPolynomialEccPoint ���Ƿ����
function CnPolynomialEccPointsEqual(P1, P2: TCnPolynomialEccPoint): Boolean;
begin
  if P1 = P2 then
    Result := True
  else
    Result := BigNumberPolynomialEqual(P1.X, P2.X) and BigNumberPolynomialEqual(P1.Y, P2.Y);
end;

// �ж��������Ƿ����
function CnEccPointsEqual(P1, P2: TCnEccPoint): Boolean;
begin
  if P1 = P2 then
    Result := True
  else
    Result := (BigNumberCompare(P1.X, P2.X) = 0) and (BigNumberCompare(P1.Y, P2.Y) = 0);
end;

function CnInt64EccPointsEqual(var P1, P2: TCnInt64EccPoint): Boolean;
begin
  Result := (P1.X = P2.X) and (P1.Y = P2.Y);
end;

// ������Բ���� y^2 = x^3 + Ax + B mod p �ĸ�������������ʵ��
function CnInt64EccGenerateParams(out FiniteFieldSize, CoefficientA, CoefficientB,
  GX, GY, Order: Int64): Boolean;
var
  I: Integer;
  N: Int64;
  P: TCnInt64EccPoint;
  Ecc64: TCnInt64Ecc;
begin
  // ���裺���ѡ���������� p��������� a��b���� SEA �㷨��������ߵĽ� N
  // �ж� N �Ǵ���������һ�������֮һ�Ǵ�������Ȼ�������������Ϊѭ����Ⱥ�Ľ� n
  // �ٸ��� n Ѱ�һ��� G �����ꡣ��� n �͵��� N ������������� G ���ѡ���С�

  repeat
    // FiniteFieldSize := CnGenerateUInt32Prime; // ����С�������������Ҳ����̫С
    Randomize;
    I := Trunc(Random * (High(CN_PRIME_NUMBERS_SQRT_UINT32) - 100)) + 100;
    FiniteFieldSize := CN_PRIME_NUMBERS_SQRT_UINT32[I];
    CoefficientA := Trunc(Random * 16);
    CoefficientB := Trunc(Random * 256);
    N := 1; // 0,0 ��Ȼ����

    // A��B ���Ƚ�С�����ﲻ�õ������
    if (4 * CoefficientA * CoefficientA * CoefficientA - 27 * CoefficientB * CoefficientB)
      mod FiniteFieldSize = 0 then
      Continue;

    GX := 0;
    GY := 0;

    // ���������Բ���ߵĽף����� SEA��ԭ��ֻ������������ٷ�����������õ¹�ʽ
    // N := 1 + P + ���е����õ�((x^3+ax+b)/p)֮�ͣ����� X �� 0 �� P - 1
    Inc(N, FiniteFieldSize);
    for I := 0 to FiniteFieldSize - 1 do
    begin
      // ������� Int64 ��ת��һ�£����� I �����η����� Integer �����
      N := N + CnInt64Legendre(Int64(I) * Int64(I) * Int64(I) + CoefficientA * I + CoefficientB, FiniteFieldSize);
    end;
  until CnInt64IsPrime(N);

  // Ȼ�������һ�� X �� Y
  Ecc64 := TCnInt64Ecc.Create(CoefficientA, CoefficientB, FiniteFieldSize, 0, 0, FiniteFieldSize);
  try
    repeat
      P.X := Trunc(Random * (FiniteFieldSize - 1)) + 1;
      for I := 0 to FiniteFieldSize - 1 do
      begin
        P.Y := I;
        if Ecc64.IsPointOnCurve(P) then
        begin
          GX := P.X;
          GY := P.Y;
          Break;
        end;
      end;
    until (GX > 0) and (GY > 0);
  finally
    Ecc64.Free;
  end;

  Order := N;
  Result := True;
end;

// �� X ��� M ��ģ��Ԫ��Ҳ����ģ��Ԫ Y������ (X * Y) mod M = 1����ΧΪ Int64��Ҳ����˵֧�� X Ϊ��ֵ
function MyInt64ModularInverse(X: Int64; Modulus: Int64): Int64;
var
  Neg: Boolean;
begin
  Neg := False;
  if X < 0 then
  begin
    X := -X;
    Neg := True;
  end;

  // ������ģ��Ԫ������������ģ��Ԫ�ĸ�ֵ����ֵ�������ټ� Modulus
  Result := CnInt64ModularInverse(X, Modulus);
  if Neg and (Result > 0) then
    Result := -Result;

  if Result < 0 then
    Result := Result + Modulus;
end;

{ TCnInt64Ecc }

procedure TCnInt64Ecc.AffineMultiplePoint(K: Int64;
  var Point: TCnInt64Ecc3Point);
var
  E, R: TCnInt64Ecc3Point;
begin
  if K < 0 then
  begin
    K := -K;
    AffinePointInverse(Point);
  end;

  if K = 0 then
  begin
    Point.X := 0;
    Point.Y := 0;
    Point.Z := 0;
    Exit;
  end;

  if K > 1 then
  begin
    R.X := 0;
    R.Y := 0;
    R.Z := 0;

    E := Point;

    while K <> 0 do
    begin
      if (K and 1) <> 0 then
        AffinePointAddPoint(R, E, R);

      AffinePointAddPoint(E, E, E);
      K := K shr 1;
    end;

    Point := R;
  end;
end;

procedure TCnInt64Ecc.AffinePointAddPoint(var P, Q: TCnInt64Ecc3Point;
  var Sum: TCnInt64Ecc3Point);
var
  T, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11: Int64;
begin
  if P.Z = 0 then
  begin
    Sum := Q;
    Exit;
  end
  else if Q.Z = 0 then
  begin
    Sum := P;
    Exit;
  end;

  // D1 := px * qz
  D1 := Int64NonNegativeMulMod(P.X, Q.Z, FFiniteFieldSize);

  // D2 := qx * pz
  D2 := Int64NonNegativeMulMod(Q.X, P.Z, FFiniteFieldSize);

  // D4 := py * qz
  D4 := Int64NonNegativeMulMod(P.Y, Q.Z, FFiniteFieldSize);

  // D5 := qy * pz
  D5 := Int64NonNegativeMulMod(Q.Y, P.Z, FFiniteFieldSize);

  if (D1 = D2) and (D4 = D5) then // P.X/P.Z = Q.X/Q.Z ���� P.Y/P.Z = Q.Y/Q.Z��˵����ͬһ����
  begin
    // ͬһ���㣬���߷�
    // D1 := 3 px^2 + A * pz^2
    D1 := Int64NonNegativeMulMod(P.X, P.X, FFiniteFieldSize);
    D1 := Int64NonNegativeMulMod(D1, 3, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(P.Z, P.Z, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, FCoefficientA, FFiniteFieldSize);
    D1 := Int64NonNegativeAddMod(D1, T, FFiniteFieldSize);

    // D2 := 2 * py * pz
    D2 := Int64NonNegativeMulMod(P.Y, 2, FFiniteFieldSize);
    D2 := Int64NonNegativeMulMod(D2, P.Z, FFiniteFieldSize);

    // D3 := py^2
    D3 := Int64NonNegativeMulMod(P.Y, P.Y, FFiniteFieldSize);

    // D4 := D3 * px * pz
    D4 := Int64NonNegativeMulMod(D3, P.X, FFiniteFieldSize);
    D4 := Int64NonNegativeMulMod(D4, P.Z, FFiniteFieldSize);

    // D5 := D2^2
    D5 := Int64NonNegativeMulMod(D2, D2, FFiniteFieldSize);

    // D6 := D1^2 - 8 * D4
    D6 := Int64NonNegativeMulMod(D1, D1, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(D4, 8, FFiniteFieldSize);
    D6 := Int64NonNegativeAddMod(D6, -T, FFiniteFieldSize);

    // X := D2 * D6
    Sum.X := Int64NonNegativeMulMod(D2, D6, FFiniteFieldSize);

    // Y := D1 * (4 * D4 - D6) - 2 * D5 * D3
    T := Int64NonNegativeMulMod(D4, 4, FFiniteFieldSize);
    T := Int64NonNegativeAddMod(T, -D6, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, D1, FFiniteFieldSize);

    Sum.Y := Int64NonNegativeMulMod(D3, D5, FFiniteFieldSize);
    Sum.Y := Int64NonNegativeAddMod(Sum.Y, Sum.Y, FFiniteFieldSize);
    Sum.Y := Int64NonNegativeAddMod(T, -Sum.Y, FFiniteFieldSize);

    // Z := D2 * D5
    Sum.Z := Int64NonNegativeMulMod(D2, D5, FFiniteFieldSize);
  end
  else  // ��ͬ�㣬���߷�
  begin
    // ��Ϊ�в�ͬ�� Z ���ڣ��������жϣ�ͬ����������
    if D1 = D2 then
    begin
      if D4 + D5 = FFiniteFieldSize then // X ����� Y ����
      begin
        Sum.X := 0;
        Sum.Y := 0;
        Sum.Z := 0;
        Exit;
      end
      else // X ����� Y ��������û�����
        raise ECnEccException.CreateFmt('Can NOT Calucate Affine %d,%d,%d + %d,%d,%d',
          [P.X, P.Y, P.Z, Q.X, Q.Y, Q.Z]);
    end;

    // D3 := D1 - D2
    D3 := Int64NonNegativeAddMod(D1, -D2, FFiniteFieldSize);

    // D6 := D4 - D5
    D6 := Int64NonNegativeAddMod(D4, -D5, FFiniteFieldSize);

    // D7 := D1 + D2
    D7 := Int64NonNegativeAddMod(D1, D2, FFiniteFieldSize);

    // D8 := pz * qz
    D8 := Int64NonNegativeMulMod(P.Z, Q.Z, FFiniteFieldSize);

    // D9 := D3 ^ 2
    D9 := Int64NonNegativeMulMod(D3, D3, FFiniteFieldSize);

    // D10 := D3 * D9
    D10 := Int64NonNegativeMulMod(D3, D9, FFiniteFieldSize);

    // D11 := D8 * D6 ^ 2 - D7 * D9
    D11 := Int64NonNegativeMulMod(D6, D6, FFiniteFieldSize);
    D11 := Int64NonNegativeMulMod(D11, D8, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(D7, D9, FFiniteFieldSize);
    D11 := Int64NonNegativeAddMod(D11, -T, FFiniteFieldSize);

    // Y := D6 * (D9 * D1 - D11) - D4 * D10
    T := Int64NonNegativeMulMod(D9, D1, FFiniteFieldSize);
    T := Int64NonNegativeAddMod(T, -D11, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, D6, FFiniteFieldSize);

    Sum.Y := Int64NonNegativeMulMod(D4, D10, FFiniteFieldSize);
    Sum.Y := Int64NonNegativeAddMod(T, -Sum.Y, FFiniteFieldSize);

    // X := D3 * D11
    Sum.X := Int64NonNegativeMulMod(D3, D11, FFiniteFieldSize);

    // Z := D10 * D8
    Sum.Z := Int64NonNegativeMulMod(D10, D8, FFiniteFieldSize);
  end;

  if Sum.Z = 0 then
  begin
    Sum.X := 0;
    Sum.Y := 0;
  end;
end;

constructor TCnInt64Ecc.Create(A, B, FieldPrime, GX, GY, Order: Int64);
var
  R: Int64;
begin
  inherited Create;

  // ����籣֤ Order Ϊ����
  if not CnInt64IsPrime(FieldPrime) then // or not CnInt64IsPrime(Order) then
    raise ECnEccException.Create('Infinite Field must be a Prime Number.');

  if not (GX >= 0) and (GX < FieldPrime) or
    not (GY >= 0) and (GY < FieldPrime) then
    raise ECnEccException.Create('Generator Point must be in Infinite Field.');

  // Ҫȷ�� 4*a^3+27*b^2 <> 0
  if 4 * A * A * A + 27 * B * B = 0 then
    raise ECnEccException.Create('Error: 4 * A^3 + 27 * B^2 = 0');

  FCoefficientA := A;
  FCoefficientB := B;
  FFiniteFieldSize := FieldPrime;
  FGenerator.X := GX;
  FGenerator.Y := GY;
  FOrder := Order;

  R := FFiniteFieldSize mod 4;
  if R = 3 then  // RFC 5639 Ҫ�� p ���� 4u + 3 ����ʽ�Ա㷽��ؼ��� Y������������δ��
  begin
    FSizePrimeType := pt4U3;
    FSizeUFactor := FFiniteFieldSize div 4;
  end
  else
  begin
    R := FFiniteFieldSize mod 8;
    if R = 1 then
    begin
      FSizePrimeType := pt8U1;
      FSizeUFactor := FFiniteFieldSize div 8;
    end
    else if R = 5 then
    begin
      FSizePrimeType := pt8U5;
      FSizeUFactor := FFiniteFieldSize div 8;
    end
    else
      raise ECnEccException.Create('Invalid Finite Field Size.');
  end;
end;

procedure TCnInt64Ecc.Decrypt(var DataPoint1, DataPoint2: TCnInt64EccPoint;
  PrivateKey: TCnInt64PrivateKey; var OutPlainPoint: TCnInt64EccPoint);
var
  P: TCnInt64EccPoint;
begin
  P := DataPoint2;
  MultiplePoint(PrivateKey, P);
  PointSubPoint(DataPoint1, P, OutPlainPoint);
end;

destructor TCnInt64Ecc.Destroy;
begin

  inherited;
end;

function TCnInt64Ecc.DivisionPolynomial(Degree: Integer;
  outDivisionPolynomial: TCnInt64Polynomial): Boolean;
begin
  Result := Int64PolynomialGaloisCalcDivisionPolynomial(FCoefficientA, FCoefficientB,
    Degree, outDivisionPolynomial, FFiniteFieldSize);
end;

procedure TCnInt64Ecc.Encrypt(var PlainPoint: TCnInt64EccPoint;
  PublicKey: TCnInt64PublicKey; var OutDataPoint1,
  OutDataPoint2: TCnInt64EccPoint; RandomKey: Int64);
begin
  if RandomKey = 0 then
  begin
    Randomize;
    RandomKey := Trunc(Random * (FOrder - 1)) + 1; // �� 0 �󵫱Ȼ����С�������
  end;

  if RandomKey mod FOrder = 0 then
    raise ECnEccException.CreateFmt('Error RandomKey %d for Order.', [RandomKey]);

  // M + rK;
  OutDataPoint1 := PublicKey;
  MultiplePoint(RandomKey, OutDataPoint1);
  PointAddPoint(PlainPoint, OutDataPoint1, OutDataPoint1);

  // r * G
  OutDataPoint2 := FGenerator;
  MultiplePoint(RandomKey, OutDataPoint2);
end;

procedure TCnInt64Ecc.GenerateKeys(out PrivateKey: TCnInt64PrivateKey;
  out PublicKey: TCnInt64PublicKey);
begin
  Randomize;
  PrivateKey := Trunc(Random * (FOrder - 1)) + 1; // �� 0 �󵫱Ȼ����С�������
  PublicKey := FGenerator;
  MultiplePoint(PrivateKey, PublicKey);           // ����� PrivateKey ��
end;

function TCnInt64Ecc.IsPointOnCurve(var P: TCnInt64EccPoint): Boolean;
var
  Y2, X3, AX, B: Int64;
begin
  // ���� (Y^2 - X^3 - A*X - B) mod p �Ƿ���� 0��Ӧ�÷�����
  // Ҳ���Ǽ���(Y^2 mod p - X^3 mod p - A*X mod p - B mod p) mod p
  Y2 := MontgomeryPowerMod(P.Y, 2, FFiniteFieldSize);
  X3 := MontgomeryPowerMod(P.X, 3, FFiniteFieldSize);
  AX := Int64MultipleMod(FCoefficientA, P.X, FFiniteFieldSize);
  B := FCoefficientB mod FFiniteFieldSize;

  Result := ((Y2 - X3 - AX - B) mod FFiniteFieldSize) = 0;
end;

procedure TCnInt64Ecc.JacobianMultiplePoint(K: Int64;
  var Point: TCnInt64Ecc3Point);
var
  E, R: TCnInt64Ecc3Point;
begin
  if K < 0 then
  begin
    K := -K;
    JacobianPointInverse(Point);
  end;

  if K = 0 then
  begin
    Point.X := 0;
    Point.Y := 0;
    Exit;
  end;

  if K > 1 then
  begin
    R.X := 0;
    R.Y := 0;
    R.Z := 0;

    E := Point;

    while K <> 0 do
    begin
      if (K and 1) <> 0 then
        JacobianPointAddPoint(R, E, R);

      JacobianPointAddPoint(E, E, E);
      K := K shr 1;
    end;

    Point := R;
  end;
end;

procedure TCnInt64Ecc.JacobianPointAddPoint(var P, Q, Sum: TCnInt64Ecc3Point);
var
  T, D1, D2, D3, D4, D5, D6, D7, D8, D9: Int64;
begin
  if P.Z = 0 then
  begin
    Sum := Q;
    Exit;
  end
  else if Q.Z = 0 then
  begin
    Sum := P;
    Exit;
  end;

  // D1 := PX * QZ^2
  D1 := Int64NonNegativeMulMod(Q.Z, Q.Z, FFiniteFieldSize);
  D1 := Int64NonNegativeMulMod(D1, P.X, FFiniteFieldSize);

  // D2 := QX * PZ^2
  D2 := Int64NonNegativeMulMod(P.Z, P.Z, FFiniteFieldSize);
  D2 := Int64NonNegativeMulMod(D2, Q.X, FFiniteFieldSize);

  // D4 := PY * QZ^3
  D4 := Int64NonNegativeMulMod(Q.Z, Q.Z, FFiniteFieldSize);
  D4 := Int64NonNegativeMulMod(D4, Q.Z, FFiniteFieldSize);
  D4 := Int64NonNegativeMulMod(D4, P.Y, FFiniteFieldSize);

  // D5 := QY * PZ^3
  D5 := Int64NonNegativeMulMod(P.Z, P.Z, FFiniteFieldSize);
  D5 := Int64NonNegativeMulMod(D5, P.Z, FFiniteFieldSize);
  D5 := Int64NonNegativeMulMod(D5, Q.Y, FFiniteFieldSize);

  if (D1 = D2) and (D4 = D5) then // P.X/P.Z^2 = Q.X/Q.Z^2 ���� P.Y/P.Z^3 = Q.Y/Q.Z^3��˵����ͬһ����
  begin
    // ͬһ���㣬���߷�
    // D1 := 3 * PX^2 + A * PZ^4
    T := Int64NonNegativeMulMod(P.Z, P.Z, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, T, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, FCoefficientA, FFiniteFieldSize);
    D1 := Int64NonNegativeMulMod(P.X, P.X, FFiniteFieldSize);
    D1 := Int64NonNegativeMulMod(D1, 3, FFiniteFieldSize);
    D1 := Int64NonNegativeAddMod(D1, T, FFiniteFieldSize);

    // D2 := 4 * PX * PY^2
    D2 := Int64NonNegativeMulMod(P.Y, P.Y, FFiniteFieldSize);
    D2 := Int64NonNegativeMulMod(D2, P.X, FFiniteFieldSize);
    D2 := Int64NonNegativeMulMod(D2, 4, FFiniteFieldSize);

    // D3 := 8 * PY^4
    D3 := Int64NonNegativeMulMod(P.Y, P.Y, FFiniteFieldSize);
    D3 := Int64NonNegativeMulMod(D3, D3, FFiniteFieldSize);
    D3 := Int64NonNegativeMulMod(D3, 8, FFiniteFieldSize);

    // X := D1^2 - 2 * D2
    Sum.X := Int64NonNegativeMulMod(D1, D1, FFiniteFieldSize);
    T := Int64NonNegativeAddMod(D2, D2, FFiniteFieldSize);
    Sum.X := Int64NonNegativeAddMod(Sum.X, -T, FFiniteFieldSize);

    // Y := D1 * (D2 - X) - D3
    T := Int64NonNegativeAddMod(D2, -Sum.X, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(D1, T, FFiniteFieldSize);
    T := Int64NonNegativeAddMod(T, -D3, FFiniteFieldSize); // �Ȳ��� Sum.Y ��ֵ����ÿ���Ӱ�� P.Y

    // Z := 2 * PY * PZ
    Sum.Z := Int64NonNegativeMulMod(P.Y, P.Z, FFiniteFieldSize);
    Sum.Z := Int64NonNegativeAddMod(Sum.Z, Sum.Z, FFiniteFieldSize);

    Sum.Y := T; // P.Y �� P.Z ���ù����ٸ� Sum.Y ��ֵ
  end
  else  // ��ͬ�㣬���߷�
  begin
    // ��Ϊ�в�ͬ�� Z ���ڣ��������жϣ�ͬ����������
    if D1 = D2 then
    begin
      if D4 + D5 = FFiniteFieldSize then // X ����� Y ����
      begin
        Sum.X := 0;
        Sum.Y := 0;
        Sum.Z := 0;
        Exit;
      end
      else // X ����� Y ��������û�����
        raise ECnEccException.CreateFmt('Can NOT Calucate Jacobian %d,%d,%d + %d,%d,%d',
          [P.X, P.Y, P.Z, Q.X, Q.Y, Q.Z]);
    end;

    // D3 := D1 - D2
    D3 := Int64NonNegativeAddMod(D1, -D2, FFiniteFieldSize);

    // D6 := D4 - D5
    D6 := Int64NonNegativeAddMod(D4, -D5, FFiniteFieldSize);

    // D7 := D1 + D2
    D7 := Int64NonNegativeAddMod(D1, D2, FFiniteFieldSize);

    // D8 := D4 + D5
    D8 := Int64NonNegativeAddMod(D4, D5, FFiniteFieldSize);

    // X := D6^2 - D7 * D3^2
    Sum.X := Int64NonNegativeMulMod(D6, D6, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(D3, D3, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, D7, FFiniteFieldSize);
    Sum.X := Int64NonNegativeAddMod(Sum.X, -T, FFiniteFieldSize);

    // D9 := D7 * D3^2 - 2 * X
    D9 := Int64NonNegativeMulMod(D3, D3, FFiniteFieldSize);
    D9 := Int64NonNegativeMulMod(D9, D7, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(Sum.X, 2, FFiniteFieldSize);
    D9 := Int64NonNegativeAddMod(D9, -T, FFiniteFieldSize);

    // Y := (D9 * D6 - D8 * D3^3) / 2
    T := Int64NonNegativeMulMod(D3, D3, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, D3, FFiniteFieldSize);
    T := Int64NonNegativeMulMod(T, D8, FFiniteFieldSize);
    Sum.Y := Int64NonNegativeMulMod(D6, D9, FFiniteFieldSize);
    Sum.Y := Int64NonNegativeAddMod(Sum.Y, -T, FFiniteFieldSize);

    if F2Inverse = 0 then
      F2Inverse := MyInt64ModularInverse(2, FFiniteFieldSize); // ���� 2
    Sum.Y := Int64NonNegativeMulMod(Sum.Y, F2Inverse, FFiniteFieldSize);

    // Z := PZ * QZ * D3
    Sum.Z := Int64NonNegativeMulMod(P.Z, Q.Z, FFiniteFieldSize);
    Sum.Z := Int64NonNegativeMulMod(Sum.Z, D3, FFiniteFieldSize);
  end;
end;

function TCnInt64Ecc.Lucas(X, P: Int64; out Y: Int64): Boolean;
var
  G, U, V, Z: Int64;
begin
  Result := False;
  G := X;

  while True do
  begin
    // ���ȡ X
    X := RandomInt64LessThan(P);

    // �ټ��� Lucas �����е� V�����±� K Ϊ (P+1)/2
    CnLucasVSequenceMod(X, G, (P + 1) shr 1, P, U, V);

    // V ż��ֱ������ 1 �� mod P��V ����� P ������ 1
    if (V and 1) = 0 then
      Z := (V shr 1) mod P
    else
      Z := (V + P) shr 1;
    // Z := (V div 2) mod P;

    if Int64MultipleMod(Z, Z, P) = G then
    begin
      Y := Z;
      Result := True;
      Exit;
    end
    else if (U > 1) and (U < P - 1) then
      Break;
  end;
end;

procedure TCnInt64Ecc.MultiplePoint(K: Int64; var Point: TCnInt64EccPoint);
var
  E, R: TCnInt64EccPoint;
begin
  if K < 0 then
  begin
    K := -K;
    PointInverse(Point);
  end;

  if K = 0 then
  begin
    Point.X := 0;
    Point.Y := 0;
    Exit;
  end;

  if K > 1 then
  begin
    R.X := 0;
    R.Y := 0;
    E := Point;

    while K <> 0 do
    begin
      if (K and 1) <> 0 then
        PointAddPoint(R, E, R);

      PointAddPoint(E, E, E);
      K := K shr 1;
    end;

    Point := R;
  end;
end;

{$WARNINGS OFF}

function TCnInt64Ecc.PlainToPoint(Plain: Int64;
  var OutPoint: TCnInt64EccPoint): Boolean;
var
  X3, AX, B, G, Y, Z: Int64;
begin
  Result := False;
  if Plain = 0 then
  begin
    OutPoint.X := 0;
    OutPoint.Y := 0;
    Result := True;
    Exit;
  end;

  // �ⷽ���� Y�� (y^2 - (Plain^3 + A * Plain + B)) mod p = 0
  // ע�� Plain ���̫�󣬼�������л���������ô���ֻ���÷����ɡ�
  // (Y^2 mod p - Plain ^ 3 mod p - A * Plain mod p - B mod p) mod p = 0;
  X3 := MontgomeryPowerMod(Plain, 3, FFiniteFieldSize);
  AX := Int64MultipleMod(FCoefficientA, Plain, FFiniteFieldSize);
  B := FCoefficientB mod FFiniteFieldSize;

  G := (X3 + AX + B) mod FFiniteFieldSize; // ���������Ļ�
  if G = 0 then   // ��� X^3 + AX + B Ϊ 0����ֱ�ӷ��� (Plain, 0) ���ҿ϶��������߷���
  begin
    OutPoint.X := Plain;
    OutPoint.Y := 0;
    Result := True;
    Exit;
  end;

  // ��Ϊ Y^2 = N * p + B Ҫ���ҳ� N ���ұ�Ϊ��ȫƽ���������� Y ����ֵ
  // Ҫ��Ӳ�� N �� 0 ��ʼ�� 1 ���������������Ƿ���ȫƽ������������������ô��
  // ���ö���ʣ������ģ�Ŀ����󷨣��������� P �����Է����֣�

  case FSizePrimeType of
  pt4U3:  // �ο��ԡ�SM2��Բ���߹�Կ�����㷨����¼ B �еġ�ģ����ƽ��������⡱һ��
    begin
      Y := MontgomeryPowerMod(G, FSizeUFactor + 1, FFiniteFieldSize);
      Z := Int64MultipleMod(Y, Y, FFiniteFieldSize);
      if Z = G then
      begin
        OutPoint.X := Plain;
        OutPoint.Y := Y;
        Result := True;
      end;
    end;
  pt8U5:  // �ο��ԡ�SM2��Բ���߹�Կ�����㷨����¼ B �еġ�ģ����ƽ��������⡱һ��
    begin
      Z := MontgomeryPowerMod(G, 2 * FSizeUFactor + 1, FFiniteFieldSize);
      if Z = 1 then
      begin
        Y := MontgomeryPowerMod(G, FSizeUFactor + 1, FFiniteFieldSize);
        OutPoint.X := Plain;
        OutPoint.Y := Y;
        Result := True;
      end
      else
      begin
        Z := FFiniteFieldSize - Z;
        if Z = 1 then
        begin
          // y = (2g * (4g)^u) mod p = (2g mod p * (4^u * g^u) mod p) mod p
          Y := (Int64MultipleMod(G, 2, FFiniteFieldSize) *
            MontgomeryPowerMod(4, FSizeUFactor, FFiniteFieldSize) *
            MontgomeryPowerMod(G, FSizeUFactor, FFiniteFieldSize)) mod FFiniteFieldSize;
          OutPoint.X := Plain;
          OutPoint.Y := Y;
          Result := True;
        end;
      end;
    end;
  pt8U1: // �ο��� wikipedia �ϵ� Tonelli-Shanks ����ʣ������㷨�Լ� IEEE P1363 ��� Lucas �����㷨
    begin
{$IFDEF USE_LUCAS}
      // ��SM2��Բ���߹�Կ�����㷨����¼ B �еġ�ģ����ƽ��������⡱һ�� Lucas ���м�������Ľ��ʵ�ڲ���
      if Lucas(G, FFiniteFieldSize, Y) then
      begin
        OutPoint.X := Plain;
        OutPoint.Y := Y;
        Result := True;
      end;
{$ELSE}
      //  ���� Tonelli-Shanks �㷨����ģ��������ʣ����⣬���ڲ���Ҫͨ�����õ·����ж�����Ƿ���ڣ������������ѭ��
      if TonelliShanks(G, FFiniteFieldSize, Y) then
      begin
        OutPoint.X := Plain;
        OutPoint.Y := Y;
        Result := True;
      end;
{$ENDIF}
    end;
  end;
end;

{$WARNINGS ON}

procedure TCnInt64Ecc.PointAddPoint(var P, Q, Sum: TCnInt64EccPoint);
var
  K, X, Y, PX: Int64;
begin
  K := 0;
  if (P.X = 0) and (P.Y = 0) then
  begin
    Sum := Q;
    Exit;
  end
  else if (Q.X = 0) and (Q.Y = 0) then
  begin
    Sum := P;
    Exit;
  end
  else if (P.X = Q.X) and (P.Y = Q.Y) then
  begin
    // ��������ͬһ���㣬����б��Ϊ�����󵼣�3 * X^2 + A / (2 * Y) ���� Y = 0 ��ֱ��������Զ 0��
    X := 3 * P.X * P.X + FCoefficientA;
    Y := 2 * P.Y;

    if Y = 0 then
    begin
      Sum.X := 0;
      Sum.Y := 0;
    end;

    Y := MyInt64ModularInverse(Y, FFiniteFieldSize);
    K := Int64MultipleMod(X, Y, FFiniteFieldSize); // �õ�б��
  end
  else if (P.X = Q.X) and ((P.Y = -Q.Y) or (P.Y + Q.Y = FFiniteFieldSize)) then        // P = -Q
  begin
    Sum.X := 0;
    Sum.Y := 0;
    Exit;
  end
  else if P.X <> Q.X then
  begin
    // б�� K := ((Q.Y - P.Y) / (Q.X - P.X)) mod p
    Y := Q.Y - P.Y;
    X := Q.X - P.X;

    // Y/X = Y*X^-1 = Y * (X ��� p ����Ԫ)
    X := MyInt64ModularInverse(X, FFiniteFieldSize);
    K := Int64MultipleMod(Y, X, FFiniteFieldSize); // �õ�б��
  end
  else if P.Y <> Q.Y then
  begin
    // P��Q ���� X ��ͬ��Y ��ͬ���ֲ�����Ԫ���������ӣ������ϲ������
    raise ECnEccException.CreateFmt('Can NOT Calucate %d,%d + %d,%d', [P.X, P.Y, Q.X, Q.Y]);
  end;

  // Xsum = (K^2 - X1 - X2) mod p
  X := K * K - P.X - Q.X;
  while X < 0 do
    X := X + FFiniteFieldSize;
  PX := P.X; // ��� Sum �� P ��ͬһ����Ҫ���� P.X �������������ȴ��� P.X
  if X < 0 then
  begin
    X := -X;
    Sum.X := X mod FFiniteFieldSize;
    if Sum.X > 0 then                      // ��� X �պ����������� 0
      Sum.X := FFiniteFieldSize - Sum.X;
  end
  else
    Sum.X := X mod FFiniteFieldSize;

  // Ysum = (K * (X1 - Xsum) - Y1) mod p  ע��Ҫȡ��
  //   Ҳ = (K * (X2 - Xsum) - Y2) mod p  ע��Ҫȡ��
  X := PX - Sum.X;
  Y := K * X - P.Y;
  if Y < 0 then
  begin
    Y := -Y;
    Sum.Y := Y mod FFiniteFieldSize;
    if Sum.Y > 0 then                      // ��� Y �պ����������� 0
      Sum.Y := FFiniteFieldSize - Sum.Y;
  end
  else
    Sum.Y := Y mod FFiniteFieldSize;
end;

procedure TCnInt64Ecc.PointInverse(var P: TCnInt64EccPoint);
begin
  // P.Y := -P.Y mod p ע������ĸ�ֵȡģ������ Delphi ��ȡ����ȡģ�ٱ为
  P.Y := FFiniteFieldSize - (P.Y mod FFiniteFieldSize);
end;

procedure TCnInt64Ecc.AffinePointInverse(var P: TCnInt64Ecc3Point);
begin
  P.Y := (FFiniteFieldSize * P.Z - (P.Y mod FFiniteFieldSize)) mod FFiniteFieldSize;
end;

procedure TCnInt64Ecc.JacobianPointInverse(var P: TCnInt64Ecc3Point);
begin
  P.Y := (FFiniteFieldSize * P.Z * P.Z * P.Z - (P.Y mod FFiniteFieldSize)) mod FFiniteFieldSize;
end;

procedure TCnInt64Ecc.PointSubPoint(var P, Q, Diff: TCnInt64EccPoint);
var
  Inv: TCnInt64EccPoint;
begin
  Inv.X := Q.X;
  Inv.Y := Q.Y;
  PointInverse(Inv);
  PointAddPoint(P, Inv, Diff);
end;

// ��������ѡ�������� PrivateKey ���� ECDH ��ԿЭ�̵������Կ��
function CnInt64EccDiffieHellmanGenerateOutKey(Ecc: TCnInt64Ecc; SelfPrivateKey: TCnInt64PrivateKey;
  out PublicKey: TCnInt64PublicKey): Boolean;
begin
  // OutPublicKey = SelfPrivateKey * G
  Result := False;
  if (Ecc <> nil) and (SelfPrivateKey > 0) then
  begin
    PublicKey := Ecc.Generator;
    Ecc.MultiplePoint(SelfPrivateKey, PublicKey);
    Result := True;
  end;
end;

// ���ݶԷ����͵� ECDH ��ԿЭ�̵������Կ�������ɹ��ϵ���Կ��
function CnInt64EccDiffieHellmanComputeKey(Ecc: TCnInt64Ecc; SelfPrivateKey: TCnInt64PrivateKey;
  var OtherPublicKey: TCnInt64PublicKey; var SharedSecretKey: TCnInt64PublicKey): Boolean;
begin
  // SecretKey = SelfPrivateKey * OtherPublicKey
  Result := False;
  if (Ecc <> nil) and (SelfPrivateKey > 0) then
  begin
    SharedSecretKey := OtherPublicKey;
    Ecc.MultiplePoint(SelfPrivateKey, SharedSecretKey);
    Result := True;
  end;
end;

function TCnInt64Ecc.TonelliShanks(X, P: Int64; out Y: Int64): Boolean;
var
  I: Integer;
  Q, S, Z, C, R, T, M, B: Int64;
begin
  Result := False;
  if (X <= 0) or (P <= 0) or (X >= P) then
    Exit;

  // ��Ҫͨ�����õ·����ж�����Ƿ���ڣ����������������ѭ��
  if CnInt64Legendre(X, P) <> 1 then
    Exit;

  S := 0;
  Q := P - 1;
  while (Q mod 2) = 0 do
  begin
    Q := Q shr 1;
    Inc(S);
  end;

  Z := 2;
  while Z < P do
  begin
    if CnInt64Legendre(Z, P) = -1 then
      Break;
    Inc(Z);
  end;

  // ����һ�� Z ���� ��� P �����õ·���Ϊ -1
  C := MontgomeryPowerMod(Z, Q, P);
  R := MontgomeryPowerMod(X, (Q + 1) div 2, P);
  T := MontgomeryPowerMod(X, Q, P);
  M := S;

  while True do
  begin
    if T mod P = 1 then
      Break;

    for I := 1 to M - 1 do
    begin
      if MontgomeryPowerMod(T, 1 shl I, P) = 1 then
        Break;
    end;

    B := MontgomeryPowerMod(C, 1 shl (M - I - 1), P);
    M := I; // M ÿ�ض����С���㷨����

    R := Int64MultipleMod(R, B, P);
    T := Int64MultipleMod(Int64MultipleMod(T, B, P),
      B mod P, P); // T*B*B mod P = (T*B mod P) * (B mod P) mod P
    C := Int64MultipleMod(B, B, P);
  end;
  Y := (R mod P + P) mod P;
  Result := True;
end;

function TCnInt64Ecc.GetJInvariance: Int64;
var
  D, T: Int64;
begin
{
  ������Բ���߷��� y^2 + a1*xy + a3*y = x^3 + a2*x^2 + a4*x + a6
  ӳ�䵽 y^2 = x^3 + Ax + B���ɵ� a1 = 0��a2 = 0��a3 = 0��a4 = A��a6 = B
  ��

    b2 = a1^2 + 4a2 = 0
    b4 = a1*a3 + 2a4 = 2A
    b6 = a3^2 + 4a6 = 4B
    b8 = a1^2*a6 + 4a2*a6 - a1*a3*a4 + a2*a3^2 - a4^2 = -A^2

    c4 = b2^2 - 24b4 = -48A
    c6 = b2^3 + 36b2*b4 - 216b6 = -864B

    Delta = -b2^2*b8 -8b4^3 -27b6^2 + 9b2*b4*b6 = -64A^3 - 432B^2

    j ������ = c4^3 / Delta = (-110592 * A^3) / (-64A^3 - 432B^2)
}

  D := GetDelta;
  D := MyInt64ModularInverse(D, FFiniteFieldSize);
  T := Int64NonNegativeMulMod(-110592, FCoefficientA, FFiniteFieldSize);
  T := Int64NonNegativeMulMod(T, FCoefficientA, FFiniteFieldSize);
  T := Int64NonNegativeMulMod(T, FCoefficientA, FFiniteFieldSize);
  Result := Int64NonNegativeMulMod(T, D, FFiniteFieldSize);
end;

function TCnInt64Ecc.GetDelta: Int64;
begin
{
  ������Բ���߷��� y^2 + a1*xy + a3*y = x^3 + a2*x^2 + a4*x + a6
  ӳ�䵽 y^2 = x^3 + Ax + B���ɵ� a1 = 0��a2 = 0��a3 = 0��a4 = A��a6 = B
  ��

    b2 = a1^2 + 4a2 = 0
    b4 = a1*a3 + 2a4 = 2A
    b6 = a3^2 + 4a6 = 4B
    b8 = a1^2*a6 + 4a2*a6 - a1*a3*a4 + a2*a3^2 - a4^2 = -A^2

    c4 = b2^2 - 24b4 = -48A
    c6 = b2^3 + 36b2*b4 - 216b6 = -864B

    Delta = -b2^2*b8 -8b4^3 -27b6^2 + 9b2*b4*b6 = -64A^3 - 432B^2
}
  Result := -64 * FCoefficientA * FCoefficientA * FCoefficientA
    - 432 * FCoefficientB * FCoefficientB;
end;

function TCnInt64Ecc.PointToPlain(var Point: TCnInt64EccPoint): Int64;
begin
  Result := Point.X;
end;

{ TCnEccPoint }

procedure TCnEccPoint.Assign(Source: TPersistent);
begin
  if Source is TCnEccPoint then
  begin
    BigNumberCopy(FX, (Source as TCnEccPoint).X);
    BigNumberCopy(FY, (Source as TCnEccPoint).Y);
  end
  else if Source is TCnEcc3Point then
  begin
    BigNumberCopy(FX, (Source as TCnEcc3Point).X);
    BigNumberCopy(FY, (Source as TCnEcc3Point).Y);
    if FX.IsZero and FY.IsZero then
      (Source as TCnEcc3Point).Z.SetZero
    else
      (Source as TCnEcc3Point).Z.SetOne;
  end
  else
    inherited;
end;

constructor TCnEccPoint.Create;
begin
  inherited;
  FX := TCnBigNumber.Create;
  FY := TCnBigNumber.Create;
  FX.SetZero;
  FY.SetZero;
end;

constructor TCnEccPoint.Create(const XDec, YDec: AnsiString);
begin
  Create;
  FX.SetDec(XDec);
  FY.SetDec(YDec);
end;

destructor TCnEccPoint.Destroy;
begin
  FY.Free;
  FX.Free;
  inherited;
end;

function TCnEccPoint.IsZero: Boolean;
begin
  Result := FX.IsZero and FY.IsZero;
end;

procedure TCnEccPoint.SetBase64(const Buf: AnsiString; Ecc: TCnEcc);
var
  B: TBytes;
begin
  if Base64Decode(string(Buf), B) = ECN_BASE64_OK then
    SetHex(AnsiString(BytesToHex(B)), Ecc);
end;

procedure TCnEccPoint.SetHex(const Buf: AnsiString; Ecc: TCnEcc);
var
  C: Integer;
  S: AnsiString;
  P: TCnEccPoint;
begin
  if Length(Buf) < 4 then
    raise ECnEccException.Create(SCnErrorEccKeyData);

  C := StrToIntDef(string(Copy(Buf, 1, 2)), 0);
  S := Copy(Buf, 3, MaxInt);

  if (C = EC_PUBLICKEY_UNCOMPRESSED) or (C = EC_PUBLICKEY_COMPRESSED_ODD) or
    (C = EC_PUBLICKEY_COMPRESSED_EVEN) then
  begin
    // ǰ���ֽں�������ݣ�Ҫ������һ�빫Կһ��˽Կ�����ȵ���ȣ�Ҫ�����ǹ�Կ X����Ҫ�� 4 ����
    if (Length(S) mod 4) <> 0 then
    begin
      // ǰ���ֽں�������ݳ��Ȳ��ԣ��������°�ǰ���ֽ������������˽Կһ���ж�
      if (Length(Buf) mod 4) <> 0 then // ������Ȼ����ԣ������
        raise ECnEccException.Create(SCnErrorEccKeyData);

      // ��ǰ���ֽ�������ĳ����ǶԵģ�ֱ������ Buf ��ֵ
      C := Length(Buf) div 2;
      FX.SetHex(Copy(Buf, 1, C));
      FY.SetHex(Copy(Buf, C + 1, MaxInt));
    end
    else // ǰ���ֽ����ݺ�ĳ��ȶ�
    begin
      if C = EC_PUBLICKEY_UNCOMPRESSED then
      begin
        C := Length(S) div 2;
        FX.SetHex(Copy(S, 1, C));
        FY.SetHex(Copy(S, C + 1, MaxInt));
      end
      else if (C = EC_PUBLICKEY_COMPRESSED_EVEN) or (C = EC_PUBLICKEY_COMPRESSED_ODD) then
      begin
        FX.SetHex(S);
        FY.SetZero;  // ѹ����ʽȫ�ǹ�Կ X��Y �� 0����ȥ���

        if Ecc <> nil then
        begin
          P := TCnEccPoint.Create;
          try
            // �� Y ����ż����Ϣ����ȥ���������õ����� Y ֵ�����
            if Ecc.PlainToPoint(FX, P) then
            begin
              if P.Y.IsOdd and (C = EC_PUBLICKEY_COMPRESSED_ODD) then
                BigNumberCopy(FY, P.Y)
              else
              begin
                Ecc.PointInverse(P);
                BigNumberCopy(FY, P.Y);
              end;
            end;
          finally
            P.Free;
          end;
        end;
      end
      else  // ǰ���ֽ����ݷǷ�
        raise ECnEccException.Create(SCnErrorEccKeyData);
    end;
  end
  else // ǰ���ֽڷǺϷ�ֵ��˵����ǰ���ֽ�
  begin
    if (Length(Buf) mod 4) <> 0 then // һ�빫Կһ��˽Կ�����ȵ����
      raise ECnEccException.Create(SCnErrorEccKeyData);

    C := Length(Buf) div 2;
    FX.SetHex(Copy(Buf, 1, C));
    FY.SetHex(Copy(Buf, C + 1, MaxInt));
  end;
end;

procedure TCnEccPoint.SetX(const Value: TCnBigNumber);
begin
  BigNumberCopy(FX, Value);
end;

procedure TCnEccPoint.SetY(const Value: TCnBigNumber);
begin
  BigNumberCopy(FY, Value);
end;

procedure TCnEccPoint.SetZero;
begin
  FX.SetZero;
  FY.SetZero;
end;

function TCnEccPoint.ToBase64(FixedLen: Integer): string;
var
  B: Byte;
  Stream: TMemoryStream;
begin
  if FY.IsZero then
    B := 3          // ��֪�� Y ����ֵ���޷�ȷ����ż����ʱд 03
  else
    B := 4;

  Stream := TMemoryStream.Create;
  try
    Stream.Write(B, SizeOf(B));
    BigNumberWriteBinaryToStream(FX, Stream, FixedLen);

    if not FY.IsZero then
      BigNumberWriteBinaryToStream(FY, Stream, FixedLen);

    Base64Encode(Stream.Memory, Stream.Size, Result);
  finally
    Stream.Free;
  end;
end;

function TCnEccPoint.ToHex(FixedLen: Integer): string;
begin
  if FY.IsZero then
    Result := '03' + FX.ToHex(FixedLen) // ��֪�� Y ����ֵ���޷�ȷ����ż����ʱд 03
  else
    Result := '04' + FX.ToHex(FixedLen) + FY.ToHex(FixedLen);
end;

function TCnEccPoint.ToString: string;
begin
  Result := CnEccPointToHex(Self);
end;

{ TCnEcc }

procedure TCnEcc.CalcX3AddAXAddB(X: TCnBigNumber);
var
  M: TCnBigNumber;
begin
  M := FEccBigNumberPool.Obtain;
  try
    BigNumberCopy(M, X);
    BigNumberMul(X, X, X);
    BigNumberMul(X, X, M); // X: X^3

    BigNumberMul(M, M, FCoefficientA); // M: A*X
    BigNumberAdd(X, X, M);             // X: X^3 + A*X
    BigNumberAdd(X, X, FCoefficientB); // X: X^3 + A*X + B
  finally
    FEccBigNumberPool.Recycle(M);
  end;
end;

constructor TCnEcc.Create(const A, B, FieldPrime, GX, GY, Order: AnsiString; H: Integer);
begin
  Create;
  Load(A, B, FIeldPrime, GX, GY, Order, H);
end;

constructor TCnEcc.Create;
begin
  inherited;
  FGenerator := TCnEccPoint.Create;
  FCoefficientB := TCnBigNumber.Create;
  FCoefficientA := TCnBigNumber.Create;
  FOrder := TCnBigNumber.Create;
  FFiniteFieldSize := TCnBigNumber.Create;

  FSizeUFactor := TCnBigNumber.Create;

  // ������ǰ����
//  F2Inverse := TCnBigNumber.Create;
//  F2Inverse.SetZero;
end;

constructor TCnEcc.Create(Predefined: TCnEccCurveType);
begin
  Create;
  Load(Predefined);
end;

procedure TCnEcc.Decrypt(DataPoint1, DataPoint2: TCnEccPoint;
  PrivateKey: TCnEccPrivateKey; OutPlainPoint: TCnEccPoint);
var
  P: TCnEccPoint;
begin
  if (BigNumberCompare(PrivateKey, CnBigNumberZero) <= 0) or
    not IsPointOnCurve(DataPoint1) or not IsPointOnCurve(DataPoint2) then
    raise ECnEccException.Create('Invalid Private Key or Data.');

  P := TCnEccPoint.Create;
  try
    P.Assign(DataPoint2);
    MultiplePoint(PrivateKey, P);
    PointSubPoint(DataPoint1, P, OutPlainPoint);
  finally
    P.Free;
  end;
end;

destructor TCnEcc.Destroy;
begin
  F2Inverse.Free; // ������ǰ����
  FSizeUFactor.Free;

  FGenerator.Free;
  FCoefficientB.Free;
  FCoefficientA.Free;
  FOrder.Free;
  FFiniteFieldSize.Free;
  inherited;
end;

procedure TCnEcc.Encrypt(PlainPoint: TCnEccPoint;
  PublicKey: TCnEccPublicKey; OutDataPoint1, OutDataPoint2: TCnEccPoint);
var
  RandomKey: TCnBigNumber;
begin
  if not IsPointOnCurve(PublicKey) or not IsPointOnCurve(PlainPoint) then
    raise ECnEccException.Create(SCnErrorEccKeyData);

  RandomKey := FEccBigNumberPool.Obtain;
  try
    BigNumberRandRange(RandomKey, FOrder);    // �� 0 �󵫱Ȼ����С�������
    if BigNumberIsZero(RandomKey) then
      BigNumberSetOne(RandomKey);

    // M + rK;
    OutDataPoint1.Assign(PublicKey);
    MultiplePoint(RandomKey, OutDataPoint1);
    PointAddPoint(PlainPoint, OutDataPoint1, OutDataPoint1);

    // r * G
    OutDataPoint2.Assign(FGenerator);
    MultiplePoint(RandomKey, OutDataPoint2);
  finally
    FEccBigNumberPool.Recycle(RandomKey);
  end;
end;

procedure TCnEcc.GenerateKeys(PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey);
begin
  BigNumberRandRange(PrivateKey, FOrder);           // �� 0 �󵫱Ȼ����С�������
  if PrivateKey.IsZero then                         // ��һ���õ� 0���ͼ� 1
    PrivateKey.SetOne;

  PublicKey.Assign(FGenerator);
  MultiplePoint(PrivateKey, PublicKey);             // ����� PrivateKey ��
end;

function TCnEcc.GetBitsCount: Integer;
begin
  Result := FFiniteFieldSize.GetBitsCount;
end;

function TCnEcc.IsPointOnCurve(P: TCnEccPoint): Boolean;
var
  X, Y: TCnBigNumber;
begin
  Result := False;
  if P = nil then
    Exit;

  X := nil;
  Y := nil;

  try
    X := FEccBigNumberPool.Obtain;
    if BigNumberCopy(X, P.X) = nil then
      Exit;

    Y := FEccBigNumberPool.Obtain;
    if BigNumberCopy(Y, P.Y) = nil then
      Exit;

    if not BigNumberDirectMulMod(Y, Y, Y, FFiniteFieldSize) then // Y: Y^2 mod P
      Exit;

    CalcX3AddAXAddB(X);                   // X: X^3 + A*X + B
    if not BigNumberMod(X, X, FFiniteFieldSize) then // X: (X^3 + A*X + B) mod P
      Exit;

    Result := BigNumberCompare(X, Y) = 0;
  finally
    FEccBigNumberPool.Recycle(Y);
    FEccBigNumberPool.Recycle(X);
  end;
end;

procedure TCnEcc.Load(Predefined: TCnEccCurveType);
begin
  Load(ECC_PRE_DEFINED_PARAMS[Predefined].A, ECC_PRE_DEFINED_PARAMS[Predefined].B,
    ECC_PRE_DEFINED_PARAMS[Predefined].P, ECC_PRE_DEFINED_PARAMS[Predefined].X,
    ECC_PRE_DEFINED_PARAMS[Predefined].Y, ECC_PRE_DEFINED_PARAMS[Predefined].N,
    StrToIntDef(string(ECC_PRE_DEFINED_PARAMS[Predefined].H), 1));
end;

procedure TCnEcc.Load(const A, B, FieldPrime, GX, GY, Order: AnsiString; H: Integer);
var
  R: Cardinal;
begin
  FGenerator.X.SetHex(GX);
  FGenerator.Y.SetHex(GY);
  FCoefficientA.SetHex(A);
  FCoefficientB.SetHex(B);
  FFiniteFieldSize.SetHex(FieldPrime);
  FOrder.SetHex(Order);
  FCoFactor := H;

  // TODO: Ҫȷ�� 4*a^3+27*b^2 <> 0

//  �ɵ����߱�֤������߽�Ϊ����
//  if not BigNumberIsProbablyPrime(FFiniteFieldSize) then
//    raise ECnEccException.Create('Error: Finite Field Size must be Prime.');

  // ȷ�� PrimeType
  R := BigNumberModWord(FFiniteFieldSize, 4);
  BigNumberCopy(FSizeUFactor, FFiniteFieldSize);
  if R = 3 then  // RFC 5639 Ҫ�� p ���� 4u + 3 ����ʽ�Ա㷽��ؼ��� Y������������δ��
  begin
    FSizePrimeType := pt4U3;
    BigNumberDivWord(FSizeUFactor, 4);
  end
  else
  begin
    R := BigNumberModWord(FFiniteFieldSize, 8);
    if R = 1 then
    begin
      FSizePrimeType := pt8U1;
      BigNumberDivWord(FSizeUFactor, 8);
    end
    else if R = 5 then
    begin
      FSizePrimeType := pt8U5;
      BigNumberDivWord(FSizeUFactor, 8);
    end
    else
      raise ECnEccException.Create('Invalid Finite Field Size.');
  end;
end;

function TCnEcc.GetBytesCount: Integer;
begin
  Result := FFiniteFieldSize.GetBytesCount;
end;

procedure TCnEcc.NormalMultiplePoint(K: TCnBigNumber; Point: TCnEccPoint);
var
  I, C: Integer;
  E, R: TCnEccPoint;
begin
  if BigNumberIsNegative(K) then
  begin
    // BigNumberSetNegative(K, False);
    PointInverse(Point);
  end;

  if BigNumberIsZero(K) then
  begin
    Point.SetZero;
    Exit;
  end
  else if BigNumberIsOne(K) then // �� 1 ���趯
    Exit;

  R := nil;
  E := nil;

  try
    R := TCnEccPoint.Create;
    E := TCnEccPoint.Create;

    // R ������ʱĬ��Ϊ����Զ��
    E.X := Point.X;
    E.Y := Point.Y;

    C := BigNumberGetBitsCount(K);
    for I := 0 to C - 1 do
    begin
      if BigNumberIsBitSet(K, I) then
        PointAddPoint(R, E, R);

      if I < C - 1 then
        PointAddPoint(E, E, E);
    end;

    Point.X := R.X;
    Point.Y := R.Y;
  finally
    E.Free;
    R.Free;
  end;
end;

procedure TCnEcc.AffineMultiplePoint(K: TCnBigNumber; Point: TCnEcc3Point);
var
  I, C: Integer;
  E, R: TCnEcc3Point;
begin
  if BigNumberIsNegative(K) then
  begin
    // BigNumberSetNegative(K, False);
    AffinePointInverse(Point);
  end;

  if BigNumberIsZero(K) then
  begin
    Point.X.SetZero;
    Point.Y.SetZero;
    Point.Z.SetZero;
    Exit;
  end
  else if BigNumberIsOne(K) then // �� 1 ���趯
    Exit;

  R := nil;
  E := nil;

  try
    R := TCnEcc3Point.Create;
    E := TCnEcc3Point.Create;

    E.X := Point.X;
    E.Y := Point.Y;
    E.Z := Point.Z;

    C := BigNumberGetBitsCount(K);
    for I := 0 to C - 1 do
    begin
      if BigNumberIsBitSet(K, I) then
        AffinePointAddPoint(R, E, R);

      if I < C - 1 then // ���һ��ѭ������� E
        AffinePointAddPoint(E, E, E);
    end;

    Point.X := R.X;
    Point.Y := R.Y;
    Point.Z := R.Z;
  finally
    R.Free;
    E.Free;
  end;
end;

procedure TCnEcc.JacobianMultiplePoint(K: TCnBigNumber; Point: TCnEcc3Point);
var
  I, C: Integer;
  E, R: TCnEcc3Point;
begin
  if BigNumberIsNegative(K) then
  begin
    // BigNumberSetNegative(K, False);
    JacobianPointInverse(Point);
  end;

  if BigNumberIsZero(K) then
  begin
    Point.X.SetZero;
    Point.Y.SetZero;
    Point.Z.SetZero;
    Exit;
  end
  else if BigNumberIsOne(K) then // �� 1 ���趯
    Exit;

  R := nil;
  E := nil;

  try
    R := TCnEcc3Point.Create;
    E := TCnEcc3Point.Create;

    E.X := Point.X;
    E.Y := Point.Y;
    E.Z := Point.Z;

    C := BigNumberGetBitsCount(K);
    for I := 0 to C - 1 do
    begin
      if BigNumberIsBitSet(K, I) then
        JacobianPointAddPoint(R, E, R);

      if I < C - 1 then
        JacobianPointAddPoint(E, E, E);
    end;

    Point.X := R.X;
    Point.Y := R.Y;
    Point.Z := R.Z;
  finally
    R.Free;
    E.Free;
  end;
end;

procedure TCnEcc.MultiplePoint(K: Int64; Point: TCnEccPoint);
var
  BK: TCnBigNumber;
begin
  BK := FEccBigNumberPool.Obtain;
  try
    BK.SetInt64(K);
    MultiplePoint(BK, Point);
  finally
    FEccBigNumberPool.Recycle(BK);
  end;
end;

procedure TCnEcc.MultiplePoint(K: TCnBigNumber; Point: TCnEccPoint);
var
  P3: TCnEcc3Point;
begin
  P3 := TCnEcc3Point.Create;
  try
    CnEccPointToEcc3Point(Point, P3);
    AffineMultiplePoint(K, P3);
    CnAffinePointToEccPoint(P3, Point, FFiniteFieldSize);
  finally
    P3.Free;
  end;
end;

function TCnEcc.PlainToPoint(Plain: TCnBigNumber;
  OutPoint: TCnEccPoint): Boolean;
var
  X, Y, Z, U, R, T, X3: TCnBigNumber;
begin
  Result := False;
  if Plain.IsNegative then
    Exit;

  if BigNumberCompare(Plain, FFiniteFieldSize) >= 0 then
    Exit;

  X := nil;
  U := nil;
  Y := nil;
  Z := nil;
  R := nil;
  T := nil;
  X3 := nil;

  try
    X := FEccBigNumberPool.Obtain;
    Y := FEccBigNumberPool.Obtain;
    Z := FEccBigNumberPool.Obtain;
    U := FEccBigNumberPool.Obtain;
    X3 := FEccBigNumberPool.Obtain;

    BigNumberCopy(X, Plain);
    BigNumberCopy(U, FSizeUFactor);

    CalcX3AddAXAddB(X);
    BigNumberMod(X, X, FFiniteFieldSize);
    BigNumberCopy(X3, X);    // ����ԭʼ g

    if X3.IsZero then // ��� (X^3 + AX + B) mod p Ϊ 0����ֱ�ӷ��� (Plain, 0) ���ҿ϶��������߷���
    begin
      BigNumberCopy(OutPoint.X, Plain);
      OutPoint.Y.SetZero;
      Result := True;
      Exit;
    end;

    // �ο��ԡ�SM2��Բ���߹�Կ�����㷨����¼ B �еġ�ģ����ƽ��������⡱һ�ڣ����� g �� X ���������ķ����Ұ벿��ֵ
    case FSizePrimeType of
      pt4U3:
        begin
          // ����� g^(u+1) mod p
          BigNumberAddWord(U, 1);
          BigNumberMontgomeryPowerMod(Y, X, U, FFiniteFieldSize);
          BigNumberDirectMulMod(Z, Y, Y, FFiniteFieldSize);
          if BigNumberCompare(Z, X) = 0 then
          begin
            BigNumberCopy(OutPoint.X, Plain);
            BigNumberCopy(OutPoint.Y, Y);
            Result := True;
            Exit;
          end;
        end;
      pt8U5:
        begin
          BigNumberMulWord(U, 2);
          BigNumberAddWord(U, 1);
          BigNumberMontgomeryPowerMod(Z, X, U, FFiniteFieldSize);
          R := FEccBigNumberPool.Obtain;
          BigNumberMod(R, Z, FFiniteFieldSize);

          if R.IsOne then
          begin
            // ����� g^(u+1) mod p
            BigNumberCopy(U, FSizeUFactor);
            BigNumberAddWord(U, 1);
            BigNumberMontgomeryPowerMod(Y, X, U, FFiniteFieldSize);

            BigNumberCopy(OutPoint.X, Plain);
            BigNumberCopy(OutPoint.Y, Y);
            Result := True;
          end
          else
          begin
            if R.IsNegative then
              BigNumberAdd(R, R, FFiniteFieldSize);
            BigNumberSub(R, FFiniteFieldSize, R);
            if R.IsOne then
            begin
              // �����(2g ��(4g)^u) mod p = (2g mod p * (4g)^u mod p) mod p
              BigNumberCopy(X, X3);
              BigNumberMulWord(X, 2);
              BigNumberMod(R, X, FFiniteFieldSize);  // R: 2g mod p

              BigNumberCopy(X, X3);
              BigNumberMulWord(X, 4);
              T := FEccBigNumberPool.Obtain;
              BigNumberMontgomeryPowerMod(T, X, FSizeUFactor, FFiniteFieldSize); // T: (4g)^u mod p
              BigNumberDirectMulMod(Y, R, T, FFiniteFieldSize);

              BigNumberCopy(OutPoint.X, Plain);
              BigNumberCopy(OutPoint.Y, Y);
              Result := True;
            end;
          end;
        end;
      pt8U1: // Lucas ���м��㷨�� Tonelli-Shanks �㷨���ܽ���ģ��������ʣ�����
        begin
{$IFDEF USE_LUCAS}
          if BigNumberLucas(OutPoint.Y, X3, FFiniteFieldSize) then
          begin
            BigNumberCopy(OutPoint.X, Plain);
            Result := True;
          end;
{$ELSE}
          if BigNumberTonelliShanks(OutPoint.Y, X3, FFiniteFieldSize) then
          begin
            BigNumberCopy(OutPoint.X, Plain);
            Result := True;
          end;
{$ENDIF}
        end;
    end;
  finally
    FEccBigNumberPool.Recycle(X);
    FEccBigNumberPool.Recycle(Y);
    FEccBigNumberPool.Recycle(Z);
    FEccBigNumberPool.Recycle(U);
    FEccBigNumberPool.Recycle(R);
    FEccBigNumberPool.Recycle(T);
    FEccBigNumberPool.Recycle(X3);
  end;
end;

procedure TCnEcc.PointAddPoint(P, Q, Sum: TCnEccPoint);
var
  K, X, Y, A, SX, SY: TCnBigNumber;
begin
  K := nil;
  X := nil;
  Y := nil;
  A := nil;
  SX := nil;
  SY := nil;

  try
    if P.IsZero then
    begin
      Sum.Assign(Q);
      Exit;
    end
    else if Q.IsZero then
    begin
      Sum.Assign(P);
      Exit;
    end
    else if (BigNumberCompare(P.X, Q.X) = 0) and (BigNumberCompare(P.Y, Q.Y) = 0) then
    begin
      // ��������ͬһ���㣬����б��Ϊ�����󵼣�3 * X^2 + A / (2 * Y) ���� Y = 0 ��ֱ��������Զ 0��
      if P.Y.IsZero then
      begin
        Sum.SetZero;
        Exit;
      end;

      X := FEccBigNumberPool.Obtain;
      Y := FEccBigNumberPool.Obtain;
      K := FEccBigNumberPool.Obtain;

      // X := 3 * P.X * P.X + CoefficientA;
      BigNumberMul(X, P.X, P.X);             // X: P.X^2
      BigNumberMulWord(X, 3);                // X: 3 * P.X^2
      BigNumberAdd(X, X, FCoefficientA);     // X: 3 * P.X^2 + A

      // Y := 2 * P.Y;
      BigNumberCopy(Y, P.Y);
      BigNumberMulWord(Y, 2);                // Y: 2 * P.Y

      A := FEccBigNumberPool.Obtain;
      BigNumberCopy(A, Y);
      BigNumberModularInverse(Y, A, FFiniteFieldSize); // Y := Y^-1

      // K := X * Y mod FFiniteFieldSize;
      BigNumberDirectMulMod(K, X, Y, FFiniteFieldSize);      // �õ�б��
    end
    else // �ǲ�ͬ��
    begin
      if BigNumberCompare(P.X, Q.X) = 0 then // ��� X ��ȣ�Ҫ�ж� Y �ǲ��ǻ����������Ϊ 0�����������
      begin
        A := FEccBigNumberPool.Obtain;
        BigNumberAdd(A, P.Y, Q.Y);
        if BigNumberCompare(A, FFiniteFieldSize) = 0 then  // ��������Ϊ 0
          Sum.SetZero
        else                                               // ������������
          raise ECnEccException.CreateFmt('Can NOT Calucate %s,%s + %s,%s',
            [P.X.ToDec, P.Y.ToDec, Q.X.ToDec, Q.Y.ToDec]);

        Exit;
      end;

      // �����X ȷ����ͬ��б�� K := ((Q.Y - P.Y) / (Q.X - P.X)) mod p
      X := FEccBigNumberPool.Obtain;
      Y := FEccBigNumberPool.Obtain;
      K := FEccBigNumberPool.Obtain;

      // Y := Q.Y - P.Y;
      // X := Q.X - P.X;
      BigNumberSub(Y, Q.Y, P.Y);
      BigNumberSub(X, Q.X, P.X);

      A := FEccBigNumberPool.Obtain;
      BigNumberCopy(A, X);
      BigNumberModularInverse(X, A, FFiniteFieldSize);
      BigNumberDirectMulMod(K, Y, X, FFiniteFieldSize);      // �õ�б��
    end;

    BigNumberCopy(X, K);
    BigNumberMul(X, X, K);
    BigNumberSub(X, X, P.X);
    BigNumberSub(X, X, Q.X);    //  X := K * K - P.X - Q.X;

    SX := FEccBigNumberPool.Obtain;
    if BigNumberIsNegative(X) then // ��ֵ��ģ������ֵ��ģ��ģ����
    begin
      BigNumberSetNegative(X, False);
      BigNumberMod(SX, X, FFiniteFieldSize);
      if not SX.IsZero then                   // �պ�����ʱ����������� 0��������� X ֵ�����������Ͻ�����
        BigNumberSub(SX, FFiniteFieldSize, SX);
    end
    else
      BigNumberMod(SX, X, FFiniteFieldSize);

    // Ysum = (K * (X1 - Xsum) - Y1) mod p  ע��Ҫȡ��
    //   Ҳ = (K * (X2 - Xsum) - Y2) mod p  ע��Ҫȡ��
    BigNumberSub(X, P.X, SX);
    BigNumberMul(Y, K, X);
    BigNumberSub(Y, Y, P.Y);

    SY := FEccBigNumberPool.Obtain;
    if BigNumberIsNegative(Y) then
    begin
      BigNumberSetNegative(Y, False);
      BigNumberMod(SY, Y, FFiniteFieldSize);
      if not SY.IsZero then                     // �պ�����ʱ����������� 0��������� Y ֵ�����������Ͻ�����
        BigNumberSub(SY, FFiniteFieldSize, SY);
    end
    else
      BigNumberMod(SY, Y, FFiniteFieldSize);

    BigNumberCopy(Sum.X, SX);
    BigNumberCopy(Sum.Y, SY);
  finally
    FEccBigNumberPool.Recycle(K);
    FEccBigNumberPool.Recycle(X);
    FEccBigNumberPool.Recycle(Y);
    FEccBigNumberPool.Recycle(A);
    FEccBigNumberPool.Recycle(SX);
    FEccBigNumberPool.Recycle(SY);
  end;
end;

procedure TCnEcc.AffinePointAddPoint(P, Q, Sum: TCnEcc3Point);
var
  T, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11: TCnBigNumber;
begin
  if P.Z.IsZero then
  begin
    BigNumberCopy(Sum.X, Q.X);
    BigNumberCopy(Sum.Y, Q.Y);
    BigNumberCopy(Sum.Z, Q.Z);
    Exit;
  end
  else if Q.Z.IsZero then
  begin
    BigNumberCopy(Sum.X, P.X);
    BigNumberCopy(Sum.Y, P.Y);
    BigNumberCopy(Sum.Z, P.Z);
    Exit;
  end;

  T := nil;
  D1 := nil;
  D2 := nil;
  D3 := nil;
  D4 := nil;
  D5 := nil;
  D6 := nil;
  D7 := nil;
  D8 := nil;
  D9 := nil;
  D10 := nil;
  D11 := nil;

  try
    T := FEccBigNumberPool.Obtain;
    D1 := FEccBigNumberPool.Obtain;
    D2 := FEccBigNumberPool.Obtain;
    D3 := FEccBigNumberPool.Obtain;
    D4 := FEccBigNumberPool.Obtain;
    D5 := FEccBigNumberPool.Obtain;
    D6 := FEccBigNumberPool.Obtain;
    D7 := FEccBigNumberPool.Obtain;
    D8 := FEccBigNumberPool.Obtain;
    D9 := FEccBigNumberPool.Obtain;
    D10 := FEccBigNumberPool.Obtain;
    D11 := FEccBigNumberPool.Obtain;

    // D1 := px * qz
    BigNumberDirectMulMod(D1, P.X, Q.Z, FFiniteFieldSize);

    // D2 := qx * pz
    BigNumberDirectMulMod(D2, Q.X, P.Z, FFiniteFieldSize);

    // D4 := py * qz
    BigNumberDirectMulMod(D4, P.Y, Q.Z, FFiniteFieldSize);

    // D5 := qy * pz
    BigNumberDirectMulMod(D5, Q.Y, P.Z, FFiniteFieldSize);

    if BigNumberEqual(D1, D2) and BigNumberEqual(D4, D5) then
    begin
      // ͬһ���㣬���߷�

      // D1 := 3 px^2 + A * pz^2
      BigNumberDirectMulMod(D1, P.X, P.X, FFiniteFieldSize);
      BigNumberMulWordNonNegativeMod(D1, D1, 3, FFiniteFieldSize);
      BigNumberDirectMulMod(T, P.Z, P.Z, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, FCoefficientA, FFiniteFieldSize);
      BigNumberAddMod(D1, D1, T, FFiniteFieldSize);

      // D2 := 2 * py * pz
      BigNumberMulWordNonNegativeMod(D2, P.Y, 2, FFiniteFieldSize);
      BigNumberDirectMulMod(D2, D2, P.Z, FFiniteFieldSize);

      // D3 := py^2
      BigNumberDirectMulMod(D3, P.Y, P.Y, FFiniteFieldSize);

      // D4 := D3 * px * pz
      BigNumberDirectMulMod(D4, D3, P.X, FFiniteFieldSize);
      BigNumberDirectMulMod(D4, D4, P.Z, FFiniteFieldSize);

      // D5 := D2^2
      BigNumberDirectMulMod(D5, D2, D2, FFiniteFieldSize);

      // D6 := D1^2 - 8 * D4
      BigNumberDirectMulMod(D6, D1, D1, FFiniteFieldSize);
      BigNumberMulWordNonNegativeMod(T, D4, 8, FFiniteFieldSize);
      BigNumberSubMod(D6, D6, T, FFiniteFieldSize);

      // X := D2 * D6
      BigNumberDirectMulMod(Sum.X, D2, D6, FFiniteFieldSize);

      // Y := D1 * (4 * D4 - D6) - 2 * D5 * D3
      BigNumberMulWordNonNegativeMod(T, D4, 4, FFiniteFieldSize);
      BigNumberSubMod(T, T, D6, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, D1, FFiniteFieldSize);

      BigNumberDirectMulMod(Sum.Y, D3, D5, FFiniteFieldSize);
      BigNumberAddMod(Sum.Y, Sum.Y, Sum.Y, FFiniteFieldSize);
      BigNumberSubMod(Sum.Y, T, Sum.Y, FFiniteFieldSize);

      // Z := D2 * D5
      BigNumberDirectMulMod(Sum.Z, D2, D5, FFiniteFieldSize);
    end
    else // ��ͬ�㣬���߷�
    begin
      // ��Ϊ�в�ͬ�� Z ���ڣ��������жϣ�ͬ����������
      if BigNumberEqual(D1, D2) then
      begin
        BigNumberAdd(T, D4, D5);
        if BigNumberEqual(T, FFiniteFieldSize) then // X ����� Y ����
        begin
          Sum.X.SetZero;
          Sum.Y.SetZero;
          Sum.Z.SetZero;
          Exit;
        end
        else // X ����� Y ��������û�����
          raise ECnEccException.CreateFmt('Can NOT Calucate Affine %d,%d,%d + %d,%d,%d',
            [P.X.ToDec, P.Y.ToDec, P.Z.ToDec, Q.X.ToDec, Q.Y.ToDec, Q.Z.ToDec]);
      end;

      // D3 := D1 - D2
      BigNumberSubMod(D3, D1, D2, FFiniteFieldSize);

      // D6 := D4 - D5
      BigNumberSubMod(D6, D4, D5, FFiniteFieldSize);

      // D7 := D1 + D2
      BigNumberAddMod(D7, D1, D2, FFiniteFieldSize);

      // D8 := pz * qz
      BigNumberDirectMulMod(D8, P.Z, Q.Z, FFiniteFieldSize);

      // D9 := D3 ^ 2
      BigNumberDirectMulMod(D9, D3, D3, FFiniteFieldSize);

      // D10 := D3 * D9
      BigNumberDirectMulMod(D10, D3, D9, FFiniteFieldSize);

      // D11 := D8 * D6 ^ 2 - D7 * D9
      BigNumberDirectMulMod(D11, D6, D6, FFiniteFieldSize);
      BigNumberDirectMulMod(D11, D11, D8, FFiniteFieldSize);
      BigNumberDirectMulMod(T, D7, D9, FFiniteFieldSize);
      BigNumberSubMod(D11, D11, T, FFiniteFieldSize);

      // Y := D6 * (D9 * D1 - D11) - D4 * D10
      BigNumberDirectMulMod(T, D9, D1, FFiniteFieldSize);
      BigNumberSubMod(T, T, D11, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, D6, FFiniteFieldSize);

      BigNumberDirectMulMod(Sum.Y, D4, D10, FFiniteFieldSize);
      BigNumberSubMod(Sum.Y, T, Sum.Y, FFiniteFieldSize);

      // X := D3 * D11
      BigNumberDirectMulMod(Sum.X, D3, D11, FFiniteFieldSize);

      // Z := D10 * D8
      BigNumberDirectMulMod(Sum.Z, D10, D8, FFiniteFieldSize);
    end;

    if Sum.Z.IsZero then
    begin
      Sum.X.SetZero;
      Sum.Y.SetZero;
    end;
  finally
    FEccBigNumberPool.Recycle(D11);
    FEccBigNumberPool.Recycle(D10);
    FEccBigNumberPool.Recycle(D9);
    FEccBigNumberPool.Recycle(D8);
    FEccBigNumberPool.Recycle(D7);
    FEccBigNumberPool.Recycle(D6);
    FEccBigNumberPool.Recycle(D5);
    FEccBigNumberPool.Recycle(D4);
    FEccBigNumberPool.Recycle(D3);
    FEccBigNumberPool.Recycle(D2);
    FEccBigNumberPool.Recycle(D1);
    FEccBigNumberPool.Recycle(T);
  end;
end;

procedure TCnEcc.JacobianPointAddPoint(P, Q, Sum: TCnEcc3Point);
var
  T, D1, D2, D3, D4, D5, D6, D7, D8, D9: TCnBigNumber;
begin
  if P.Z.IsZero then
  begin
    BigNumberCopy(Sum.X, Q.X);
    BigNumberCopy(Sum.Y, Q.Y);
    BigNumberCopy(Sum.Z, Q.Z);
    Exit;
  end
  else if Q.Z.IsZero then
  begin
    BigNumberCopy(Sum.X, P.X);
    BigNumberCopy(Sum.Y, P.Y);
    BigNumberCopy(Sum.Z, P.Z);
    Exit;
  end;

  T := nil;
  D1 := nil;
  D2 := nil;
  D3 := nil;
  D4 := nil;
  D5 := nil;
  D6 := nil;
  D7 := nil;
  D8 := nil;
  D9 := nil;

  try
    T := FEccBigNumberPool.Obtain;
    D1 := FEccBigNumberPool.Obtain;
    D2 := FEccBigNumberPool.Obtain;
    D3 := FEccBigNumberPool.Obtain;
    D4 := FEccBigNumberPool.Obtain;
    D5 := FEccBigNumberPool.Obtain;
    D6 := FEccBigNumberPool.Obtain;
    D7 := FEccBigNumberPool.Obtain;
    D8 := FEccBigNumberPool.Obtain;
    D9 := FEccBigNumberPool.Obtain;

    // D1 := PX * QZ^2
    BigNumberDirectMulMod(D1, Q.Z, Q.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(D1, D1, P.X, FFiniteFieldSize);

    // D2 := QX * PZ^2
    BigNumberDirectMulMod(D2, P.Z, P.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(D2, D2, Q.X, FFiniteFieldSize);

    // D4 := PY * QZ^3
    BigNumberDirectMulMod(D4, Q.Z, Q.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(D4, D4, Q.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(D4, D4, P.Y, FFiniteFieldSize);

    // D5 := QY * PZ^3
    BigNumberDirectMulMod(D5, P.Z, P.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(D5, D5, P.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(D5, D5, Q.Y, FFiniteFieldSize);

    if BigNumberEqual(D1, D2) and BigNumberEqual(D4, D5) then
    begin
      // ͬһ���㣬���߷�
      // D1 := 3 * PX^2 + A * PZ^4
      BigNumberDirectMulMod(T, P.Z, P.Z, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, T, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, FCoefficientA, FFiniteFieldSize);
      BigNumberDirectMulMod(D1, P.X, P.X, FFiniteFieldSize);
      BigNumberMulWordNonNegativeMod(D1, D1, 3, FFiniteFieldSize);
      BigNumberAddMod(D1, D1, T, FFiniteFieldSize);

      // D2 := 4 * PX * PY^2
      BigNumberDirectMulMod(D2, P.Y, P.Y, FFiniteFieldSize);
      BigNumberDirectMulMod(D2, D2, P.X, FFiniteFieldSize);
      BigNumberMulWordNonNegativeMod(D2, D2, 4, FFiniteFieldSize);

      // D3 := 8 * PY^4
      BigNumberDirectMulMod(D3, P.Y, P.Y, FFiniteFieldSize);
      BigNumberDirectMulMod(D3, D3, D3, FFiniteFieldSize);
      BigNumberMulWordNonNegativeMod(D3, D3, 8, FFiniteFieldSize);

      // X := D1^2 - 2 * D2
      BigNumberDirectMulMod(Sum.X, D1, D1, FFiniteFieldSize);
      BigNumberAddMod(T, D2, D2, FFiniteFieldSize);
      BigNumberSubMod(Sum.X, Sum.X, T, FFiniteFieldSize);

      // Y := D1 * (D2 - X) - D3
      BigNumberSubMod(T, D2, Sum.X, FFiniteFieldSize);
      BigNumberDirectMulMod(T, D1, T, FFiniteFieldSize);
      BigNumberSubMod(T, T, D3, FFiniteFieldSize); // �Ȳ��� Sum.Y ��ֵ����ÿ���Ӱ�� P.Y

      // Z := 2 * PY * PZ
      BigNumberDirectMulMod(Sum.Z, P.Y, P.Z, FFiniteFieldSize);
      BigNumberAddMod(Sum.Z, Sum.Z, Sum.Z, FFiniteFieldSize);

      BigNumberCopy(Sum.Y, T); // P.Y �� P.Z ���ù����ٸ� Sum.Y ��ֵ
    end
    else // ��ͬ�㣬���߷�
    begin
      if BigNumberEqual(D1, D2) then
      begin
        BigNumberAdd(T, D4, D5);
        if BigNumberEqual(T, FFiniteFieldSize) then // X ����� Y ����
        begin
          Sum.X.SetZero;
          Sum.Y.SetZero;
          Sum.Z.SetZero;
          Exit;
        end
        else // X ����� Y ��������û�����
          raise ECnEccException.CreateFmt('Can NOT Calucate Jacobian %d,%d,%d + %d,%d,%d',
            [P.X.ToDec, P.Y.ToDec, P.Z.ToDec, Q.X.ToDec, Q.Y.ToDec, Q.Z.ToDec]);
      end;

      // D3 := D1 - D2
      BigNumberSubMod(D3, D1, D2, FFiniteFieldSize);

      // D6 := D4 - D5
      BigNumberSubMod(D6, D4, D5, FFiniteFieldSize);

      // D7 := D1 + D2
      BigNumberAddMod(D7, D1, D2, FFiniteFieldSize);

      // D8 := D4 + D5
      BigNumberAddMod(D8, D4, D5, FFiniteFieldSize);

      // X := D6^2 - D7 * D3^2
      BigNumberDirectMulMod(Sum.X, D6, D6, FFiniteFieldSize);
      BigNumberDirectMulMod(T, D3, D3, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, D7, FFiniteFieldSize);
      BigNumberSubMod(Sum.X, Sum.X, T, FFiniteFieldSize);

      // D9 := D7 * D3^2 - 2 * X
      BigNumberDirectMulMod(D9, D3, D3, FFiniteFieldSize);
      BigNumberDirectMulMod(D9, D9, D7, FFiniteFieldSize);
      BigNumberMulWordNonNegativeMod(T, Sum.X, 2, FFiniteFieldSize);
      BigNumberSubMod(D9, D9, T, FFiniteFieldSize);

      // Y := (D9 * D6 - D8 * D3^3) / 2
      BigNumberDirectMulMod(T, D3, D3, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, D3, FFiniteFieldSize);
      BigNumberDirectMulMod(T, T, D8, FFiniteFieldSize);
      BigNumberDirectMulMod(Sum.Y, D6, D9, FFiniteFieldSize);
      BigNumberSubMod(Sum.Y, Sum.Y, T, FFiniteFieldSize);

      if F2Inverse = nil then
      begin
        F2Inverse := TCnBigNumber.Create;
        T.SetWord(2);
        BigNumberModularInverse(F2Inverse, T, FFiniteFieldSize);
      end;
      BigNumberDirectMulMod(Sum.Y, Sum.Y, F2Inverse, FFiniteFieldSize);

      // Z := PZ * QZ * D3
      BigNumberDirectMulMod(Sum.Z, P.Z, Q.Z, FFiniteFieldSize);
      BigNumberDirectMulMod(Sum.Z, Sum.Z, D3, FFiniteFieldSize);
    end;
  finally
    FEccBigNumberPool.Recycle(D9);
    FEccBigNumberPool.Recycle(D8);
    FEccBigNumberPool.Recycle(D7);
    FEccBigNumberPool.Recycle(D6);
    FEccBigNumberPool.Recycle(D5);
    FEccBigNumberPool.Recycle(D4);
    FEccBigNumberPool.Recycle(D3);
    FEccBigNumberPool.Recycle(D2);
    FEccBigNumberPool.Recycle(D1);
    FEccBigNumberPool.Recycle(T);
  end;
end;

procedure TCnEcc.AffinePointSubPoint(P, Q, Diff: TCnEcc3Point);
var
  Inv: TCnEcc3Point;
begin
  Inv := TCnEcc3Point.Create;
  try
    Inv.X := Q.X;
    Inv.Y := Q.Y;
    Inv.Z := Q.Z;

    AffinePointInverse(Inv);
    AffinePointAddPoint(P, Inv, Diff);
  finally
    Inv.Free;
  end;
end;

procedure TCnEcc.JacobianPointSubPoint(P, Q, Diff: TCnEcc3Point);
var
  Inv: TCnEcc3Point;
begin
  Inv := TCnEcc3Point.Create;
  try
    Inv.X := Q.X;
    Inv.Y := Q.Y;
    Inv.Z := Q.Z;

    JacobianPointInverse(Inv);
    JacobianPointAddPoint(P, Inv, Diff);
  finally
    Inv.Free;
  end;
end;

procedure TCnEcc.PointInverse(P: TCnEccPoint);
begin
  if BigNumberIsNegative(P.Y) or (BigNumberCompare(P.Y, FFiniteFieldSize) >= 0) then
    raise ECnEccException.Create('Inverse Error.');

  BigNumberSub(P.Y, FFiniteFieldSize, P.Y);
end;

procedure TCnEcc.AffinePointInverse(P: TCnEcc3Point);
var
  T: TCnBigNumber;
begin
  T := FEccBigNumberPool.Obtain;
  try
    BigNumberDirectMulMod(T, P.Z, FFiniteFieldSize, FFiniteFieldSize);
    BigNumberSubMod(P.Y, T, P.Y, FFiniteFieldSize);
  finally
    FEccBigNumberPool.Recycle(T);
  end;
end;

procedure TCnEcc.JacobianPointInverse(P: TCnEcc3Point);
var
  T: TCnBigNumber;
begin
  T := FEccBigNumberPool.Obtain;
  try
    BigNumberDirectMulMod(T, P.Z, P.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(T, T, P.Z, FFiniteFieldSize);
    BigNumberDirectMulMod(T, T, FFiniteFieldSize, FFiniteFieldSize);
    BigNumberSubMod(P.Y, T, P.Y, FFiniteFieldSize);
  finally
    FEccBigNumberPool.Recycle(T);
  end;
end;

procedure TCnEcc.PointSubPoint(P, Q, Diff: TCnEccPoint);
var
  Inv: TCnEccPoint;
begin
  Inv := TCnEccPoint.Create;
  try
    Inv.Assign(Q);
    PointInverse(Inv);
    PointAddPoint(P, Inv, Diff);
  finally
    Inv.Free;
  end;
end;

function TCnEcc.PointToPlain(Point: TCnEccPoint; OutPlain: TCnBigNumber): Boolean;
begin
  Result := False;
  if (Point <> nil) and (OutPlain <> nil) and IsPointOnCurve(Point) then
  begin
    BigNumberCopy(OutPlain, Point.X);
    Result := True;
  end;
end;

function CnEccDiffieHellmanGenerateOutKey(Ecc: TCnEcc; SelfPrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey): Boolean;
begin
  // PublicKey = SelfPrivateKey * G
  Result := False;
  if (Ecc <> nil) and (SelfPrivateKey <> nil) and not BigNumberIsNegative(SelfPrivateKey) then
  begin
    PublicKey.Assign(Ecc.Generator);
    Ecc.MultiplePoint(SelfPrivateKey, PublicKey);
    Result := True;
  end;
end;

function CnEccDiffieHellmanComputeKey(Ecc: TCnEcc; SelfPrivateKey: TCnEccPrivateKey;
  OtherPublicKey: TCnEccPublicKey; SharedSecretKey: TCnEccPublicKey): Boolean;
begin
  // SecretKey = SelfPrivateKey * OtherPublicKey
  Result := False;
  if (Ecc <> nil) and (SelfPrivateKey <> nil) and not BigNumberIsNegative(SelfPrivateKey) then
  begin
    SharedSecretKey.Assign(OtherPublicKey);
    Ecc.MultiplePoint(SelfPrivateKey, SharedSecretKey);
    Result := True;
  end;
end;

// ============== ��ͨ��Ԫ����㵽��Ԫ��������/�ſɱ������ת�� ================

function CnInt64EccPointToEcc3Point(var P: TCnInt64EccPoint; var P3: TCnInt64Ecc3Point): Boolean;
begin
  P3.X := P.X;
  P3.Y := P.Y;

  if (P3.X = 0) and (P3.Y = 0) then
    P3.Z := 0
  else
    P3.Z := 1;
  Result := True;
end;

function CnInt64AffinePointToEccPoint(var P3: TCnInt64Ecc3Point;
  var P: TCnInt64EccPoint; Prime: Int64): Boolean;
var
  V: Int64;
begin
  V := MyInt64ModularInverse(P3.Z, Prime);
  P.X := Int64NonNegativeMulMod(P3.X, V, Prime);
  P.Y := Int64NonNegativeMulMod(P3.Y, V, Prime);
  Result := True;
end;

function CnInt64JacobianPointToEccPoint(var P3: TCnInt64Ecc3Point;
  var P: TCnInt64EccPoint; Prime: Int64): Boolean;
var
  T, V: Int64;
begin
  T := Int64NonNegativeMulMod(P3.Z, P3.Z, Prime); // Z^2
  V := MyInt64ModularInverse(T, Prime);       // 1 / Z^2
  P.X := Int64NonNegativeMulMod(P3.X, V, Prime);

  T := Int64NonNegativeMulMod(P3.Z, T, Prime); // Z^3
  V := MyInt64ModularInverse(T, Prime);       // 1 / Z^3
  P.Y := Int64NonNegativeMulMod(P3.Y, V, Prime);
  Result := True;
end;

function CnEccPointToEcc3Point(P: TCnEccPoint; P3: TCnEcc3Point): Boolean;
begin
  BigNumberCopy(P3.X, P.X);
  BigNumberCopy(P3.Y, P.Y);

  if P3.X.IsZero and P3.Y.IsZero then
    P3.Z.SetZero
  else
    P3.Z.SetOne;
  Result := True;
end;

function CnAffinePointToEccPoint(P3: TCnEcc3Point; P: TCnEccPoint; Prime: TCnBigNumber): Boolean;
var
  V: TCnBigNumber;
begin
  // X := X/Z   Y := Y/Z

  V := FEccBigNumberPool.Obtain;
  try
    BigNumberModularInverse(V, P3.Z, Prime);
    BigNumberDirectMulMod(P.X, P3.X, V, Prime);
    BigNumberDirectMulMod(P.Y, P3.Y, V, Prime);

    Result := True;
  finally
    FEccBigNumberPool.Recycle(V);
  end;
end;

function CnJacobianPointToEccPoint(P3: TCnEcc3Point; P: TCnEccPoint; Prime: TCnBigNumber): Boolean;
var
  T, V: TCnBigNumber;
begin
  // X := X/Z^2   Y := Y/Z^3
  T := nil;
  V := nil;

  try
    T := FEccBigNumberPool.Obtain;
    V := FEccBigNumberPool.Obtain;

    BigNumberDirectMulMod(T, P3.Z, P3.Z, Prime);
    BigNumberModularInverse(V, T, Prime);
    BigNumberDirectMulMod(P.X, P3.X, V, Prime);

    BigNumberDirectMulMod(T, T, P3.Z, Prime);
    BigNumberModularInverse(V, T, Prime);
    BigNumberDirectMulMod(P.Y, P3.Y, V, Prime);

    Result := True;
  finally
    FEccBigNumberPool.Recycle(V);
    FEccBigNumberPool.Recycle(T);
  end;
end;

function CnEccPointToStream(P: TCnEccPoint; Stream: TStream; FixedLen: Integer): Integer;
begin
  Result := BigNumberWriteBinaryToStream(P.X, Stream, FixedLen)
    + BigNumberWriteBinaryToStream(P.Y, Stream, FixedLen);
end;

function CnEccVerifyKeys(Ecc: TCnEcc; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey): Boolean;
var
  P: TCnEccPoint;
begin
  Result := False;
  if (Ecc = nil) or (PrivateKey = nil) or (PublicKey = nil) then
    Exit;

  P := TCnEccPoint.Create;
  try
    P.Assign(Ecc.Generator);
    Ecc.MultiplePoint(PrivateKey, P);
    Result := CnEccPointsEqual(P, PublicKey);
  finally
    P.Free;
  end;
end;

function CnEccVerifyKeys(CurveType: TCnEccCurveType; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey): Boolean;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccVerifyKeys(Ecc, PrivateKey, PublicKey);
  finally
    Ecc.Free;
  end;
end;

function GetCurveTypeFromOID(Data: PAnsiChar; DataByteLen: Cardinal): TCnEccCurveType;
var
  P: PByte;
  L: Byte;
begin
  Result := ctCustomized;
  if (Data = nil) or (DataByteLen < 3) then
    Exit;

  P := PByte(Data);
  if P^ <> CN_BER_TAG_OBJECT_IDENTIFIER then
    Exit;
  Inc(P);

  L := P^;
  if L > EC_CURVE_TYPE_OID_MAX_LENGTH then
    Exit;

  Inc(P);
  if CompareMem(P, @OID_ECPARAM_CURVE_TYPE_SECP256K1[0],
    Min(L, SizeOf(OID_ECPARAM_CURVE_TYPE_SECP256K1))) then
    Result := ctSecp256k1
  else if CompareMem(P, @OID_ECPARAM_CURVE_TYPE_SM2[0],
    Min(L, SizeOf(OID_ECPARAM_CURVE_TYPE_SM2))) then
    Result := ctSM2
  else if CompareMem(P, @OID_ECPARAM_CURVE_TYPE_PRIME256V1[0],
    Min(L, SizeOf(OID_ECPARAM_CURVE_TYPE_PRIME256V1))) then
    Result := ctPrime256v1
end;

// �����������ͷ����� OID ��ַ�볤�ȣ����ʹ�ú������ͷ�
function GetOIDFromCurveType(Curve: TCnEccCurveType; out OIDAddr: Pointer): Integer;
begin
  Result := 0;
  OIDAddr := nil;

  case Curve of
    ctSecp256k1:
      begin
        OIDAddr := @OID_ECPARAM_CURVE_TYPE_SECP256K1[0];
        Result := SizeOf(OID_ECPARAM_CURVE_TYPE_SECP256K1);
      end;
    ctSM2:
      begin
        OIDAddr := @OID_ECPARAM_CURVE_TYPE_SM2[0];
        Result := SizeOf(OID_ECPARAM_CURVE_TYPE_SM2);
      end;
    ctPrime256v1:
      begin
        OIDAddr := @OID_ECPARAM_CURVE_TYPE_PRIME256V1[0];
        Result := SizeOf(OID_ECPARAM_CURVE_TYPE_PRIME256V1);
      end;
  end;
end;

function ReadEccPublicKeyFromBitStringNode(BitStringNode: TCnBerReadNode; PublicKey: TCnEccPublicKey): Boolean;
var
  B: PByte;
  Len: Integer;
begin
  Result := False;
  if (BitStringNode = nil) or (PublicKey = nil) then
    Exit;

  // PubNode �� Data �� BITSTRING��00 04 ��ͷ
  // BITSTRING ��������һ�������ֽ��Ǹ� BITSTRING �ճ� 8 �ı�����ȱ�ٵ� Bit ���������� 0������
  B := BitStringNode.BerDataAddress;
  Inc(B); // ���� 00��ָ��ѹ��ģʽ�ֽ�

  if B^ = EC_PUBLICKEY_UNCOMPRESSED then
  begin
    // δѹ����ʽ��ǰһ���ǹ�Կ�� X����һ���ǹ�Կ�� Y
    Inc(B);
    Len := (BitStringNode.BerDataLength - 2) div 2;
    PublicKey.X.SetBinary(PAnsiChar(B), Len);
    Inc(B, Len);
    PublicKey.Y.SetBinary(PAnsiChar(B), Len);

    Result := True;
  end
  else if (B^ = EC_PUBLICKEY_COMPRESSED_ODD) or (B^ = EC_PUBLICKEY_COMPRESSED_EVEN) then
  begin
    Inc(B);
    // ѹ����ʽ��ȫ�ǹ�Կ X
    PublicKey.X.SetBinary(PAnsiChar(B), BitStringNode.BerDataLength - 2);
    PublicKey.Y.SetZero; // Y �� 0���ⲿ��ȥ���

    Result := True;
  end;
end;

function WriteEccPublicKeyToBitStringNode(Writer: TCnBerWriter;
  ParentNode: TCnBerWriteNode; PublicKey: TCnEccPublicKey): Boolean;
var
  Cnt: Integer;
  B: Byte;
  OP, P: PByte;
begin
  Result := False;
  if (ParentNode = nil) or (PublicKey = nil) then
    Exit;

  Cnt := PublicKey.X.GetBytesCount;
  if not PublicKey.Y.IsZero then
  begin
    Cnt := Cnt + PublicKey.Y.GetBytesCount;
    B := EC_PUBLICKEY_UNCOMPRESSED;
  end
  else if PublicKey.Y.IsOdd then
    B := EC_PUBLICKEY_COMPRESSED_ODD
  else
    B := EC_PUBLICKEY_COMPRESSED_EVEN;

  OP := GetMemory(Cnt + 1);
  P := OP;
  P^ := B;

  Inc(P);
  PublicKey.X.ToBinary(PAnsiChar(P));
  if B = EC_PUBLICKEY_UNCOMPRESSED then
  begin
    Inc(P, PublicKey.X.GetBytesCount);
    PublicKey.Y.ToBinary(PAnsiChar(P));
  end;
  Writer.AddBasicNode(CN_BER_TAG_BIT_STRING, OP, Cnt + 1, ParentNode);
  FreeMemory(OP);
end;

(*
  SEQUENCE (2 elem)
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
      OBJECT IDENTIFIER 1.3.132.0.10 secp256k1 (SECG (Certicom) named elliptic curve)
    BIT STRING
*)
function CnEccLoadPublicKeyFromPem(const PemFileName: string;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(PemFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := CnEccLoadPublicKeyFromPem(Stream, PublicKey, CurveType, KeyHashMethod, Password);
  finally
    Stream.Free;
  end;
end;

function CnEccLoadPublicKeyFromPem(PemStream: TStream;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  MemStream: TMemoryStream;
  Reader: TCnBerReader;
  Node: TCnBerReadNode;
begin
  Result := False;
  MemStream := nil;
  Reader := nil;

  if PublicKey = nil then
    Exit;

  try
    MemStream := TMemoryStream.Create;
    if LoadPemStreamToMemory(PemStream, PEM_EC_PUBLIC_HEAD, PEM_EC_PUBLIC_TAIL,
      MemStream, Password, KeyHashMethod) then
    begin
      Reader := TCnBerReader.Create(PByte(MemStream.Memory), MemStream.Size);
      Reader.ParseToTree;
      if Reader.TotalCount >= 5 then
      begin
        // 2 Ҫ�ж��Ƿ�Կ
        Node := Reader.Items[2];
        if (Node.BerDataLength <> SizeOf(CN_OID_EC_PUBLIC_KEY)) or not CompareMem(@CN_OID_EC_PUBLIC_KEY[0],
          Node.BerDataAddress, Node.BerDataLength) then
          Exit;

        // 3 ����������
        Node := Reader.Items[3];
        CurveType := GetCurveTypeFromOID(Node.BerAddress, Node.BerLength);

        // �� 4 ��Ĺ�Կ
        Result := ReadEccPublicKeyFromBitStringNode(Reader.Items[4], PublicKey);
      end;
    end;
  finally
    MemStream.Free;
    Reader.Free;
  end;
end;

(*
  PKCS#1: RFC5915

  ECPrivateKey ::= SEQUENCE {
    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
    privateKey     OCTET STRING,
    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    publicKey  [1] BIT STRING OPTIONAL
  }

  SEQUENCE (4 elem)
    INTEGER 1
    OCTET STRING (32 byte) ˽Կ
    [0] (1 elem)
      OBJECT IDENTIFIER 1.3.132.0.10 secp256k1 (SECG (Certicom) named elliptic curve)
    [1] (1 elem)
      BIT STRING  ��Կ

  PKCS#8: ����һ��

  SEQUENCE (3 elem)
    INTEGER 0  Version
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
      OBJECT IDENTIFIER 1.3.132.0.10 secp256k1 (SECG (Certicom) named elliptic curve)
    OCTET STRING (109 byte) ��
      SEQUENCE (3 elem)
        INTEGER 1
        OCTET STRING (32 byte) ˽Կ
        [0] (1 elem)               // ע�⣺����������һ�� OI ��ѡ�����������Ҫ���ݴ���ͬʱ����һ�п�����������
          OBJECT IDENTIFIER 1.2.156.10197.1.301 sm2ECC (China GM Standards Committee)
        [1] (1 elem)
          BIT STRING (520 bit) ��Կ

*)
function CnEccLoadKeysFromPem(const PemFileName: string; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(PemFileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := CnEccLoadKeysFromPem(Stream, PrivateKey, PublicKey, CurveType,
      KeyHashMethod, Password);
  finally
    Stream.Free;
  end;
end;

function CnEccLoadKeysFromPem(PemStream: TStream; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; out CurveType: TCnEccCurveType;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  MemStream: TMemoryStream;
  Reader: TCnBerReader;
  Node: TCnBerReadNode;
  CurveType2: TCnEccCurveType;
  OldPos: Int64;
  IsPkcs1: Boolean;
begin
  Result := False;
  MemStream := nil;
  Reader := nil;

  try
    MemStream := TMemoryStream.Create;
    OldPos := PemStream.Position;
    IsPkcs1 := False;
    if LoadPemStreamToMemory(PemStream, PEM_EC_PARAM_HEAD, PEM_EC_PARAM_TAIL,
      MemStream, Password, KeyHashMethod) then
    begin
      // �� ECPARAM Ҳ����Բ��������
      CurveType := GetCurveTypeFromOID(PAnsiChar(MemStream.Memory), MemStream.Size);
      IsPkcs1 := True;
    end;

    PemStream.Position := OldPos;
    if IsPkcs1 then
    begin
      if LoadPemStreamToMemory(PemStream, PEM_EC_PRIVATE_HEAD, PEM_EC_PRIVATE_TAIL,
        MemStream, Password, KeyHashMethod) then
      begin
        Reader := TCnBerReader.Create(PByte(MemStream.Memory), MemStream.Size);
        Reader.ParseToTree;
        if Reader.TotalCount >= 7 then
        begin
          Node := Reader.Items[1]; // 0 ������ Sequence��1 �� Version
          if Node.AsByte = 1 then  // ֻ֧�ְ汾 1
          begin
            // 2 ��˽Կ
            if PrivateKey <> nil then
              PutIndexedBigIntegerToBigNumber(Reader.Items[2], PrivateKey);

            // 4 ������������
            Node := Reader.Items[4];
            CurveType2 := GetCurveTypeFromOID(Node.BerAddress, Node.BerLength);
            if (CurveType <> ctCustomized) and (CurveType2 <> CurveType) then
              Exit;

            CurveType := CurveType2; // �����������һ�����Եڶ���Ϊ׼

            // �� 6 ��Ĺ�Կ
            if PublicKey <> nil then
              Result := ReadEccPublicKeyFromBitStringNode(Reader.Items[6], PublicKey);
          end;
        end;
      end;
    end
    else // ���� PKCS#1���ж��Ƿ��� PKCS#8 �ı��
    begin
      if LoadPemStreamToMemory(PemStream, PEM_PRIVATE_HEAD, PEM_PRIVATE_TAIL,
        MemStream, Password, KeyHashMethod) then
      begin
        Reader := TCnBerReader.Create(PByte(MemStream.Memory), MemStream.Size, True);
        Reader.ParseToTree;
        if Reader.TotalCount >= 11 then // �� PKCS#8 �����������
        begin
          Node := Reader.Items[1]; // 0 ������ Sequence��1 �� Version
          if Node.AsByte = 0 then  // ֻ֧�ְ汾 0
          begin
            Node := Reader.Items[3]; // 3 �� ecPublicKey �� Object Identifier
            if CompareObjectIdentifier(Node, @CN_OID_EC_PUBLIC_KEY[0], SizeOf(CN_OID_EC_PUBLIC_KEY)) then
            begin
              // 4 ������������
              Node := Reader.Items[4];
              CurveType := GetCurveTypeFromOID(Node.BerAddress, Node.BerLength);

              if PrivateKey <> nil then
                PutIndexedBigIntegerToBigNumber(Reader.Items[8], PrivateKey);

              if PublicKey <> nil then
              begin
                Result := ReadEccPublicKeyFromBitStringNode(Reader.Items[10], PublicKey);
                if not Result then // ���ݴ�������������һ�� OI ��֧�Ҷ������˽Կ���ӽڵ�
                  Result := ReadEccPublicKeyFromBitStringNode(Reader.Items[12], PublicKey);
                if not Result then
                  Result := ReadEccPublicKeyFromBitStringNode(Reader.Items[13], PublicKey);
              end;
            end;
          end;
        end;
      end;
    end;
  finally
    MemStream.Free;
    Reader.Free;
  end;
end;

function CnEccSaveKeysToPem(const PemFileName: string; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType; KeyType: TCnEccKeyType;
  KeyEncryptMethod: TCnKeyEncryptMethod; KeyHashMethod: TCnKeyHashMethod;
  const Password: string): Boolean;
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(PemFileName, fmCreate);
  try
    Result := CnEccSaveKeysToPem(Stream, PrivateKey, PublicKey, CurveType,
      KeyType, KeyEncryptMethod, KeyHashMethod, Password);
  finally
    Stream.Free;
  end;
end;

function CnEccSaveKeysToPem(PemStream: TStream; PrivateKey: TCnEccPrivateKey;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType; KeyType: TCnEccKeyType;
  KeyEncryptMethod: TCnKeyEncryptMethod;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  Root, Node: TCnBerWriteNode;
  Writer: TCnBerWriter;
  Mem: TMemoryStream;
  OIDPtr: Pointer;
  OIDLen: Integer;
  B: Byte;
begin
  Result := False;
  if (PrivateKey = nil) or (PublicKey = nil) then
    Exit;

  OIDLen := GetOIDFromCurveType(CurveType, OIDPtr);
  if (OIDPtr = nil) or (OIDLen <= 0) then
    Exit;

  Mem := nil;
  Writer := nil;

  try
    if KeyType = cktPKCS1 then // PKCS1 ��ʽ��������
    begin
      Mem := TMemoryStream.Create;
      if (KeyEncryptMethod = ckeNone) or (Password = '') then
      begin
        // �����ܣ������Σ���һ���ֹ�д
        B := CN_BER_TAG_OBJECT_IDENTIFIER;
        Mem.Write(B, 1);
        B := OIDLen;
        Mem.Write(B, 1);

        Mem.Write(OIDPtr^, OIDLen);
        if not SaveMemoryToPemStream(PemStream, PEM_EC_PARAM_HEAD, PEM_EC_PARAM_TAIL, Mem) then
          Exit;

        Mem.Clear;
      end;

      Writer := TCnBerWriter.Create;

      // �ڶ�������
      Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);
      B := 1;
      Writer.AddBasicNode(CN_BER_TAG_INTEGER, @B, 1, Root); // д Version 1
      AddBigNumberToWriter(Writer, PrivateKey, Root, CN_BER_TAG_OCTET_STRING);   // д˽Կ

      Node := Writer.AddContainerNode(CN_BER_TAG_RESERVED, Root);
      Node.BerTypeMask := ECC_PRIVATEKEY_TYPE_MASK;
      Writer.AddBasicNode(CN_BER_TAG_OBJECT_IDENTIFIER, PByte(OIDPtr), OIDLen, Node);

      Node := Writer.AddContainerNode(CN_BER_TAG_BOOLEAN, Root); // ��ȻҪ�� BOOLEAN ����
      Node.BerTypeMask := ECC_PRIVATEKEY_TYPE_MASK;

      WriteEccPublicKeyToBitStringNode(Writer, Node, PublicKey);
      Writer.SaveToStream(Mem);
      Result := SaveMemoryToPemStream(PemStream, PEM_EC_PRIVATE_HEAD, PEM_EC_PRIVATE_TAIL, Mem,
        KeyEncryptMethod, KeyHashMethod, Password, True);
    end
    else if KeyType = cktPKCS8 then
    begin
      Writer := TCnBerWriter.Create;

      Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);
      B := 0;
      Writer.AddBasicNode(CN_BER_TAG_INTEGER, @B, 1, Root); // д Version 0

      Node := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE, Root);
      Writer.AddBasicNode(CN_BER_TAG_OBJECT_IDENTIFIER, @CN_OID_EC_PUBLIC_KEY[0], SizeOf(CN_OID_EC_PUBLIC_KEY), Node);
      Writer.AddBasicNode(CN_BER_TAG_OBJECT_IDENTIFIER, PByte(OIDPtr), OIDLen, Node);

      Node := Writer.AddContainerNode(CN_BER_TAG_OCTET_STRING, Root);
      Node := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE, Node);
      B := 1;
      Writer.AddBasicNode(CN_BER_TAG_INTEGER, @B, 1, Node);

      AddBigNumberToWriter(Writer, PrivateKey, Node, CN_BER_TAG_OCTET_STRING);   // д˽Կ

      Node := Writer.AddContainerNode(CN_BER_TAG_BOOLEAN, Node);
      Node.BerTypeMask := ECC_PRIVATEKEY_TYPE_MASK;
      WriteEccPublicKeyToBitStringNode(Writer, Node, PublicKey);                 // д��Կ

      Mem := TMemoryStream.Create;
      Writer.SaveToStream(Mem);

      Result := SaveMemoryToPemStream(PemStream, PEM_PRIVATE_HEAD, PEM_PRIVATE_TAIL, Mem,
        KeyEncryptMethod, KeyHashMethod, Password, True);
    end;
  finally
    Writer.Free;
    Mem.Free;
  end;
end;

function CnEccSavePublicKeyToPem(const PemFileName: string;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType;
  KeyType: TCnEccKeyType; KeyEncryptMethod: TCnKeyEncryptMethod;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(PemFileName, fmCreate);
  try
    Result := CnEccSavePublicKeyToPem(Stream, PublicKey, CurveType, KeyType,
      KeyEncryptMethod, KeyHashMethod, Password);
  finally
    Stream.Free;
  end;
end;

function CnEccSavePublicKeyToPem(PemStream: TStream;
  PublicKey: TCnEccPublicKey; CurveType: TCnEccCurveType;
  KeyType: TCnEccKeyType; KeyEncryptMethod: TCnKeyEncryptMethod;
  KeyHashMethod: TCnKeyHashMethod; const Password: string): Boolean;
var
  Root, Node: TCnBerWriteNode;
  Writer: TCnBerWriter;
  Mem: TMemoryStream;
  OIDPtr: Pointer;
  OIDLen: Integer;
begin
  // TODO: PKCS8 ��ʵ��
  Result := False;
  if (PublicKey = nil) or (PublicKey.X.IsZero) then
    Exit;

  OIDLen := GetOIDFromCurveType(CurveType, OIDPtr);
  if (OIDPtr = nil) or (OIDLen <= 0) then
    Exit;

  Writer := nil;
  Mem := nil;

  try
    Writer := TCnBerWriter.Create;
    Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);
    Node := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE, Root);

    // �� Node �� ECPublicKey �� �������͵� ObjectIdentifier
    Writer.AddBasicNode(CN_BER_TAG_OBJECT_IDENTIFIER, @CN_OID_EC_PUBLIC_KEY[0],
      SizeOf(CN_OID_EC_PUBLIC_KEY), Node);
    Writer.AddBasicNode(CN_BER_TAG_OBJECT_IDENTIFIER, OIDPtr, OIDLen, Node);
    WriteEccPublicKeyToBitStringNode(Writer, Root, PublicKey);

    Mem := TMemoryStream.Create;
    Writer.SaveToStream(Mem);

    Result := SaveMemoryToPemStream(PemStream, PEM_EC_PUBLIC_HEAD, PEM_EC_PUBLIC_TAIL, Mem,
      KeyEncryptMethod, KeyHashMethod, Password);
  finally
    Mem.Free;
    Writer.Free;
  end;
end;

// ============================ ECC ǩ������֤ =================================

// ����ָ������ժҪ�㷨����ָ�����Ķ������Ӵ�ֵ��д�� Stream
function CalcDigestStream(InStream: TStream; SignType: TCnEccSignDigestType;
  outStream: TStream): Boolean;
var
  Md5: TCnMD5Digest;
  Sha1: TCnSHA1Digest;
  Sha256: TCnSHA256Digest;
  Sm3Dig: TCnSM3Digest;
begin
  Result := False;
  case SignType of
    esdtMD5:
      begin
        Md5 := MD5Stream(InStream);
        outStream.Write(Md5, SizeOf(TCnMD5Digest));
        Result := True;
      end;
    esdtSHA1:
      begin
        Sha1 := SHA1Stream(InStream);
        outStream.Write(Sha1, SizeOf(TCnSHA1Digest));
        Result := True;
      end;
    esdtSHA256:
      begin
        Sha256 := SHA256Stream(InStream);
        outStream.Write(Sha256, SizeOf(TCnSHA256Digest));
        Result := True;
      end;
    esdtSM3:
      begin
        Sm3Dig := SM3Stream(InStream);
        outStream.Write(Sm3Dig, SizeOf(TCnSM3Digest));
        Result := True;
      end;
  end;
end;

// ����ָ������ժҪ�㷨�����ļ��Ķ������Ӵ�ֵ��д�� Stream
function CalcDigestFile(const FileName: string; SignType: TCnEccSignDigestType;
  outStream: TStream): Boolean;
var
  Md5: TCnMD5Digest;
  Sha1: TCnSHA1Digest;
  Sha256: TCnSHA256Digest;
  Sm3Dig: TCnSM3Digest;
begin
  Result := False;
  case SignType of
    esdtMD5:
      begin
        Md5 := MD5File(FileName);
        outStream.Write(Md5, SizeOf(TCnMD5Digest));
        Result := True;
      end;
    esdtSHA1:
      begin
        Sha1 := SHA1File(FileName);
        outStream.Write(Sha1, SizeOf(TCnSHA1Digest));
        Result := True;
      end;
    esdtSHA256:
      begin
        Sha256 := SHA256File(FileName);
        outStream.Write(Sha256, SizeOf(TCnSHA256Digest));
        Result := True;
      end;
    esdtSM3:
      begin
        Sm3Dig := SM3File(FileName);
        outStream.Write(Sm3Dig, SizeOf(TCnSM3Digest));
        Result := True;
      end;
  end;
end;

{
  ��ά���ٿ���˵���� ECDSA �㷨����ǩ����
  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

  r = ���k * G�㣨�� x��
  s = (r * Private + ����) / k

  ������Բ���ߵĽ���ģ�����Ƕ���������ģ
}
function EccSignValue(Ecc: TCnEcc; PrivateKey: TCnEccPrivateKey; InE: TCnBigNumber;
  OutSignature: TCnEccSignature): Boolean;
var
  K, X, KInv: TCnBigNumber;
  P: TCnEccPoint;
begin
  Result := False;
  BuildShortXValue(InE, Ecc.Order); // InE ������ z

  K := nil;
  X := nil;
  KInv := nil;
  P := nil;

  try
    K := TCnBigNumber.Create;
    KInv := TCnBigNumber.Create;
    X := TCnBigNumber.Create;
    P := TCnEccPoint.Create;

    while True do
    begin
      if not BigNumberRandRange(K, Ecc.Order) then // ������Ҫ����� K
        Exit;

      P.Assign(Ecc.Generator);
      Ecc.MultiplePoint(K, P);

      if not BigNumberNonNegativeMod(OutSignature.R, P.X, Ecc.Order) then
        Exit;

      if OutSignature.R.IsZero then
        Continue;
      // �����ǩ����һ���� R

      if not BigNumberMul(X, PrivateKey, OutSignature.R) then   // X <= r * PrivateKey
        Exit;
      if not BigNumberAdd(X, X, InE) then             // X <= X + z
        Exit;
      if not BigNumberModularInverse(KInv, K, Ecc.Order) then
        Exit;
      if not BigNumberMul(X, KInv, X) then            // X <= K^-1 * X
        Exit;
      if not BigNumberNonNegativeMod(OutSignature.S, X, Ecc.Order) then  // OutS <= K^-1 * (z + r * PrivateKey) mod N
        Exit;

      if OutSignature.S.IsZero then
        Continue;

      Break;
    end;
    Result := True;
  finally
    P.Free;
    KInv.Free;
    X.Free;
    K.Free;
  end;
end;

{
  �����ݿ���ǩ������Ϣ��ԭ�� SM2 ��Կ�������Ƿ�ԭ�ɹ���ע��������������Ҫ�ⲿ�ж�

  ��Ϊ r = ���k * G�㣨�� x������ s = (r * Private + ����z) / k

  ����ͬʱ���� k �� k*s*G = (r*Private + ����)*G

  ��� s*(k*G) = r*Private*G+ ����*G

  s*(kG) = r*Public + ����*G

  Public = r^-1 * (s*(kG) - ����*G)������ k*G �� x ������ r����������� y ��
}
function CnEccRecoverPublicKey(Ecc: TCnEcc; InE: TCnBigNumber; InSignature: TCnEccSignature;
  OutPublicKey1, OutPublicKey2: TCnEccPublicKey): Boolean;
var
  P, Q, T: TCnEccPoint;
  RInv: TCnBigNumber;
begin
  Result := False;

  RInv := nil;
  P := nil;
  Q := nil;
  T := nil;

  try
    RInv := TCnBigNumber.Create;
    if not BigNumberModularInverse(RInv, InSignature.R, Ecc.Order) then
      Exit;

    P := TCnEccPoint.Create;
    if not Ecc.PlainToPoint(InSignature.R, P) then  // P.Y ��һ�� y �����Դ˴� P �� k*G ��һ��ȡֵ
      Exit;

    Q := TCnEccPoint.Create;
    Q.Assign(Ecc.Generator);
    Ecc.MultiplePoint(InE, Q); // �õ�����*G
    Ecc.PointInverse(Q);       // Q �õ� -���� * G

    T := TCnEccPoint.Create;
    T.Assign(P);
    Ecc.MultiplePoint(InSignature.S, T);    // T �õ� s*(k*G)

    Ecc.PointAddPoint(Q, T, OutPublicKey1);
    Ecc.MultiplePoint(RInv, OutPublicKey1); // PublicKey1 �õ� r^-1 * (s*(kG) - ����*G)

    Ecc.PointInverse(P);
    T.Assign(P);
    Ecc.MultiplePoint(InSignature.S, T);    // T �ٴεõ� s* ��һ��(k*G)

    Ecc.PointAddPoint(Q, T, OutPublicKey2);
    Ecc.MultiplePoint(RInv, OutPublicKey2); // PublicKey2 �õ� r^-1 * (s*(kG) - ����*G)

    Result := True;
  finally
    T.Free;
    Q.Free;
    P.Free;
    RInv.Free;
  end;
end;

function CnEccSignFile(const InFileName, OutSignFileName: string; Ecc: TCnEcc;
  PrivateKey: TCnEccPrivateKey; SignType: TCnEccSignDigestType = esdtMD5): Boolean;
var
  Stream: TMemoryStream;
  E: TCnBigNumber;
  Sig: TCnEccSignature;
  Writer: TCnBerWriter;
  Root: TCnBerWriteNode;
begin
  Result := False;
  Stream := nil;
  Writer := nil;
  E := nil;
  Sig := nil;

  try
    Stream := TMemoryStream.Create;
    if not CalcDigestFile(InFileName, SignType, Stream) then // �����ļ����Ӵ�ֵ
      Exit;

    E := TCnBigNumber.Create;
    E.SetBinary(Stream.Memory, Stream.Size);

    Sig := TCnEccSignature.Create;
    if EccSignValue(Ecc, PrivateKey, E, Sig) then
    begin
      // Ȼ�󰴸�ʽ���� BER ����
      Writer := TCnBerWriter.Create;
      Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);
      AddBigNumberToWriter(Writer, Sig.R, Root);
      AddBigNumberToWriter(Writer, Sig.S, Root);

      Writer.SaveToFile(OutSignFileName);
      Result := True;
    end;
  finally
    Stream.Free;
    E.Free;
    Sig.Free;
    Writer.Free;
  end;
end;

function CnEccSignFile(const InFileName, OutSignFileName: string; CurveType: TCnEccCurveType;
  PrivateKey: TCnEccPrivateKey; SignType: TCnEccSignDigestType = esdtMD5): Boolean;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccSignFile(InFileName, OutSignFileName, Ecc, PrivateKey, SignType);
  finally
    Ecc.Free;
  end;
end;

{
  ��ά���ٿ���˵���� ECDSA �㷨����ǩ����֤��
  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
}
function EccVerifyValue(Ecc: TCnEcc; PublicKey: TCnEccPublicKey; InE: TCnBigNumber;
  InSignature: TCnEccSignature): Boolean;
var
  U1, U2, SInv: TCnBigNumber;
  P1, P2: TCnEccPoint;
begin
  Result := False;
  if not CheckEccPublicKey(Ecc, PublicKey) then
    Exit;

  BuildShortXValue(InE, Ecc.Order); // InE is z

  U1 := nil;
  U2 := nil;
  P1 := nil;
  P2 := nil;
  SInv := nil;

  try
    SInv := TCnBigNumber.Create;
    BigNumberModularInverse(SInv, InSignature.S, Ecc.Order);
    U1 := TCnBigNumber.Create;
    if not BigNumberMul(U1, InE, SInv) then
      Exit;
    if not BigNumberNonNegativeMod(U1, U1, Ecc.Order) then // u1 = (z * s^-1) mod N
      Exit;

    U2 := TCnBigNumber.Create;
    if not BigNumberMul(U2, InSignature.R, SInv) then
      Exit;
    if not BigNumberNonNegativeMod(U1, U1, Ecc.Order) then // u2 = (r * s^-1) mod N
      Exit;

    P1 := TCnEccPoint.Create;
    P1.Assign(Ecc.Generator);
    Ecc.MultiplePoint(U1, P1);

    P2 := TCnEccPoint.Create;
    P2.Assign(PublicKey);
    Ecc.MultiplePoint(U2, P2);
    Ecc.PointAddPoint(P1, P2, P1);  // ���� u1 * G + u2 * PublicKey ��
    if P1.IsZero then
      Exit;

    if not BigNumberNonNegativeMod(P1.X, P1.X, Ecc.Order) then // ���� P1.X mod N
      Exit;

    if not BigNumberNonNegativeMod(P1.Y, InSignature.R, Ecc.Order) then  // ���� r mod N
      Exit;

    Result := BigNumberCompare(P1.X, P1.Y) = 0;
  finally
    SInv.Free;
    P2.Free;
    P1.Free;
    U2.Free;
    U1.Free;
  end;
end;

function CnEccVerifyFile(const InFileName, InSignFileName: string; Ecc: TCnEcc;
  PublicKey: TCnEccPublicKey; SignType: TCnEccSignDigestType): Boolean;
var
  Stream: TMemoryStream;
  E: TCnBigNumber;
  Sig: TCnEccSignature;
  Reader: TCnBerReader;
begin
  Result := False;
  Stream := nil;
  Reader := nil;
  E := nil;
  Sig := nil;

  try
    Stream := TMemoryStream.Create;

    if not CalcDigestFile(InFileName, SignType, Stream) then // �����ļ����Ӵ�ֵ
      Exit;

    E := TCnBigNumber.Create;
    E.SetBinary(Stream.Memory, Stream.Size);

    Stream.Clear;
    Stream.LoadFromFile(InSignFileName);
    Reader := TCnBerReader.Create(Stream.Memory, Stream.Size);
    Reader.ParseToTree;

    if Reader.TotalCount <> 3 then
      Exit;

    Sig := TCnEccSignature.Create;
    PutIndexedBigIntegerToBigNumber(Reader.Items[1], Sig.R);
    PutIndexedBigIntegerToBigNumber(Reader.Items[2], Sig.S);

    Result := EccVerifyValue(Ecc, PublicKey, E, Sig);
  finally
    Stream.Free;
    Reader.Free;
    E.Free;
    Sig.Free
  end;
end;

function CnEccVerifyFile(const InFileName, InSignFileName: string; CurveType: TCnEccCurveType;
  PublicKey: TCnEccPublicKey; SignType: TCnEccSignDigestType): Boolean;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccVerifyFile(InFileName, InSignFileName, Ecc, PublicKey, SignType);
  finally
    Ecc.Free;
  end;
end;

function CnEccRecoverPublicKeyFromFile(const InFileName, InSignFileName: string;
  Ecc: TCnEcc; OutPublicKey1, OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType): Boolean; overload;
var
  Stream: TMemoryStream;
  E: TCnBigNumber;
  Sig: TCnEccSignature;
  Reader: TCnBerReader;
begin
  Result := False;
  Stream := nil;
  Reader := nil;
  E := nil;
  Sig := nil;

  try
    Stream := TMemoryStream.Create;

    if not CalcDigestFile(InFileName, SignType, Stream) then // �����ļ����Ӵ�ֵ
      Exit;

    E := TCnBigNumber.Create;
    E.SetBinary(Stream.Memory, Stream.Size);

    Stream.Clear;
    Stream.LoadFromFile(InSignFileName);
    Reader := TCnBerReader.Create(Stream.Memory, Stream.Size);
    Reader.ParseToTree;

    if Reader.TotalCount <> 3 then
      Exit;

    Sig := TCnEccSignature.Create;
    PutIndexedBigIntegerToBigNumber(Reader.Items[1], Sig.R);
    PutIndexedBigIntegerToBigNumber(Reader.Items[2], Sig.S);

    Result := CnEccRecoverPublicKey(Ecc, E, Sig, OutPublicKey1, OutPublicKey2);
  finally
    Stream.Free;
    Reader.Free;
    E.Free;
    Sig.Free
  end;
end;

function CnEccRecoverPublicKeyFromFile(const InFileName, InSignFileName: string;
  CurveType: TCnEccCurveType; OutPublicKey1, OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType): Boolean; overload;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccRecoverPublicKeyFromFile(InFileName, InSignFileName, Ecc,
      OutPublicKey1, OutPublicKey2, SignType);
  finally
    Ecc.Free;
  end;
end;

{
  ECC ǩ������� BER ��ʽ���£�ֱ�Ӵ�ɶ������ļ�����
  SEQUENCE (2 elem)
    INTEGER r
    INTEGER s
}
function CnEccSignStream(InStream: TMemoryStream; OutSignStream: TMemoryStream;
  Ecc: TCnEcc; PrivateKey: TCnEccPrivateKey;
  SignType: TCnEccSignDigestType): Boolean;
var
  Stream: TMemoryStream;
  E: TCnBigNumber;
  Sig: TCnEccSignature;
  Writer: TCnBerWriter;
  Root: TCnBerWriteNode;
begin
  Result := False;
  Stream := nil;
  Writer := nil;
  E := nil;
  Sig := nil;

  try
    Stream := TMemoryStream.Create;
    if not CalcDigestStream(InStream, SignType, Stream) then // ���������Ӵ�ֵ
      Exit;

    E := TCnBigNumber.Create;
    E.SetBinary(Stream.Memory, Stream.Size);

    Sig := TCnEccSignature.Create;
    if EccSignValue(Ecc, PrivateKey, E, Sig) then
    begin
      // Ȼ�󰴸�ʽ���� BER ����
      Writer := TCnBerWriter.Create;
      Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);
      AddBigNumberToWriter(Writer, Sig.R, Root);
      AddBigNumberToWriter(Writer, Sig.S, Root);

      Writer.SaveToStream(OutSignStream);
      Result := True;
    end;
  finally
    Stream.Free;
    E.Free;
    Sig.Free;
    Writer.Free;
  end;
end;

function CnEccSignStream(InStream: TMemoryStream; OutSignStream: TMemoryStream;
  CurveType: TCnEccCurveType; PrivateKey: TCnEccPrivateKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccSignStream(InStream, OutSignStream, Ecc, PrivateKey, SignType);
  finally
    Ecc.Free;
  end;
end;

function CnEccVerifyStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  Ecc: TCnEcc; PublicKey: TCnEccPublicKey;
  SignType: TCnEccSignDigestType): Boolean;
var
  Stream: TMemoryStream;
  E: TCnBigNumber;
  Sig: TCnEccSignature;
  Reader: TCnBerReader;
begin
  Result := False;
  Stream := nil;
  Reader := nil;
  E := nil;
  Sig := nil;

  try
    Stream := TMemoryStream.Create;
    if not CalcDigestStream(InStream, SignType, Stream) then // ���������Ӵ�ֵ
      Exit;

    E := TCnBigNumber.Create;
    E.SetBinary(Stream.Memory, Stream.Size);

    Stream.Clear;
    Stream.LoadFromStream(InSignStream);
    Reader := TCnBerReader.Create(Stream.Memory, Stream.Size);
    Reader.ParseToTree;

    if Reader.TotalCount <> 3 then
      Exit;

    Sig := TCnEccSignature.Create;
    PutIndexedBigIntegerToBigNumber(Reader.Items[1], Sig.R);
    PutIndexedBigIntegerToBigNumber(Reader.Items[2], Sig.S);

    Result := EccVerifyValue(Ecc, PublicKey, E, Sig);
  finally
    Stream.Free;
    Reader.Free;
    E.Free;
    Sig.Free;
  end;
end;

function CnEccVerifyStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  CurveType: TCnEccCurveType; PublicKey: TCnEccPublicKey;
  SignType: TCnEccSignDigestType = esdtMD5): Boolean;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccVerifyStream(InStream, InSignStream, Ecc, PublicKey, SignType);
  finally
    Ecc.Free;
  end;
end;

function CnEccRecoverPublicKeyFromStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  Ecc: TCnEcc; OutPublicKey1, OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType): Boolean; overload;
var
  Stream: TMemoryStream;
  E: TCnBigNumber;
  Sig: TCnEccSignature;
  Reader: TCnBerReader;
begin
  Result := False;
  Stream := nil;
  Reader := nil;
  E := nil;
  Sig := nil;

  try
    Stream := TMemoryStream.Create;
    if not CalcDigestStream(InStream, SignType, Stream) then // ���������Ӵ�ֵ
      Exit;

    E := TCnBigNumber.Create;
    E.SetBinary(Stream.Memory, Stream.Size);

    Stream.Clear;
    Stream.LoadFromStream(InSignStream);
    Reader := TCnBerReader.Create(Stream.Memory, Stream.Size);
    Reader.ParseToTree;

    if Reader.TotalCount <> 3 then
      Exit;

    Sig := TCnEccSignature.Create;
    PutIndexedBigIntegerToBigNumber(Reader.Items[1], Sig.R);
    PutIndexedBigIntegerToBigNumber(Reader.Items[2], Sig.S);

    Result := CnEccRecoverPublicKey(Ecc, E, Sig, OutPublicKey1, OutPublicKey2);
  finally
    Stream.Free;
    Reader.Free;
    E.Free;
    Sig.Free;
  end;
end;

function CnEccRecoverPublicKeyFromStream(InStream: TMemoryStream; InSignStream: TMemoryStream;
  CurveType: TCnEccCurveType; OutPublicKey1, OutPublicKey2: TCnEccPublicKey;
  SignType: TCnEccSignDigestType): Boolean; overload;
var
  Ecc: TCnEcc;
begin
  if CurveType = ctCustomized then
    raise ECnEccException.Create(SCnErrorEccCurveType);

  Ecc := TCnEcc.Create(CurveType);
  try
    Result := CnEccRecoverPublicKeyFromStream(InStream, InSignStream, Ecc,
      OutPublicKey1, OutPublicKey2, SignType);
  finally
    Ecc.Free;
  end;
end;

function CheckEccPublicKey(Ecc: TCnEcc; PublicKey: TCnEccPublicKey): Boolean;
var
  P: TCnEccPoint;
begin
  Result := False;
  if (Ecc <> nil) and (PublicKey <> nil) then
  begin
    if PublicKey.IsZero then
      Exit;
    if not Ecc.IsPointOnCurve(PublicKey) then
      Exit;

    P := TCnEccPoint.Create;
    try
      P.Assign(PublicKey);
      Ecc.MultiplePoint(Ecc.Order, P);
      Result := P.IsZero;
    finally
      P.Free;
    end;
  end;
end;

function GetEccDigestNameFromSignDigestType(Digest: TCnEccSignDigestType): string;
begin
  case Digest of
    esdtMD5: Result := 'MD5';
    esdtSHA1: Result := 'SHA1';
    esdtSHA256: Result := 'SHA256';
    esdtSM3: Result := 'SM3';
  else
    Result := '<Unknown>';
  end;
end;

{ TCnInt64PolynomialEccPoint }

procedure TCnInt64PolynomialEccPoint.Assign(Source: TPersistent);
begin
  if Source is TCnInt64PolynomialEccPoint then
  begin
    Int64PolynomialCopy(FX, (Source as TCnInt64PolynomialEccPoint).X);
    Int64PolynomialCopy(FY, (Source as TCnInt64PolynomialEccPoint).Y);
  end
  else
    inherited;
end;

constructor TCnInt64PolynomialEccPoint.Create;
begin
  inherited;
  FX := TCnInt64Polynomial.Create;
  FY := TCnInt64Polynomial.Create;
end;

constructor TCnInt64PolynomialEccPoint.Create(const XLowToHighCoefficients,
  YLowToHighCoefficients: array of const);
begin
  Create;
  FX.SetCoefficents(XLowToHighCoefficients);
  FY.SetCoefficents(YLowToHighCoefficients);
end;

destructor TCnInt64PolynomialEccPoint.Destroy;
begin
  FY.Free;
  FX.Free;
  inherited;
end;

function TCnInt64PolynomialEccPoint.IsZero: Boolean;
begin
  Result := FX.IsZero and FY.IsZero;
end;

procedure TCnInt64PolynomialEccPoint.SetX(
  const Value: TCnInt64Polynomial);
begin
  if Value <> nil then
    Int64PolynomialCopy(FX, Value);
end;

procedure TCnInt64PolynomialEccPoint.SetY(
  const Value: TCnInt64Polynomial);
begin
  if Value <> nil then
    Int64PolynomialCopy(FY, Value);
end;

procedure TCnInt64PolynomialEccPoint.SetZero;
begin
  FX.SetZero;
  FY.SetZero;
end;

function TCnInt64PolynomialEccPoint.ToString: string;
begin
  Result := CnInt64PolynomialEccPointToString(Self);
end;

function CnInt64PolynomialEccPointToString(P: TCnInt64PolynomialEccPoint): string;
begin
  Result := Format('%s; %s', [P.X.ToString, P.Y.ToString]);
end;

function CnInt64PolynomialEccPointsEqual(P1, P2: TCnInt64PolynomialEccPoint): Boolean;
begin
  Result := Int64PolynomialEqual(P1.X, P2.X) and Int64PolynomialEqual(P1.Y, P2.Y);
end;

{ TCnInt64PolynomialEcc }

constructor TCnInt64PolynomialEcc.Create(A, B, FieldPrime: Int64; Ext: Integer;
  GX, GY: array of const; Order: Int64; PrimitivePolynomial: array of const);
begin
  inherited Create;

  // ����籣֤ Prime �� Order Ϊ����
  // if not CnInt64IsPrime(FieldPrime) then // or not CnInt64IsPrime(Order) then
  //  raise ECnEccException.Create('Infinite Field must be a Prime Number.');

  // ��������ô��� 1
  if Ext <= 1 then
    raise ECnEccException.Create('Field Extension must > 1.');

  // Ҫȷ�� 4*a^3+27*b^2 <> 0
  if 4 * A * A * A + 27 * B * B = 0 then
    raise ECnEccException.Create('Error: 4 * A^3 + 27 * B^2 = 0');

  FCoefficientA := A;
  FCoefficientB := B;
  FFiniteFieldSize := FieldPrime;
  FExtension := Ext;

  FGenerator := TCnInt64PolynomialEccPoint.Create;
  FGenerator.X.SetCoefficents(GX);
  FGenerator.Y.SetCoefficents(GY);

  FOrder := Order;

  FPrimitive := TCnInt64Polynomial.Create;
  FPrimitive.SetCoefficents(PrimitivePolynomial);
end;

destructor TCnInt64PolynomialEcc.Destroy;
begin
  FPrimitive.Free;
  FGenerator.Free;
  inherited;
end;

function TCnInt64PolynomialEcc.DivisionPolynomial(Degree: Integer;
  outDivisionPolynomial: TCnInt64Polynomial): Boolean;
begin
  Result := Int64PolynomialGaloisCalcDivisionPolynomial(FCoefficientA, FCoefficientB,
    Degree, outDivisionPolynomial, FFiniteFieldSize);
end;

function TCnInt64PolynomialEcc.IsPointOnCurve(P: TCnInt64PolynomialEccPoint): Boolean;
var
  X, Y: TCnInt64Polynomial;
begin
  // ���� (Y^2 - X^3 - A*X - B) mod primitive ������ʽϵ������Ҫ mod p���Ƿ���� 0 ����ʽ
  Result := False;
  if P = nil then
    Exit;

  X := nil;
  Y := nil;

  try
    X := FEccInt64PolynomialPool.Obtain;
    Y := FEccInt64PolynomialPool.Obtain;

    Int64PolynomialCopy(Y, P.Y);
    Int64PolynomialGaloisMul(Y, Y, Y, FFiniteFieldSize, FPrimitive);

    Int64PolynomialCopy(X, P.X);
    Int64PolynomialGaloisPower(X, X, 3, FFiniteFieldSize, FPrimitive);

    Int64PolynomialGaloisSub(Y, Y, X, FFiniteFieldSize, FPrimitive);  // Y := Y^2 - X^3 mod

    Int64PolynomialCopy(X, P.X);
    Int64PolynomialMulWord(X, FCoefficientA);
    Int64PolynomialAddWord(X, FCoefficientB);
    Int64PolynomialNonNegativeModWord(X, FFiniteFieldSize);  // X := A*X + B mod

    Int64PolynomialGaloisSub(Y, Y, X, FFiniteFieldSize, FPrimitive);
    Int64PolynomialGaloisMod(Y, Y, FPrimitive, FFiniteFieldSize);

    Result := Y.IsZero;
  finally
    FEccInt64PolynomialPool.Recycle(Y);
    FEccInt64PolynomialPool.Recycle(X);
  end;
end;

class function TCnInt64PolynomialEcc.IsPointOnCurve2(PX, PY: TCnInt64Polynomial;
  A, B, APrime: Int64; APrimitive: TCnInt64Polynomial): Boolean;
var
  X, Y: TCnInt64Polynomial;
begin
  // ���� (Y^2 - X^3 - A*X - B) mod primitive ������ʽϵ������Ҫ mod p���Ƿ���� 0 ����ʽ
  X := nil;
  Y := nil;

  try
    X := FEccInt64PolynomialPool.Obtain;
    Y := FEccInt64PolynomialPool.Obtain;

    Int64PolynomialCopy(Y, PY);
    Int64PolynomialGaloisMul(Y, Y, Y, APrime, APrimitive);

    Int64PolynomialCopy(X, PX);
    Int64PolynomialGaloisPower(X, X, 3, APrime, APrimitive);

    Int64PolynomialGaloisSub(Y, Y, X, APrime, APrimitive);                // Y := Y^2 - X^3

    Int64PolynomialCopy(X, PX);
    Int64PolynomialMulWord(X, A);
    Int64PolynomialAddWord(X, B);   // X := A*X + B
    Int64PolynomialNonNegativeModWord(X, APrime);

    Int64PolynomialGaloisSub(Y, Y, X, APrime, APrimitive);
    Int64PolynomialGaloisMod(Y, Y, APrimitive, APrime);

    Result := Y.IsZero;
  finally
    FEccInt64PolynomialPool.Recycle(Y);
    FEccInt64PolynomialPool.Recycle(X);
  end;
end;

class function TCnInt64PolynomialEcc.IsRationalPointOnCurve(PX,
  PY: TCnInt64RationalPolynomial; A, B, APrime: Int64;
  APrimitive: TCnInt64Polynomial): Boolean;
var
  Y2, T1: TCnInt64Polynomial;
  RL, RR, T2: TCnInt64RationalPolynomial;
begin
  // ���� PY^2 * (x^3 + Ax + B) �Ƿ���� PX^3 + A * PX + B��ϵ���� mod APrime
  Y2 := nil;
  T1 := nil;
  T2 := nil;
  RL := nil;
  RR := nil;

  try
    Y2 := FEccInt64PolynomialPool.Obtain;
    Y2.SetCoefficents([B, A, 0, 1]);

    RL := FEccInt64RationalPolynomialPool.Obtain;
    Int64RationalPolynomialGaloisMul(PY, PY, RL, APrime);
    Int64RationalPolynomialGaloisMul(RL, Y2, RL, APrime);  // �õ��Ⱥ���ߵ�ֵ

    RR := FEccInt64RationalPolynomialPool.Obtain;
    Int64RationalPolynomialGaloisMul(PX, PX, RR, APrime);
    Int64RationalPolynomialGaloisMul(RR, PX, RR, APrime);  // �õ� PX^3

    T1 := FEccInt64PolynomialPool.Obtain;
    T1.SetCoefficents([A]);

    T2 := FEccInt64RationalPolynomialPool.Obtain;
    Int64RationalPolynomialGaloisMul(PX, T1, T2, APrime);  // T2 �õ� A * PX

    T1.SetCoefficents([B]);
    Int64RationalPolynomialGaloisAdd(T2, T1, T2, APrime);  // T2 �õ� A * PX + B

    Int64RationalPolynomialGaloisAdd(T2, RR, RR, APrime);  // RR �õ� PX^3 + A * PX + B

    if APrimitive <> nil then
    begin
      Int64PolynomialGaloisMod(RL.Nominator, RL.Nominator, APrimitive, APrime);
      Int64PolynomialGaloisMod(RL.Denominator, RL.Denominator, APrimitive, APrime);
      Int64PolynomialGaloisMod(RR.Nominator, RR.Nominator, APrimitive, APrime);
      Int64PolynomialGaloisMod(RR.Denominator, RR.Denominator, APrimitive, APrime);
    end;

    Result := Int64RationalPolynomialGaloisEqual(RL, RR, APrime, APrimitive);       // �Ƚ��Ƿ����
  finally
    FEccInt64PolynomialPool.Recycle(Y2);
    FEccInt64PolynomialPool.Recycle(T1);
    FEccInt64RationalPolynomialPool.Recycle(T2);
    FEccInt64RationalPolynomialPool.Recycle(RL);
    FEccInt64RationalPolynomialPool.Recycle(RR);
  end;
end;

procedure TCnInt64PolynomialEcc.MultiplePoint(K: Int64;
  Point: TCnInt64PolynomialEccPoint);
var
  E, R: TCnInt64PolynomialEccPoint;
begin
  if K = 0 then
  begin
    Point.SetZero;
    Exit;
  end
  else if K < 0 then
  begin
    K := -K;
    PointInverse(Point);
  end;

  R := nil;
  E := nil;

  try
    R := TCnInt64PolynomialEccPoint.Create;
    E := TCnInt64PolynomialEccPoint.Create;

    R.SetZero;
    E.Assign(Point);

    while K <> 0 do
    begin
      if (K and 1) <> 0 then
        PointAddPoint(R, E, R);

      PointAddPoint(E, E, E);
      K := K shr 1;
    end;

    Point.Assign(R);
  finally
    R.Free;
    E.Free;
  end;
end;

//class procedure TCnInt64PolynomialEcc.MultiplePoint1(K: Integer; PX,
//  PY: TCnInt64Polynomial; A, B, APrime: Int64;
//  APrimitive: TCnInt64Polynomial);
//var
//  EX, EY, RX, RY, SX, SY: TCnInt64Polynomial;
//begin
//  if K = 0 then
//  begin
//    PX.SetZero;
//    PY.SetZero;
//    Exit;
//  end
//  else if K < 0 then
//    raise ECnEccException.Create('Negative Multiple NOT Support');
//
//  EX := nil;
//  EY := nil;
//  RX := nil;
//  RY := nil;
//  SX := nil;
//  SY := nil;
//
//  try
//    EX := FEccInt64PolynomialPool.Obtain;
//    EY := FEccInt64PolynomialPool.Obtain;
//    RX := FEccInt64PolynomialPool.Obtain;
//    RY := FEccInt64PolynomialPool.Obtain;
//    SX := FEccInt64PolynomialPool.Obtain;
//    SY := FEccInt64PolynomialPool.Obtain;
//
//    RX.SetZero;
//    RY.SetZero;
//
//    Int64PolynomialCopy(EX, PX);
//    Int64PolynomialCopy(EY, PY);
//
//    while K <> 0 do
//    begin
//      if (K and 1) <> 0 then
//      begin
//        PointAddPoint1(RX, RY, EX, EY, SX, SY, A, B, APrime, APrimitive);
//        Int64PolynomialCopy(RX, SX);
//        Int64PolynomialCopy(RY, SY);
//      end;
//
//      PointAddPoint1(EX, EY, EX, EY, SX, SY, A, B, APrime, APrimitive);
//      Int64PolynomialCopy(EX, SX);
//      Int64PolynomialCopy(EY, SY);
//
//      K := K shr 1;
//    end;
//
//    Int64PolynomialCopy(PX, RX);
//    Int64PolynomialCopy(PY, RY);
//  finally
//    FEccInt64PolynomialPool.Recycle(EX);
//    FEccInt64PolynomialPool.Recycle(EY);
//    FEccInt64PolynomialPool.Recycle(RX);
//    FEccInt64PolynomialPool.Recycle(RY);
//    FEccInt64PolynomialPool.Recycle(SX);
//    FEccInt64PolynomialPool.Recycle(SY);
//  end;
//end;

procedure TCnInt64PolynomialEcc.PointAddPoint(P, Q,
  Sum: TCnInt64PolynomialEccPoint);
var
  K, X, Y, T: TCnInt64Polynomial;
begin
  K := nil;
  X := nil;
  Y := nil;
  T := nil;

  try
    if P.IsZero then
    begin
      Sum.Assign(Q);
      Exit;
    end
    else if Q.IsZero then
    begin
      Sum.Assign(P);
      Exit;
    end
    else if Int64PolynomialEqual(P.X, Q.X) and Int64PolynomialEqual(P.Y, Q.Y) then
    begin
      // ��������ͬһ���㣬����б��Ϊ�����󵼣�3 * X^2 + A / (2 * Y) ���� Y = 0 ��ֱ��������Զ 0��
      X := FEccInt64PolynomialPool.Obtain;
      Y := FEccInt64PolynomialPool.Obtain;

      // X := 3 * P.X * P.X + FCoefficientA
      Int64PolynomialGaloisMul(X, P.X, P.X, FFiniteFieldSize, FPrimitive);
      Int64PolynomialGaloisMulWord(X, 3, FFiniteFieldSize);
      Int64PolynomialGaloisAddWord(X, FCoefficientA, FFiniteFieldSize);

      // Y := 2 * P.Y;
      Int64PolynomialCopy(Y, P.Y);
      Int64PolynomialGaloisMulWord(Y, 2, FFiniteFieldSize);

      if Y.IsZero then
      begin
        Sum.X.SetZero;
        Sum.Y.SetZero;
      end;

      // Y := Y^-1
      T := FEccInt64PolynomialPool.Obtain;
      Int64PolynomialCopy(T, Y);
      Int64PolynomialGaloisModularInverse(Y, T, FPrimitive, FFiniteFieldSize);

      // K := X * Y mod FFiniteFieldSize;
      K := FEccInt64PolynomialPool.Obtain;
      Int64PolynomialGaloisMul(K, X, Y, FFiniteFieldSize, FPrimitive);
      // �õ�����б�� K
    end
    else // �ǲ�ͬ��
    begin
      if Int64PolynomialEqual(P.X, Q.X) then // ��� X ��ȣ�Ҫ�ж� Y �ǲ��ǻ����������Ϊ 0�����������
      begin
        T := FEccInt64PolynomialPool.Obtain;
        Int64PolynomialGaloisAdd(T, P.Y, Q.Y, FFiniteFieldSize);
        if T.IsZero then
          Sum.SetZero
        else
          raise ECnEccException.CreateFmt('Can NOT Calucate %s,%s + %s,%s',
            [P.X.ToString, P.Y.ToString, Q.X.ToString, Q.Y.ToString]);

        Exit;
      end;

      // �����X ȷ����ͬ��б�� K := ((Q.Y - P.Y) / (Q.X - P.X)) mod p
      X := FEccInt64PolynomialPool.Obtain;
      Y := FEccInt64PolynomialPool.Obtain;
      K := FEccInt64PolynomialPool.Obtain;

      Int64PolynomialGaloisSub(Y, Q.Y, P.Y, FFiniteFieldSize);
      Int64PolynomialGaloisSub(X, Q.X, P.X, FFiniteFieldSize);

      T := FEccInt64PolynomialPool.Obtain;
      Int64PolynomialCopy(T, X);
      Int64PolynomialGaloisModularInverse(X, T, FPrimitive, FFiniteFieldSize);
      Int64PolynomialGaloisMul(K, Y, X, FFiniteFieldSize, FPrimitive); // �õ�б��
    end;

    //  X := K * K - P.X - Q.X;
    Int64PolynomialCopy(X, K);
    Int64PolynomialGaloisMul(X, X, K, FFiniteFieldSize, FPrimitive);
    Int64PolynomialGaloisSub(X, X, P.X, FFiniteFieldSize);
    Int64PolynomialGaloisSub(X, X, Q.X, FFiniteFieldSize);

    // Ysum = (K * (X1 - Xsum) - Y1) mod p
    Int64PolynomialGaloisSub(X, P.X, X, FFiniteFieldSize);
    Int64PolynomialGaloisMul(Y, K, X, FFiniteFieldSize, FPrimitive);
    Int64PolynomialGaloisSub(Y, Y, P.Y, FFiniteFieldSize);

    Int64PolynomialCopy(Sum.X, X);
    Int64PolynomialCopy(Sum.Y, Y);
  finally
    FEccInt64PolynomialPool.Recycle(K);
    FEccInt64PolynomialPool.Recycle(X);
    FEccInt64PolynomialPool.Recycle(Y);
    FEccInt64PolynomialPool.Recycle(T);
  end;
end;

procedure TCnInt64PolynomialEcc.PointInverse(
  P: TCnInt64PolynomialEccPoint);
var
  I: Integer;
begin
  for I := 0 to P.Y.MaxDegree do
    P.Y[I] := FFiniteFieldSize - P.Y[I];
end;

procedure TCnInt64PolynomialEcc.PointSubPoint(P, Q,
  Diff: TCnInt64PolynomialEccPoint);
var
  Inv: TCnInt64PolynomialEccPoint;
begin
  Inv := TCnInt64PolynomialEccPoint.Create;
  try
    Inv.Assign(Q);
    PointInverse(Inv);
    PointAddPoint(P, Inv, Diff);
  finally
    Inv.Free;
  end;
end;

class procedure TCnInt64PolynomialEcc.RationalMultiplePoint(K: Integer;
  MX, MY: TCnInt64RationalPolynomial; A, B, APrime: Int64; APrimitive: TCnInt64Polynomial);
var
  Neg: Boolean;
  FN, FNa1, FNa2, FNs1, FNs2, P1, P2, X1, Y2: TCnInt64Polynomial;
begin
  if K = 0 then
  begin
    if MX <> nil then
      MX.SetZero;
    if MY <> nil then
      MY.SetZero;
    Exit;
  end;

  Neg := K < 0;
  if Neg then
    K := -K;

  if K = 1 then // û�ˣ�ԭ�ⲻ������ x �� 1
  begin
    if MX <> nil then
    begin
      MX.Nominator.SetCoefficents([0, 1]);
      MX.Denominator.SetOne;
    end;

    if MY <> nil then
    begin
      MY.Nominator.SetOne;
      MY.Denominator.SetOne;
    end;
  end
  else
  begin
    FN := FEccInt64PolynomialPool.Obtain;
    FNa1 := FEccInt64PolynomialPool.Obtain;
    FNa2 := FEccInt64PolynomialPool.Obtain;
    FNs1 := FEccInt64PolynomialPool.Obtain;
    FNs2 := FEccInt64PolynomialPool.Obtain;
    X1 := FEccInt64PolynomialPool.Obtain;
    Y2 := FEccInt64PolynomialPool.Obtain;
    P1 := FEccInt64PolynomialPool.Obtain;
    P2 := FEccInt64PolynomialPool.Obtain;

    try
      X1.SetCoefficents([0, 1]);
      Y2.SetCoefficents([B, A, 0, 1]);

      Int64PolynomialGaloisCalcDivisionPolynomial(A, B, K, FN, APrime);
      Int64PolynomialGaloisCalcDivisionPolynomial(A, B, K + 1, FNa1, APrime);
      Int64PolynomialGaloisCalcDivisionPolynomial(A, B, K + 2, FNa2, APrime);
      Int64PolynomialGaloisCalcDivisionPolynomial(A, B, K - 1, FNs1, APrime);
      Int64PolynomialGaloisCalcDivisionPolynomial(A, B, K - 2, FNs2, APrime);

      // �� X ���ʽ
      if MX <> nil then
      begin
        if (K and 1) = 0 then // K ż��ʱ
        begin
          // ����� x ����Ϊ (x*fn^2 * Y^2 - fn+1 * fn-1) / fn^2 * Y^2
          Int64PolynomialGaloisMul(MX.Denominator, FN, FN, APrime);
          Int64PolynomialGaloisMul(MX.Denominator, MX.Denominator, Y2, APrime);

          Int64PolynomialGaloisMul(P1, FNa1, FNs1, APrime); // P1 �õ� fn+1 * fn-1
          Int64PolynomialGaloisMul(P2, FN, FN, APrime);
          Int64PolynomialGaloisMul(P2, P2, X1, APrime);     // P2 �õ� x*fn^2
          Int64PolynomialGaloisMul(P2, P2, Y2, APrime);     // P2 �õ� x*fn^2 * Y^2

          Int64PolynomialGaloisSub(MX.Nominator, P2, P1, APrime); // MX �������
        end
        else // K ����ʱ
        begin
          // ����� x ����Ϊ (x*fn^2 - Y^2 * fn+1 * fn-1) / fn^2
          Int64PolynomialGaloisMul(MX.Denominator, FN, FN, APrime);

          Int64PolynomialGaloisMul(P1, FNa1, FNs1, APrime); // P1 �õ� fn+1 * fn-1
          Int64PolynomialGaloisMul(P1, P1, Y2, APrime);     // P1 �õ� Y^2 * fn+1 * fn-1

          Int64PolynomialGaloisMul(P2, FN, FN, APrime);
          Int64PolynomialGaloisMul(P2, P2, X1, APrime);     // P2 �õ� x*fn^2
          Int64PolynomialGaloisSub(MX.Nominator, P2, P1, APrime); // MX �������
        end;
      end;

      // �� Y ���ʽ
      if MY <> nil then
      begin
        if K = 2 then // Y �ķ����� f2n��n Ϊ 2 ʱ����ݹ飬ֱ���� f4
        begin
          Int64PolynomialCopy(MY.Nominator, FNa2);
        end
        else
        begin
          // ����� y �������Ϊ fn+2 * fn-1^2 - fn-2 * fn+1 ^2
          Int64PolynomialGaloisMul(P1, FNs1, FNs1, APrime);
          Int64PolynomialGaloisMul(P1, P1, FNa2, APrime);
          Int64PolynomialGaloisMul(P2, FNa1, FNa1, APrime);
          Int64PolynomialGaloisMul(P2, P2, FNs2, APrime);

          Int64PolynomialGaloisSub(MY.Nominator, P1, P2, APrime); // MY ���Ӽ������
        end;

        Int64PolynomialGaloisPower(MY.Denominator, FN, 3, APrime);
        Int64PolynomialGaloisMulWord(MY.Denominator, 4, APrime);   // ������ĸ 4 * fn^3 �������

        if (K and 1) = 0 then // ż����ĸ���ó��� y^4
        begin
          Int64PolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime);
          Int64PolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime);
        end;
      end;
    finally
      FEccInt64PolynomialPool.Recycle(FN);
      FEccInt64PolynomialPool.Recycle(FNa1);
      FEccInt64PolynomialPool.Recycle(FNa2);
      FEccInt64PolynomialPool.Recycle(FNs1);
      FEccInt64PolynomialPool.Recycle(FNs2);
      FEccInt64PolynomialPool.Recycle(X1);
      FEccInt64PolynomialPool.Recycle(Y2);
      FEccInt64PolynomialPool.Recycle(P1);
      FEccInt64PolynomialPool.Recycle(P2);
    end;
  end;

  if Neg then
    MY.Neg;

  if APrimitive <> nil then
  begin
    if MX <> nil then
    begin
      Int64PolynomialGaloisMod(MX.Nominator, MX.Nominator, APrimitive, APrime);
      Int64PolynomialGaloisMod(MX.Denominator, MX.Denominator, APrimitive, APrime);
    end;
    if MY <> nil then
    begin
      Int64PolynomialGaloisMod(MY.Nominator, MY.Nominator, APrimitive, APrime);
      Int64PolynomialGaloisMod(MY.Denominator, MY.Denominator, APrimitive, APrime);
    end;
  end;
end;

class procedure TCnInt64PolynomialEcc.RationalPointAddPoint(PX, PY, QX, QY,
  SX, SY: TCnInt64RationalPolynomial; A, B, APrime: Int64; APrimitive: TCnInt64Polynomial);
var
  R, T1, T2: TCnInt64RationalPolynomial;
  Y2, C: TCnInt64Polynomial;
begin
  // �� (PX, PY * y) + (QX, QY * y) = (SX, SY * y)
  // ����б�� R = y * (QY - PY) / (QX - PX) �� (3PX^2 + A) / 2PY * y

  if PX.IsZero and PY.IsZero then
  begin
    Int64RationalPolynomialCopy(SX, QX);
    Int64RationalPolynomialCopy(SY, QY);
    Exit;
  end
  else if QX.IsZero and QY.IsZero then
  begin
    Int64RationalPolynomialCopy(SX, PX);
    Int64RationalPolynomialCopy(SY, PY);
    Exit;
  end;

  R := nil;
  T1 := nil;
  T2 := nil;

  Y2 := nil;
  C := nil;

  try
    R := FEccInt64RationalPolynomialPool.Obtain;
    T1 := FEccInt64RationalPolynomialPool.Obtain;
    T2 := FEccInt64RationalPolynomialPool.Obtain;

    Y2 := FEccInt64PolynomialPool.Obtain;
    C := FEccInt64PolynomialPool.Obtain;
    Y2.SetCoefficents([B, A, 0, 1]);

    if Int64RationalPolynomialGaloisEqual(PX, QX, APrime, APrimitive) then // ����ֱ���ж���ȣ��û��˺������Ա�ԭ����ʽ��������ж����
    begin
      // X ��ȣ��ж� Y �Ƿ���ȣ���������������෴������ 0
      // TODO: �ж� PY QY �Ƿ��෴
      if not Int64RationalPolynomialGaloisEqual(PY, QY, APrime, APrimitive) then
      begin
        SX.SetZero;
        SY.SetZero;
        Exit;
      end;

      // X Y ����ȣ���
      C.SetCoefficents([3]);

      Int64RationalPolynomialGaloisMul(PX, PX, T1, APrime);
      Int64RationalPolynomialGaloisMul(T1, C, T1, APrime);  // T1 �õ� 3PX^2

      C.SetCoefficents([A]);
      Int64RationalPolynomialGaloisAdd(T1, C, T1, APrime);  // T1 �õ� 3PX^2 + A

      C.SetCoefficents([2]);
      Int64RationalPolynomialGaloisMul(PY, C, T2, APrime);  // T2 �õ� 2PY��ʵ���ϻ�Ҫ����һ�� y

      Int64RationalPolynomialGaloisDiv(T1, T2, R, APrime);  // �õ�б�� R������ʵ��б�ʷ�ĸʵ���ϻ�Ҫ����һ�� y�����油��

      // SX = ��ʵб��^2 - PX - QX = R^2 / (x^3+Ax+B) - PX - QX
      // ��ʵб�ʵ�ƽ�� = R^2 / y^2����ĸ���滻�� x^3+Ax+B
      Int64RationalPolynomialGaloisMul(R, R, SX, APrime);
      Int64RationalPolynomialGaloisDiv(SX, Y2, SX, APrime);
      Int64RationalPolynomialGaloisSub(SX, PX, SX, APrime);
      Int64RationalPolynomialGaloisSub(SX, QX, SX, APrime);

      if APrimitive <> nil then
      begin
        Int64PolynomialGaloisMod(SX.Nominator, SX.Nominator, APrimitive, APrime);
        Int64PolynomialGaloisMod(SX.Denominator, SX.Denominator, APrimitive, APrime);
      end;

      // SY * y = ��ʵб�� * (PX - SX) - PY * y
      // SY = (R/y * (PX - SX) - PY * y) / y = R * (PX - SX)/ y^2 - PY
      Int64RationalPolynomialGaloisSub(PX, SX, SY, APrime);
      Int64RationalPolynomialGaloisMul(SY, R, SY, APrime);
      Int64RationalPolynomialGaloisDiv(SY, Y2, SY, APrime);
      Int64RationalPolynomialGaloisSub(SY, PY, SY, APrime);

      if APrimitive <> nil then
      begin
        Int64PolynomialGaloisMod(SY.Nominator, SY.Nominator, APrimitive, APrime);
        Int64PolynomialGaloisMod(SY.Denominator, SY.Denominator, APrimitive, APrime);
      end;
    end
    else
    begin
      // ����ȣ�������ʵб�ʵ��� y * (QY - PY) / (QX - PX)
      Int64RationalPolynomialGaloisSub(QY, PY, T1, APrime);
      Int64RationalPolynomialGaloisSub(QX, PX, T2, APrime);
      Int64RationalPolynomialGaloisDiv(T1, T2, R, APrime);

      // R �õ�б���ˣ�����ʵ��б�ʷ���ʵ���ϻ�Ҫ����һ�� y�����油��
      // SX = R^2 * (x^3+Ax+B) - PX - QX
      Int64RationalPolynomialGaloisMul(R, R, SX, APrime);
      Int64RationalPolynomialGaloisMul(SX, Y2, SX, APrime);
      Int64RationalPolynomialGaloisSub(SX, PX, SX, APrime);
      Int64RationalPolynomialGaloisSub(SX, QX, SX, APrime);
      if APrimitive <> nil then
      begin
        Int64PolynomialGaloisMod(SX.Nominator, SX.Nominator, APrimitive, APrime);
        Int64PolynomialGaloisMod(SX.Denominator, SX.Denominator, APrimitive, APrime);
      end;

      // SY * y = R * y * (PX - SX) - PY * y ������ y �� SY = R * (PX - SX) - PY
      Int64RationalPolynomialGaloisSub(PX, SX, SY, APrime);
      Int64RationalPolynomialGaloisMul(SY, R, SY, APrime);
      Int64RationalPolynomialGaloisSub(SY, PY, SY, APrime);

      if APrimitive <> nil then
      begin
        Int64PolynomialGaloisMod(SY.Nominator, SY.Nominator, APrimitive, APrime);
        Int64PolynomialGaloisMod(SY.Denominator, SY.Denominator, APrimitive, APrime);
      end;
    end;
  finally
    FEccInt64PolynomialPool.Recycle(Y2);
    FEccInt64PolynomialPool.Recycle(C);

    FEccInt64RationalPolynomialPool.Recycle(T2);
    FEccInt64RationalPolynomialPool.Recycle(T1);
    FEccInt64RationalPolynomialPool.Recycle(R);
  end;
end;

procedure TCnInt64PolynomialEcc.SetPrimitive(const Value: TCnInt64Polynomial);
begin
  if Value <> nil then
  begin
    if Value.MaxDegree <> FExtension then
      raise ECnEccException.Create('Primitive Polynomial Max Degree must be Field Extension.');
    Int64PolynomialCopy(FPrimitive, Value);
  end;
end;

procedure CnInt64GenerateGaloisDivisionPolynomials(A, B, APrime: Int64; MaxDegree: Integer;
  PolynomialList: TObjectList);
var
  I, N: Integer;

  // ���ص� Degree ���ɳ����ʽ�����ã���ͬʱ���� PolynomialList �Ķ�Ӧλ�ã�ע�ⷵ��ֵ��Ҫ�Ķ�
  function GetInt64GaloisDivisionPolynomial(Degree: Integer): TCnInt64Polynomial;
  var
    MI, T1, T2: Int64;
    F1, F2, F3, F4, F5: TCnInt64Polynomial;  // �ӵݹ� GetInt64GaloisDivisionPolynomial �õ������ã�������Ķ�
    D1, D2, D3, Y4: TCnInt64Polynomial;      // �����м�����Ҫ����Ҫ�ͷ�
  begin
    if PolynomialList[Degree] <> nil then // ����л���ͷ��ػ����
    begin
      Result := TCnInt64Polynomial(PolynomialList[Degree]);
      Exit;
    end;

    if Degree = 0 then
    begin
      Result := TCnInt64Polynomial.Create;
      Result.SetCoefficents([0]);  // f0(X) = 0
      PolynomialList[0] := Result;
    end
    else if Degree = 1 then
    begin
      Result := TCnInt64Polynomial.Create;
      Result.SetCoefficents([1]);  // f1(X) = 1
      PolynomialList[1] := Result;
    end
    else if Degree = 2 then
    begin
      Result := TCnInt64Polynomial.Create;
      Result.SetCoefficents([2]);  // f2(X) = 2
      PolynomialList[2] := Result;
    end
    else if Degree = 3 then   // f3(X) = 3 X4 + 6 a X2 + 12 b X - a^2
    begin
      Result := TCnInt64Polynomial.Create;
      Result.MaxDegree := 4;
      Result[4] := 3;
      Result[3] := 0;
      Result[2] := Int64NonNegativeMulMod(6, A, APrime);
      Result[1] := Int64NonNegativeMulMod(12, B, APrime);
      Result[0] := Int64NonNegativeMulMod(-A, A, APrime);

      PolynomialList[3] := Result;
    end
    else if Degree = 4 then // f4(X) = 4 X6 + 20 a X4 + 80 b X3 - 20 a2X2 - 16 a b X - 4 a3 - 32 b^2
    begin
      Result := TCnInt64Polynomial.Create;
      Result.MaxDegree := 6;
      Result[6] := 4;
      Result[5] := 0;
      Result[4] := Int64NonNegativeMulMod(20, A, APrime);
      Result[3] := Int64NonNegativeMulMod(80, B, APrime);
      Result[2] := Int64NonNegativeMulMod(Int64NonNegativeMulMod(-20, A, APrime), A, APrime);
      Result[1] := Int64NonNegativeMulMod(Int64NonNegativeMulMod(-16, A, APrime), B, APrime);
      T1 := Int64NonNegativeMulMod(Int64NonNegativeMulMod(Int64NonNegativeMulMod(-4, A, APrime), A, APrime), A, APrime);
      T2 := Int64NonNegativeMulMod(Int64NonNegativeMulMod(-32, B, APrime), B, APrime);
      Result[0] := Int64NonNegativeMod(T1 + T2, APrime); // TODO: ��δ������������ȡģ

      PolynomialList[4] := Result;
    end
    else
    begin
      // ����� Degree ���ɳ����ʽ���м���ܵݹ���õ�����ͬ�������ӻ�����ȡ
      D1 := nil;
      D2 := nil;
      D3 := nil;
      Y4 := nil;

      try
        // ��ʼ�ݹ����
        N := Degree shr 1;
        if (Degree and 1) = 0 then // Degree ��ż��
        begin
          F1 := GetInt64GaloisDivisionPolynomial(N + 2); // F1 �õ� Fn+2
          F2 := GetInt64GaloisDivisionPolynomial(N - 1); // F2 �õ� Fn-1

          D2 := FEccInt64PolynomialPool.Obtain;
          Int64PolynomialGaloisMul(D2, F2, F2, APrime);   // D2 �õ� Fn-1 ^ 2

          D1 := FEccInt64PolynomialPool.Obtain;
          Int64PolynomialGaloisMul(D1, F1, D2, APrime);   // D1 �õ� Fn+2 * Fn-1 ^ 2

          F3 := GetInt64GaloisDivisionPolynomial(N - 2);  // F3 �õ� Fn-2
          F4 := GetInt64GaloisDivisionPolynomial(N + 1);  // F4 �õ� Fn+1

          Int64PolynomialGaloisMul(D2, F4, F4, APrime);   // D2 �õ� Fn+1 ^ 2
          Int64PolynomialGaloisMul(D2, D2, F3, APrime);   // D2 �õ� Fn-2 * Fn+1 ^ 2

          Int64PolynomialGaloisSub(D1, D1, D2, APrime);   // D1 �õ� Fn+2 * Fn-1 ^ 2 - Fn-2 * Fn+1 ^ 2

          F5 := GetInt64GaloisDivisionPolynomial(N);     // F5 �õ� Fn

          Result := TCnInt64Polynomial.Create;
          Int64PolynomialGaloisMul(Result, F5, D1, APrime);           // ��˵õ� Fn * (Fn+2 * Fn-1 ^ 2 - Fn-2 * Fn+1 ^ 2)

          MI := CnInt64ModularInverse(2, APrime);
          Int64PolynomialGaloisMulWord(Result, MI, APrime);           // �ٳ��� 2

          PolynomialList[Degree] := Result;
        end
        else // Degree ������
        begin
          Y4 := FEccInt64PolynomialPool.Obtain;
          Y4.SetCoefficents([B, A, 0, 1]);
          Int64PolynomialGaloisMul(Y4, Y4, Y4, APrime);

          F1 := GetInt64GaloisDivisionPolynomial(N + 2); // F1 �õ� Fn+2

          D2 := FEccInt64PolynomialPool.Obtain;
          F2 := GetInt64GaloisDivisionPolynomial(N);     // F2 �õ� Fn
          Int64PolynomialGaloisPower(D2, F2, 3, APrime);  // D2 �õ� Fn^3

          D3 := FEccInt64PolynomialPool.Obtain;
          F3 := GetInt64GaloisDivisionPolynomial(N + 1); // F3 �õ� Fn+1
          Int64PolynomialGaloisPower(D3, F3, 3, APrime);  // D3 �õ� Fn+1 ^ 3

          if (N and 1) <> 0 then // N ������
          begin
            D1 := FEccInt64PolynomialPool.Obtain;
            Int64PolynomialGaloisMul(D1, F1, D2, APrime);     // D1 �õ� Fn+2 * Fn ^ 3�����ͷ� D2

            F4 := GetInt64GaloisDivisionPolynomial(N - 1);
            Int64PolynomialGaloisMul(D2, F4, Y4, APrime);     // D2 �õ� Fn-1 * Y^2

            Int64PolynomialGaloisMul(D2, D2, D3, APrime);     // D2 �õ� Fn+1 ^ 3 * Fn-1(Y)

            Result := TCnInt64Polynomial.Create;
            Int64PolynomialGaloisSub(Result, D1, D2, APrime); // D1 - D2

            PolynomialList[Degree] := Result;
          end
          else // N ��ż��
          begin
            D1 := FEccInt64PolynomialPool.Obtain;
            Int64PolynomialGaloisMul(D1, F1, D2, APrime);     // D1 �õ� Fn+2 * Fn ^ 3�����ͷ� D2
            Int64PolynomialGaloisMul(D1, D1, Y4, APrime);     // D1 �õ� Y * Fn+2 * Fn ^ 3

            F4 := GetInt64GaloisDivisionPolynomial(N - 1);   // F4 �õ� Fn-1

            Int64PolynomialGaloisMul(D2, F4, D3, APrime);     // D2 �õ� Fn+1 ^ 3 * Fn-1

            Result := TCnInt64Polynomial.Create;
            Int64PolynomialGaloisSub(Result, D1, D2, APrime); // D1 - D2

            PolynomialList[Degree] := Result;
          end;
        end;
      finally
        FEccInt64PolynomialPool.Recycle(D1);
        FEccInt64PolynomialPool.Recycle(D2);
        FEccInt64PolynomialPool.Recycle(D3);
        FEccInt64PolynomialPool.Recycle(Y4);
      end;
    end;
  end;

begin
  // ���� 0 �� MaxDegree �Ŀɳ�����ʽ���洢�� PolynomialList �С�
  PolynomialList.Clear;
  PolynomialList.Count := MaxDegree + 1;

  for I := 0 to MaxDegree do
    GetInt64GaloisDivisionPolynomial(I);
end;

procedure CnGenerateGaloisDivisionPolynomials(A, B, APrime: TCnBigNumber; MaxDegree: Integer;
  PolynomialList: TObjectList);
var
  I: Integer;

  // ���ص� Degree ���ɳ����ʽ�����ã���ͬʱ���� PolynomialList �Ķ�Ӧλ�ã�ע�ⷵ��ֵ��Ҫ�Ķ�
  function GetGaloisDivisionPolynomial(Degree: Integer): TCnBigNumberPolynomial;
  var
    N: Integer;
    MI, T: TCnBigNumber;
    F1, F2, F3, F4, F5: TCnBigNumberPolynomial;  // �ӵݹ� GetGaloisDivisionPolynomial �õ������ã�������Ķ�
    D1, D2, D3, Y4: TCnBigNumberPolynomial;      // �����м�����Ҫ����Ҫ�ͷ�
  begin
    if PolynomialList[Degree] <> nil then // ����л���ͷ��ػ����
    begin
      Result := TCnBigNumberPolynomial(PolynomialList[Degree]);
      Exit;
    end;

    if Degree = 0 then
    begin
      Result := TCnBigNumberPolynomial.Create;
      Result.SetCoefficents([0]);  // f0(X) = 0
      PolynomialList[0] := Result;
    end
    else if Degree = 1 then
    begin
      Result := TCnBigNumberPolynomial.Create;
      Result.SetCoefficents([1]);  // f1(X) = 1
      PolynomialList[1] := Result;
    end
    else if Degree = 2 then
    begin
      Result := TCnBigNumberPolynomial.Create;
      Result.SetCoefficents([2]);  // f2(X) = 2
      PolynomialList[2] := Result;
    end
    else if Degree = 3 then   // f3(X) = 3 X4 + 6 a X2 + 12 b X - a^2
    begin
      Result := TCnBigNumberPolynomial.Create;
      Result.MaxDegree := 4;
      Result[4].SetWord(3);
      Result[3].SetWord(0);
      BigNumberMulWordNonNegativeMod(Result[2], A, 6, APrime);
      BigNumberMulWordNonNegativeMod(Result[1], B, 12, APrime);

      T := FEccBigNumberPool.Obtain;
      try
        BigNumberCopy(T, A);
        T.Negate;
        BigNumberDirectMulMod(Result[0], T, A, APrime);
      finally
        FEccBigNumberPool.Recycle(T);
      end;
      PolynomialList[3] := Result;
    end
    else if Degree = 4 then // f4(X) = 4 X6 + 20 a X4 + 80 b X3 - 20 a2X2 - 16 a b X - 4 a3 - 32 b^2
    begin
      Result := TCnBigNumberPolynomial.Create;
      Result.MaxDegree := 6;
      Result[6].SetWord(4);
      Result[5].SetWord(0);
      BigNumberMulWordNonNegativeMod(Result[4], A, 20, APrime);
      BigNumberMulWordNonNegativeMod(Result[3], B, 80, APrime);

      T := FEccBigNumberPool.Obtain;
      try
        BigNumberMulWordNonNegativeMod(T, A, -20, APrime);
        BigNumberDirectMulMod(Result[2], T, A, APrime);
        BigNumberMulWordNonNegativeMod(T, A, -16, APrime);
        BigNumberDirectMulMod(Result[1], T, B, APrime);

        BigNumberMulWordNonNegativeMod(T, A, -4, APrime);
        BigNumberDirectMulMod(T, T, A, APrime);
        BigNumberDirectMulMod(Result[0], T, A, APrime);

        BigNumberMulWordNonNegativeMod(T, B, -32, APrime);
        BigNumberDirectMulMod(T, T, B, APrime);
        BigNumberAdd(Result[0], Result[0], T);
        BigNumberNonNegativeMod(Result[0], Result[0], APrime);
      finally
        FEccBigNumberPool.Recycle(T);
      end;
      PolynomialList[4] := Result;
    end
    else
    begin
      // ����� Degree ���ɳ����ʽ���м���ܵݹ���õ�����ͬ�������ӻ�����ȡ
      D1 := nil;
      D2 := nil;
      D3 := nil;
      Y4 := nil;
      MI := nil;

      try
        // ��ʼ�ݹ����
        N := Degree shr 1;
        if (Degree and 1) = 0 then // Degree ��ż��
        begin
          F1 := GetGaloisDivisionPolynomial(N + 2); // F1 �õ� Fn+2
          F2 := GetGaloisDivisionPolynomial(N - 1); // F2 �õ� Fn-1

          D2 := FEccPolynomialPool.Obtain;
          BigNumberPolynomialGaloisMul(D2, F2, F2, APrime);   // D2 �õ� Fn-1 ^ 2

          D1 := FEccPolynomialPool.Obtain;
          BigNumberPolynomialGaloisMul(D1, F1, D2, APrime);   // D1 �õ� Fn+2 * Fn-1 ^ 2

          F3 := GetGaloisDivisionPolynomial(N - 2);  // F3 �õ� Fn-2
          F4 := GetGaloisDivisionPolynomial(N + 1);  // F4 �õ� Fn+1

          BigNumberPolynomialGaloisMul(D2, F4, F4, APrime);   // D2 �õ� Fn+1 ^ 2
          BigNumberPolynomialGaloisMul(D2, D2, F3, APrime);   // D2 �õ� Fn-2 * Fn+1 ^ 2

          BigNumberPolynomialGaloisSub(D1, D1, D2, APrime);   // D1 �õ� Fn+2 * Fn-1 ^ 2 - Fn-2 * Fn+1 ^ 2

          F5 := GetGaloisDivisionPolynomial(N);     // F5 �õ� Fn

          Result := TCnBigNumberPolynomial.Create;
          BigNumberPolynomialGaloisMul(Result, F5, D1, APrime);           // ��˵õ� Fn * (Fn+2 * Fn-1 ^ 2 - Fn-2 * Fn+1 ^ 2)

          MI := FEccBigNumberPool.Obtain;
          BigNumberModularInverseWord(MI, 2, APrime);
          BigNumberPolynomialGaloisMulBigNumber(Result, MI, APrime);           // �ٳ��� 2

          PolynomialList[Degree] := Result;
        end
        else // Degree ������
        begin
          Y4 := FEccPolynomialPool.Obtain;
          Y4.MaxDegree := 3;
          BigNumberCopy(Y4[0], B);
          BigNumberCopy(Y4[1], A);
          Y4[2].SetZero;
          Y4[3].SetOne;

          BigNumberPolynomialGaloisMul(Y4, Y4, Y4, APrime);

          F1 := GetGaloisDivisionPolynomial(N + 2); // F1 �õ� Fn+2

          D2 := FEccPolynomialPool.Obtain;
          F2 := GetGaloisDivisionPolynomial(N);     // F2 �õ� Fn
          BigNumberPolynomialGaloisPower(D2, F2, 3, APrime);  // D2 �õ� Fn^3

          D3 := FEccPolynomialPool.Obtain;
          F3 := GetGaloisDivisionPolynomial(N + 1); // F3 �õ� Fn+1
          BigNumberPolynomialGaloisPower(D3, F3, 3, APrime);  // D3 �õ� Fn+1 ^ 3

          if (N and 1) <> 0 then // N ������
          begin
            D1 := FEccPolynomialPool.Obtain;
            BigNumberPolynomialGaloisMul(D1, F1, D2, APrime);     // D1 �õ� Fn+2 * Fn ^ 3�����ͷ� D2

            F4 := GetGaloisDivisionPolynomial(N - 1);
            BigNumberPolynomialGaloisMul(D2, F4, Y4, APrime);     // D2 �õ� Fn-1 * Y^2

            BigNumberPolynomialGaloisMul(D2, D2, D3, APrime);     // D2 �õ� Fn+1 ^ 3 * Fn-1(Y)

            Result := TCnBigNumberPolynomial.Create;
            BigNumberPolynomialGaloisSub(Result, D1, D2, APrime); // D1 - D2

            PolynomialList[Degree] := Result;
          end
          else // N ��ż��
          begin
            D1 := FEccPolynomialPool.Obtain;
            BigNumberPolynomialGaloisMul(D1, F1, D2, APrime);     // D1 �õ� Fn+2 * Fn ^ 3�����ͷ� D2
            BigNumberPolynomialGaloisMul(D1, D1, Y4, APrime);     // D1 �õ� Y * Fn+2 * Fn ^ 3

            F4 := GetGaloisDivisionPolynomial(N - 1);   // F4 �õ� Fn-1

            BigNumberPolynomialGaloisMul(D2, F4, D3, APrime);     // D2 �õ� Fn+1 ^ 3 * Fn-1

            Result := TCnBigNumberPolynomial.Create;
            BigNumberPolynomialGaloisSub(Result, D1, D2, APrime); // D1 - D2

            PolynomialList[Degree] := Result;
          end;
        end;
      finally
        FEccPolynomialPool.Recycle(D1);
        FEccPolynomialPool.Recycle(D2);
        FEccPolynomialPool.Recycle(D3);
        FEccPolynomialPool.Recycle(Y4);
        FEccBigNumberPool.Recycle(MI);
      end;
    end;
  end;

begin
  // ���� 0 �� MaxDegree �Ŀɳ�����ʽ���洢�� PolynomialList �С�
  PolynomialList.Clear;
  PolynomialList.Count := MaxDegree + 1;

  for I := 0 to MaxDegree do
    GetGaloisDivisionPolynomial(I);
end;

// �ÿɳ�����ʽֱ���㵽 K �α�������꣬ԭ�����£�
// (x, y) * K �ÿɳ�����ʽ������Ľ������д�� (F(x), G(x) * y)
// ��ô (f(x), g(x) * y) * K �ÿɳ�����ʽ������Ľ�����Դ���д��(F(f(x))��G(f(x)) * g(x) * y)
// ���������� F(f(x))
procedure Int64RationalMultiplePointX(Res, PX: TCnInt64RationalPolynomial; K: Integer;
  A, B, APrime: Int64; DivisionPolynomialList: TObjectList; APrimitive: TCnInt64Polynomial);
var
  MX: TCnInt64RationalPolynomial;
  FN, FNa1, FNs1, P1, P2, X1, Y2: TCnInt64Polynomial;
begin
  if K = 0 then
  begin
    Res.SetZero;
    Exit;
  end;

  if K < 0 then
    K := -K;

  MX := FEccInt64RationalPolynomialPool.Obtain;
  if K = 1 then
  begin
    MX.Nominator.SetCoefficents([0, 1]);
    MX.Denominator.SetOne;
  end
  else
  begin
    X1 := FEccInt64PolynomialPool.Obtain;
    Y2 := FEccInt64PolynomialPool.Obtain;
    P1 := FEccInt64PolynomialPool.Obtain;
    P2 := FEccInt64PolynomialPool.Obtain;

    try
      X1.SetCoefficents([0, 1]);
      Y2.SetCoefficents([B, A, 0, 1]);

      FN := TCnInt64Polynomial(DivisionPolynomialList[K]);
      FNa1 := TCnInt64Polynomial(DivisionPolynomialList[K + 1]);
      FNs1 := TCnInt64Polynomial(DivisionPolynomialList[K - 1]);

      // �� X ���ʽ
      if (K and 1) = 0 then // K ż��ʱ
      begin
        // ����� x ����Ϊ (x*fn^2 * Y^2 - fn+1 * fn-1) / fn^2 * Y^2
        Int64PolynomialGaloisMul(MX.Denominator, FN, FN, APrime, APrimitive);
        Int64PolynomialGaloisMul(MX.Denominator, MX.Denominator, Y2, APrime, APrimitive);

        Int64PolynomialGaloisMul(P1, FNa1, FNs1, APrime, APrimitive); // P1 �õ� fn+1 * fn-1
        Int64PolynomialGaloisMul(P2, FN, FN, APrime, APrimitive);
        Int64PolynomialGaloisMul(P2, P2, X1, APrime, APrimitive);     // P2 �õ� x*fn^2
        Int64PolynomialGaloisMul(P2, P2, Y2, APrime, APrimitive);     // P2 �õ� x*fn^2 * Y^2

        Int64PolynomialGaloisSub(MX.Nominator, P2, P1, APrime, APrimitive); // MX �������
      end
      else // K ����ʱ
      begin
        // ����� x ����Ϊ (x*fn^2 - Y^2 * fn+1 * fn-1) / fn^2
        Int64PolynomialGaloisMul(MX.Denominator, FN, FN, APrime, APrimitive);

        Int64PolynomialGaloisMul(P1, FNa1, FNs1, APrime, APrimitive); // P1 �õ� fn+1 * fn-1
        Int64PolynomialGaloisMul(P1, P1, Y2, APrime, APrimitive);     // P1 �õ� Y^2 * fn+1 * fn-1

        Int64PolynomialGaloisMul(P2, FN, FN, APrime, APrimitive);
        Int64PolynomialGaloisMul(P2, P2, X1, APrime, APrimitive);     // P2 �õ� x*fn^2
        Int64PolynomialGaloisSub(MX.Nominator, P2, P1, APrime, APrimitive); // MX �������
      end;
    finally
      FEccInt64PolynomialPool.Recycle(X1);
      FEccInt64PolynomialPool.Recycle(Y2);
      FEccInt64PolynomialPool.Recycle(P1);
      FEccInt64PolynomialPool.Recycle(P2);
    end;

    if APrimitive <> nil then
    begin
      Int64PolynomialGaloisMod(MX.Nominator, MX.Nominator, APrimitive, APrime);
      Int64PolynomialGaloisMod(MX.Denominator, MX.Denominator, APrimitive, APrime);
    end;
  end;

  Int64RationalPolynomialGaloisCompose(Res, MX, PX, APrime, APrimitive);
  FEccInt64RationalPolynomialPool.Recycle(MX);

  if APrimitive <> nil then
  begin
    Int64PolynomialGaloisMod(Res.Nominator, Res.Nominator, APrimitive, APrime);
    Int64PolynomialGaloisMod(Res.Denominator, Res.Denominator, APrimitive, APrime);
  end;
end;

// �ÿɳ�����ʽֱ���㵽 K �α�������꣬ԭ�����£�
// (x, y) * K �ÿɳ�����ʽ������Ľ������д�� (F(x), G(x) * y)
// ��ô (f(x), g(x) * y) * K �ÿɳ�����ʽ������Ľ�����Դ���д��(F(f(x))��G(f(x)) * g(x) * y)
// ���������� G(f(x)) * g(x)
procedure Int64RationalMultiplePointY(Res, PX, PY: TCnInt64RationalPolynomial; K: Integer;
  A, B, APrime: Int64; DivisionPolynomialList: TObjectList; APrimitive: TCnInt64Polynomial);
var
  Neg: Boolean;
  MY: TCnInt64RationalPolynomial;
  FN, FNa1, FNa2, FNs1, FNs2, P1, P2, X1, Y2: TCnInt64Polynomial;
begin
  if K = 0 then
  begin
    Res.SetZero;
    Exit;
  end;

  Neg := K < 0;
  if K < 0 then
    K := -K;

  MY := FEccInt64RationalPolynomialPool.Obtain;
  if K = 1 then // û�ˣ�ԭ�ⲻ������ x �� 1
  begin
    MY.Nominator.SetOne;
    MY.Denominator.SetOne;
  end
  else
  begin
    X1 := FEccInt64PolynomialPool.Obtain;
    Y2 := FEccInt64PolynomialPool.Obtain;
    P1 := FEccInt64PolynomialPool.Obtain;
    P2 := FEccInt64PolynomialPool.Obtain;

    try
      X1.SetCoefficents([0, 1]);
      Y2.SetCoefficents([B, A, 0, 1]);

      FN := TCnInt64Polynomial(DivisionPolynomialList[K]);
      FNa1 := TCnInt64Polynomial(DivisionPolynomialList[K + 1]);
      FNa2 := TCnInt64Polynomial(DivisionPolynomialList[K + 2]);
      FNs1 := TCnInt64Polynomial(DivisionPolynomialList[K - 1]);
      FNs2 := TCnInt64Polynomial(DivisionPolynomialList[K - 2]);

      if K = 2 then // Y �ķ����� f2n��n Ϊ 2 ʱ����ݹ飬ֱ���� f4
      begin
        MY.Denominator.SetOne;
        Int64PolynomialCopy(MY.Nominator, FNa2);
      end
      else
      begin
        // ����� y �������Ϊ fn+2 * fn-1^2 - fn-2 * fn+1 ^2
        Int64PolynomialGaloisMul(P1, FNs1, FNs1, APrime, APrimitive);
        Int64PolynomialGaloisMul(P1, P1, FNa2, APrime, APrimitive);
        Int64PolynomialGaloisMul(P2, FNa1, FNa1, APrime, APrimitive);
        Int64PolynomialGaloisMul(P2, P2, FNs2, APrime, APrimitive);

        Int64PolynomialGaloisSub(MY.Nominator, P1, P2, APrime, APrimitive); // MY ���Ӽ������
      end;

      Int64PolynomialGaloisPower(MY.Denominator, FN, 3, APrime, APrimitive);
      Int64PolynomialGaloisMulWord(MY.Denominator, 4, APrime);   // ������ĸ 4 * fn^3 �������

      if (K and 1) = 0 then // ż����ĸ���ó��� y^4
      begin
        Int64PolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime, APrimitive);
        Int64PolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime, APrimitive);
      end;
    finally
      FEccInt64PolynomialPool.Recycle(X1);
      FEccInt64PolynomialPool.Recycle(Y2);
      FEccInt64PolynomialPool.Recycle(P1);
      FEccInt64PolynomialPool.Recycle(P2);
    end;
  end;

  if Neg then
    MY.Neg;

  if APrimitive <> nil then
  begin
    Int64PolynomialGaloisMod(MY.Nominator, MY.Nominator, APrimitive, APrime);
    Int64PolynomialGaloisMod(MY.Denominator, MY.Denominator, APrimitive, APrime);
  end;

  Int64RationalPolynomialGaloisCompose(Res, MY, PX, APrime, APrimitive);
  Int64RationalPolynomialGaloisMul(Res, PY, Res, APrime);
  FEccInt64RationalPolynomialPool.Recycle(MY);

  if APrimitive <> nil then
  begin
    Int64PolynomialGaloisMod(Res.Nominator, Res.Nominator, APrimitive, APrime);
    Int64PolynomialGaloisMod(Res.Denominator, Res.Denominator, APrimitive, APrime);
  end;
end;

function CnInt64EccSchoof(A, B, Q: Int64): Int64;
var
  Pa, Ta: TCnInt64List;
  QMul, QMax, L, K, W: Int64;
  I, J: Integer;
  Q2Lo, Q2Hi: TUInt64;
  F, G, Y2, P1, P2, LDP: TCnInt64Polynomial;
  Pi2PX, Pi2PY, PiPX, PiPY, KPX, KPY, LSX, LSY, RSX, RSY, TSX, TSY: TCnInt64RationalPolynomial;
  DPs: TObjectList;
begin
  // �� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�����
  // �Ƚ��� List��������� 2 ~ lmax ������������ 3 * ... * lmax �պ� > 4 ������ q
  // �� x^q -x �� x^3 + Ax + B �Ĺ���ʽ������� 1 �� t2 = 1������ t2 = 0��
  // ���� t2 �� List ��������� 2 ��Ԫ�أ������±꣬����ͬ

  Pa := nil;
  Ta := nil;

  Y2 := FEccInt64PolynomialPool.Obtain;
  P1 := FEccInt64PolynomialPool.Obtain;
  P2 := FEccInt64PolynomialPool.Obtain;

  F := FEccInt64PolynomialPool.Obtain;
  G := FEccInt64PolynomialPool.Obtain;

  QMax := 4 * (UInt64Sqrt(Q) + 1);
  QMul := 1;
  I := Low(CN_PRIME_NUMBERS_SQRT_UINT32);

  DPs := nil;
  Pi2PX := FEccInt64RationalPolynomialPool.Obtain;
  Pi2PY := FEccInt64RationalPolynomialPool.Obtain;
  PiPX := FEccInt64RationalPolynomialPool.Obtain;
  PiPY := FEccInt64RationalPolynomialPool.Obtain;
  KPX := FEccInt64RationalPolynomialPool.Obtain;
  KPY := FEccInt64RationalPolynomialPool.Obtain;
  LSX := FEccInt64RationalPolynomialPool.Obtain;
  LSY := FEccInt64RationalPolynomialPool.Obtain;
  RSX := FEccInt64RationalPolynomialPool.Obtain;
  RSY := FEccInt64RationalPolynomialPool.Obtain;
  TSX := FEccInt64RationalPolynomialPool.Obtain;
  TSY := FEccInt64RationalPolynomialPool.Obtain;

  try
    Pa := TCnInt64List.Create;
    Ta := TCnInt64List.Create;

    while (QMul <= QMax) and (I <= High(CN_PRIME_NUMBERS_SQRT_UINT32)) do
    begin
      QMul := QMul * CN_PRIME_NUMBERS_SQRT_UINT32[I];
      Pa.Add(CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Ta.Add(0);
      Inc(I);
    end;

    if I > High(CN_PRIME_NUMBERS_SQRT_UINT32) then
      raise ECnEccException.Create('Prime Number is Too Large.');

    Y2.SetCoefficents([B, A, 0, 1]);

    // Ta �� Pa ������׼���ã��ȴ��� t = 2 �����
    P1.SetCoefficents([0, 1]); // P1 := X
    Int64PolynomialGaloisPower(P1, P1, Q, Q, Y2); // X^q �� mod Y^2

    P2.SetCoefficents([0, 1]); // P2 := X
    Int64PolynomialGaloisSub(P1, P1, P2, Q); // P1 := (X^q mod Y^2) - x

    // �����Լʽ
    Int64PolynomialGaloisGreatestCommonDivisor(G, P1, Y2, Q);

    if G.IsOne then
      Ta[0] := 1
    else
      Ta[0] := 0;   // ��� T2������˲��һ��������

    // ��ǰ���������� + 2 �׵Ŀɳ�����ʽ���Լ�׼���� Y^2
    DPs := TObjectList.Create(True);
    CnInt64GenerateGaloisDivisionPolynomials(A, B, Q, Pa[Pa.Count - 1] + 2, DPs);

    for I := 1 to Ta.Count - 1 do  // ���ÿһ�� L
    begin
      L := Pa[I];
      K := Q mod L;

      // �ȵõ� L �׿ɳ�����ʽ����Ϊ���������ģ����ʽ
      LDP := TCnInt64Polynomial(DPs[L]);

      Pi2PX.SetOne;                           // ԭʼ��
      Pi2PX.Nominator.SetCoefficents([0, 1]); // x
      Pi2PY.Setone;                           // 1 * y

      // ��� ��^2 �� X ������ LDP ���ڵı���ʽ��Ҳ���� Q*Q �� x ����� mod LDP
      Int64PolynomialGaloisPower(Pi2PX.Nominator, Pi2PX.Nominator, Q, Q, LDP);
      Int64PolynomialGaloisPower(Pi2PX.Nominator, Pi2PX.Nominator, Q, Q, LDP);  // ֱ�� Q*Q ����������ֲ���

      // ��� ��^2 �� Y ������ LDP ���ڵı���ʽ��Q*Q �� y ��˵��� y * [(Q*Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
      UInt64MulUInt64(Q, Q, Q2Lo, Q2Hi);
      if Q2Hi = 0 then
        Int64PolynomialGaloisPower(Pi2PY.Nominator, Y2, (Q * Q) shr 1, Q, LDP)
      else
      begin
        // ���� (Q * Q) > UInt64 �����Σ�����������
        Q2Lo := Q2Lo shr 1;
        if (Q2Hi and 1) <> 0 then
          Q2Lo := Q2Lo or $8000000000000000;
        Q2Hi := Q2Hi shr 1;

        Int64PolynomialGaloisPower(Pi2PY.Nominator, Y2, Q2Lo, Q, LDP, Q2Hi);
      end;

      KPX.SetOne;                             // ԭʼ��
      KPX.Nominator.SetCoefficents([0, 1]);   // x
      KPY.SetOne;                             // 1 * y

      // ��� K * P �� X Y ����
      TCnInt64PolynomialEcc.RationalMultiplePoint(K, KPX, KPY, A, B, Q, LDP);

      PiPX.SetOne;                            // ԭʼ��
      PiPX.Nominator.SetCoefficents([0, 1]);  // x
      PiPY.Setone;                            // 1 * y

      // �� ��^2(P) + K * (P) �ĺ͵� SX SY
      TCnInt64PolynomialEcc.RationalPointAddPoint(Pi2PX, Pi2PY, KPX, KPY, LSX, LSY, A, B, Q, LDP);

      if LSX.IsZero and LSY.IsZero then  // ����͵�Ϊ 0�����ʾ t * �н������ 0��t ��Ȼ���� 0
        Ta[I] := 0
      else
      begin
        // ��� �е� X ������ LDP ���ڵı���ʽ��Ҳ���� Q �� x ����� mod LDP
        Int64PolynomialGaloisPower(PiPX.Nominator, PiPX.Nominator, Q, Q, LDP);

        // ��� �е� Y ������ LDP ���ڵı���ʽ��Q �� y ��˵��� y * [(Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
        Int64PolynomialGaloisPower(PiPY.Nominator, Y2, Q shr 1, Q, LDP);

        Int64RationalPolynomialCopy(RSX, PiPX);
        Int64RationalPolynomialCopy(RSY, PiPY);
        for J := 1 to (L + 1) shr 1 do
        begin
          // ��������ֱ���ÿɳ�����ʽ���� RSX := J * (PiPX, PiPY) �� X�����ƺ�����ȵ�����������õ��
          // Int64RationalMultiplePointX(RSX, PiPX, J, A, B, Q, DPs, LDP);

          if Int64RationalPolynomialGaloisEqual(LSX, RSX, Q, LDP) then
          begin
            // ��������ֱ���ÿɳ�����ʽ���� RSY := J * (PiPX, PiPY) �� Y�����ƺ�����ȵ�����������õ��
            // Int64RationalMultiplePointY(RSY, PiPX, PiPY, J, A, B, Q, DPs, LDP);

            if Int64RationalPolynomialGaloisEqual(LSY, RSY, Q, LDP) then
              Ta[I] := J
            else
              Ta[I] := L - J;
            Break;
          end;

          // ��������ֱ���ÿɳ�����ʽ���㣬���ڴ˴�������ӣ���ǰ�߽������������ǵ��
          TCnInt64PolynomialEcc.RationalPointAddPoint(RSX, RSY, PiPX, PiPY, TSX, TSY, A, B, Q, LDP);
          Int64RationalPolynomialCopy(RSX, TSX);
          Int64RationalPolynomialCopy(RSY, TSY);
        end;
      end;
    end;

    // ����������������й�ʣ�ඨ�������ս�
    L := ChineseRemainderTheoremInt64(Ta, Pa); // ���� L W K �ȱ���

    // ע������� T �������� Hasse ����T �ľ���ֵ <= 2 * ���� Q���糬����Χ����������
    K := UInt64Sqrt(TUInt64(Q)) * 2 + 1;
    if (L <= -K) or (L >= K) then
    begin
      // �й�ʣ�ඨ�������һ������С��������Ҫ��ȥȫ�� Pa �ĳ˻�
      W := 1;
      for J := 0 to Pa.Count - 1 do
        W := W * Pa[J];

      if L <= -K then
        L := L + W
      else
        L := L - W;
    end;

    Result := Q + 1 - L;
  finally
    FEccInt64PolynomialPool.Recycle(Y2);
    FEccInt64PolynomialPool.Recycle(P1);
    FEccInt64PolynomialPool.Recycle(P2);

    FEccInt64PolynomialPool.Recycle(G);
    FEccInt64PolynomialPool.Recycle(F);

    FEccInt64RationalPolynomialPool.Recycle(Pi2PX);
    FEccInt64RationalPolynomialPool.Recycle(Pi2PY);
    FEccInt64RationalPolynomialPool.Recycle(PiPX);
    FEccInt64RationalPolynomialPool.Recycle(PiPY);
    FEccInt64RationalPolynomialPool.Recycle(KPX);
    FEccInt64RationalPolynomialPool.Recycle(KPY);
    FEccInt64RationalPolynomialPool.Recycle(LSX);
    FEccInt64RationalPolynomialPool.Recycle(LSY);
    FEccInt64RationalPolynomialPool.Recycle(RSX);
    FEccInt64RationalPolynomialPool.Recycle(RSY);
    FEccInt64RationalPolynomialPool.Recycle(TSX);
    FEccInt64RationalPolynomialPool.Recycle(TSY);

    DPs.Free;
    Pa.Free;
    Ta.Free;
  end;
end;

{ TCnPolynomialEccPoint }

procedure TCnPolynomialEccPoint.Assign(Source: TPersistent);
begin
  if Source is TCnPolynomialEccPoint then
  begin
    BigNumberPolynomialCopy(FX, (Source as TCnPolynomialEccPoint).X);
    BigNumberPolynomialCopy(FY, (Source as TCnPolynomialEccPoint).Y);
  end
  else
    inherited;
end;

constructor TCnPolynomialEccPoint.Create;
begin
  inherited;
  FX := TCnBigNumberPolynomial.Create;
  FY := TCnBigNumberPolynomial.Create;
end;

constructor TCnPolynomialEccPoint.Create(const XLowToHighCoefficients,
  YLowToHighCoefficients: array of const);
begin
  Create;
  FX.SetCoefficents(XLowToHighCoefficients);
  FY.SetCoefficents(YLowToHighCoefficients);
end;

destructor TCnPolynomialEccPoint.Destroy;
begin
  FY.Free;
  FX.Free;
  inherited;
end;

function TCnPolynomialEccPoint.IsZero: Boolean;
begin
  Result := FX.IsZero and FY.IsZero;
end;

procedure TCnPolynomialEccPoint.SetX(const Value: TCnBigNumberPolynomial);
begin
  if Value <> nil then
    BigNumberPolynomialCopy(FX, Value);
end;

procedure TCnPolynomialEccPoint.SetY(const Value: TCnBigNumberPolynomial);
begin
  if Value <> nil then
    BigNumberPolynomialCopy(FY, Value);
end;

procedure TCnPolynomialEccPoint.SetZero;
begin
  FX.SetZero;
  FY.SetZero;
end;

function TCnPolynomialEccPoint.ToString: string;
begin
  Result := CnPolynomialEccPointToString(Self);
end;

{ TCnPolynomialEcc }

constructor TCnPolynomialEcc.Create(A, B, FieldPrime: TCnBigNumber;
  Ext: Integer; GX, GY: TCnBigNumberPolynomial; AnOrder: TCnBigNumber;
  PrimitivePolynomial: TCnBigNumberPolynomial);
begin
  inherited Create;
  if not BigNumberIsProbablyPrime(FieldPrime) then
    raise ECnEccException.Create('Infinite Field must be a Prime Number.');

  // ��������ô��� 1
  if Ext <= 1 then
    raise ECnEccException.Create('Field Extension must > 1.');

  // TODO: Ҫȷ�� 4*a^3+27*b^2 <> 0�������ȷ��

  FGenerator := TCnPolynomialEccPoint.Create;
  FCoefficientB := TCnBigNumber.Create;
  FCoefficientA := TCnBigNumber.Create;
  FOrder := TCnBigNumber.Create;
  FFiniteFieldSize := TCnBigNumber.Create;
  FPrimitive := TCnBigNumberPolynomial.Create;

  BigNumberCopy(FCoefficientA, A);
  BigNumberCopy(FCoefficientB, B);
  BigNumberCopy(FOrder, AnOrder);
  BigNumberCopy(FFiniteFieldSize, FieldPrime);

  BigNumberPolynomialCopy(FGenerator.X, GX);
  BigNumberPolynomialCopy(FGenerator.Y, GY);

  FExtension := Ext;
  BigNumberPolynomialCopy(FPrimitive, PrimitivePolynomial);
end;

constructor TCnPolynomialEcc.Create(const A, B, FieldPrime: AnsiString;
  Ext: Integer; GX, GY: TCnBigNumberPolynomial; const Order: AnsiString;
  PrimitivePolynomial: TCnBigNumberPolynomial);
var
  BA, BB, BFP, BO: TCnBigNumber;
begin
  BA := nil;
  BB := nil;
  BFP := nil;
  BO := nil;

  try
    BA := FEccBigNumberPool.Obtain;
    BB := FEccBigNumberPool.Obtain;
    BFP := FEccBigNumberPool.Obtain;
    BO := FEccBigNumberPool.Obtain;

    BA.SetHex(A);
    BB.SetHex(B);
    BFP.SetHex(FieldPrime);
    BO.SetHex(Order);

    Create(BA, BB, BFP, Ext, GX, GY, BO, PrimitivePolynomial);
  finally
    FEccBigNumberPool.Recycle(BO);
    FEccBigNumberPool.Recycle(BB);
    FEccBigNumberPool.Recycle(BFP);
    FEccBigNumberPool.Recycle(BA);
  end;
end;

destructor TCnPolynomialEcc.Destroy;
begin
  FPrimitive.Free;
  FGenerator.Free;
  FCoefficientB.Free;
  FCoefficientA.Free;
  FOrder.Free;
  FFiniteFieldSize.Free;
  inherited;
end;

function TCnPolynomialEcc.DivisionPolynomial(Degree: Integer;
  outDivisionPolynomial: TCnBigNumberPolynomial): Boolean;
begin
  Result := BigNumberPolynomialGaloisCalcDivisionPolynomial(FCoefficientA, FCoefficientB,
    Degree, outDivisionPolynomial, FFiniteFieldSize);
end;

function TCnPolynomialEcc.IsPointOnCurve(P: TCnPolynomialEccPoint): Boolean;
var
  X, Y: TCnBigNumberPolynomial;
begin
  // ���� (Y^2 - X^3 - A*X - B) mod primitive ������ʽϵ������Ҫ mod p���Ƿ���� 0 ����ʽ
  Result := False;
  if P = nil then
    Exit;

  X := nil;
  Y := nil;

  try
    X := FEccPolynomialPool.Obtain;
    Y := FEccPolynomialPool.Obtain;

    BigNumberPolynomialCopy(Y, P.Y);
    BigNumberPolynomialGaloisMul(Y, Y, Y, FFiniteFieldSize, FPrimitive);

    BigNumberPolynomialCopy(X, P.X);
    BigNumberPolynomialGaloisPower(X, X, 3, FFiniteFieldSize, FPrimitive);

    BigNumberPolynomialGaloisSub(Y, Y, X, FFiniteFieldSize, FPrimitive);   // Y := Y^2 - X^3 mod

    BigNumberPolynomialCopy(X, P.X);
    BigNumberPolynomialMulBigNumber(X, FCoefficientA);
    BigNumberPolynomialAddBigNumber(X, FCoefficientB);
    BigNumberPolynomialNonNegativeModBigNumber(X, FFiniteFieldSize);  // X := A*X + B  mod

    BigNumberPolynomialGaloisSub(Y, Y, X, FFiniteFieldSize, FPrimitive);
    BigNumberPolynomialGaloisMod(Y, Y, FPrimitive, FFiniteFieldSize);

    Result := Y.IsZero;
  finally
    FEccPolynomialPool.Recycle(Y);
    FEccPolynomialPool.Recycle(X);
  end;
end;

class function TCnPolynomialEcc.IsPointOnCurve2(PX,
  PY: TCnBigNumberPolynomial; A, B, APrime: TCnBigNumber;
  APrimitive: TCnBigNumberPolynomial): Boolean;
var
  X, Y: TCnBigNumberPolynomial;
begin
  // ���� (Y^2 - X^3 - A*X - B) mod primitive ������ʽϵ������Ҫ mod p���Ƿ���� 0 ����ʽ
  X := nil;
  Y := nil;

  try
    X := FEccPolynomialPool.Obtain;
    Y := FEccPolynomialPool.Obtain;

    BigNumberPolynomialCopy(Y, PY);
    BigNumberPolynomialGaloisMul(Y, Y, Y, APrime, APrimitive);

    BigNumberPolynomialCopy(X, PX);
    BigNumberPolynomialGaloisPower(X, X, 3, APrime, APrimitive);

    BigNumberPolynomialGaloisSub(Y, Y, X, APrime, APrimitive);  // Y := Y^2 - X^3 mod

    BigNumberPolynomialCopy(X, PX);
    BigNumberPolynomialMulBigNumber(X, A);
    BigNumberPolynomialAddBigNumber(X, B);
    BigNumberPolynomialNonNegativeModBigNumber(X, APrime); // X := A*X + B mod

    BigNumberPolynomialGaloisSub(Y, Y, X, APrime, APrimitive);
    BigNumberPolynomialGaloisMod(Y, Y, APrimitive, APrime);

    Result := Y.IsZero;
  finally
    FEccPolynomialPool.Recycle(Y);
    FEccPolynomialPool.Recycle(X);
  end;
end;

class function TCnPolynomialEcc.IsRationalPointOnCurve(PX,
  PY: TCnBigNumberRationalPolynomial; A, B, APrime: TCnBigNumber): Boolean;
var
  Y2, T1: TCnBigNumberPolynomial;
  RL, RR, T2: TCnBigNumberRationalPolynomial;
begin
  // ���� PY^2 * (x^3 + Ax + B) �Ƿ���� PX^3 + A * PX + B��ϵ���� mod APrime
  Y2 := nil;
  T1 := nil;
  T2 := nil;
  RL := nil;
  RR := nil;

  try
    Y2 := FEccPolynomialPool.Obtain;
    Y2.SetCoefficents([B, A, 0, 1]);

    RL := FEccRationalPolynomialPool.Obtain;
    BigNumberRationalPolynomialGaloisMul(PY, PY, RL, APrime);
    BigNumberRationalPolynomialGaloisMul(RL, Y2, RL, APrime);  // �õ��Ⱥ���ߵ�ֵ

    RR := FEccRationalPolynomialPool.Obtain;
    BigNumberRationalPolynomialGaloisMul(PX, PX, RR, APrime);
    BigNumberRationalPolynomialGaloisMul(RR, PX, RR, APrime);  // �õ� PX^3

    T1 := FEccPolynomialPool.Obtain;
    T1.SetCoefficents([A]);

    T2 := FEccRationalPolynomialPool.Obtain;
    BigNumberRationalPolynomialGaloisMul(PX, T1, T2, APrime);  // T2 �õ� A * PX

    T1.SetCoefficents([B]);
    BigNumberRationalPolynomialGaloisAdd(T2, T1, T2, APrime);  // T2 �õ� A * PX + B

    BigNumberRationalPolynomialGaloisAdd(T2, RR, RR, APrime);  // RR �õ� PX^3 + A * PX + B

    Result := BigNumberRationalPolynomialGaloisEqual(RL, RR, APrime);       // �Ƚ��Ƿ����
  finally
    FEccPolynomialPool.Recycle(Y2);
    FEccPolynomialPool.Recycle(T1);
    FEccRationalPolynomialPool.Recycle(T2);
    FEccRationalPolynomialPool.Recycle(RL);
    FEccRationalPolynomialPool.Recycle(RR);
  end;
end;

procedure TCnPolynomialEcc.MultiplePoint(K: TCnBigNumber;
  Point: TCnPolynomialEccPoint);
var
  I, C: Integer;
  E, R: TCnPolynomialEccPoint;
begin
  if K.IsZero then
  begin
    Point.SetZero;
    Exit;
  end
  else if K.IsNegative then
  begin
    K.Negate;
    PointInverse(Point);
  end;

  R := nil;
  E := nil;

  try
    R := TCnPolynomialEccPoint.Create;
    E := TCnPolynomialEccPoint.Create;

    R.SetZero;
    E.Assign(Point);

    C := BigNumberGetBitsCount(K);
    for I := 0 to C - 1 do
    begin
      if BigNumberIsBitSet(K, I) then
        PointAddPoint(R, E, R);

      if I < C - 1 then
        PointAddPoint(E, E, E);
    end;

    Point.Assign(R);
  finally
    R.Free;
    E.Free;
  end;
end;

procedure TCnPolynomialEcc.MultiplePoint(K: Int64;
  Point: TCnPolynomialEccPoint);
var
  BK: TCnBigNumber;
begin
  BK := FEccBigNumberPool.Obtain;
  try
    BK.SetInt64(K);
    MultiplePoint(BK, Point);
  finally
    FEccBigNumberPool.Recycle(BK);
  end;
end;

procedure TCnPolynomialEcc.PointAddPoint(P, Q, Sum: TCnPolynomialEccPoint);
var
  K, X, Y, T: TCnBigNumberPolynomial;
begin
  K := nil;
  X := nil;
  Y := nil;
  T := nil;

  try
    if P.IsZero then
    begin
      Sum.Assign(Q);
      Exit;
    end
    else if Q.IsZero then
    begin
      Sum.Assign(P);
      Exit;
    end
    else if BigNumberPolynomialEqual(P.X, Q.X) and BigNumberPolynomialEqual(P.Y, Q.Y) then
    begin
      // ��������ͬһ���㣬����б��Ϊ�����󵼣�3 * X^2 + A / (2 * Y) ���� Y = 0 ��ֱ��������Զ 0��
      X := FEccPolynomialPool.Obtain;
      Y := FEccPolynomialPool.Obtain;

      // X := 3 * P.X * P.X + FCoefficientA
      BigNumberPolynomialGaloisMul(X, P.X, P.X, FFiniteFieldSize, FPrimitive);
      BigNumberPolynomialGaloisMulWord(X, 3, FFiniteFieldSize);
      BigNumberPolynomialGaloisAddBigNumber(X, FCoefficientA, FFiniteFieldSize);

      // Y := 2 * P.Y;
      BigNumberPolynomialCopy(Y, P.Y);
      BigNumberPolynomialGaloisMulWord(Y, 2, FFiniteFieldSize);

      if Y.IsZero then
      begin
        Sum.X.SetZero;
        Sum.Y.SetZero;
      end;

      // Y := Y^-1
      T := FEccPolynomialPool.Obtain;
      BigNumberPolynomialCopy(T, Y);
      BigNumberPolynomialGaloisModularInverse(Y, T, FPrimitive, FFiniteFieldSize);

      // K := X * Y mod FFiniteFieldSize;
      K := FEccPolynomialPool.Obtain;
      BigNumberPolynomialGaloisMul(K, X, Y, FFiniteFieldSize, FPrimitive);
      // �õ�����б�� K
    end
    else // �ǲ�ͬ��
    begin
      if BigNumberPolynomialEqual(P.X, Q.X) then // ��� X ��ȣ�Ҫ�ж� Y �ǲ��ǻ����������Ϊ 0�����������
      begin
        T := FEccPolynomialPool.Obtain;
        BigNumberPolynomialGaloisAdd(T, P.Y, Q.Y, FFiniteFieldSize);
        if T.IsZero then
          Sum.SetZero
        else
          raise ECnEccException.CreateFmt('Can NOT Calucate %s,%s + %s,%s',
            [P.X.ToString, P.Y.ToString, Q.X.ToString, Q.Y.ToString]);

        Exit;
      end;

      // �����X ȷ����ͬ��б�� K := ((Q.Y - P.Y) / (Q.X - P.X)) mod p
      X := FEccPolynomialPool.Obtain;
      Y := FEccPolynomialPool.Obtain;
      K := FEccPolynomialPool.Obtain;

      BigNumberPolynomialGaloisSub(Y, Q.Y, P.Y, FFiniteFieldSize);
      BigNumberPolynomialGaloisSub(X, Q.X, P.X, FFiniteFieldSize);

      T := FEccPolynomialPool.Obtain;
      BigNumberPolynomialCopy(T, X);
      BigNumberPolynomialGaloisModularInverse(X, T, FPrimitive, FFiniteFieldSize);
      BigNumberPolynomialGaloisMul(K, Y, X, FFiniteFieldSize, FPrimitive); // �õ�б��
    end;

    //  X := K * K - P.X - Q.X;
    BigNumberPolynomialCopy(X, K);
    BigNumberPolynomialGaloisMul(X, X, K, FFiniteFieldSize, FPrimitive);
    BigNumberPolynomialGaloisSub(X, X, P.X, FFiniteFieldSize);
    BigNumberPolynomialGaloisSub(X, X, Q.X, FFiniteFieldSize);

    // Ysum = (K * (X1 - Xsum) - Y1) mod p
    BigNumberPolynomialGaloisSub(X, P.X, X, FFiniteFieldSize);
    BigNumberPolynomialGaloisMul(Y, K, X, FFiniteFieldSize, FPrimitive);
    BigNumberPolynomialGaloisSub(Y, Y, P.Y, FFiniteFieldSize);

    BigNumberPolynomialCopy(Sum.X, X);
    BigNumberPolynomialCopy(Sum.Y, Y);
  finally
    FEccPolynomialPool.Recycle(K);
    FEccPolynomialPool.Recycle(X);
    FEccPolynomialPool.Recycle(Y);
    FEccPolynomialPool.Recycle(T);
  end;
end;

procedure TCnPolynomialEcc.PointInverse(P: TCnPolynomialEccPoint);
var
  I: Integer;
begin
  for I := 0 to P.Y.MaxDegree do
    BigNumberSub(P.Y[I], FFiniteFieldSize, P.Y[I]);
end;

procedure TCnPolynomialEcc.PointSubPoint(P, Q,
  Diff: TCnPolynomialEccPoint);
var
  Inv: TCnPolynomialEccPoint;
begin
  Inv := TCnPolynomialEccPoint.Create;
  try
    Inv.Assign(Q);
    PointInverse(Inv);
    PointAddPoint(P, Inv, Diff);
  finally
    Inv.Free;
  end;
end;

class procedure TCnPolynomialEcc.RationalMultiplePoint(K: Integer; MX,
  MY: TCnBigNumberRationalPolynomial; A, B, APrime: TCnBigNumber;
  APrimitive: TCnBigNumberPolynomial);
var
  Neg: Boolean;
  FN, FNa1, FNa2, FNs1, FNs2, P1, P2, X1, Y2: TCnBigNumberPolynomial;
begin
  if K = 0 then
  begin
    MX.SetZero;
    MY.SetZero;
    Exit;
  end;

  Neg := K < 0;
  if Neg then
    K := -K;

  if K = 1 then // û�ˣ�ԭ�ⲻ������ MX �� MY�������Ķ�
  begin
//    MX.Nominator.SetCoefficents([0, 1]);
//    MX.Denominator.SetOne;
//
//    MY.Nominator.SetOne;
//    MY.Denominator.SetOne;
  end
  else
  begin
    FN := FEccPolynomialPool.Obtain;
    FNa1 := FEccPolynomialPool.Obtain;
    FNa2 := FEccPolynomialPool.Obtain;
    FNs1 := FEccPolynomialPool.Obtain;
    FNs2 := FEccPolynomialPool.Obtain;
    X1 := FEccPolynomialPool.Obtain;
    Y2 := FEccPolynomialPool.Obtain;
    P1 := FEccPolynomialPool.Obtain;
    P2 := FEccPolynomialPool.Obtain;

    try
      X1.SetCoefficents([0, 1]);
      Y2.SetCoefficents([B, A, 0, 1]);

      BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, K, FN, APrime);
      BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, K + 1, FNa1, APrime);
      BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, K + 2, FNa2, APrime);
      BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, K - 1, FNs1, APrime);
      BigNumberPolynomialGaloisCalcDivisionPolynomial(A, B, K - 2, FNs2, APrime);

      // �� X ���ʽ
      if (K and 1) = 0 then // K ż��ʱ
      begin
        // ����� x ����Ϊ (x*fn^2 * Y^2 - fn+1 * fn-1) / fn^2 * Y^2
        BigNumberPolynomialGaloisMul(MX.Denominator, FN, FN, APrime);
        BigNumberPolynomialGaloisMul(MX.Denominator, MX.Denominator, Y2, APrime);

        BigNumberPolynomialGaloisMul(P1, FNa1, FNs1, APrime); // P1 �õ� fn+1 * fn-1
        BigNumberPolynomialGaloisMul(P2, FN, FN, APrime);
        BigNumberPolynomialGaloisMul(P2, P2, X1, APrime);     // P2 �õ� x*fn^2
        BigNumberPolynomialGaloisMul(P2, P2, Y2, APrime);     // P2 �õ� x*fn^2 * Y^2

        BigNumberPolynomialGaloisSub(MX.Nominator, P2, P1, APrime); // MX �������
      end
      else // K ����ʱ
      begin
        // ����� x ����Ϊ (x*fn^2 - Y^2 * fn+1 * fn-1) / fn^2
        BigNumberPolynomialGaloisMul(MX.Denominator, FN, FN, APrime);

        BigNumberPolynomialGaloisMul(P1, FNa1, FNs1, APrime); // P1 �õ� fn+1 * fn-1
        BigNumberPolynomialGaloisMul(P1, P1, Y2, APrime);     // P1 �õ� Y^2 * fn+1 * fn-1

        BigNumberPolynomialGaloisMul(P2, FN, FN, APrime);
        BigNumberPolynomialGaloisMul(P2, P2, X1, APrime);     // P2 �õ� x*fn^2
        BigNumberPolynomialGaloisSub(MX.Nominator, P2, P1, APrime); // MX �������
      end;

      // �� Y ���ʽ
      if K = 2 then // Y �ķ����� f2n��n Ϊ 2 ʱ����ݹ飬ֱ���� f4
      begin
        MY.Denominator.SetOne;
        BigNumberPolynomialCopy(MY.Nominator, FNa2);
      end
      else
      begin
        // ����� y �������Ϊ fn+2 * fn-1^2 - fn-2 * fn+1 ^2
        BigNumberPolynomialGaloisMul(P1, FNs1, FNs1, APrime);
        BigNumberPolynomialGaloisMul(P1, P1, FNa2, APrime);
        BigNumberPolynomialGaloisMul(P2, FNa1, FNa1, APrime);
        BigNumberPolynomialGaloisMul(P2, P2, FNs2, APrime);

        BigNumberPolynomialGaloisSub(MY.Nominator, P1, P2, APrime); // MY ���Ӽ������
      end;

      BigNumberPolynomialGaloisPower(MY.Denominator, FN, 3, APrime);
      BigNumberPolynomialGaloisMulWord(MY.Denominator, 4, APrime);   // ������ĸ 4 * fn^3 �������

      if (K and 1) = 0 then // ż����ĸ���ó��� y^4
      begin
        BigNumberPolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime);
        BigNumberPolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime);
      end;
    finally
      FEccPolynomialPool.Recycle(FN);
      FEccPolynomialPool.Recycle(FNa1);
      FEccPolynomialPool.Recycle(FNa2);
      FEccPolynomialPool.Recycle(FNs1);
      FEccPolynomialPool.Recycle(FNs2);
      FEccPolynomialPool.Recycle(X1);
      FEccPolynomialPool.Recycle(Y2);
      FEccPolynomialPool.Recycle(P1);
      FEccPolynomialPool.Recycle(P2);
    end;
  end;

  if Neg then
    MY.Neg;

  if APrimitive <> nil then
  begin
    BigNumberPolynomialGaloisMod(MX.Nominator, MX.Nominator, APrimitive, APrime);
    BigNumberPolynomialGaloisMod(MX.Denominator, MX.Denominator, APrimitive, APrime);
    BigNumberPolynomialGaloisMod(MY.Nominator, MY.Nominator, APrimitive, APrime);
    BigNumberPolynomialGaloisMod(MY.Denominator, MY.Denominator, APrimitive, APrime);
  end;
end;

class procedure TCnPolynomialEcc.RationalPointAddPoint(PX, PY, QX, QY, SX,
  SY: TCnBigNumberRationalPolynomial; A, B, APrime: TCnBigNumber;
  APrimitive: TCnBigNumberPolynomial);
var
  R, T1, T2: TCnBigNumberRationalPolynomial;
  Y2, C: TCnBigNumberPolynomial;
begin
  // �� (PX, PY * y) + (QX, QY * y) = (SX, SY * y)
  // ����б�� R = y * (QY - PY) / (QX - PX) �� (3PX^2 + A) / 2PY * y

  if PX.IsZero and PY.IsZero then
  begin
    BigNumberRationalPolynomialCopy(SX, QX);
    BigNumberRationalPolynomialCopy(SY, QY);
    Exit;
  end
  else if QX.IsZero and QY.IsZero then
  begin
    BigNumberRationalPolynomialCopy(SX, PX);
    BigNumberRationalPolynomialCopy(SY, PY);
    Exit;
  end;

  R := nil;
  T1 := nil;
  T2 := nil;

  Y2 := nil;
  C := nil;

  try
    R := FEccRationalPolynomialPool.Obtain;
    T1 := FEccRationalPolynomialPool.Obtain;
    T2 := FEccRationalPolynomialPool.Obtain;

    Y2 := FEccPolynomialPool.Obtain;
    C := FEccPolynomialPool.Obtain;
    Y2.SetCoefficents([B, A, 0, 1]);

    if BigNumberRationalPolynomialGaloisEqual(PX, QX, APrime, APrimitive) then // ����ֱ���ж���ȣ��û��˺������Ա�ԭ����ʽ��������ж����
    begin
      // X ��ȣ��ж� Y �Ƿ���ȣ���������������෴������ 0
      // TODO: �ж� PY QY �Ƿ��෴
      if not BigNumberRationalPolynomialGaloisEqual(PY, QY, APrime, APrimitive) then
      begin
        SX.SetZero;
        SY.SetZero;
        Exit;
      end;

      // X Y ����ȣ���
      C.SetCoefficents([3]);

      BigNumberRationalPolynomialGaloisMul(PX, PX, T1, APrime);
      BigNumberRationalPolynomialGaloisMul(T1, C, T1, APrime);  // T1 �õ� 3PX^2

      C.SetCoefficents([A]);
      BigNumberRationalPolynomialGaloisAdd(T1, C, T1, APrime);  // T1 �õ� 3PX^2 + A

      C.SetCoefficents([2]);
      BigNumberRationalPolynomialGaloisMul(PY, C, T2, APrime);  // T2 �õ� 2PY��ʵ���ϻ�Ҫ����һ�� y

      BigNumberRationalPolynomialGaloisDiv(T1, T2, R, APrime);  // �õ�б�� R������ʵ��б�ʷ�ĸʵ���ϻ�Ҫ����һ�� y�����油��

      // SX = ��ʵб��^2 - PX - QX = R^2 / (x^3+Ax+B) - PX - QX
      // ��ʵб�ʵ�ƽ�� = R^2 / y^2����ĸ���滻�� x^3+Ax+B
      BigNumberRationalPolynomialGaloisMul(R, R, SX, APrime);
      BigNumberRationalPolynomialGaloisDiv(SX, Y2, SX, APrime);
      BigNumberRationalPolynomialGaloisSub(SX, PX, SX, APrime);
      BigNumberRationalPolynomialGaloisSub(SX, QX, SX, APrime);

      if APrimitive <> nil then
      begin
        BigNumberPolynomialGaloisMod(SX.Nominator, SX.Nominator, APrimitive, APrime);
        BigNumberPolynomialGaloisMod(SX.Denominator, SX.Denominator, APrimitive, APrime);
      end;

      // SY * y = ��ʵб�� * (PX - SX) - PY * y
      // SY = (R/y * (PX - SX) - PY * y) / y = R * (PX - SX)/ y^2 - PY
      BigNumberRationalPolynomialGaloisSub(PX, SX, SY, APrime);
      BigNumberRationalPolynomialGaloisMul(SY, R, SY, APrime);
      BigNumberRationalPolynomialGaloisDiv(SY, Y2, SY, APrime);
      BigNumberRationalPolynomialGaloisSub(SY, PY, SY, APrime);

      if APrimitive <> nil then
      begin
        BigNumberPolynomialGaloisMod(SY.Nominator, SY.Nominator, APrimitive, APrime);
        BigNumberPolynomialGaloisMod(SY.Denominator, SY.Denominator, APrimitive, APrime);
      end;
    end
    else
    begin
      // ����ȣ�������ʵб�ʵ��� y * (QY - PY) / (QX - PX)
      BigNumberRationalPolynomialGaloisSub(QY, PY, T1, APrime);
      BigNumberRationalPolynomialGaloisSub(QX, PX, T2, APrime);
      BigNumberRationalPolynomialGaloisDiv(T1, T2, R, APrime);

      // R �õ�б���ˣ�����ʵ��б�ʷ���ʵ���ϻ�Ҫ����һ�� y�����油��
      // SX = R^2 * (x^3+Ax+B) - PX - QX
      BigNumberRationalPolynomialGaloisMul(R, R, SX, APrime);
      BigNumberRationalPolynomialGaloisMul(SX, Y2, SX, APrime);
      BigNumberRationalPolynomialGaloisSub(SX, PX, SX, APrime);
      BigNumberRationalPolynomialGaloisSub(SX, QX, SX, APrime); // �ⲽ����ˣ�

      if APrimitive <> nil then
      begin
        BigNumberPolynomialGaloisMod(SX.Nominator, SX.Nominator, APrimitive, APrime);
        BigNumberPolynomialGaloisMod(SX.Denominator, SX.Denominator, APrimitive, APrime);
      end;

      // SY * y = R * y * (PX - SX) - PY * y ������ y �� SY = R * (PX - SX) - PY
      BigNumberRationalPolynomialGaloisSub(PX, SX, SY, APrime);
      BigNumberRationalPolynomialGaloisMul(SY, R, SY, APrime);
      BigNumberRationalPolynomialGaloisSub(SY, PY, SY, APrime);

      if APrimitive <> nil then
      begin
        BigNumberPolynomialGaloisMod(SY.Nominator, SY.Nominator, APrimitive, APrime);
        BigNumberPolynomialGaloisMod(SY.Denominator, SY.Denominator, APrimitive, APrime);
      end;
    end;
  finally
    FEccPolynomialPool.Recycle(Y2);
    FEccPolynomialPool.Recycle(C);

    FEccRationalPolynomialPool.Recycle(T2);
    FEccRationalPolynomialPool.Recycle(T1);
    FEccRationalPolynomialPool.Recycle(R);
  end;
end;

procedure TCnPolynomialEcc.SetPrimitive(
  const Value: TCnBigNumberPolynomial);
begin
  if Value <> nil then
  begin
    if Value.MaxDegree <> FExtension then
      raise ECnEccException.Create('Primitive Polynomial Max Degree must be Field Extension.');
    BigNumberPolynomialCopy(FPrimitive, Value);
  end;
end;

procedure RationalMultiplePointX(Res, PX: TCnBigNumberRationalPolynomial; K: Integer;
  A, B, APrime: TCnBigNumber; DivisionPolynomialList: TObjectList; APrimitive: TCnBigNumberPolynomial);
var
  MX: TCnBigNumberRationalPolynomial;
  FN, FNa1, FNs1, P1, P2, X1, Y2: TCnBigNumberPolynomial;
begin
  if K = 0 then
  begin
    Res.SetZero;
    Exit;
  end;

  if K < 0 then
    K := -K;

  MX := FEccRationalPolynomialPool.Obtain;
  if K = 1 then // û�ˣ�ԭ�ⲻ������ x �� 1
  begin
    MX.Nominator.SetCoefficents([0, 1]);
    MX.Denominator.SetOne;
  end
  else
  begin
    X1 := FEccPolynomialPool.Obtain;
    Y2 := FEccPolynomialPool.Obtain;
    P1 := FEccPolynomialPool.Obtain;
    P2 := FEccPolynomialPool.Obtain;

    try
      X1.SetCoefficents([0, 1]);
      Y2.SetCoefficents([B, A, 0, 1]);

      FN := TCnBigNumberPolynomial(DivisionPolynomialList[K]);
      FNa1 := TCnBigNumberPolynomial(DivisionPolynomialList[K + 1]);
      FNs1 := TCnBigNumberPolynomial(DivisionPolynomialList[K - 1]);

      // �� X ���ʽ
      if (K and 1) = 0 then // K ż��ʱ
      begin
        // ����� x ����Ϊ (x*fn^2 * Y^2 - fn+1 * fn-1) / fn^2 * Y^2
        BigNumberPolynomialGaloisMul(MX.Denominator, FN, FN, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(MX.Denominator, MX.Denominator, Y2, APrime, APrimitive);

        BigNumberPolynomialGaloisMul(P1, FNa1, FNs1, APrime, APrimitive); // P1 �õ� fn+1 * fn-1
        BigNumberPolynomialGaloisMul(P2, FN, FN, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(P2, P2, X1, APrime, APrimitive);     // P2 �õ� x*fn^2
        BigNumberPolynomialGaloisMul(P2, P2, Y2, APrime, APrimitive);     // P2 �õ� x*fn^2 * Y^2

        BigNumberPolynomialGaloisSub(MX.Nominator, P2, P1, APrime); // MX �������
      end
      else // K ����ʱ
      begin
        // ����� x ����Ϊ (x*fn^2 - Y^2 * fn+1 * fn-1) / fn^2
        BigNumberPolynomialGaloisMul(MX.Denominator, FN, FN, APrime, APrimitive);

        BigNumberPolynomialGaloisMul(P1, FNa1, FNs1, APrime, APrimitive); // P1 �õ� fn+1 * fn-1
        BigNumberPolynomialGaloisMul(P1, P1, Y2, APrime, APrimitive);     // P1 �õ� Y^2 * fn+1 * fn-1

        BigNumberPolynomialGaloisMul(P2, FN, FN, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(P2, P2, X1, APrime, APrimitive);     // P2 �õ� x*fn^2
        BigNumberPolynomialGaloisSub(MX.Nominator, P2, P1, APrime, APrimitive); // MX �������
      end;
    finally
      FEccPolynomialPool.Recycle(X1);
      FEccPolynomialPool.Recycle(Y2);
      FEccPolynomialPool.Recycle(P1);
      FEccPolynomialPool.Recycle(P2);
    end;

    if APrimitive <> nil then
    begin
      BigNumberPolynomialGaloisMod(MX.Nominator, MX.Nominator, APrimitive, APrime);
      BigNumberPolynomialGaloisMod(MX.Denominator, MX.Denominator, APrimitive, APrime);
    end;
  end;

  BigNumberRationalPolynomialGaloisCompose(Res, MX, PX, APrime, APrimitive);
  FEccRationalPolynomialPool.Recycle(MX);

  if APrimitive <> nil then
  begin
    BigNumberPolynomialGaloisMod(Res.Nominator, Res.Nominator, APrimitive, APrime);
    BigNumberPolynomialGaloisMod(Res.Denominator, Res.Denominator, APrimitive, APrime);
  end;
end;

procedure RationalMultiplePointY(Res, PX, PY: TCnBigNumberRationalPolynomial; K: Integer;
  A, B, APrime: TCnBigNumber; DivisionPolynomialList: TObjectList; APrimitive: TCnBigNumberPolynomial = nil);
var
  Neg: Boolean;
  MY: TCnBigNumberRationalPolynomial;
  FN, FNa1, FNa2, FNs1, FNs2, P1, P2, X1, Y2: TCnBigNumberPolynomial;
begin
  if K = 0 then
  begin
    Res.SetZero;
    Exit;
  end;

  Neg := K < 0;
  if K < 0 then
    K := -K;

  MY := FEccRationalPolynomialPool.Obtain;
  if K = 1 then // û�ˣ�ԭ�ⲻ������ x �� 1
  begin
    MY.Nominator.SetOne;
    MY.Denominator.SetOne;
  end
  else
  begin
    X1 := FEccPolynomialPool.Obtain;
    Y2 := FEccPolynomialPool.Obtain;
    P1 := FEccPolynomialPool.Obtain;
    P2 := FEccPolynomialPool.Obtain;

    try
      X1.SetCoefficents([0, 1]);
      Y2.SetCoefficents([B, A, 0, 1]);

      FN := TCnBigNumberPolynomial(DivisionPolynomialList[K]);
      FNa1 := TCnBigNumberPolynomial(DivisionPolynomialList[K + 1]);
      FNa2 := TCnBigNumberPolynomial(DivisionPolynomialList[K + 2]);
      FNs1 := TCnBigNumberPolynomial(DivisionPolynomialList[K - 1]);
      FNs2 := TCnBigNumberPolynomial(DivisionPolynomialList[K - 2]);

      if K = 2 then // Y �ķ����� f2n��n Ϊ 2 ʱ����ݹ飬ֱ���� f4
      begin
        MY.Denominator.SetOne;
        BigNumberPolynomialCopy(MY.Nominator, FNa2);
      end
      else
      begin
        // ����� y �������Ϊ fn+2 * fn-1^2 - fn-2 * fn+1 ^2
        BigNumberPolynomialGaloisMul(P1, FNs1, FNs1, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(P1, P1, FNa2, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(P2, FNa1, FNa1, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(P2, P2, FNs2, APrime, APrimitive);

        BigNumberPolynomialGaloisSub(MY.Nominator, P1, P2, APrime, APrimitive); // MY ���Ӽ������
      end;

      BigNumberPolynomialGaloisPower(MY.Denominator, FN, 3, APrime, APrimitive);
      BigNumberPolynomialGaloisMulWord(MY.Denominator, 4, APrime);   // ������ĸ 4 * fn^3 �������

      if (K and 1) = 0 then // ż����ĸ���ó��� y^4
      begin
        BigNumberPolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime, APrimitive);
        BigNumberPolynomialGaloisMul(MY.Denominator, Y2, MY.Denominator, APrime, APrimitive);
      end;
    finally
      FEccPolynomialPool.Recycle(X1);
      FEccPolynomialPool.Recycle(Y2);
      FEccPolynomialPool.Recycle(P1);
      FEccPolynomialPool.Recycle(P2);
    end;
  end;

  if Neg then
    MY.Neg;

  if APrimitive <> nil then
  begin
    BigNumberPolynomialGaloisMod(MY.Nominator, MY.Nominator, APrimitive, APrime);
    BigNumberPolynomialGaloisMod(MY.Denominator, MY.Denominator, APrimitive, APrime);
  end;

  BigNumberRationalPolynomialGaloisCompose(Res, MY, PX, APrime, APrimitive);
  BigNumberRationalPolynomialGaloisMul(Res, PY, Res, APrime);
  FEccRationalPolynomialPool.Recycle(MY);

  if APrimitive <> nil then
  begin
    BigNumberPolynomialGaloisMod(Res.Nominator, Res.Nominator, APrimitive, APrime);
    BigNumberPolynomialGaloisMod(Res.Denominator, Res.Denominator, APrimitive, APrime);
  end;
end;

function CnEccSchoof(Res, A, B, Q: TCnBigNumber): Boolean;
var
  Pa, Ta: TCnInt64List;
  QMul, QMax, BQ: TCnBigNumber;
  L, K: Int64;
  I, J: Integer;
  G, Y2, P1, P2, LDP: TCnBigNumberPolynomial;
  Pi2PX, Pi2PY, PiPX, PiPY, KPX, KPY, LSX, LSY, RSX, RSY, TSX, TSY: TCnBigNumberRationalPolynomial;
  DPs: TObjectList;
begin
  // �� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�����
  // �Ƚ��� List��������� 2 ~ lmax ������������ 3 * ... * lmax �պ� > 4 ������ q
  // �� x^q -x �� x^3 + Ax + B �Ĺ���ʽ������� 1 �� t2 = 1������ t2 = 0��
  // ���� t2 �� List ��������� 2 ��Ԫ�أ������±꣬����ͬ

  Result := False;
  if Q.IsZero or Q.IsNegative then
    Exit;

  Pa := nil;
  Ta := nil;
  DPs := nil;
  Pi2PX := nil;
  Pi2PY := nil;
  PiPX := nil;
  PiPY := nil;
  KPX := nil;
  KPY := nil;
  LSX := nil;
  LSY := nil;
  RSX := nil;
  RSY := nil;
  TSX := nil;
  TSY := nil;

  Y2 := nil;
  P1 := nil;
  P2 := nil;

  G := nil;

  QMax := nil;
  QMul := nil;
  BQ := nil;

  try
    Pa := TCnInt64List.Create;
    Ta := TCnInt64List.Create;

    Y2 := FEccPolynomialPool.Obtain;
    P1 := FEccPolynomialPool.Obtain;
    P2 := FEccPolynomialPool.Obtain;

    G := FEccPolynomialPool.Obtain;

    QMax := FEccBigNumberPool.Obtain;
    QMul := FEccBigNumberPool.Obtain;
    BQ := FEccBigNumberPool.Obtain;

    if not BigNumberSqrt(QMax, Q) then
      Exit;

    BigNumberAddWord(QMax, 1);
    BigNumberMulWord(QMax, 4);
    QMul.SetOne;
    I := Low(CN_PRIME_NUMBERS_SQRT_UINT32);

    Pi2PX := FEccRationalPolynomialPool.Obtain;
    Pi2PY := FEccRationalPolynomialPool.Obtain;
    PiPX := FEccRationalPolynomialPool.Obtain;
    PiPY := FEccRationalPolynomialPool.Obtain;
    KPX := FEccRationalPolynomialPool.Obtain;
    KPY := FEccRationalPolynomialPool.Obtain;
    LSX := FEccRationalPolynomialPool.Obtain;
    LSY := FEccRationalPolynomialPool.Obtain;
    RSX := FEccRationalPolynomialPool.Obtain;
    RSY := FEccRationalPolynomialPool.Obtain;
    TSX := FEccRationalPolynomialPool.Obtain;
    TSY := FEccRationalPolynomialPool.Obtain;

    while (BigNumberCompare(QMul, QMax) <= 0) and (I <= High(CN_PRIME_NUMBERS_SQRT_UINT32)) do
    begin
      BigNumberMulWord(QMul, CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Pa.Add(CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Ta.Add(0);
      Inc(I);
    end;

    if I > High(CN_PRIME_NUMBERS_SQRT_UINT32) then
      raise ECnEccException.Create('Prime Number is Too Large.');

    Y2.SetCoefficents([B, A, 0, 1]);

    // Ta �� Pa ������׼���ã��ȴ��� t = 2 �����
    P1.SetCoefficents([0, 1]); // P1 := X
    BigNumberPolynomialGaloisPower(P1, P1, Q, Q, Y2); // X^q �� mod Y^2

    P2.SetCoefficents([0, 1]); // P2 := X
    BigNumberPolynomialGaloisSub(P1, P1, P2, Q); // P1 := (X^q mod Y^2) - x

    // �����Լʽ
    BigNumberPolynomialGaloisGreatestCommonDivisor(G, P1, Y2, Q);

    if G.IsOne then
      Ta[0] := 1
    else
      Ta[0] := 0;   // ��� T2������˲��һ��������

    // ��ǰ���������� + 2 �׵Ŀɳ�����ʽ���Լ�׼���� Y^2
    DPs := TObjectList.Create(True);
    CnGenerateGaloisDivisionPolynomials(A, B, Q, Pa[Pa.Count - 1] + 2, DPs);

    for I := 1 to Ta.Count - 1 do  // ���ÿһ�� L�������� ��^2(P) + K * (P) = J * ��^(P) mod L�׿ɳ�����ʽ
    begin
      L := Pa[I];
      K := BigNumberModWord(Q, L);

      // �ȵõ� L �׿ɳ�����ʽ����Ϊ���������ģ����ʽ
      LDP := TCnBigNumberPolynomial(DPs[L]);

      Pi2PX.SetOne;                           // ԭʼ��
      Pi2PX.Nominator.SetCoefficents([0, 1]); // x
      Pi2PY.Setone;                           // 1 * y

      // ��� ��^2 �� X ������ LDP ���ڵı���ʽ��Ҳ���� Q*Q �� x ����� mod LDP
      BigNumberPolynomialGaloisPower(Pi2PX.Nominator, Pi2PX.Nominator, Q, Q, LDP);
      BigNumberPolynomialGaloisPower(Pi2PX.Nominator, Pi2PX.Nominator, Q, Q, LDP);  // ֱ�� Q*Q ����������ֲ���

      // ��� ��^2 �� Y ������ LDP ���ڵı���ʽ��Q*Q �� y ��˵��� y * [(Q*Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
      BigNumberMul(BQ, Q, Q);
      BigNumberShiftRightOne(BQ, BQ);
      BigNumberPolynomialGaloisPower(Pi2PY.Nominator, Y2, BQ, Q, LDP);

      KPX.SetOne;                             // ԭʼ��
      KPX.Nominator.SetCoefficents([0, 1]);   // x
      KPY.SetOne;                             // 1 * y

      // ��� K * P �� X Y ����
      TCnPolynomialEcc.RationalMultiplePoint(K, KPX, KPY, A, B, Q, LDP);

      PiPX.SetOne;                            // ԭʼ��
      PiPX.Nominator.SetCoefficents([0, 1]);  // x
      PiPY.Setone;                            // 1 * y

      // �� ��^2(P) + K * (P) �ĺ͵� SX SY
      TCnPolynomialEcc.RationalPointAddPoint(Pi2PX, Pi2PY, KPX, KPY, LSX, LSY, A, B, Q, LDP);

      if LSX.IsZero and LSY.IsZero then  // ����͵�Ϊ 0�����ʾ t * �н������ 0��t ��Ȼ���� 0
      begin
        Ta[I] := 0;
      end
      else
      begin
        // ��� �е� X ������ LDP ���ڵı���ʽ��Ҳ���� Q �� x ����� mod LDP
        BigNumberPolynomialGaloisPower(PiPX.Nominator, PiPX.Nominator, Q, Q, LDP);

        // ��� �е� Y ������ LDP ���ڵı���ʽ��Q �� y ��˵��� y * [(Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
        BigNumberShiftRightOne(BQ, Q);
        BigNumberPolynomialGaloisPower(PiPY.Nominator, Y2, BQ, Q, LDP);

        BigNumberRationalPolynomialCopy(RSX, PiPX);
        BigNumberRationalPolynomialCopy(RSY, PiPY);

        for J := 1 to (L + 1) shr 1 do
        begin
          // ��������ֱ���ÿɳ�����ʽ���� RSX := J * (PiPX, PiPY) �� X�����ƺ�����ȵ�����������õ��
          // RationalMultiplePointX(RSX, PiPX, J, A, B, Q, DPs, LDP);

          if BigNumberRationalPolynomialGaloisEqual(LSX, RSX, Q, LDP) then
          begin
            // ��������ֱ���ÿɳ�����ʽ���� RSY := J * (PiPX, PiPY) �� Y�����ƺ�����ȵ�����������õ��
            // RationalMultiplePointY(RSY, PiPX, PiPY, J, A, B, Q, DPs, LDP);

            if BigNumberRationalPolynomialGaloisEqual(LSY, RSY, Q, LDP) then
              Ta[I] := J
            else
              Ta[I] := L - J;
            Break;
          end;

          TCnPolynomialEcc.RationalPointAddPoint(RSX, RSY, PiPX, PiPY, TSX, TSY, A, B, Q, LDP);
          BigNumberRationalPolynomialCopy(RSX, TSX);
          BigNumberRationalPolynomialCopy(RSY, TSY);
        end;
      end;
    end;

    // ����������������й�ʣ�ඨ�������ս�
    BigNumberChineseRemainderTheorem(Res, Ta, Pa);

    // ע������� T �������� Hasse ����T �ľ���ֵ <= 2 * ���� Q���糬����Χ����������
    BigNumberSqrt(QMax, Q);
    QMax.AddWord(1);
    QMax.ShiftLeftOne;     // QMax ���ã��� 2 ���� Q + 1�������ֵ����� Res ��

    if BigNumberUnsignedCompare(Res, QMax) >= 0 then
    begin
      // �й�ʣ�ඨ�������һ������С��������Ҫ��ȥȫ�� Pa �ĳ˻�
      QMul.SetOne;
      for J := 0 to Pa.Count - 1 do
      begin
        BQ.SetInt64(Pa[J]);
        BigNumberMul(QMul, QMul, BQ);
      end;

      if Res.IsNegative then
        BigNumberAdd(Res, Res, QMul)
      else
        BigNumberSub(Res, Res, QMul);
    end;

    Res.Negate;
    BigNumberAdd(Res, Res, Q);
    Res.AddWord(1); // Q + 1 - L
    Result := True;
  finally
    FEccPolynomialPool.Recycle(Y2);
    FEccPolynomialPool.Recycle(P1);
    FEccPolynomialPool.Recycle(P2);

    FEccPolynomialPool.Recycle(G);

    FEccBigNumberPool.Recycle(QMax);
    FEccBigNumberPool.Recycle(QMul);
    FEccBigNumberPool.Recycle(BQ);

    FEccRationalPolynomialPool.Recycle(Pi2PX);
    FEccRationalPolynomialPool.Recycle(Pi2PY);
    FEccRationalPolynomialPool.Recycle(PiPX);
    FEccRationalPolynomialPool.Recycle(PiPY);
    FEccRationalPolynomialPool.Recycle(KPX);
    FEccRationalPolynomialPool.Recycle(KPY);
    FEccRationalPolynomialPool.Recycle(LSX);
    FEccRationalPolynomialPool.Recycle(LSY);
    FEccRationalPolynomialPool.Recycle(RSX);
    FEccRationalPolynomialPool.Recycle(RSY);
    FEccRationalPolynomialPool.Recycle(TSX);
    FEccRationalPolynomialPool.Recycle(TSY);

    DPs.Free;
    Pa.Free;
    Ta.Free;
  end;
end;

function CnEccSchoof2(Res, A, B, Q: TCnBigNumber): Boolean;
var
  Pa, Ta: TCnInt64List;
  QMul, QMax, BQ: TCnBigNumber;
  L, W, K: Int64;
  I, J: Integer;
  G, Y2, P1, P2, LDP: TCnBigNumberPolynomial;
  Pi2PX, Pi2PY, PiPX, PiPY, KPX, KPY, LSX, LSY, RSX, RSY, TSX, TSY, WPiPX, WPiPY: TCnBigNumberRationalPolynomial;
  DPs: TObjectList;
begin
  // �� Schoof �㷨����Բ���� y^2 = x^3 + Ax + B ������ Fq �ϵĵ�����
  // �Ƚ��� List��������� 2 ~ lmax ������������ 3 * ... * lmax �պ� > 4 ������ q
  // �� x^q -x �� x^3 + Ax + B �Ĺ���ʽ������� 1 �� t2 = 1������ t2 = 0��
  // ���� t2 �� List ��������� 2 ��Ԫ�أ������±꣬����ͬ

  Result := False;
  if Q.IsZero or Q.IsNegative then
    Exit;

  Pa := nil;
  Ta := nil;
  DPs := nil;
  Pi2PX := nil;
  Pi2PY := nil;
  PiPX := nil;
  PiPY := nil;
  KPX := nil;
  KPY := nil;
  LSX := nil;
  LSY := nil;
  RSX := nil;
  RSY := nil;
  TSX := nil;
  TSY := nil;
  WPiPX := nil;
  WPiPY := nil;

  Y2 := nil;
  P1 := nil;
  P2 := nil;

  G := nil;

  QMax := nil;
  QMul := nil;
  BQ := nil;

  try
    Pa := TCnInt64List.Create;
    Ta := TCnInt64List.Create;

    Y2 := FEccPolynomialPool.Obtain;
    P1 := FEccPolynomialPool.Obtain;
    P2 := FEccPolynomialPool.Obtain;

    G := FEccPolynomialPool.Obtain;

    QMax := FEccBigNumberPool.Obtain;
    QMul := FEccBigNumberPool.Obtain;
    BQ := FEccBigNumberPool.Obtain;

    if not BigNumberSqrt(QMax, Q) then
      Exit;

    BigNumberAddWord(QMax, 1);
    BigNumberMulWord(QMax, 4);
    QMul.SetOne;
    I := Low(CN_PRIME_NUMBERS_SQRT_UINT32);

    Pi2PX := FEccRationalPolynomialPool.Obtain;
    Pi2PY := FEccRationalPolynomialPool.Obtain;
    PiPX := FEccRationalPolynomialPool.Obtain;
    PiPY := FEccRationalPolynomialPool.Obtain;
    KPX := FEccRationalPolynomialPool.Obtain;
    KPY := FEccRationalPolynomialPool.Obtain;
    LSX := FEccRationalPolynomialPool.Obtain;
    LSY := FEccRationalPolynomialPool.Obtain;
    RSX := FEccRationalPolynomialPool.Obtain;
    RSY := FEccRationalPolynomialPool.Obtain;
    TSX := FEccRationalPolynomialPool.Obtain;
    TSY := FEccRationalPolynomialPool.Obtain;
    WPiPX := FEccRationalPolynomialPool.Obtain;
    WPiPY := FEccRationalPolynomialPool.Obtain;

    while (BigNumberCompare(QMul, QMax) <= 0) and (I <= High(CN_PRIME_NUMBERS_SQRT_UINT32)) do
    begin
      BigNumberMulWord(QMul, CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Pa.Add(CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Ta.Add(0);
      Inc(I);
    end;

    if I > High(CN_PRIME_NUMBERS_SQRT_UINT32) then
      raise ECnEccException.Create('Prime Number is Too Large.');

    Y2.SetCoefficents([B, A, 0, 1]);

    // Ta �� Pa ������׼���ã��ȴ��� t = 2 �����
    P1.SetCoefficents([0, 1]); // P1 := X
    BigNumberPolynomialGaloisPower(P1, P1, Q, Q, Y2); // X^q �� mod Y^2

    P2.SetCoefficents([0, 1]); // P2 := X
    BigNumberPolynomialGaloisSub(P1, P1, P2, Q); // P1 := (X^q mod Y^2) - x

    // �����Լʽ
    BigNumberPolynomialGaloisGreatestCommonDivisor(G, P1, Y2, Q);

    if G.IsOne then
      Ta[0] := 1
    else
      Ta[0] := 0;   // ��� T2������˲��һ��������

    // ��ǰ���������� + 2 �׵Ŀɳ�����ʽ���Լ�׼���� Y^2
    DPs := TObjectList.Create(True);
    CnGenerateGaloisDivisionPolynomials(A, B, Q, Pa[Pa.Count - 1] + 2, DPs);

    for I := 1 to Ta.Count - 1 do  // ���ÿһ�� L�������� ��^2(P) + K * (P) = J * ��^(P) mod L�׿ɳ�����ʽ
    begin
      L := Pa[I];
      K := BigNumberModWord(Q, L);

      // �ȵõ� L �׿ɳ�����ʽ����Ϊ���������ģ����ʽ
      LDP := TCnBigNumberPolynomial(DPs[L]);

      Pi2PX.SetOne;                           // ԭʼ��
      Pi2PX.Nominator.SetCoefficents([0, 1]); // x
      Pi2PY.Setone;                           // 1 * y

      // ��� ��^2 �� X ������ LDP ���ڵı���ʽ��Ҳ���� Q*Q �� x ����� mod LDP
      BigNumberPolynomialGaloisPower(Pi2PX.Nominator, Pi2PX.Nominator, Q, Q, LDP);
      BigNumberPolynomialGaloisPower(Pi2PX.Nominator, Pi2PX.Nominator, Q, Q, LDP);  // ֱ�� Q*Q ����������ֲ���

      // ��� ��^2 �� Y ������ LDP ���ڵı���ʽ��Q*Q �� y ��˵��� y * [(Q*Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
      BigNumberMul(BQ, Q, Q);
      BigNumberShiftRightOne(BQ, BQ);
      BigNumberPolynomialGaloisPower(Pi2PY.Nominator, Y2, BQ, Q, LDP);

      KPX.SetOne;                             // ԭʼ��
      KPX.Nominator.SetCoefficents([0, 1]);   // x
      KPY.SetOne;                             // 1 * y

      // ��� K * P �� X Y ���꣬���� K �൱�� Wikepedia �����е� q ��
      TCnPolynomialEcc.RationalMultiplePoint(K, KPX, KPY, A, B, Q, LDP);

      // �˴� Wikipedia �������� KPX �� Pi2PX �Ƿ���ͬ���жϣ���ͬ������ö���ʣ���ж�
      if BigNumberRationalPolynomialGaloisEqual(KPX, Pi2PX, Q) then
      begin
        // ����� X ������ͬ����ƽ��ʣ�� w^2 = K mod L
        W := CnInt64SquareRoot(K, L);
        if W = 0 then // �����ڶ���ʣ�࣬t Ϊ 0
        begin
          Ta[I] := 0;
          Continue;
        end;

        // ���ڶ���ʣ�࣬t Ϊ���� 2W���ж�����ţ�Ҫ���� W *  �е� X �� Y ����

        PiPX.SetOne;                            // ԭʼ��
        PiPX.Nominator.SetCoefficents([0, 1]);  // x
        PiPY.Setone;                            // 1 * y

        // ��� �е� X ������ LDP ���ڵı���ʽ��Ҳ���� Q �� x ����� mod LDP
        BigNumberPolynomialGaloisPower(PiPX.Nominator, PiPX.Nominator, Q, Q, LDP);

        // ��� �е� Y ������ LDP ���ڵı���ʽ��Q �� y ��˵��� y * [(Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
        BigNumberShiftRightOne(BQ, Q);
        BigNumberPolynomialGaloisPower(PiPY.Nominator, Y2, BQ, Q, LDP);

        // ���ƹ�ȥ��� W ����
        BigNumberRationalPolynomialCopy(WPiPX, PiPX);
        BigNumberRationalPolynomialCopy(WPiPY, PiPY);

        TCnPolynomialEcc.RationalMultiplePoint(W, WPiPX, WPiPY, A, B, Q, LDP);

        if BigNumberRationalPolynomialGaloisEqual(WPiPX, Pi2PX, Q, LDP) then
        begin
          if BigNumberRationalPolynomialGaloisEqual(WPiPY, Pi2PY, Q, LDP) then
           Ta[I] := 2 * W
          else
          begin
           BigNumberRationalPolynomialGaloisNegate(WPiPY, Q);
           if BigNumberRationalPolynomialGaloisEqual(WPiPY, Pi2PY, Q, LDP) then
             Ta[I] := L - 2 * W
           else
             Ta[I] := 0;
          end;
        end
        else
          Ta[I] := 0;
      end
      else
      begin
        // ��ͬ������Ҫ�ۼ�
        // �� ��^2(P) + K * (P) �ĺ͵� SX SY
        TCnPolynomialEcc.RationalPointAddPoint(Pi2PX, Pi2PY, KPX, KPY, LSX, LSY, A, B, Q, LDP);

        PiPX.SetOne;                            // ԭʼ��
        PiPX.Nominator.SetCoefficents([0, 1]);  // x
        PiPY.Setone;                            // 1 * y

        // ��� �е� X ������ LDP ���ڵı���ʽ��Ҳ���� Q �� x ����� mod LDP
        BigNumberPolynomialGaloisPower(PiPX.Nominator, PiPX.Nominator, Q, Q, LDP);

        // ��� �е� Y ������ LDP ���ڵı���ʽ��Q �� y ��˵��� y * [(Q shr 1) �� y^2 ���]���� y^2 ���滻�� x^3+Ax+B
        BigNumberShiftRightOne(BQ, Q);
        BigNumberPolynomialGaloisPower(PiPY.Nominator, Y2, BQ, Q, LDP);

        BigNumberRationalPolynomialCopy(RSX, PiPX);
        BigNumberRationalPolynomialCopy(RSY, PiPY);

        for J := 1 to (L + 1) shr 1 do
        begin
          // ��������ֱ���ÿɳ�����ʽ���� RSX := J * (PiPX, PiPY) �� X�����ƺ�����ȵ�����������õ��
          // RationalMultiplePointX(RSX, PiPX, J, A, B, Q, DPs, LDP);

          if BigNumberRationalPolynomialGaloisEqual(LSX, RSX, Q, LDP) then
          begin
            // ��������ֱ���ÿɳ�����ʽ���� RSY := J * (PiPX, PiPY) �� Y�����ƺ�����ȵ�����������õ��
            // RationalMultiplePointY(RSY, PiPX, PiPY, J, A, B, Q, DPs, LDP);

            if BigNumberRationalPolynomialGaloisEqual(LSY, RSY, Q, LDP) then
              Ta[I] := J
            else
              Ta[I] := L - J;
            Break;
          end;

          TCnPolynomialEcc.RationalPointAddPoint(RSX, RSY, PiPX, PiPY, TSX, TSY, A, B, Q, LDP);
          BigNumberRationalPolynomialCopy(RSX, TSX);
          BigNumberRationalPolynomialCopy(RSY, TSY);
        end;
      end;
    end;

    // ����������������й�ʣ�ඨ�������ս�
    BigNumberChineseRemainderTheorem(Res, Ta, Pa);

    // ע������� T �������� Hasse ����T �ľ���ֵ <= 2 * ���� Q���糬����Χ����������
    BigNumberSqrt(QMax, Q);
    QMax.AddWord(1);
    QMax.ShiftLeftOne;     // QMax ���ã��� 2 ���� Q + 1�������ֵ����� Res ��

    if BigNumberUnsignedCompare(Res, QMax) >= 0 then
    begin
      // �й�ʣ�ඨ�������һ������С��������Ҫ��ȥȫ�� Pa �ĳ˻�
      QMul.SetOne;
      for J := 0 to Pa.Count - 1 do
      begin
        BQ.SetInt64(Pa[J]);
        BigNumberMul(QMul, QMul, BQ);
      end;

      if Res.IsNegative then
        BigNumberAdd(Res, Res, QMul)
      else
        BigNumberSub(Res, Res, QMul);
    end;

    Res.Negate;
    BigNumberAdd(Res, Res, Q);
    Res.AddWord(1); // Q + 1 - L
    Result := True;
  finally
    FEccPolynomialPool.Recycle(Y2);
    FEccPolynomialPool.Recycle(P1);
    FEccPolynomialPool.Recycle(P2);

    FEccPolynomialPool.Recycle(G);

    FEccBigNumberPool.Recycle(QMax);
    FEccBigNumberPool.Recycle(QMul);
    FEccBigNumberPool.Recycle(BQ);

    FEccRationalPolynomialPool.Recycle(Pi2PX);
    FEccRationalPolynomialPool.Recycle(Pi2PY);
    FEccRationalPolynomialPool.Recycle(PiPX);
    FEccRationalPolynomialPool.Recycle(PiPY);
    FEccRationalPolynomialPool.Recycle(KPX);
    FEccRationalPolynomialPool.Recycle(KPY);
    FEccRationalPolynomialPool.Recycle(LSX);
    FEccRationalPolynomialPool.Recycle(LSY);
    FEccRationalPolynomialPool.Recycle(RSX);
    FEccRationalPolynomialPool.Recycle(RSY);
    FEccRationalPolynomialPool.Recycle(TSX);
    FEccRationalPolynomialPool.Recycle(TSY);
    FEccRationalPolynomialPool.Recycle(WPiPX);
    FEccRationalPolynomialPool.Recycle(WPiPY);

    DPs.Free;
    Pa.Free;
    Ta.Free;
  end;
end;

function CnEccFastSchoof(Res, A, B, Q: TCnBigNumber): Boolean;
var
  Pa, Ta: TCnInt64List;
  QMul, QMax, BQ, Q12, Q32, Q23, QT: TCnBigNumber;
  L, K, W: Int64;
  I, J, T: Integer;
  G, Y2, P1, P2, LDP: TCnBigNumberPolynomial;
  PXP2X, PXPX, NPXP2X, PXP2XPX, P16, P17, P18, P19X, P19Y, T1, T2, T3, T4, PAlpha, PBeta: TCnBigNumberPolynomial;
  DPs: TObjectList;

  function F(DPIdx: Integer): TCnBigNumberPolynomial; // �򻯵ĵõ� Division Polynomial ��
  begin
    Result := TCnBigNumberPolynomial(DPs[DPIdx]);
  end;

begin
{
    Ren�� Schoof��s Algorithm
  for Determining the Order of the Group of Points
    on an Elliptic Curve over a Finite Field
}

  Result := False;
  if Q.IsZero or Q.IsNegative then
    Exit;

  Pa := nil;
  Ta := nil;
  DPs := nil;

  Y2 := nil;
  P1 := nil;
  P2 := nil;

  G := nil;

  QMax := nil;
  QMul := nil;
  BQ := nil;
  Q12 := nil;
  Q32 := nil;
  Q23 := nil;
  QT := nil;

  PXP2X := nil;
  PXPX := nil;
  NPXP2X := nil;
  PXP2XPX := nil;
  T1 := nil;
  T2 := nil;
  T3 := nil;
  T4 := nil;
  P16 := nil;
  P17 := nil;
  P18 := nil;
  P19X := nil;
  P19Y := nil;
  PAlpha := nil;
  PBeta := nil;

  try
    Y2 := FEccPolynomialPool.Obtain;
    P1 := FEccPolynomialPool.Obtain;
    P2 := FEccPolynomialPool.Obtain;

    G := FEccPolynomialPool.Obtain;

    QMax := FEccBigNumberPool.Obtain;
    QMul := FEccBigNumberPool.Obtain;
    BQ := FEccBigNumberPool.Obtain;
    Q12 := FEccBigNumberPool.Obtain;
    Q32 := FEccBigNumberPool.Obtain;

    if not BigNumberSqrt(QMax, Q) then
      Exit;

    BigNumberAddWord(QMax, 1);
    BigNumberMulWord(QMax, 4);
    QMul.SetOne;
    I := Low(CN_PRIME_NUMBERS_SQRT_UINT32);

    Pa := TCnInt64List.Create;
    Ta := TCnInt64List.Create;

    PXP2X := FEccPolynomialPool.Obtain;
    PXPX := FEccPolynomialPool.Obtain;
    T1 := FEccPolynomialPool.Obtain;
    T2 := FEccPolynomialPool.Obtain;
    T3 := FEccPolynomialPool.Obtain;
    T4 := FEccPolynomialPool.Obtain;
    P16 := FEccPolynomialPool.Obtain;
    P17 := FEccPolynomialPool.Obtain;
    P18 := FEccPolynomialPool.Obtain;
    P19X := FEccPolynomialPool.Obtain;
    P19Y := FEccPolynomialPool.Obtain;

    while (BigNumberCompare(QMul, QMax) <= 0) and (I <= High(CN_PRIME_NUMBERS_SQRT_UINT32)) do
    begin
      BigNumberMulWord(QMul, CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Pa.Add(CN_PRIME_NUMBERS_SQRT_UINT32[I]);
      Ta.Add(0);
      Inc(I);
    end;

    if I > High(CN_PRIME_NUMBERS_SQRT_UINT32) then
      raise ECnEccException.Create('Prime Number is Too Large.');

    // ׼���� Y2������ x^3 + Ax + B
    Y2.SetCoefficents([B, A, 0, 1]);

    // Ta �� Pa ������׼���ã��ȴ��� t = 2 �����
    P1.SetCoefficents([0, 1]); // P1 := X
    BigNumberPolynomialGaloisPower(P1, P1, Q, Q, Y2); // X^q �� mod Y^2

    P2.SetCoefficents([0, 1]); // P2 := X
    BigNumberPolynomialGaloisSub(P1, P1, P2, Q); // P1 := (X^q mod Y^2) - x

    // �����Լʽ
    BigNumberPolynomialGaloisGreatestCommonDivisor(G, P1, Y2, Q);

    if G.IsOne then
      Ta[0] := 1
    else
      Ta[0] := 0;   // ��� T2������˲��һ��������

    // ��ǰ���������� + 2 �׵Ŀɳ�����ʽ���Լ�׼���� Y^2
    DPs := TObjectList.Create(True);
    CnGenerateGaloisDivisionPolynomials(A, B, Q, Pa[Pa.Count - 1] + 2, DPs);

    for I := 1 to Ta.Count - 1 do  // ���ÿһ�� L�������� ��^2(P) + K * (P) = J * ��^(P) mod L�׿ɳ�����ʽ
    begin
      L := Pa[I];
      K := BigNumberModWord(Q, L);

      // �ȵõ� L �׿ɳ�����ʽ����Ϊ���������ģ����ʽ
      LDP := F(L);

      // ׼���� PXP2X �� Y2���ֱ���� x^(q^2) - x �� x^3 + Ax + B
      PXP2X.SetCoefficents([0, 1]); // PXP2X := x
      BigNumberPolynomialGaloisPower(PXP2X, PXP2X, Q, Q, LDP); // x^q
      BigNumberPolynomialGaloisPower(PXP2X, PXP2X, Q, Q, LDP); // x^(q^2)
      T1.SetCoefficents([0, 1]);   // T1 = x
      BigNumberPolynomialGaloisSub(PXP2X, PXP2X, T1, Q, LDP);  // x^(q^2) - x

      // ׼���� PXPX������ x^q - x
      PXPX.SetCoefficents([0, 1]); // PXP2X := X
      BigNumberPolynomialGaloisPower(PXPX, PXPX, Q, Q, LDP); // X^q
      T1.SetCoefficents([0, 1]);   // T1 = x
      BigNumberPolynomialGaloisSub(PXPX, PXPX, T1, Q, LDP);  // X^q - X

      // �ж��Ƿ���� L ��Ť�� P��ʹ�� ��^2(P) = ���� K * (P)���� K ����ż���ֱ���� P16�������Ϻ������еļ�������һ��
      if K and 1 <> 0 then
      begin
        // K ��������P16 = (X^(q^2) - X) * F[K]^2 + F[K-1] * F[K+1] * (x^3 + Ax + B)
        BigNumberPolynomialGaloisMul(T1, F(K), F(K), Q, LDP);
        BigNumberPolynomialGaloisMul(T1, T1, PXP2X, Q, LDP);

        BigNumberPolynomialGaloisMul(T2, F(K - 1), F(K + 1), Q, LDP);
        BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);

        BigNumberPolynomialGaloisAdd(P16, T1, T2, Q, LDP);
      end
      else
      begin
        // K ��ż����P16 = (X^(q^2) - X) * F[K]^2 * (x^3 + Ax + B) + F[K-1] * F[K+1]
        BigNumberPolynomialGaloisMul(T1, F(K), F(K), Q, LDP);
        BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP);
        BigNumberPolynomialGaloisMul(T1, T1, PXP2X, Q, LDP);

        BigNumberPolynomialGaloisMul(T2, F(K - 1), F(K + 1), Q, LDP);

        BigNumberPolynomialGaloisAdd(P16, T1, T2, Q, LDP);
      end;

      // �õ� P16 ����㹫��ʽ
      BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P16, LDP, Q);

      if not T1.IsOne then // �й���ʽ������ ��^2(P) = ���� K * (P)
      begin
        // ���������������������������� W^2 = K mod L��W ������˵�� K �� L �Ķ���ʣ��
        W := CnInt64SquareRoot(K, L);
        if W = 0 then // �����ڶ���ʣ�࣬t Ϊ 0
        begin
          Ta[I] := 0;
          Continue;
        end;

        // ���ڶ���ʣ�࣬t Ϊ���� 2W���ж�����ţ�Ҫ���� P17�������Ϻ������еļ�������Ķ��ԱȺ���Ϊһ��
        if W and 1 <> 0 then
        begin
          // W ��������P17 = (X^q - X) * F[W]^2 + F[W-1] * F[W+1] * (x^3 + Ax + B)
          BigNumberPolynomialGaloisMul(T1, F(W), F(W), Q, LDP);
          BigNumberPolynomialGaloisMul(T1, T1, PXPX, Q, LDP);

          BigNumberPolynomialGaloisMul(T2, F(W - 1), F(W + 1), Q, LDP);
          BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);

          BigNumberPolynomialGaloisAdd(P17, T1, T2, Q, LDP);
        end
        else
        begin
          // W ��ż����P17 = (X^q - X) * F[W]^2 * (x^3 + Ax + B) + F[W-1] * F[W+1]
          BigNumberPolynomialGaloisMul(T1, F(W), F(W), Q, LDP);
          BigNumberPolynomialGaloisMul(T1, T1, PXPX, Q, LDP);
          BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP);

          BigNumberPolynomialGaloisMul(T2, F(W - 1), F(W + 1), Q, LDP);

          BigNumberPolynomialGaloisAdd(P17, T1, T2, Q, LDP);
        end;

        // �õ� P17 ����㹫��ʽ
        BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P17, LDP, Q);
        if T1.IsOne then // ���أ�t Ϊ 0
        begin
          Ta[I] := 0;
          Continue;
        end;

        // ���� t ������ 2W�����ж������ţ��� P18�������Ϻ������еļ�������Ķ��ԱȺ���Ϊһ��
        BigNumberCopy(Q12, Q);
        Q12.SubWord(1);
        Q12.ShiftRightOne;   // �õ� (Q - 1) / 2

        BigNumberCopy(Q32, Q);
        Q32.SubWord(3);
        Q32.ShiftRightOne;   // �õ� (Q - 3) / 2

        if W and 1 <> 0 then
        begin
          // W ��������P18 = 4*(x^3 + Ax + B)^(Q-1)/2) * F[W]^3 - F[W+2]^2 * F[W-1] + F[W-2]^2 * F[W+1]
          BigNumberPolynomialGaloisPower(T1, Y2, Q12, Q, LDP);
        end
        else
        begin
          // W ��ż����P18 = 4*(x^3 + Ax + B)^(Q+3)/2) * F[W]^3 - F[W+2]^2 * F[W-1] + F[W-2]^2 * F[W+1]
          BigNumberPolynomialGaloisPower(T1, Y2, Q32, Q, LDP);
        end;
        BigNumberPolynomialGaloisMulWord(T1, 4, Q);
        BigNumberPolynomialGaloisPower(T2, F(W), 3, Q, LDP);
        BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP); // T1 �õ���һ����

        BigNumberPolynomialGaloisMul(T2, F(W + 2), F(W + 2), Q, LDP);  // T2 �õ�����
        BigNumberPolynomialGaloisMul(T2, T2, F(W - 1), Q, LDP);

        BigNumberPolynomialGaloisMul(T3, F(W - 2), F(W - 2), Q, LDP);  // T3 �õ�����
        BigNumberPolynomialGaloisMul(T3, T3, F(W + 1), Q, LDP);

        BigNumberPolynomialGaloisSub(P18, T1, T2, Q, LDP);
        BigNumberPolynomialGaloisAdd(P18, P18, T3, Q, LDP);

        // �õ� P18 ����㹫��ʽ
        BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P18, LDP, Q);
        if T1.IsOne then
          Ta[I] := L - 2 * W
        else
          Ta[I] := 2 * W;
      end
      else // ��������������ʼ�� P19X �� P19Y
      begin
        QT := FEccBigNumberPool.Obtain; // ׼��һ����ʱ������Ϊ Q ��ص�ָ������ʱ�洢

        PAlpha := FEccPolynomialPool.Obtain;
        PBeta := FEccPolynomialPool.Obtain;

        // �ȼ��� Alpha
        BigNumberPolynomialGaloisMul(T1, F(K - 1), F(K - 1), Q, LDP);
        BigNumberPolynomialGaloisMul(T1, T1, F(K + 2), Q, LDP);                 // T1 �õ� Fk-1^2 * Fk+2

        BigNumberPolynomialGaloisMul(T2, F(K + 1), F(K + 1), Q, LDP);
        BigNumberPolynomialGaloisMul(T2, T2, F(K - 2), Q, LDP);                 // T2 �õ� Fk+1^2 * Fk-2

        BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP); // T1 �Ǽ�ʽ Fk-1^2 * Fk+2 - Fk+1^2 * Fk-2���ͷ� T2

        Q23 := FEccBigNumberPool.Obtain;
        BigNumberMul(Q23, Q, Q);

        if K and 1 <> 0 then  // K ż��ʱ��Ҫ (Q^2 + 3)/2
          Q23.AddWord(3)
        else
          Q23.AddWord(1);     // K ����ʱ��Ҫ (Q^2 + 1)/2

        Q23.ShiftRightOne;  // �õ� (Q^2 + 3)/2 �� (Q^2 + 1)/2�������� Y^2 ��ָ��

        BigNumberPolynomialGaloisPower(T2, Y2, Q23, Q, LDP);
        BigNumberPolynomialGaloisPower(T3, F(K), 3, Q, LDP);
        BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);
        BigNumberPolynomialGaloisMulWord(T2, 4, Q); // �õ���������ʽ

        BigNumberPolynomialSub(PAlpha, T1, T2);     // ����� PAlpha���ͷ� T1 T2
        // ע��˴���� K ���������õ��� PAlpha ��ʹ��ʱ��Ҫ����һ�� Y2
        // ��� K ��ż�����õ��� PAlpha ��ʵ�� Alpha / y ��ֵ

        // �ټ��� Beta
        NPXP2X := FEccPolynomialPool.Obtain;
        BigNumberPolynomialCopy(NPXP2X, PXP2X);
        BigNumberPolynomialGaloisNegate(NPXP2X, Q); // NPXPX �õ� x - x^(q^2)

        BigNumberPolynomialGaloisMul(T1, F(K), F(K), Q, LDP); // T1 �õ� Fk^2
        BigNumberPolynomialGaloisMul(T1, NPXP2X, T1, Q, LDP); // T1 �õ� Fk^2 * (x - x^(q^2))��������ʹ��

        BigNumberPolynomialGaloisMul(T2, F(K - 1), F(K + 1), Q, LDP); // T2 �õ� F(k-1)* F(k+1)

        if K and 1 <> 0 then // ����
        begin
          // K ����������Ӧ�� Alpha �Ǵ� x ��ϵ����Beta ����Ҫ��һ�� y��Ҳ����˵��PBeta ��ʵ�� Beta / y ��ֵ
          // Alpha = Y^2 * ����� PAlpha
          BigNumberPolynomialGaloisMul(PAlpha, PAlpha, Y2, Q, LDP); // ������ Alpha �������

          // �ٷֱ���� Beta T2 Ҫ���� Y2
          BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);

          BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP); // T1 �õ����Ľ��

          // �ٳ��� 4Fk
          BigNumberPolynomialGaloisMul(PBeta, T1, F(K), Q, LDP);
          BigNumberPolynomialGaloisMulWord(PBeta, 4, Q);          // �õ��� PBeta ��ʹ��ʱ��Ҫ�������һ�� y
        end
        else // ż��
        begin
          // K ��ż������Ӧ�� Alpha ����Ҫ��һ�� y��Ҳ����˵��PAlpha ��ʵ�� Alpha / y ��ֵ��Beta ���Ǵ� x ��ϵ��

          // �ٷֱ���� Beta��T1 Ҫ���� Y2
          BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP);

          BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP); // T1 �õ����Ľ��

          // �ٳ��� 4Fk
          BigNumberPolynomialGaloisMul(PBeta, T1, F(K), Q, LDP);
          BigNumberPolynomialGaloisMulWord(PBeta, 4, Q);

          // Beta = Y^2 * ����� PBeta
          BigNumberPolynomialGaloisMul(PBeta, PBeta, Y2, Q, LDP);    // ������ Beta �������
        end;

        // ���� Alpha �� Beta ׼�����ˣ�����׼���� x^(p^2) + x^p + x
        PXP2XPX := FEccPolynomialPool.Obtain;
        PXP2XPX.SetCoefficents([0, 2]);        // �õ� 2x
        BigNumberPolynomialGaloisAdd(PXP2XPX, PXP2X, PXP2XPX, Q, LDP); // ��ɵļ�һ�µõ� x^(p^2) + x

        T3.SetCoefficents([0, 1]);
        BigNumberPolynomialGaloisPower(T3, T3, Q, Q, LDP);
        BigNumberPolynomialGaloisAdd(PXP2XPX, PXP2XPX, T3, Q, LDP);   // �õ� x^(p^2) + x^p + x

        if K and 1 <> 0 then
        begin
          for T := 1 to L - 1 do // ��� T ָϣ����ĸ�е� Tao
          begin
            // K ������������£���Ӧ PBeta ʵ������ Beta / y����Ҫ����һ�� Y
            // Ҳ�������� P19X������ mod LDP = 0 �Һ� LDP �����Լʽ <> 1 ʱ�������� T ����Ҫ��
            // K �� t �������� P19X = ������ a ��ʾ alpha��b ��ʾ beta/y��
            // Ft^2p * (b^2 * Y^2 * (Y^2 * Fk-1 * Fk+1 - Fk^2 *(x^(p^2) + x^p + x) + a^2 * Fk^2)) + Fk^2 * b^2 * Y^2 * (Ft-1 * Ft+1)^p * (Y^2)^p
            // t ż������� P19X ��ɣ����ɱ�Ϊ�� x ����ʽ��
            // Ft^2p * (Y^2)^p * (b^2 * Y^2 * (Y^2 * Fk-1 * Fk+1 - Fk^2 *(x^(p^2) + x^p + x) + a^2 * Fk^2)) + Fk^2 * b^2 * Y^2 * (Ft-1 * Ft+1)^p

            // �ȼ���ǰ������������ǰ��� Y^2p��֮���ٸ��� T ����ż�Ը��Գ���
            // �ȼ��� Fk^2 * b^2 * Y^2 * (Ft-1 * Ft+1)^p �ŵ� T3 ��
            BigNumberPolynomialGaloisMul(T1, F(K), F(K), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, PBeta, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP); // T1 �õ� Fk^2 * b^2 * Y^2��

            BigNumberPolynomialGaloisMul(T2, F(T - 1), F(T + 1), Q, LDP);
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);

            BigNumberPolynomialGaloisMul(T3, T1, T2, Q, LDP); // T3 �õ� Fk^2 * b^2 * Y^2 * (Ft-1 * Ft+1)^p���ͷ� T1 T2
            if T and 1 <> 0 then // T Ϊ����ʱҪ���һ��
            begin
              BigNumberPolynomialGaloisPower(T1, Y2, Q, Q, LDP);
              BigNumberPolynomialGaloisMul(T3, T3, T1, Q, LDP);
            end;

            // ����ǰ��ļ�������� T3
            BigNumberPolynomialGaloisMul(T1, F(K - 1), F(K + 1), Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP); // T1 �õ� Y^2 * Fk-1 * Fk+1

            BigNumberPolynomialGaloisMul(T2, F(K), F(K), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PXP2XPX, Q, LDP); // T2 �õ� Fk^2 *(x^(p^2) + x^p + x)

            BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP); // T1 �����ͷ� T2

            BigNumberPolynomialGaloisMul(T2, F(K), PAlpha, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, T2, Q, LDP); // T2 �õ� a^2 * Fk^2

            BigNumberPolynomialGaloisAdd(T1, T1, T2, Q, LDP); // T1 �õ�ȫ��ʽ���ͷ� T2

            BigNumberPolynomialGaloisMul(T2, PBeta, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP); // T2 �õ� b^2 * Y^2����Ӧ PBeta ��Ҫ����һ�� Y

            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP); // ȫ��ʽ�˺���� T1���ͷ� T2

            BigNumberPolynomialGaloisMul(T2, F(T), F(T), Q, LDP);        // T2 �õ� Ft^2

            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);// T2 �õ� (Ft^2)^p = Ft^2p

            if T and 1 = 0 then // T Ϊż��ʱ T2 Ҫ���һ�� (Y^2)^p
            begin
              BigNumberPolynomialGaloisPower(T4, Y2, Q, Q, LDP);
              BigNumberPolynomialGaloisMul(T2, T2, T4, Q, LDP);
            end;

            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP); // T1 �õ��Ӻ���ߵģ����ұ����
            BigNumberPolynomialGaloisAdd(P19X, T1, T3, Q, LDP);  // �Ӻ�õ� P19X

            BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P19X, LDP, Q);

            if T1.IsOne then // ��Ϊ 1 ʱ���ڷ���Ҫ��ĵ㡣Ϊ 1 ʱ�����ڣ����� T ������Ҫ����һѭ��
              Continue;

            // ��Ϊ 1 ʱ������ T ������Ҫ������ K �����������µ� P19Y���� T ����ż����
            // �ֱ����������������
            // ��һ�������4Ft^3p * ( ( (2x^(p^2)+x)*a*y^2*b^2 - b^3*y^(p^2+3) - a^3  )* Fk^2 - a*y^2*b^2 * Fk-1* Fk+1 )
            //��������� T ��ż�����ó��� y^(3p-3)
            // �ڶ��������b^3 * Fk^2 * (Ft-1^2 * Ft+2 - Ft-2 * Ft+1^2)^p
            //��������� T ���棬���ó��� y^(p+3)

            BigNumberPolynomialGaloisPower(T1, Y2, Q23, Q, LDP);                // T1 �õ� y^(p^2+3)
            BigNumberPolynomialGaloisMul(T1, PBeta, T1, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, PBeta, T1, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, PBeta, T1, Q, LDP);                // T1 �õ� b^3*y^(p^2+3)

            BigNumberPolynomialGaloisMul(T2, PAlpha, PAlpha, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PAlpha, Q, LDP);               // T2 �õ� a^3

            BigNumberPolynomialGaloisAdd(T1, T1, T2, Q, LDP);                   // T1 �õ�  b^3*y^(p^2+3) + a^3�����ű��������ͷ� T2��ֻռ�� T1

            T2.SetCoefficents([0, 1]);                                          // x
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);                  // x^q
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);                  // x^(q^2)
            BigNumberPolynomialGaloisAdd(T2, T2, T2, Q, LDP);                   // 2*x^(q^2)

            T3.SetCoefficents([0, 1]);
            BigNumberPolynomialGaloisAdd(T2, T2, T3, Q, LDP);                   // T2 �õ� 2x^(p^2)+x)���ͷ� T3

            BigNumberPolynomialGaloisMul(T2, T2, PAlpha, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);                // T2 �õ� (2x^(p^2)+x)*a*y^2*b^2

            BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP);                   // T1 �õ� (2x^(p^2)+x)*a*y^2*b^2 - b^3*y^(p^2+3) - a^3�����ͷ� T2

            BigNumberPolynomialGaloisMul(T1, T1, F(K), Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, F(K), Q, LDP);                 // T1 �ٳ��� Fk^2

            BigNumberPolynomialGaloisMul(T2, PAlpha, Y2, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, F(K - 1), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, F(K + 1), Q, LDP);             // T2 �õ� a*y^2*b^2 * Fk-1* Fk+1

            BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP);                   // T1 �õ�δ���� 4Ft^3p �ĵ�һ����������ͷ� T2

            BigNumberPolynomialCopy(T2, F(T));                                  // �� T2 ���� 4Ft^3p
            BigNumberCopy(QT, Q);
            BigNumberMulWord(QT, 3);
            BigNumberPolynomialGaloisPower(T2, T2, QT, Q, LDP);
            BigNumberPolynomialGaloisMulWord(T2, 4, Q);                         // T2 �õ� 4Ft^3p

            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP);                   // T1 �õ���һ�����������ֻռ�� T1

            // ����ڶ��������� b^3 * Fk^2 * (Ft-1^2 * Ft+2 - Ft-2 * Ft+1^2)^p
            BigNumberPolynomialGaloisMul(T2, F(T - 1), F(T + 2), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, F(T - 1), T2, Q, LDP);
            BigNumberPolynomialGaloisMul(T3, F(T + 1), F(T - 2), Q, LDP);
            BigNumberPolynomialGaloisMul(T3, F(T + 1), T3, Q, LDP);

            BigNumberPolynomialGaloisSub(T2, T2, T3, Q, LDP);                   // �õ���ʽ Ft-1^2 * Ft+2 - Ft-2 * Ft+1^2�����ͷ� T3
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);                  // p �η�

            BigNumberPolynomialGaloisMul(T3, F(K), F(K), Q, LDP);               // T3 �õ� Fk^2
            BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);                   // T2 ���� T3�����ͷ� T3

            BigNumberPolynomialGaloisPower(T3, PBeta, 3, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);                   // T2 �ٳ��� T3���õ��ڶ�����������ͷ� T3

            if T and 1 = 0 then // T ��ż��������һҪ��
            begin
              // ���� y^(3p-3)
              BigNumberCopy(QT, Q);
              BigNumberMulWord(QT, 3);
              BigNumberSubWord(QT, 3);
              QT.ShiftRightOne;

              BigNumberPolynomialGaloisPower(T3, Y2, QT, Q, LDP);
              BigNumberPolynomialGaloisMul(T1, T1, T3, Q, LDP);
            end
            else // T ���棬�������Ҫ��
            begin
              // ���� y^(p+3)
              BigNumberCopy(QT, Q);
              BigNumberAddWord(QT, 3);
              QT.ShiftRightOne;

              BigNumberPolynomialGaloisPower(T3, Y2, QT, Q, LDP);
              BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);
            end;

            BigNumberPolynomialGaloisSub(P19Y, T1, T2, Q, LDP);  // �����������õ� P19Y

            BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P19Y, LDP, Q);

            if T1.IsOne then // ��Ϊ 1 ʱ T������ -T
              Ta[I] := T
            else
              Ta[I] := L - T;
          end;
        end
        else
        begin
          for T := 1 to L - 1 do
          begin
            // K ż��ʱ��PAlpha ��ʵ�� Alpha / y ��ֵ
            // K ż t �������� P19X = ���� a ��ʾ alpha/y��b ��ʾ beta
            // Ft^2p * (b^2 * (Fk-1 * Fk+1 - Y^2 * Fk^2 *(x^(p^2) + x^p + x) + (Y^2)^2 * a^2 * Fk^2)) + Fk^2 * b^2 * Y^2 *(Ft-1 * Ft+1)^p * (Y^2)^p
            // t ż������� P19X ��ɣ����ɱ�Ϊ�� x ����ʽ��
            // Ft^2p * (Y^2)^p * (b^2 * (Fk-1 * Fk+1 - Y^2 * Fk^2 *(x^(p^2) + x^p + x) + (Y^2)^2 * a^2 * Fk^2)) + Fk^2 * b^2 * Y^2 *(Ft-1 * Ft+1)^p

            // �ȼ���ǰ������������ǰ��� Y^2p��֮���ٸ��� T ����ż�Ը��Գ���
            // �ȼ��� Fk^2 * b^2 * Y^2 * (Ft-1 * Ft+1)^p �ŵ� T3 ��
            BigNumberPolynomialGaloisMul(T1, F(K), F(K), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, PBeta, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP); // T1 �õ� Fk^2 * b^2 * Y^2

            BigNumberPolynomialGaloisMul(T2, F(T - 1), F(T + 1), Q, LDP);
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);

            BigNumberPolynomialGaloisMul(T3, T1, T2, Q, LDP); // T3 �õ� Fk^2 * b^2 * Y^2 * (Ft-1 * Ft+1)^p���ͷ� T1 T2
            if T and 1 <> 0 then // T Ϊ����ʱҪ���һ��
            begin
              BigNumberPolynomialGaloisPower(T1, Y2, Q, Q, LDP);
              BigNumberPolynomialGaloisMul(T3, T3, T1, Q, LDP);
            end;

            // ����ǰ��ļ�������� T3
            BigNumberPolynomialGaloisMul(T1, F(K - 1), F(K + 1), Q, LDP);       // T1 �õ� Fk-1 * Fk+1

            BigNumberPolynomialGaloisMul(T2, F(K), F(K), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PXP2XPX, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);  // T2 �õ� y^2 * Fk^2 *(x^(p^2) + x^p + x)

            BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP); // T1 �����ͷ� T2

            BigNumberPolynomialGaloisMul(T2, F(K), PAlpha, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, T2, Q, LDP); // T2 �õ� a^2 * Fk^2
            BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP); // T2 �õ� (Y^2)^2 * a^2 * Fk^2

            BigNumberPolynomialGaloisAdd(T1, T1, T2, Q, LDP); // T1 �õ�ȫ��ʽ���ͷ� T2

            BigNumberPolynomialGaloisMul(T2, PBeta, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP); // ȫ��ʽ�� Beta^2 ����� T1���ͷ� T2

            BigNumberPolynomialGaloisMul(T2, F(T), F(T), Q, LDP);        // T2 �õ� Ft^2

            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);// T2 �õ� (Ft^2)^p = Ft^2p

            if T and 1 = 0 then // T Ϊż��ʱ T2 Ҫ���һ�� (Y^2)^p
            begin
              BigNumberPolynomialGaloisPower(T4, Y2, Q, Q, LDP);
              BigNumberPolynomialGaloisMul(T2, T2, T4, Q, LDP);
            end;

            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP); // T1 �õ��Ӻ���ߵģ����ұ����
            BigNumberPolynomialGaloisAdd(P19X, T1, T3, Q, LDP);  // �Ӻ�õ� P19X

            BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P19X, LDP, Q);

            if T1.IsOne then // ��Ϊ 1 ʱ���ڷ���Ҫ��ĵ㡣Ϊ 1 ʱ�����ڣ����� T ������Ҫ����һѭ��
              Continue;

            // ��Ϊ 1 ʱ������ T ������Ҫ������ K ��ż�������µ� P19Y���� T ����ż����
            // �ֱ����������������
            // ��һ�������4Ft^3p * ( ( (2x^(p^2)+x)*a*b^2 - b^3*y^(p^2-1) - y^2 * a^3  )* y^2 * Fk^2 - a*b^2 * Fk-1* Fk+1 )
            //��������� T ��ż�����ó��� y^(3p-1)
            // �ڶ��������b^3 * Fk^2 * (Ft-1^2 * Ft+2 - Ft-2 * Ft+1^2)^p
            //��������� T ���棬���ó��� y^(p+1)

            BigNumberMul(QT, Q, Q);
            BigNumberSubWord(QT, 1);
            QT.ShiftRightOne;
            BigNumberPolynomialGaloisPower(T1, Y2, QT, Q, LDP);                // T1 �õ� y^(p^2-1)
            BigNumberPolynomialGaloisMul(T1, PBeta, T1, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, PBeta, T1, Q, LDP);
            BigNumberPolynomialGaloisMul(T1, PBeta, T1, Q, LDP);                // T1 �õ� b^3*y^(p^2-1)

            BigNumberPolynomialGaloisMul(T2, PAlpha, PAlpha, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PAlpha, Q, LDP);               // T2 �õ� a^3
            BigNumberPolynomialGaloisMul(T2, T2, Y2, Q, LDP);                   // T2 �õ� y^2 * a^3

            BigNumberPolynomialGaloisAdd(T1, T1, T2, Q, LDP);                   // T1 �õ�  b^3*y^(p^2-1) + y^2 * a^3�����ű��������ͷ� T2��ֻռ�� T1

            T2.SetCoefficents([0, 1]);                                          // x
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);                  // x^q
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);                  // x^(q^2)
            BigNumberPolynomialGaloisAdd(T2, T2, T2, Q, LDP);                   // 2*x^(q^2)

            T3.SetCoefficents([0, 1]);
            BigNumberPolynomialGaloisAdd(T2, T2, T3, Q, LDP);                   // T2 �õ� 2x^(p^2)+x)���ͷ� T3

            BigNumberPolynomialGaloisMul(T2, T2, PAlpha, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);                // T2 �õ� (2x^(p^2)+x)*a*b^2

            BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP);                   // T1 �õ� (2x^(p^2)+x)*a*b^2 - b^3*y^(p^2-1) - y^2 * a^3�����ͷ� T2

            BigNumberPolynomialGaloisMul(T1, T1, F(K), Q, LDP);
            BigNumberPolynomialGaloisMul(T1, T1, F(K), Q, LDP);                 // T1 �ٳ��� Fk^2
            BigNumberPolynomialGaloisMul(T1, T1, Y2, Q, LDP);                   // T1 �ٳ��� y^2

            BigNumberPolynomialGaloisMul(T2, PAlpha, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, PBeta, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, F(K - 1), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, F(K + 1), Q, LDP);             // T2 �õ� a*b^2 * Fk-1* Fk+1

            BigNumberPolynomialGaloisSub(T1, T1, T2, Q, LDP);                   // T1 �õ�δ���� 4Ft^3p �ĵ�һ����������ͷ� T2

            BigNumberPolynomialCopy(T2, F(T));                                  // �� T2 ���� 4Ft^3p
            BigNumberCopy(QT, Q);
            BigNumberMulWord(QT, 3);
            BigNumberPolynomialGaloisPower(T2, T2, QT, Q, LDP);
            BigNumberPolynomialGaloisMulWord(T2, 4, Q);                         // T2 �õ� 4Ft^3p

            BigNumberPolynomialGaloisMul(T1, T1, T2, Q, LDP);                   // T1 �õ���һ�����������ֻռ�� T1

            // ����ڶ��������� b^3 * Fk^2 * (Ft-1^2 * Ft+2 - Ft-2 * Ft+1^2)^p
            BigNumberPolynomialGaloisMul(T2, F(T - 1), F(T + 2), Q, LDP);
            BigNumberPolynomialGaloisMul(T2, F(T - 1), T2, Q, LDP);
            BigNumberPolynomialGaloisMul(T3, F(T + 1), F(T - 2), Q, LDP);
            BigNumberPolynomialGaloisMul(T3, F(T + 1), T3, Q, LDP);

            BigNumberPolynomialGaloisSub(T2, T2, T3, Q, LDP);                   // �õ���ʽ Ft-1^2 * Ft+2 - Ft-2 * Ft+1^2�����ͷ� T3
            BigNumberPolynomialGaloisPower(T2, T2, Q, Q, LDP);                  // p �η�

            BigNumberPolynomialGaloisMul(T3, F(K), F(K), Q, LDP);               // T3 �õ� Fk^2
            BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);                   // T2 ���� T3�����ͷ� T3

            BigNumberPolynomialGaloisPower(T3, PBeta, 3, Q, LDP);
            BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);                   // T2 �ٳ��� T3���õ��ڶ�����������ͷ� T3

            if T and 1 = 0 then // T ��ż��������һҪ��
            begin
              // ���� y^(3p-1)
              BigNumberCopy(QT, Q);
              BigNumberMulWord(QT, 3);
              BigNumberSubWord(QT, 1);
              QT.ShiftRightOne;

              BigNumberPolynomialGaloisPower(T3, Y2, QT, Q, LDP);
              BigNumberPolynomialGaloisMul(T1, T1, T3, Q, LDP);
            end
            else // T ���棬�������Ҫ��
            begin
              // ���� y^(p+1)
              BigNumberCopy(QT, Q);
              BigNumberAddWord(QT, 1);
              QT.ShiftRightOne;

              BigNumberPolynomialGaloisPower(T3, Y2, QT, Q, LDP);
              BigNumberPolynomialGaloisMul(T2, T2, T3, Q, LDP);
            end;

            BigNumberPolynomialGaloisSub(P19Y, T1, T2, Q, LDP);  // �����������õ� P19Y

            BigNumberPolynomialGaloisGreatestCommonDivisor(T1, P19Y, LDP, Q);

            if T1.IsOne then // ��Ϊ 1 ʱ T������ -T
              Ta[I] := T
            else
              Ta[I] := L - T;
          end;
        end;
      end;
    end;

    // ����������������й�ʣ�ඨ�������ս�
    BigNumberChineseRemainderTheorem(Res, Ta, Pa);

    // ע������� T �������� Hasse ����T �ľ���ֵ <= 2 * ���� Q���糬����Χ����������
    BigNumberSqrt(QMax, Q);
    QMax.AddWord(1);
    QMax.ShiftLeftOne;     // QMax ���ã��� 2 ���� Q + 1�������ֵ����� Res ��

    if BigNumberUnsignedCompare(Res, QMax) >= 0 then
    begin
      // �й�ʣ�ඨ�������һ������С��������Ҫ��ȥȫ�� Pa �ĳ˻�
      QMul.SetOne;
      for J := 0 to Pa.Count - 1 do
      begin
        BQ.SetInt64(Pa[J]);
        BigNumberMul(QMul, QMul, BQ);
      end;

      if Res.IsNegative then
        BigNumberAdd(Res, Res, QMul)
      else
        BigNumberSub(Res, Res, QMul);
    end;

    Res.Negate;
    BigNumberAdd(Res, Res, Q);
    Res.AddWord(1); // Q + 1 - L
    Result := True;
  finally
    FEccPolynomialPool.Recycle(PXP2X);
    FEccPolynomialPool.Recycle(PXPX);
    FEccPolynomialPool.Recycle(NPXP2X);
    FEccPolynomialPool.Recycle(PXP2XPX);
    FEccPolynomialPool.Recycle(T1);
    FEccPolynomialPool.Recycle(T2);
    FEccPolynomialPool.Recycle(T3);
    FEccPolynomialPool.Recycle(T4);
    FEccPolynomialPool.Recycle(P16);
    FEccPolynomialPool.Recycle(P17);
    FEccPolynomialPool.Recycle(P18);
    FEccPolynomialPool.Recycle(P19X);
    FEccPolynomialPool.Recycle(P19Y);
    FEccPolynomialPool.Recycle(PAlpha);
    FEccPolynomialPool.Recycle(PBeta);

    FEccPolynomialPool.Recycle(Y2);
    FEccPolynomialPool.Recycle(P1);
    FEccPolynomialPool.Recycle(P2);

    FEccPolynomialPool.Recycle(G);

    FEccBigNumberPool.Recycle(QMax);
    FEccBigNumberPool.Recycle(QMul);
    FEccBigNumberPool.Recycle(BQ);
    FEccBigNumberPool.Recycle(Q12);
    FEccBigNumberPool.Recycle(Q32);
    FEccBigNumberPool.Recycle(Q23);
    FEccBigNumberPool.Recycle(QT);

    DPs.Free;
    Pa.Free;
    Ta.Free;
  end;
end;

{ TCnEcc3Point }

procedure TCnEcc3Point.Assign(Source: TPersistent);
begin
  if Source is TCnEcc3Point then
  begin
    BigNumberCopy(FX, (Source as TCnEcc3Point).X);
    BigNumberCopy(FY, (Source as TCnEcc3Point).Y);
    BigNumberCopy(FZ, (Source as TCnEcc3Point).Z);
  end
  else
    inherited;
end;

constructor TCnEcc3Point.Create;
begin
  inherited;
  FX := TCnBigNumber.Create;
  FY := TCnBigNumber.Create;
  FZ := TCnBigNumber.Create;
end;

destructor TCnEcc3Point.Destroy;
begin
  FZ.Free;
  FY.Free;
  FX.Free;
  inherited;
end;

function TCnEcc3Point.IsZero: Boolean;
begin
  Result := Z.IsZero;
end;

procedure TCnEcc3Point.SetX(const Value: TCnBigNumber);
begin
  BigNumberCopy(FX, Value);
end;

procedure TCnEcc3Point.SetY(const Value: TCnBigNumber);
begin
  BigNumberCopy(FY, Value);
end;

procedure TCnEcc3Point.SetZ(const Value: TCnBigNumber);
begin
  BigNumberCopy(FZ, Value);
end;

procedure TCnEcc3Point.SetZero;
begin
  X.SetZero;
  Y.SetZero;
  Z.SetZero;
end;

function TCnEcc3Point.ToString: string;
begin
  Result := CnEcc3PointToHex(Self);
end;

{ TCnEccSignature }

procedure TCnEccSignature.Assign(Source: TPersistent);
begin
  if Source is TCnEccSignature then
  begin
    BigNumberCopy(FR, (Source as TCnEccSignature).R);
    BigNumberCopy(FS, (Source as TCnEccSignature).S);
  end
  else
    inherited;
end;

constructor TCnEccSignature.Create;
begin
  inherited;
  FR := TCnBigNumber.Create;
  FS := TCnBigNumber.Create;
end;

destructor TCnEccSignature.Destroy;
begin
  FS.Free;
  FR.Free;
  inherited;
end;

function TCnEccSignature.SetAsn1Base64(const Buf: AnsiString): Boolean;
var
  B: TBytes;
  Reader: TCnBerReader;
  NR, NS: TCnBerReadNode;
begin
  Result := False;
  Reader := nil;

  try
    if Base64Decode(string(Buf), B) = ECN_BASE64_OK then
    begin
      Reader := TCnBerReader.Create(PByte(@B[0]), Length(B));
      Reader.ParseToTree;

      if Reader.TotalCount = 3 then
      begin
        NR := Reader.Items[1];
        NS := Reader.Items[2];

        PutIndexedBigIntegerToBigNumber(NR, FR);
        PutIndexedBigIntegerToBigNumber(NS, FS);
        Result := True;
      end;
    end;
  finally
    Reader.Free;
  end;
end;

function TCnEccSignature.SetAsn1Hex(const Buf: AnsiString): Boolean;
var
  B: TBytes;
  Reader: TCnBerReader;
  NR, NS: TCnBerReadNode;
begin
  Result := False;
  B := HexToBytes(string(Buf));
  if Length(B) <= 1 then
    Exit;

  Reader := nil;
  try
    Reader := TCnBerReader.Create(PByte(@B[0]), Length(B));
    Reader.ParseToTree;

    if Reader.TotalCount = 3 then
    begin
      NR := Reader.Items[1];
      NS := Reader.Items[2];

      PutIndexedBigIntegerToBigNumber(NR, FR);
      PutIndexedBigIntegerToBigNumber(NS, FS);
      Result := True;
    end;
  finally
    Reader.Free;
  end;
end;

function TCnEccSignature.SetBase64(const Buf: AnsiString): Boolean;
var
  B: TBytes;
begin
  Result := False;
  if Base64Decode(string(Buf), B) = ECN_BASE64_OK then
  begin
    SetHex(AnsiString(BytesToHex(B)));
    Result := True;
  end;
end;

procedure TCnEccSignature.SetHex(const Buf: AnsiString);
var
  C: Integer;
begin
  if (Length(Buf) < 4) or ((Length(Buf) mod 4) <> 0) then
    raise ECnEccException.Create(SCnErrorEccKeyData);

  // һ��һ�룬���ȵ����
  C := Length(Buf) div 2;
  FR.SetHex(Copy(Buf, 1, C));
  FS.SetHex(Copy(Buf, C + 1, MaxInt));
end;

function TCnEccSignature.ToAsn1Base64: string;
var
  Writer: TCnBerWriter;
  Root: TCnBerWriteNode;
  Stream: TMemoryStream;
begin
  Writer := nil;
  Stream := nil;

  try
    Writer := TCnBerWriter.Create;

    Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);
    AddBigNumberToWriter(Writer, FR, Root);
    AddBigNumberToWriter(Writer, FS, Root);

    Stream := TMemoryStream.Create;
    Writer.SaveToStream(Stream);

    Base64Encode(Stream.Memory, Stream.Size, Result);
  finally
    Writer.Free;
    Stream.Free;
  end;
end;

function TCnEccSignature.ToAsn1Hex(FixedLen: Integer): string;
var
  Writer: TCnBerWriter;
  Root: TCnBerWriteNode;
  Stream: TMemoryStream;
begin
  Writer := nil;
  Stream := nil;

  try
    Writer := TCnBerWriter.Create;

    Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);

    // ������� FixedLen ��Ҫ��Ŀ�� ASN1 ����ʱ�����Ϊ��ǰ�� 0 ����λ������Ҳ��ͨ��
    // �������ʱ���׸����Գ��Ȳ�һ���������������ϣ��������ָ���̶�����
    AddBigNumberToWriter(Writer, FR, Root, CN_BER_TAG_INTEGER, FixedLen);
    AddBigNumberToWriter(Writer, FS, Root, CN_BER_TAG_INTEGER, FixedLen);

    Stream := TMemoryStream.Create;
    Writer.SaveToStream(Stream);

    Result := DataToHex(Stream.Memory, Stream.Size);
  finally
    Writer.Free;
    Stream.Free;
  end;
end;

function TCnEccSignature.ToBase64(FixedLen: Integer): string;
var
  M: TMemoryStream;
begin
  M := TMemoryStream.Create;
  try
    FR.SaveToStream(M, FixedLen);
    FS.SaveToStream(M, FixedLen);
    Base64Encode(M.Memory, M.Size, Result);
  finally
    M.Free;
  end;
end;

function TCnEccSignature.ToHex(FixedLen: Integer): string;
begin
  Result := FR.ToHex(FixedLen) + FS.ToHex(FixedLen);
end;

{ TCnEcc2Matrix }

constructor TCnEcc2Matrix.Create(ARow, ACol: Integer);
var
  I, J: Integer;
begin
  inherited;
  for I := 0 to RowCount - 1 do
    for J := 0 to ColCount - 1 do
      ValueObject[I, J] := TCnEccPoint.Create;
end;

function TCnEcc2Matrix.GetValueObject(Row, Col: Integer): TCnEccPoint;
begin
  Result := TCnEccPoint(inherited GetValueObject(Row, Col));
end;

procedure TCnEcc2Matrix.SetValueObject(Row, Col: Integer;
  const Value: TCnEccPoint);
begin
  inherited SetValueObject(Row, Col, Value);
end;

{ TCnEcc3Matrix }

constructor TCnEcc3Matrix.Create(ARow, ACol: Integer);
var
  I, J: Integer;
begin
  inherited;
  for I := 0 to RowCount - 1 do
    for J := 0 to ColCount - 1 do
      ValueObject[I, J] := TCnEcc3Point.Create;
end;

function TCnEcc3Matrix.GetValueObject(Row, Col: Integer): TCnEcc3Point;
begin
  Result := TCnEcc3Point(inherited GetValueObject(Row, Col));
end;

procedure TCnEcc3Matrix.SetValueObject(Row, Col: Integer;
  const Value: TCnEcc3Point);
begin
  inherited SetValueObject(Row, Col, Value);
end;

initialization
  FEccBigNumberPool := TCnBigNumberPool.Create;
  FEccInt64PolynomialPool := TCnInt64PolynomialPool.Create;
  FEccPolynomialPool := TCnBigNumberPolynomialPool.Create;
  FEccInt64RationalPolynomialPool := TCnInt64RationalPolynomialPool.Create;
  FEccRationalPolynomialPool := TCnBigNumberRationalPolynomialPool.Create;

finalization
  FEccInt64RationalPolynomialPool.Free;
  FEccRationalPolynomialPool.Free;
  FEccPolynomialPool.Free;
  FEccInt64PolynomialPool.Free;
  FEccBigNumberPool.Free;

end.
