{******************************************************************************}
{                       CnPack For Delphi/C++Builder                           }
{                     �й����Լ��Ŀ���Դ�������������                         }
{                   (C)Copyright 2001-2020 CnPack ������                       }
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

unit CnSM9;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ������������� SM9 ������Բ����˫����ӳ��ı�ʶ�����㷨��Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
*           �ο��� GmSSL/PBC/Federico2014 Դ�롣
* ��    ע������Ԫʵ���˹����������� SM9 ������Բ����˫����ӳ��ı�ʶ�����㷨��
*
*           ���Ρ��ĴΡ�ʮ��������ֱ��� U V W �˷�������Ԫ�طֱ��� FP2��FP4��FP12 ��ʾ
*           G1 �� G2 Ⱥ����� TCnEccPoint �� TCnFP2Point ����ΪԪ������㣬���� X Y
*           ��������ϵ/�ſɱ�����ϵ�����Ԫ��Ҳ�мӡ��ˡ��󷴡�Frobenius �Ȳ���
*           ����������ʵ���˻��� SM9 �� BN ���߲����Ļ��� R-ate ����
*           �Լ���һ��ʵ���˳����ǩ����ǩ����Կ��װ���ӽ�������Կ�����ȵ��͹��ܡ�
*           �����ڹ��ܱ�׼ GM/T 0044-2016��SM9 ��ʶ�����㷨��ʵ�ֲ�ͨ��ʾ��������֤��
*
*           ע�� Miller �㷨�Ƕ����� F(q^k) �����ϵ���Բ�����еģ����һ��Ԫ���� k ά����
*           ��ȷ�� Miller �㷨�������ʵ������ʲô��
*
* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2022.07.21 V1.4
*               ȥ���������õ��ж�
*           2022.01.02 V1.3
*               ʵ����Կ�����Ĺ���
*           2022.01.01 V1.2
*               ʵ�ּӽ��ܵĹ���
*           2021.12.30 V1.1
*               ʵ��ǩ����ǩ����Կ��װ�Ĺ��ܣ������ٶ�����
*           2020.04.04 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  Classes, SysUtils, SysConst,
  CnConsts, CnContainers, CnNative, CnBigNumber, CnECC, CnSM3;

const
  CN_SM9_T = '600000000058F98A';
  {* һ������ T����֪����ɶ���� SM9 ��ѡ��� BN �����
     �����������׺͸��ޱ�����˹��̬ͬӳ��ļ����� T ��ָ���Ķ���ʽ���ʽ}

  CN_SM9_ECC_A = 0;
  {* SM9 ��Բ���߷��̵� A ϵ��ֵ}

  CN_SM9_ECC_B = 5;
  {* SM9 ��Բ���߷��̵� B ϵ��ֵ}

  CN_SM9_FINITE_FIELD = 'B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D';
  {* SM9 ��Բ���ߵ�������Ҳ�л������������������ 36T^4 + 36T^3 + 24T^2 + 6T + 1}

  CN_SM9_ORDER = 'B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25';
  {* SM9 ��Բ���ߵĽף�Ҳ�����ܵ�������������� 36T^4 + 36T^3 + 18T^2 + 6T + 1
     ��ò�ƽ� N��Ҫ���� cf ���ܽ� Order�������� cf = 1������ N �� Order �ȼۣ�}

  CN_SM9_CF = 1;
  {* SM9 ��Բ���ߵ������ӣ����� N �͵õ���}

  CN_SM9_K = 12;
  {* SM9 ��Բ���ߵ�Ƕ�������Ҳ���� Prime ����СǶ������η��� Order ��ģΪ 1}

  CN_SM9_FROBENIUS_TRACE = 'D8000000019062ED0000B98B0CB27659';
  {* ���ޱ�����˹��̬ͬӳ��ļ���Ҳ���� Hasse �����е� ��=q+1-trace �е� trace
     �� SM9 ��Բ�����е��� 6T^2 + 1}

  CN_SM9_G1_P1X = '93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD';
  {* G1 ����Ԫ�ĵ����� X}
  CN_SM9_G1_P1Y = '21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616';
  {* G1 ����Ԫ�ĵ����� Y}

  CN_SM9_G2_P2X0 = '3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B';
  {* G2 ����Ԫ��˫���� X0}
  CN_SM9_G2_P2X1 = '85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141';
  {* G2 ����Ԫ��˫���� X1}
  CN_SM9_G2_P2Y0 = 'A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7';
  {* G2 ����Ԫ��˫���� Y0}
  CN_SM9_G2_P2Y1 = '17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96';
  {* G2 ����Ԫ��˫���� Y1}

  CN_SM9_6T_PLUS_2 = '02400000000215D93E';
  {* R-ate �Եļ����������ʵ���� 6T + 2}

  CN_SM9_FAST_EXP_P3 = '5C5E452404034E2AF12FCAD3B31FE2B0D62CD8FB7B497A0ADC53E586930846F1' +
    'BA4CADE09029E4717C0CA02D9B0D8649A5782C82FDB6B0A10DA3D71BCDB13FE5E0D49DE3AA8A4748' +
    '83687EE0C6D9188C44BF9D0FA74DDFB7A9B2ADA593152855';
  {* һ�� SM9 ���ټ������}

  CN_SM9_FAST_EXP_PW20 = 'F300000002A3A6F2780272354F8B78F4D5FC11967BE65334';
  {* һ�� SM9 ���ټ������}
  CN_SM9_FAST_EXP_PW21 = 'B640000002A3A6F0E303AB4FF2EB2052A9F02115CAEF75E70F738991676AF249';
  {* һ�� SM9 ���ټ������}
  CN_SM9_FAST_EXP_PW22 = 'F300000002A3A6F2780272354F8B78F4D5FC11967BE65333';
  {* һ�� SM9 ���ټ������}
  CN_SM9_FAST_EXP_PW23 = 'B640000002A3A6F0E303AB4FF2EB2052A9F02115CAEF75E70F738991676AF24A';
  {* һ�� SM9 ���ټ������}

  CN_SM9_SIGNATURE_USER_HID = 1;
  {* ǩ��˽Կ���ɺ���ʶ���}

  CN_SM9_KEY_EXCHANGE_USER_HID = 2;
  {* ��Կ����ʱ�ļ���˽Կ���ɺ���ʶ���}

  CN_SM9_KEY_ENCAPSULATION_USER_HID = 3;
  {* ��Կ��װ�ļ���˽Կ���ɺ���ʶ���}

  CN_SM9_ENCRYPTION_USER_HID = 3;
  {* ����ʱ�ļ���˽Կ���ɺ���ʶ���}

  CN_SM9_KEY_EXCHANGE_HASHID1 = $82;
  {* ��Կ����ǰ�����е�����ǰ׺֮һ}
  CN_SM9_KEY_EXCHANGE_HASHID2 = $83;
  {* ��Կ����ǰ�����е�����ǰ׺֮��}

  // ������
  ECN_SM9_OK                           = ECN_OK;
  {* SM9 ϵ�д����룺�޴���ֵΪ 0}

  ECN_SM9_ERROR_BASE                   = ECN_CUSTOM_ERROR_BASE + $600; // SM9 �������׼
  {* SM9 ϵ�д�����Ļ�׼��ʼֵ��Ϊ ECN_CUSTOM_ERROR_BASE ���� $600}

  ECN_SM9_INVALID_INPUT                = ECN_SM9_ERROR_BASE + 1;
  {* SM9 ������֮����Ϊ�ջ򳤶ȴ���}
  ECN_SM9_RANDOM_ERROR                 = ECN_SM9_ERROR_BASE + 2;
  {* SM9 ������֮�������ش���}
  ECN_SM9_BIGNUMBER_ERROR              = ECN_SM9_ERROR_BASE + 3;
  {* SM9 ������֮�����������}
  ECN_SM9_ENCRYPT_MASTERKEY_ZERO_ERROR = ECN_SM9_ERROR_BASE + 4;
  {* SM9 ������֮����ʱ����ԿΪ 0}
  ECN_SM9_SIGN_MASTERKEY_ZERO_ERROR    = ECN_SM9_ERROR_BASE + 5;
  {* SM9 ������֮ǩ��ʱ����ԿΪ 0}
  ECN_SM9_HASH_ERROR                   = ECN_SM9_ERROR_BASE + 6;
  {* SM9 ������֮�Ӵմ���}
  ECN_SM9_KDF_ERROR                    = ECN_SM9_ERROR_BASE + 7;
  {* SM9 ������֮��Կ��������}

type
  ECnSM9Exception = class(Exception);
  {* SM9 ����쳣}

  TCnFP2 = class
  {* �����������ϵ��Ԫ��ʵ����}
  private
    F0: TCnBigNumber;
    F1: TCnBigNumber;
    function GetItems(Index: Integer): TCnBigNumber;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    function IsOne: Boolean;
    {* �Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure SetZero;
    {* ����Ϊ 0}

    procedure SetOne;
    {* ����Ϊ 1}

    procedure SetU;
    {* ����Ϊ U ֵ}

    procedure SetBigNumber(Num: TCnBigNumber);
    {* ����Ϊһ������

       ������
         Num: TCnBigNumber                - �����õĴ���

       ����ֵ�����ޣ�
    }

    procedure SetHex(const S0: string; const S1: string);
    {* ����Ϊ����ʮ�������ַ�����

       ������
         const S0: string                 - ʮ�������ַ���һ
         const S1: string                 - ʮ�������ַ�����

       ����ֵ�����ޣ�
    }

    procedure SetWord(Value: Cardinal);
    {* ����Ϊ����������

       ������
         Value: Cardinal                  - �����õ�����

       ����ֵ�����ޣ�
    }

    procedure SetWords(Value0: Cardinal; Value1: Cardinal);
    {* ����Ϊ����������

       ������
         Value0: Cardinal                 - ����һ
         Value1: Cardinal                 - ������

       ����ֵ�����ޣ�
    }

    property Items[Index: Integer]: TCnBigNumber read GetItems; default;
    {* ��Ŀ����}
  end;

  TCnFP2Pool = class(TCnMathObjectPool)
  {* �����������ϵ��Ԫ�س�ʵ���࣬����ʹ�õ������������ϵ��Ԫ�صĵط����д�����}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnFP2; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnFP2                     - ���صĶ����������ϵ������
    }

    procedure Recycle(Num: TCnFP2); reintroduce;
    {* ��һ������黹������ء�

       ������
         Num: TCnFP2                      - ���黹�Ķ����������ϵ������

       ����ֵ�����ޣ�
    }
  end;

  TCnFP4 = class
  {* �Ĵ��������ϵ��Ԫ��ʵ����}
  private
    F0: TCnFP2;
    F1: TCnFP2;
    function GetItems(Index: Integer): TCnFP2;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    function IsOne: Boolean;
    {* �Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure SetZero;
    {* ����Ϊ 0}

    procedure SetOne;
    {* ����Ϊ 1}

    procedure SetU;
    {* ����Ϊ U ֵ}

    procedure SetV;
    {* ����Ϊ V ֵ}

    procedure SetBigNumber(Num: TCnBigNumber);
    {* ����Ϊ����������

       ������
         Num: TCnBigNumber                - �����õĴ���

       ����ֵ�����ޣ�
    }

    procedure SetBigNumbers(Num0, Num1: TCnBigNumber);
    {* ����Ϊ������������

       ������
         Num0: TCnBigNumber               - ����һ
         Num1: TCnBigNumber               - ������

       ����ֵ�����ޣ�
    }

    procedure SetHex(const S0: string; const S1: string; const S2: string; const S3: string);
    {* ����Ϊ�ĸ�ʮ�������ַ�����

       ������
         const S0: string                 - ʮ�������ַ���һ
         const S1: string                 - ʮ�������ַ�����
         const S2: string                 - ʮ�������ַ�����
         const S3: string                 - ʮ�������ַ�����

       ����ֵ�����ޣ�
    }

    procedure SetWord(Value: Cardinal);
    {* ����Ϊ����������

       ������
         Value: Cardinal                  - �����õ�����

       ����ֵ�����ޣ�
    }

    procedure SetWords(Value0, Value1, Value2, Value3: Cardinal);
    {* ����Ϊ�ĸ�����

       ������
         Value0: Cardinal                 - ����һ
         Value1: Cardinal                 - ������
         Value2: Cardinal                 - ������
         Value3: Cardinal                 - ������

       ����ֵ�����ޣ�
    }

    property Items[Index: Integer]: TCnFP2 read GetItems; default;
    {* ��Ŀ����}
  end;

  TCnFP4Pool = class(TCnMathObjectPool)
  {* �Ĵ��������ϵ��Ԫ�س�ʵ���࣬����ʹ�õ��Ĵ��������ϵ��Ԫ�صĵط����д�����}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnFP4; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnFP4                     - ���ص��Ĵ��������ϵ������
    }

    procedure Recycle(Num: TCnFP4); reintroduce;
    {* ��һ������黹������ء�

       ������
         Num: TCnFP4                      - ���黹���Ĵ��������ϵ������

       ����ֵ�����ޣ�
    }
  end;

  TCnFP12 = class
  {* ʮ�����������ϵ��Ԫ��ʵ����}
  private
    F0: TCnFP4;
    F1: TCnFP4;
    F2: TCnFP4;
    function GetItems(Index: Integer): TCnFP4;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    function IsZero: Boolean;
    {* �Ƿ�Ϊ 0��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 0
    }

    function IsOne: Boolean;
    {* �Ƿ�Ϊ 1��

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�Ϊ 1
    }

    procedure SetZero;
    {* ����Ϊ 0}

    procedure SetOne;
    {* ����Ϊ 1}

    procedure SetU;
    {* ����Ϊ U ֵ}

    procedure SetV;
    {* ����Ϊ V ֵ}

    procedure SetW;
    {* ����Ϊ W ֵ}

    procedure SetWSqr;
    {* ����Ϊ W ƽ��ֵ}

    procedure SetBigNumber(Num: TCnBigNumber);
    {* ����Ϊ����������

       ������
         Num: TCnBigNumber                - �����õĴ���

       ����ֵ�����ޣ�
    }

    procedure SetBigNumbers(Num0, Num1, Num2: TCnBigNumber);
    {* ����Ϊ����������

       ������
         Num0: TCnBigNumber               - ����һ
         Num1: TCnBigNumber               - ������
         Num2: TCnBigNumber               - ������

       ����ֵ�����ޣ�
    }

    procedure SetHex(const S0: string; const S1: string; const S2: string; const S3: string;
      const S4: string; const S5: string; const S6: string; const S7: string;
      const S8: string; const S9: string; const S10: string; const S11: string);
    {* ����Ϊʮ����ʮ�������ַ�����

       ������
         const S0: string                 - ʮ�������ַ���һ
         const S1: string                 - ʮ�������ַ�����
         const S2: string                 - ʮ�������ַ�����
         const S3: string                 - ʮ�������ַ�����
         const S4: string                 - ʮ�������ַ�����
         const S5: string                 - ʮ�������ַ�����
         const S6: string                 - ʮ�������ַ�����
         const S7: string                 - ʮ�������ַ�����
         const S8: string                 - ʮ�������ַ�����
         const S9: string                 - ʮ�������ַ���ʮ
         const S10: string                - ʮ�������ַ���ʮһ
         const S11: string                - ʮ�������ַ���ʮ��

       ����ֵ�����ޣ�
    }
      
    procedure SetWord(Value: Cardinal);
    {* ����Ϊ����������

       ������
         Value: Cardinal                  - �����õ�����

       ����ֵ�����ޣ�
    }

    procedure SetWords(Value0: Cardinal; Value1: Cardinal; Value2: Cardinal; Value3: Cardinal;
      Value4: Cardinal; Value5: Cardinal; Value6: Cardinal; Value7: Cardinal;
      Value8: Cardinal; Value9: Cardinal; Value10: Cardinal; Value11: Cardinal);
    {* ����Ϊʮ����������

       ������
         Value0: Cardinal                 - ����һ
         Value1: Cardinal                 - ������
         Value2: Cardinal                 - ������
         Value3: Cardinal                 - ������
         Value4: Cardinal                 - ������
         Value5: Cardinal                 - ������
         Value6: Cardinal                 - ������
         Value7: Cardinal                 - ������
         Value8: Cardinal                 - ������
         Value9: Cardinal                 - ����ʮ
         Value10: Cardinal                - ����ʮһ
         Value11: Cardinal                - ����ʮ��

       ����ֵ�����ޣ�
    }

    property Items[Index: Integer]: TCnFP4 read GetItems; default;
    {* ��Ŀ����}
  end;

  TCnFP12Pool = class(TCnMathObjectPool)
  {* ʮ�����������ϵ��Ԫ�س�ʵ���࣬����ʹ�õ�ʮ�����������ϵ��Ԫ�صĵط����д�����}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnFP12; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnFP12                     - ���ص�ʮ�����������ϵ������
    }

    procedure Recycle(Num: TCnFP12); reintroduce;
    {* ��һ������黹������ء�

       ������
         Num: TCnFP12                     - ���黹��ʮ�����������ϵ������

       ����ֵ�����ޣ�
    }
  end;

  TCnFP2Point = class(TPersistent)
  {* ��ͨ����ϵ��� FP2 ƽ��㣬���������� X Y ��ɣ����ﲻֱ�Ӳ�����㣬��ת���ɷ�������ϵ����}
  private
    FX: TCnFP2;
    FY: TCnFP2;
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

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property X: TCnFP2 read FX;
    {* X ����}
    property Y: TCnFP2 read FY;
    {* Y ����}
  end;

  TCnFP2AffinePoint = class
  {* ��������ϵ��� FP2 ƽ��㣬���������� X Y Z ���}
  private
    FX: TCnFP2;
    FY: TCnFP2;
    FZ: TCnFP2;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    procedure SetZero;
    {* ����Ϊȫ 0���ƺ�ûɶ��}

    function IsAtInfinity: Boolean;
    {* �Ƿ�λ������Զ����

       ������
         ���ޣ�

       ����ֵ��Boolean                    - �����Ƿ�λ������Զ��
    }

    procedure SetToInfinity;
    {* ������Ϊ����Զ}

    procedure GetCoordinatesFP2(FP2X, FP2Y: TCnFP2);
    {* ��ȡ X��Y ����ֵ���ڲ����ø��ơ�

       ������
         FP2X: TCnFP2                     - ����� X ����
         FP2Y: TCnFP2                     - ����� Y ����

       ����ֵ�����ޣ�
    }

    procedure SetCoordinatesFP2(FP2X, FP2Y: TCnFP2);
    {* ���� X��Y ����ֵ���ڲ����ø��ơ�

       ������
         FP2X: TCnFP2                     - �����õ� X ����
         FP2Y: TCnFP2                     - �����õ� Y ����

       ����ֵ�����ޣ�
    }

    procedure SetCoordinatesHex(const SX0: string; const SX1: string;
      const SY0: string; const SY1: string);
    {* ���� X��Y ����ֵ��ʹ��ʮ�������ַ�����

       ������
         const SX0: string                - X0 ��ʮ�������ַ���
         const SX1: string                - X1 ��ʮ�������ַ���
         const SY0: string                - Y0 ��ʮ�������ַ���
         const SY0: string                - Y1 ��ʮ�������ַ���

       ����ֵ�����ޣ�
    }

    procedure SetCoordinatesBigNumbers(X0, X1, Y0, Y1: TCnBigNumber);
    {* ���� X��Y ����ֵ��ʹ�ô��������ڲ����ø��ơ�

       ������
         X0: TCnBigNumber                 - X0 ����ֵ
         X1: TCnBigNumber                 - X1 ����ֵ
         Y0: TCnBigNumber                 - Y0 ����ֵ
         Y1: TCnBigNumber                 - Y1 ����ֵ

       ����ֵ�����ޣ�
    }

    procedure GetJacobianCoordinatesFP12(FP12X: TCnFP12; FP12Y: TCnFP12; Prime: TCnBigNumber);
    {* ��ȡ��չ X��Y ����ֵ���ڲ����ø��ơ�

       ������
         FP12X: TCnFP12                   - ����� X ����ֵ
         FP12Y: TCnFP12                   - ����� Y ����ֵ
         Prime: TCnBigNumber              - �������Ͻ�

       ����ֵ�����ޣ�
    }

    procedure SetJacobianCoordinatesFP12(FP12X: TCnFP12; FP12Y: TCnFP12; Prime: TCnBigNumber);
    {* ������չ X��Y ����ֵ���ڲ����ø��ơ�

       ������
         FP12X: TCnFP12                   - �����õ� X ����ֵ
         FP12Y: TCnFP12                   - �����õ� Y ����ֵ
         Prime: TCnBigNumber              - �������Ͻ�

       ����ֵ�����ޣ�
    }

    function IsOnCurve(Prime: TCnBigNumber): Boolean;
    {* �ж��Ƿ�����Բ���� y^2 = x^3 + 5 �ϡ�

       ������
         Prime: TCnBigNumber              - �������Ͻ�

       ����ֵ��Boolean                    - �����Ƿ��ڸ���Բ������
    }

    property X: TCnFP2 read FX;
    {* X ����}
    property Y: TCnFP2 read FY;
    {* Y ����}
    property Z: TCnFP2 read FZ;
    {* Z ����}
  end;

  TCnFP2AffinePointPool = class(TCnMathObjectPool)
  {* ��������ϵ���ƽ����ʵ���࣬����ʹ�õ���������ϵ���ƽ���ĵط����д�����}
  protected
    function CreateObject: TObject; override;
  public
    function Obtain: TCnFP2AffinePoint; reintroduce;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TCnFP2AffinePoint          - ���صķ�����������
    }

    procedure Recycle(Num: TCnFP2AffinePoint); reintroduce;
    {* ��һ������黹������ء�

       ������
         Num: TCnFP2AffinePoint           - ���黹�ķ�����������

       ����ֵ�����ޣ�
    }
  end;

// ============================ SM9 ����ʵ���� =================================

  TCnSM9SignatureMasterPrivateKey = class(TCnBigNumber);
  {* SM9 �е�ǩ����˽Կ���������}

  TCnSM9SignatureMasterPublicKey  = class(TCnFP2Point);
  {* SM9 �е�ǩ������Կ����ǩ����˽Կ���� G2 �����}

  TCnSM9SignatureMasterKey = class
  {* SM9 �е�ǩ������Կ���� KGC ��Կ�����������ɣ���Կ�ɹ���}
  private
    FPrivateKey: TCnSM9SignatureMasterPrivateKey;
    FPublicKey: TCnSM9SignatureMasterPublicKey;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    property PrivateKey: TCnSM9SignatureMasterPrivateKey read FPrivateKey;
    {* ǩ������Կ�е�˽Կ}
    property PublicKey: TCnSM9SignatureMasterPublicKey read FPublicKey;
    {* ǩ������Կ�еĹ�Կ}
  end;

  TCnSM9SignatureUserPrivateKey = class(TCnEccPoint);
  {* SM9 �е��û�ǩ��˽Կ���� KGC ��Կ�������ĸ����û���ʶ���ɣ��޶�Ӧ��Կ
     ����˵���û���֤ǩ��ʱ�õĹ�Կ�����û���ʶ��ǩ������Կ}

  TCnSM9Signature = class
  {* SM9 ��ǩ��ֵ��ʾ�࣬���� H ������ S ��}
  private
    FH: TCnBigNumber;
    FS: TCnEccPoint;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property H: TCnBigNumber read FH;
    {* ǩ������ H}
    property S: TCnEccPoint read FS;
    {* ǩ������� S}
  end;

  TCnSM9EncryptionMasterPrivateKey = class(TCnBigNumber);
  {* SM9 ��������Կ��װ��ӽ��ܵļ�����˽Կ���������}

  TCnSM9EncryptionMasterPublicKey = class(TCnEccPoint);
  {* SM9 ��������Կ��װ��ӽ��ܵļ�������Կ���ü�����˽Կ���� G1 �����}

  TCnSM9EncryptionMasterKey = class
  {* SM9 ��������Կ��װ��ӽ��ܵļ�������Կ���� KGC ��Կ�����������ɣ���Կ�ɹ���}
  private
    FPrivateKey: TCnSM9EncryptionMasterPrivateKey;
    FPublicKey: TCnSM9EncryptionMasterPublicKey;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    property PrivateKey: TCnSM9EncryptionMasterPrivateKey read FPrivateKey;
    {* ��Կ��װ��ӽ��ܵ�����Կ��˽Կ}
    property PublicKey: TCnSM9EncryptionMasterPublicKey read FPublicKey;
    {* ��Կ��װ��ӽ��ܵ�����Կ�Ĺ�Կ}
  end;

  TCnSM9EncryptionUserPrivateKey = class(TCnFP2Point);
  {* SM9 �е��û�����˽Կ��������Կ��װ��ӽ��ܣ��� KGC ��Կ�������ĸ����û���ʶ���ɣ��޶�Ӧ��Կ
     ����˵���û�����ʱ�õĹ�Կ�����û���ʶ���������Կ}

  TCnSM9KeyEncapsulationCode = class(TCnEccPoint);
  {* ��Կ��װ���������}

  TCnSM9KeyEncapsulation = class
  {* ��Կ��װ����࣬ע�����⴫ֻ��Ҫ�� Code}
  private
    FKey: TBytes;
    FKeyLength: Integer;
    FCode: TCnSM9KeyEncapsulationCode;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}
    {* ת��Ϊ�ַ�����

       ������
         ���ޣ�

       ����ֵ��string                     - �����ַ���
    }

    property KeyByteLength: Integer read FKeyLength;
    {* ���ĵ��ֽڳ���}
    property Key: TBytes read FKey write FKey;
    {* ��װ����Կ���������⴫}
    property Code: TCnSM9KeyEncapsulationCode read FCode;
    {* ��װ�����ģ���Ҫ���⴫}
  end;

  TCnSM9EncrytionMode = (semSM4, semKDF);
  {* SM9 ��Կ���ܵ�����ģʽ���� SM4 ������ܻ� KDF �����������}

  TCnSM9KeyExchangeUserPrivateKey = class(TCnFP2Point);
  {* SM9 �е��û�����˽Կ��������Կ�������� KGC ��Կ�������ĸ����û���ʶ���ɣ��޶�Ӧ��Կ}

  TCnSM9KeyExchangeMasterPrivateKey = class(TCnBigNumber);
  {* SM9 ��������Կ�����ļ�����˽Կ���������}

  TCnSM9KeyExchangeMasterPublicKey = class(TCnEccPoint);
  {* SM9 ��������Կ�����ļ�������Կ���ü�����˽Կ���� G1 �����}

  TCnSM9KeyExchangeMasterKey = class
  {* SM9 ��������Կ�����ļ�������Կ���� KGC ��Կ�����������ɣ���Կ�ɹ���}
  private
    FPrivateKey: TCnSM9KeyExchangeMasterPrivateKey;
    FPublicKey: TCnSM9KeyExchangeMasterPublicKey;
  public
    constructor Create; virtual;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    property PrivateKey: TCnSM9KeyExchangeMasterPrivateKey read FPrivateKey;
    {* ��Կ�����ļ�������Կ��˽Կ}
    property PublicKey: TCnSM9KeyExchangeMasterPublicKey read FPublicKey;
    {* ��Կ�����ļ�������Կ�Ĺ�Կ}
  end;

  TCnSM9 = class(TCnEcc)
  {* SM9 ���ݷ�װ�࣬����Ҳ��һ����Բ��������}
  private
    FGenerator2: TCnFP2Point;
  public
    constructor Create; reintroduce;
    {* ���캯��}
    destructor Destroy; override;
    {* ��������}

    property Generator2: TCnFP2Point read FGenerator2;
    {* G2 ����Ԫ}
  end;

// ====================== �����������ϵ��Ԫ�����㺯�� =========================

function FP2New: TCnFP2;
{* ����һ�����������ϵ��Ԫ�ض��󣬵�ͬ�� TCnFP2.Create��

   ������
     ���ޣ�

   ����ֵ��TCnFP2                         - ���ش����Ķ����������ϵ��Ԫ�ض���
}

procedure FP2Free(FP2: TCnFP2);
{* �ͷ�һ�����������ϵ��Ԫ�ض��󣬵�ͬ�� TCnFP2.Free

   ������
     FP2: TCnFP2                          - ���ͷŵĶ����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

function FP2IsZero(FP2: TCnFP2): Boolean;
{* �ж�һ�����������ϵ��Ԫ�ض����Ƿ�Ϊ 0��

   ������
     FP2: TCnFP2                          - ���жϵĶ����������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

function FP2IsOne(FP2: TCnFP2): Boolean;
{* �ж�һ�����������ϵ��Ԫ�ض����Ƿ�Ϊ 1��

   ������
     FP2: TCnFP2                          - ���жϵĶ����������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 1
}

procedure FP2SetZero(FP2: TCnFP2);
{* ��һ�����������ϵ��Ԫ�ض�������Ϊ 0��

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP2SetOne(FP2: TCnFP2);
{* ��һ�����������ϵ��Ԫ�ض�������Ϊ 1��Ҳ���� [0] Ϊ 1��[1] Ϊ 0��

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

function FP2SetU(FP2: TCnFP2): Boolean;
{* ��һ�����������ϵ��Ԫ�ض�����Ϊ U��Ҳ���� [0] Ϊ 0��[1] Ϊ 1��

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ����óɹ�
}

function FP2SetBigNumber(FP2: TCnFP2; Num: TCnBigNumber): Boolean;
{* ��һ�����������ϵ��Ԫ�ض�������Ϊĳһ��������

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���
     Num: TCnBigNumber                    - �����õĴ�������

   ����ֵ��Boolean                        - �����Ƿ����óɹ�
}

function FP2SetBigNumbers(FP2: TCnFP2; Num0: TCnBigNumber; Num1: TCnBigNumber): Boolean;
{* ��һ�����������ϵ��Ԫ�ض�������Ϊ��������ֵ��

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���
     Num0: TCnBigNumber                   - �����õĴ�������һ
     Num1: TCnBigNumber                   - �����õĴ��������

   ����ֵ��Boolean                        - �����Ƿ����óɹ�
}

function FP2SetHex(FP2: TCnFP2; const S0: string; const S1: string): Boolean;
{* ��һ�����������ϵ��Ԫ�ض�������Ϊ����ʮ�������ַ�����

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���
     const S0: string                     - ʮ�������ַ���һ
     const S1: string                     - ʮ�������ַ�����

   ����ֵ��Boolean                        -
}

function FP2ToString(FP2: TCnFP2): string;
{* ��һ�����������ϵ��Ԫ�ض���ת��Ϊ�ַ�����

   ������
     FP2: TCnFP2                          - ��ת���Ķ����������ϵ��Ԫ�ض���

   ����ֵ��string                         - �����ַ���
}

procedure FP2SetWord(FP2: TCnFP2; Value: Cardinal);
{* ��һ�����������ϵ��Ԫ�ض�������Ϊһ��������

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���
     Value: Cardinal                      -

   ����ֵ�����ޣ�
}

procedure FP2SetWords(FP2: TCnFP2; Value0: Cardinal; Value1: Cardinal);
{* ��һ�����������ϵ��Ԫ�ض�������Ϊ����������

   ������
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���
     Value0: Cardinal                     -
     Value1: Cardinal                     -

   ����ֵ�����ޣ�
}

function FP2Equal(F1: TCnFP2; F2: TCnFP2): Boolean;
{* �ж����������������ϵ��Ԫ�ض���ֵ�Ƿ���ȡ�

   ������
     F1: TCnFP2                           - ���ȽϵĶ����������ϵ��Ԫ�ض���һ
     F2: TCnFP2                           - ���ȽϵĶ����������ϵ��Ԫ�ض����

   ����ֵ��Boolean                        - �����Ƿ����
}

function FP2Copy(Dst: TCnFP2; Src: TCnFP2): TCnFP2;
{* ��һ�����������ϵ��Ԫ�ض���ֵ���Ƶ���һ�������������ϵ��Ԫ�ض����С�

   ������
     Dst: TCnFP2                          - Ŀ������������ϵ��Ԫ�ض���
     Src: TCnFP2                          - Դ�����������ϵ��Ԫ�ض���

   ����ֵ��TCnFP2                         - ����Ŀ������������ϵ��Ԫ�ض���
}

procedure FP2Negate(Res: TCnFP2; F: TCnFP2; Prime: TCnBigNumber);
{* ��һ�����������ϵ��Ԫ�ض���ֵ���������󸺡�

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F: TCnFP2                            - ������Ķ����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Add(Res: TCnFP2; F1: TCnFP2; F2: TCnFP2; Prime: TCnBigNumber);
{* �������ж����������ϵ��Ԫ�ؼӷ���Prime Ϊ��������Res ������ F1��F2��F1 ������ F2��

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F1: TCnFP2                           - ����һ
     F2: TCnFP2                           - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Sub(Res: TCnFP2; F1: TCnFP2; F2: TCnFP2; Prime: TCnBigNumber);
{* �������ж����������ϵ��Ԫ�ؼ�����Prime Ϊ��������Res ������ F1��F2��F1 ������ F2��

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F1: TCnFP2                           - ������
     F2: TCnFP2                           - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Mul(Res: TCnFP2; F1: TCnFP2; F2: TCnFP2; Prime: TCnBigNumber); overload;
{* �������ж����������ϵ��Ԫ�س˷���Prime Ϊ��������Res �������� F1 �� F2��F1 ������ F2��

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F1: TCnFP2                           - ����һ
     F2: TCnFP2                           - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Mul3(Res: TCnFP2; F: TCnFP2; Prime: TCnBigNumber);
{* �������ж����������ϵ��Ԫ�ض������ 3��Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F: TCnFP2                            - ������Ķ����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2MulU(Res: TCnFP2; F1: TCnFP2; F2: TCnFP2; Prime: TCnBigNumber);
{* �������ж����������ϵ��Ԫ�� U �˷���Prime Ϊ��������Res �������� F1 �� F2��F1 ������ F2��

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F1: TCnFP2                           - ����һ
     F2: TCnFP2                           - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Mul(Res: TCnFP2; F: TCnFP2; Num: TCnBigNumber; Prime: TCnBigNumber); overload;
{* �������ж����������ϵ��Ԫ��������ĳ˷���Prime Ϊ��������Res ������ F���� Num ������ Res �� F �е����ݡ�

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F: TCnFP2                            - ����
     Num: TCnBigNumber                    - ��������ʽ�Ǵ���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Inverse(Res: TCnFP2; F: TCnFP2; Prime: TCnBigNumber);
{* �������ж����������ϵ��Ԫ����ģ����Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F: TCnFP2                            - ������Ķ����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2Div(Res: TCnFP2; F1: TCnFP2; F2: TCnFP2; Prime: TCnBigNumber);
{* �������ж����������ϵ��Ԫ�س�����Prime Ϊ��������Res ������ F1��F2��F1 ������ F2���ڲ���ģ���˷�ʵ�֡�

   ������
     Res: TCnFP2                          - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     F1: TCnFP2                           - ������
     F2: TCnFP2                           - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

function FP2ToStream(FP2: TCnFP2; Stream: TStream; FixedLen: Integer = 0): Integer;
{* ��һ�����������ϵ��Ԫ�ض��������д����������д�볤�ȡ�

   ������
     FP2: TCnFP2                          - ��д��Ķ����������ϵ��Ԫ�ض���
     Stream: TStream                      - ��д�����
     FixedLen: Integer                    - ָ������ʵ���ֽڳ��Ȳ���ʱʹ�õĹ̶��ֽڳ��ȣ�Ϊ 0 ʱ��ʹ�ô���ʵ���ֽڳ���

   ����ֵ��Integer                        - ����д���ֽڳ���
}

// ====================== �Ĵ��������ϵ��Ԫ�����㺯�� =========================

function FP4New: TCnFP4;
{* ����һ�Ĵ��������ϵ��Ԫ�ض��󣬵�ͬ�� TCnFP4.Create��

   ������
     ���ޣ�

   ����ֵ��TCnFP4                         - ���ش������Ĵ��������ϵ��Ԫ�ض���
}

procedure FP4Free(FP4: TCnFP4);
{* �ͷ�һ�Ĵ��������ϵ��Ԫ�ض��󣬵�ͬ�� TCnFP4.Free��

   ������
     FP4: TCnFP4                          - ���ͷŵ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

function FP4IsZero(FP4: TCnFP4): Boolean;
{* �ж�һ�Ĵ��������ϵ��Ԫ�ض����Ƿ�Ϊ 0��

   ������
     FP4: TCnFP4                          - ���жϵ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

function FP4IsOne(FP4: TCnFP4): Boolean;
{* �ж�һ�Ĵ��������ϵ��Ԫ�ض����Ƿ�Ϊ 1��

   ������
     FP4: TCnFP4                          - ���жϵ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 1
}

procedure FP4SetZero(FP4: TCnFP4);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊ 0��

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP4SetOne(FP4: TCnFP4);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊ 1��Ҳ���� [0] Ϊ 1��[1] Ϊ 0

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP4SetU(FP4: TCnFP4);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�����Ϊ U��Ҳ���� [0] Ϊ U��[1] Ϊ 0��

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP4SetV(FP4: TCnFP4);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�����Ϊ V��Ҳ���� [0] Ϊ 0��[1] Ϊ 1��

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP4SetBigNumber(FP4: TCnFP4; Num: TCnBigNumber);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊĳһ��������

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     Num: TCnBigNumber                    - �����õĴ���

   ����ֵ�����ޣ�
}

procedure FP4SetBigNumbers(FP4: TCnFP4; Num0: TCnBigNumber; Num1: TCnBigNumber);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊ��������ֵ��

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     Num0: TCnBigNumber                   - �����õĴ���һ
     Num1: TCnBigNumber                   - �����õĴ�����

   ����ֵ�����ޣ�
}

procedure FP4SetFP2(FP4: TCnFP4; FP2: TCnFP2);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊһ�������������ϵ��Ԫ�ء�

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP4Set2FP2S(FP4: TCnFP4; FP20: TCnFP2; FP21: TCnFP2);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊ���������������ϵ��Ԫ��

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     FP20: TCnFP2                         - �����õĶ����������ϵ��Ԫ�ض���һ
     FP21: TCnFP2                         - �����õĶ����������ϵ��Ԫ�ض����

   ����ֵ�����ޣ�
}

procedure FP4SetHex(FP4: TCnFP4; const S0: string; const S1: string;
  const S2: string; const S3: string);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊ�ĸ�ʮ�������ַ�����

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     const S0: string                     - ʮ�������ַ���һ
     const S1: string                     - ʮ�������ַ�����
     const S2: string                     - ʮ�������ַ�����
     const S3: string                     - ʮ�������ַ�����

   ����ֵ�����ޣ�
}

function FP4ToString(FP4: TCnFP4): string;
{* ��һ�Ĵ��������ϵ��Ԫ�ض���ת��Ϊ�ַ�����

   ������
     FP4: TCnFP4                          - ��ת�����Ĵ��������ϵ��Ԫ�ض���

   ����ֵ��string                         - �����ַ���
}

procedure FP4SetWord(FP4: TCnFP4; Value: Cardinal);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊһ��������

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     Value: Cardinal                      - ����

   ����ֵ�����ޣ�
}

procedure FP4SetWords(FP4: TCnFP4; Value0: Cardinal; Value1: Cardinal;
  Value2: Cardinal; Value3: Cardinal);
{* ��һ�Ĵ��������ϵ��Ԫ�ض�������Ϊ�ĸ�������

   ������
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
     Value0: Cardinal                     - ����һ
     Value1: Cardinal                     - ������
     Value2: Cardinal                     - ������
     Value3: Cardinal                     - ������

   ����ֵ�����ޣ�
}

function FP4Equal(F1: TCnFP4; F2: TCnFP4): Boolean;
{* �ж������Ĵ��������ϵ��Ԫ�ض���ֵ�Ƿ���ȡ�

   ������
     F1: TCnFP4                           - ���Ƚϵ��Ĵ��������ϵ��Ԫ�ض���һ
     F2: TCnFP4                           - ���Ƚϵ��Ĵ��������ϵ��Ԫ�ض����

   ����ֵ��Boolean                        - �����Ƿ����
}

function FP4Copy(Dst: TCnFP4; Src: TCnFP4): TCnFP4;
{* ��һ�Ĵ��������ϵ��Ԫ�ض���ֵ���Ƶ���һ���Ĵ��������ϵ��Ԫ�ض����С�

   ������
     Dst: TCnFP4                          - Ŀ���Ĵ��������ϵ��Ԫ�ض���
     Src: TCnFP4                          - Դ�Ĵ��������ϵ��Ԫ�ض���

   ����ֵ��TCnFP4                         - ����Ŀ���Ĵ��������ϵ��Ԫ�ض���
}

procedure FP4Negate(Res: TCnFP4; F: TCnFP4; Prime: TCnBigNumber);
{* ��һ�Ĵ��������ϵ��Ԫ�ض���ֵ���������󸺡�

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F: TCnFP4                            - ��������Ĵ��������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4Add(Res: TCnFP4; F1: TCnFP4; F2: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ�ؼӷ���Prime Ϊ��������Res ������ F1��F2��F1 ������ F2��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F1: TCnFP4                           - ����һ
     F2: TCnFP4                           - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4Sub(Res: TCnFP4; F1: TCnFP4; F2: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ�ؼ�����Prime Ϊ��������Res ������ F1��F2��F1 ������ F2��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F1: TCnFP4                           - ������
     F2: TCnFP4                           - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4Mul(Res: TCnFP4; F1: TCnFP4; F2: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ�س˷���Prime Ϊ��������Res �������� F1 �� F2��F1 ������ F2��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F1: TCnFP4                           - ����һ
     F2: TCnFP4                           - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4Mul3(Res: TCnFP4; F: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ�ض������ 3��Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F: TCnFP4                            - ��������Ĵ��������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4MulV(Res: TCnFP4; F1: TCnFP4; F2: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ�� V �˷���Prime Ϊ��������Res �������� F1 �� F2��F1 ������ F2��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F1: TCnFP4                           - ����һ
     F2: TCnFP4                           - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4Inverse(Res: TCnFP4; F: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ����ģ����Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F: TCnFP4                            - ��������Ĵ��������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP4Div(Res: TCnFP4; F1: TCnFP4; F2: TCnFP4; Prime: TCnBigNumber);
{* ���������Ĵ��������ϵ��Ԫ�س�����Prime Ϊ��������Res ������ F1��F2��F1 ������ F2���ڲ���ģ���˷�ʵ��

   ������
     Res: TCnFP4                          - �������ɽ�����Ĵ��������ϵ��Ԫ�ض���
     F1: TCnFP4                           - ������
     F2: TCnFP4                           - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

function FP4ToStream(FP4: TCnFP4; Stream: TStream; FixedLen: Integer = 0): Integer;
{* ��һ�Ĵ��������ϵ��Ԫ�ض��������д����������д�볤�ȡ�

   ������
     FP4: TCnFP4                          - ��д����Ĵ��������ϵ��Ԫ�ض���
     Stream: TStream                      - ��д�����
     FixedLen: Integer                    - ָ������ʵ���ֽڳ��Ȳ���ʱʹ�õĹ̶��ֽڳ��ȣ�Ϊ 0 ʱ��ʹ�ô���ʵ���ֽڳ���

   ����ֵ��Integer                        - ����д���ֽڳ���
}

// ===================== ʮ�����������ϵ��Ԫ�����㺯�� ========================

function FP12New: TCnFP12;
{* ����һʮ�����������ϵ��Ԫ�ض��󣬵�ͬ�� TCnFP12.Create��

   ������
     ���ޣ�

   ����ֵ��TCnFP12                        - ���ش�����ʮ�����������ϵ��Ԫ�ض���
}

procedure FP12Free(FP12: TCnFP12);
{* �ͷ�һʮ�����������ϵ��Ԫ�ض��󣬵�ͬ�� TCnFP12.Free��

   ������
     FP12: TCnFP12                        - ���ͷŵ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

function FP12IsZero(FP12: TCnFP12): Boolean;
{* �ж�һʮ�����������ϵ��Ԫ�ض����Ƿ�Ϊ 0��

   ������
     FP12: TCnFP12                        - ���жϵ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 0
}

function FP12IsOne(FP12: TCnFP12): Boolean;
{* �ж�һʮ�����������ϵ��Ԫ�ض����Ƿ�Ϊ 1��

   ������
     FP12: TCnFP12                        - ���жϵ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ��Boolean                        - �����Ƿ�Ϊ 1
}

procedure FP12SetZero(FP12: TCnFP12);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊ 0��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetOne(FP12: TCnFP12);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊ 1��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetU(FP12: TCnFP12);
{* ��һʮ�����������ϵ��Ԫ�ض�����Ϊ U��Ҳ������ FP4 �ֱ� U��0��0��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetV(FP12: TCnFP12);
{* ��һʮ�����������ϵ��Ԫ�ض�����Ϊ V��Ҳ������ FP4 �ֱ� V��0��0��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetW(FP12: TCnFP12);
{* ��һʮ�����������ϵ��Ԫ�ض�����Ϊ W��Ҳ������ FP4 �ֱ� 0��1��0��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetWSqr(FP12: TCnFP12);
{* ��һʮ�����������ϵ��Ԫ�ض�����Ϊ W^2��Ҳ������ FP4 �ֱ� 0��0��1��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetBigNumber(FP12: TCnFP12; Num: TCnBigNumber);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊĳһ��������

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     Num: TCnBigNumber                    - �����õĴ���

   ����ֵ�����ޣ�
}

procedure FP12SetBigNumbers(FP12: TCnFP12; Num0: TCnBigNumber;
  Num1: TCnBigNumber; Num2: TCnBigNumber);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊ��������ֵ��

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     Num0: TCnBigNumber                   - �����õĴ���һ
     Num1: TCnBigNumber                   - �����õĴ�����
     Num2: TCnBigNumber                   - �����õĴ�����

   ����ֵ�����ޣ�
}

procedure FP12SetFP4(FP12: TCnFP12; FP4: TCnFP4);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊһ���Ĵ��������ϵ��Ԫ�ء�

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     FP4: TCnFP4                          - �����õ��Ĵ��������ϵ��Ԫ�ض���
                                            
   ����ֵ�����ޣ�
}

procedure FP12Set3FP4S(FP12: TCnFP12; FP40: TCnFP4; FP41: TCnFP4; FP42: TCnFP4);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊ�����Ĵ��������ϵ��Ԫ�ء�

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     FP40: TCnFP4                         - �����õ��Ĵ��������ϵ��Ԫ��һ
     FP41: TCnFP4                         - �����õ��Ĵ��������ϵ��Ԫ�ض�
     FP42: TCnFP4                         - �����õ��Ĵ��������ϵ��Ԫ����

   ����ֵ�����ޣ�
}

procedure FP12SetFP2(FP12: TCnFP12; FP2: TCnFP2);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊһ�������������ϵ��Ԫ�ء�

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     FP2: TCnFP2                          - �����õĶ����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP12SetHex(FP12: TCnFP12; const S0: string; const S1: string;
  const S2: string; const S3: string; const S4: string; const S5: string;
  const S6: string; const S7: string; const S8: string; const S9: string;
  const S10: string; const S11: string);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊʮ����ʮ�������ַ�����

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     const S0: string                     - ʮ�������ַ���һ
     const S1: string                     - ʮ�������ַ�����
     const S2: string                     - ʮ�������ַ�����
     const S3: string                     - ʮ�������ַ�����
     const S4: string                     - ʮ�������ַ�����
     const S5: string                     - ʮ�������ַ�����
     const S6: string                     - ʮ�������ַ�����
     const S7: string                     - ʮ�������ַ�����
     const S8: string                     - ʮ�������ַ�����
     const S9: string                     - ʮ�������ַ���ʮ
     const S10: string                    - ʮ�������ַ���ʮһ
     const S11: string                    - ʮ�������ַ���ʮ��

   ����ֵ�����ޣ�
}

function FP12ToString(FP12: TCnFP12): string;
{* ��һʮ�����������ϵ��Ԫ�ض���ת��Ϊ�ַ�����

   ������
     FP12: TCnFP12                        - ��ת����ʮ�����������ϵ��Ԫ�ض���

   ����ֵ��string                         - �����ַ���
}

procedure FP12SetWord(FP12: TCnFP12; Value: Cardinal);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊһ��������

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     Value: Cardinal                      - �����õ�����

   ����ֵ�����ޣ�
}

procedure FP12SetWords(FP12: TCnFP12; Value0: Cardinal; Value1: Cardinal;
  Value2: Cardinal; Value3: Cardinal; Value4: Cardinal; Value5: Cardinal;
  Value6: Cardinal; Value7: Cardinal; Value8: Cardinal; Value9: Cardinal;
  Value10: Cardinal; Value11: Cardinal);
{* ��һʮ�����������ϵ��Ԫ�ض�������Ϊʮ����������

   ������
     FP12: TCnFP12                        - �����õ�ʮ�����������ϵ��Ԫ�ض���
     Value0: Cardinal                     - ����һ
     Value1: Cardinal                     - ������
     Value2: Cardinal                     - ������
     Value3: Cardinal                     - ������
     Value4: Cardinal                     - ������
     Value5: Cardinal                     - ������
     Value6: Cardinal                     - ������
     Value7: Cardinal                     - ������
     Value8: Cardinal                     - ������
     Value9: Cardinal                     - ����ʮ
     Value10: Cardinal                    - ����ʮһ
     Value11: Cardinal                    - ����ʮ��

   ����ֵ�����ޣ�
}

function FP12Equal(F1: TCnFP12; F2: TCnFP12): Boolean;
{* �ж�����ʮ�����������ϵ��Ԫ�ض���ֵ�Ƿ����

   ������
     F1: TCnFP12                          - ���Ƚϵ�ʮ�����������ϵ��Ԫ�ض���һ
     F2: TCnFP12                          - ���Ƚϵ�ʮ�����������ϵ��Ԫ�ض����

   ����ֵ��Boolean                        - �����Ƿ����
}

function FP12Copy(Dst: TCnFP12; Src: TCnFP12): TCnFP12;
{* ��һʮ�����������ϵ��Ԫ�ض���ֵ���Ƶ���һ��ʮ�����������ϵ��Ԫ�ض����С�

   ������
     Dst: TCnFP12                         - Ŀ��ʮ�����������ϵ��Ԫ�ض���
     Src: TCnFP12                         - Դʮ�����������ϵ��Ԫ�ض���

   ����ֵ��TCnFP12                        - ����Ŀ��ʮ�����������ϵ��Ԫ�ض���
}

procedure FP12Negate(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
{* ��һʮ�����������ϵ��Ԫ�ض���ֵ���������󸺡�

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F: TCnFP12                           - �������ʮ�����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Add(Res: TCnFP12; F1: TCnFP12; F2: TCnFP12; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ�ؼӷ���Prime Ϊ��������Res ������ F1��F2��F1 ������ F2

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F1: TCnFP12                          - ����һ
     F2: TCnFP12                          - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Sub(Res: TCnFP12; F1: TCnFP12; F2: TCnFP12; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ�ؼ�����Prime Ϊ��������Res ������ F1��F2��F1 ������ F2��

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F1: TCnFP12                          - ������
     F2: TCnFP12                          - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Mul(Res: TCnFP12; F1: TCnFP12; F2: TCnFP12; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ�س˷���Prime Ϊ��������Res �������� F1 �� F2��F1 ������ F2��

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F1: TCnFP12                          - ����һ
     F2: TCnFP12                          - ������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Mul3(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ�ض������ 3��Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F: TCnFP12                           - �������ʮ�����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Inverse(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ����ģ����Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F: TCnFP12                           - �������ʮ�����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Div(Res: TCnFP12; F1: TCnFP12; F2: TCnFP12; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ�س�����Prime Ϊ��������Res ������ F1��F2��F1 ������ F2���ڲ���ģ���˷�ʵ�֡�

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F1: TCnFP12                          - ������
     F2: TCnFP12                          - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP12Power(Res: TCnFP12; F: TCnFP12; Exponent: TCnBigNumber; Prime: TCnBigNumber);
{* ��������ʮ�����������ϵ��Ԫ�س˷���Prime Ϊ��������Res ������ F��

   ������
     Res: TCnFP12                         - �������ɽ����ʮ�����������ϵ��Ԫ�ض���
     F: TCnFP12                           - ����
     Exponent: TCnBigNumber               - ָ��
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

function FP12ToStream(FP12: TCnFP12; Stream: TStream; FixedLen: Integer = 0): Integer;
{* ��һʮ�����������ϵ��Ԫ�ض��������д����������д�볤�ȡ�

   ������
     FP12: TCnFP12                        - ��д���ʮ�����������ϵ��Ԫ�ض���
     Stream: TStream                      - ��д�����
     FixedLen: Integer                    - ָ������ʵ���ֽڳ��Ȳ���ʱʹ�õĹ̶��ֽڳ��ȣ�Ϊ 0 ʱ��ʹ�ô���ʵ���ֽڳ���

   ����ֵ��Integer                        - ����д���ֽڳ���
}

// ===================== ��������ϵ�����Ԫ������㺯�� ========================

function FP2AffinePointNew: TCnFP2AffinePoint;
{* ����һ��������ϵ�����Ԫ����󣬵�ͬ�� TCnAffinePoint.Create

   ������
     ���ޣ�

   ����ֵ��TCnFP2AffinePoint              - ���ش����ķ�������ϵ�����Ԫ�����ʵ��
}

procedure AffinePointFree(P: TCnFP2AffinePoint);
{* �ͷ�һ��������ϵ�����Ԫ����󣬵�ͬ�� TCnAffinePoint.Free

   ������
     P: TCnFP2AffinePoint                 - ���ͷŵķ�������ϵ�����Ԫ�����

   ����ֵ�����ޣ�
}

procedure FP2AffinePointSetZero(P: TCnFP2AffinePoint);
{* ��һ����������ϵ�����Ԫ����������Ϊȫ 0��

   ������
     P: TCnFP2AffinePoint                 - �����õķ�������ϵ�����Ԫ�����

   ����ֵ�����ޣ�
}

function FP2AffinePointToString(P: TCnFP2AffinePoint): string;
{* ��һ��������ϵ�����Ԫ�����ת��Ϊ�ַ�����

   ������
     P: TCnFP2AffinePoint                 - ��ת���ķ�������ϵ�����Ԫ�����

   ����ֵ��string                         - �����ַ���
}

function FP2AffinePointEqual(P1: TCnFP2AffinePoint; P2: TCnFP2AffinePoint): Boolean;
{* �ж�������������ϵ�����Ԫ�����ֵ�Ƿ���ȡ�

   ������
     P1: TCnFP2AffinePoint                - ���Ƚϵķ�������ϵ�����Ԫ�����һ
     P2: TCnFP2AffinePoint                - ���Ƚϵķ�������ϵ�����Ԫ������

   ����ֵ��Boolean                        - �����Ƿ����
}

function FP2AffinePointCopy(Dst: TCnFP2AffinePoint; Src: TCnFP2AffinePoint): TCnFP2AffinePoint;
{* ��һ��������ϵ�����Ԫ�����ֵ���Ƶ���һ����������ϵ�����Ԫ������С�

   ������
     Dst: TCnFP2AffinePoint               - Ŀ���������ϵ�����Ԫ�����
     Src: TCnFP2AffinePoint               - ԴĿ���������ϵ�����Ԫ�����

   ����ֵ��TCnFP2AffinePoint              - ����Ŀ���������ϵ�����Ԫ�����
}

function FP2AffinePointIsAtInfinity(P: TCnFP2AffinePoint): Boolean;
{* �ж�һ��������ϵ�����Ԫ������Ƿ�λ������Զ����

   ������
     P: TCnFP2AffinePoint                 - ���жϵķ�������ϵ�����Ԫ�����

   ����ֵ��Boolean                        - �����Ƿ�����Զ
}

procedure FP2AffinePointSetToInfinity(P: TCnFP2AffinePoint);
{* ��һ��������ϵ�����Ԫ�����������Ϊ����Զ��

   ������
     P: TCnFP2AffinePoint                 - �����õķ�������ϵ�����Ԫ�����

   ����ֵ�����ޣ�
}

procedure FP2AffinePointGetCoordinates(P: TCnFP2AffinePoint; FP2X: TCnFP2; FP2Y: TCnFP2);
{* ��ȡһ��������ϵ�����Ԫ������ X��Y ����ֵ���ڲ����ø��ƣ�ֻ֧�� Z Ϊ 1 �����Ρ�

   ������
     P: TCnFP2AffinePoint                 - ����ȡ�ķ�������ϵ�����Ԫ�����
     FP2X: TCnFP2                         - �������� X ����ֵ�Ķ����������ϵ��Ԫ�ض���
     FP2Y: TCnFP2                         - �������� Y ����ֵ�Ķ����������ϵ��Ԫ�ض���

   ����ֵ�����ޣ�
}

procedure FP2AffinePointSetCoordinates(P: TCnFP2AffinePoint; FP2X: TCnFP2; FP2Y: TCnFP2);
{* ����һ��������ϵ�����Ԫ������ X��Y ����ֵ���ڲ����ø��ơ�

   ������
     P: TCnFP2AffinePoint                 - �����õķ�������ϵ�����Ԫ�����
     FP2X: TCnFP2                         - �����õĶ����������ϵ��Ԫ�� X ����
     FP2Y: TCnFP2                         - �����õĶ����������ϵ��Ԫ�� Y ����

   ����ֵ�����ޣ�
}

procedure FP2AffinePointSetCoordinatesHex(P: TCnFP2AffinePoint;
  const SX0: string; const SX1: string; const SY0: string; const SY1: string);
{* ����һ��������ϵ�����Ԫ������ XY ����ֵ��ʹ��ʮ�������ַ�����

   ������
     P: TCnFP2AffinePoint                 - �����õķ�������ϵ�����Ԫ�����
     const SX0: string                    - X0 ��ʮ�������ַ���
     const SX1: string                    - X1 ��ʮ�������ַ���
     const SY0: string                    - Y0 ��ʮ�������ַ���
     const SY1: string                    - Y1 ��ʮ�������ַ���

   ����ֵ�����ޣ�
}

procedure FP2AffinePointSetCoordinatesBigNumbers(P: TCnFP2AffinePoint;
  X0: TCnBigNumber; X1: TCnBigNumber; Y0: TCnBigNumber; Y1: TCnBigNumber);
{* ����һ��������ϵ�����Ԫ������ XY ����ֵ��ʹ�ô��������ڲ����ø��ơ�

   ������
     P: TCnFP2AffinePoint                 - �����õķ�������ϵ�����Ԫ�����
     X0: TCnBigNumber                     - X0 ����ֵ
     X1: TCnBigNumber                     - X1 ����ֵ
     Y0: TCnBigNumber                     - Y0 ����ֵ
     Y1: TCnBigNumber                     - Y1 ����ֵ

   ����ֵ�����ޣ�
}

procedure FP2AffinePointGetJacobianCoordinates(P: TCnFP2AffinePoint;
  FP12X: TCnFP12; FP12Y: TCnFP12; Prime: TCnBigNumber);
{* ��ȡһ��������ϵ�����Ԫ�������ſɱ� X��Y ����ֵ���ڲ����ø��ơ�

   ������
     P: TCnFP2AffinePoint                 - ����ȡ�ķ�������ϵ�����Ԫ�����
     FP12X: TCnFP12                       - �������� X ����ֵ��ʮ�����������ϵ��Ԫ�ض���
     FP12Y: TCnFP12                       - �������� Y ����ֵ��ʮ�����������ϵ��Ԫ�ض���
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2AffinePointSetJacobianCoordinates(P: TCnFP2AffinePoint;
  FP12X: TCnFP12; FP12Y: TCnFP12; Prime: TCnBigNumber);
{* ����һ��������ϵ�����Ԫ�������ſɱ� X��Y ����ֵ���ڲ����ø��ơ�

   ������
     P: TCnFP2AffinePoint                 - �����õķ�������ϵ�����Ԫ�����
     FP12X: TCnFP12                       - �����õ�ʮ�����������ϵ��Ԫ�� X ����
     FP12Y: TCnFP12                       - �����õ�ʮ�����������ϵ��Ԫ�� Y ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

function FP2AffinePointIsOnCurve(P: TCnFP2AffinePoint; Prime: TCnBigNumber): Boolean;
{* �ж�һ��������ϵ�����Ԫ������Ƿ�����Բ���� y^2 = x^3 + 5 �ϡ�

   ������
     P: TCnFP2AffinePoint                 - ���жϵķ�������ϵ�����Ԫ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ��Boolean                        - �����Ƿ���������
}

procedure FP2AffinePointNegate(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
{* һ����������ϵ�����Ԫ��������Բ�����󷴣�Res ������ P��

   ������
     Res: TCnFP2AffinePoint               - �������ɽ���ķ�������ϵ�����Ԫ�����
     P: TCnFP2AffinePoint                 - ������ķ�������ϵ�����Ԫ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2AffinePointDouble(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
{* һ����������ϵ�����Ԫ��������Բ���߱��㷨��Res ������ P��

   ������
     Res: TCnFP2AffinePoint               - �������ɽ���ķ�������ϵ�����Ԫ�����
     P: TCnFP2AffinePoint                 - ������ķ�������ϵ�����Ԫ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2AffinePointAdd(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Q: TCnFP2AffinePoint; Prime: TCnBigNumber);
{* ������������ϵ�����Ԫ��������Բ���߼ӷ���Res ������ P �� Q��P ������ Q��
   ע���ڲ����ǽ� Z ���� 1����Ȼ���󷴵���ͨ������

   ������
     Res: TCnFP2AffinePoint               - �������ɽ���ķ�������ϵ�����Ԫ�����
     P: TCnFP2AffinePoint                 - ���������һ
     Q: TCnFP2AffinePoint                 - ����������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2AffinePointSub(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Q: TCnFP2AffinePoint; Prime: TCnBigNumber);
{* ������������ϵ�����Ԫ��������Բ���߼�����Res ������ P �� Q��P ������ Q��

   ������
     Res: TCnFP2AffinePoint               - �������ɽ���ķ�������ϵ�����Ԫ�����
     P: TCnFP2AffinePoint                 - �����������
     Q: TCnFP2AffinePoint                 - ���������
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2AffinePointMul(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Num: TCnBigNumber; Prime: TCnBigNumber);
{* һ����������ϵ�����Ԫ��������Բ���� N ���㷨��Res ������ P��

   ������
     Res: TCnFP2AffinePoint               - �������ɽ���ķ�������ϵ�����Ԫ�����
     P: TCnFP2AffinePoint                 - ������ķ�������ϵ�����Ԫ�����
     Num: TCnBigNumber                    - ����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2AffinePointFrobenius(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
{* ����һ����������ϵ�����Ԫ�����ĸ��ޱ�����˹��ֵ̬ͬ��Res ������ P��
   ��ʵ���� P �� Prime �η��Ľ�� mod Prime

   ������
     Res: TCnFP2AffinePoint               - �������ɽ���ķ�������ϵ�����Ԫ�����
     P: TCnFP2AffinePoint                 - ������ķ�������ϵ�����Ԫ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

function FP2PointToString(P: TCnFP2Point): string;
{* ��һ��ͨ����ϵ��Ķ�Ԫ�� FP2 ����ת��Ϊ�ַ�����

   ������
     P: TCnFP2Point                       - ��ת���Ķ�Ԫ�����

   ����ֵ��string                         - �����ַ���
}

procedure FP2AffinePointToFP2Point(FP2P: TCnFP2Point; FP2AP: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
{* ��һ��������ϵ�����Ԫ�� FP2 ����ת��Ϊ��ͨ����ϵ��Ķ�Ԫ�� FP2 ����

   ������
     FP2P: TCnFP2Point                    - ��ת���Ķ�Ԫ�����
     FP2AP: TCnFP2AffinePoint             - Ŀ���������ϵ�����Ԫ�����
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure FP2PointToFP2AffinePoint(FP2AP: TCnFP2AffinePoint; FP2P: TCnFP2Point);
{* ��һ��������ϵ�����Ԫ�� FP2 ����ת��Ϊ��ͨ����ϵ��Ķ�Ԫ�� FP2 ����

   ������
     FP2AP: TCnFP2AffinePoint             - ��ת���ķ�������ϵ�����Ԫ�����
     FP2P: TCnFP2Point                    - Ŀ���Ԫ�����

   ����ֵ�����ޣ�
}

// ============================ ˫���ԶԼ��㺯�� ===============================

procedure Rate(F: TCnFP12; Q: TCnFP2AffinePoint; XP: TCnBigNumber;
  YP: TCnBigNumber; A: TCnBigNumber; K: TCnBigNumber; Prime: TCnBigNumber);
{* ���� R-ate �ԡ������һ�� FP12 ֵ��������һ�� BN �����ϵĵ������ XP��YP��
   һ�� FP2 �ϵ� XYZ ��������㣬һ��ָ�� K��һ��ѭ������ A��

   ������
     F: TCnFP12                           - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     Q: TCnFP2AffinePoint                 - ���������
     XP: TCnBigNumber                     - BN �����ϵ������� X ����
     YP: TCnBigNumber                     - BN �����ϵ������� Y ����
     A: TCnBigNumber                      - ѭ������
     K: TCnBigNumber                      - ָ��
     Prime: TCnBigNumber                  - �������Ͻ�

   ����ֵ�����ޣ�
}

procedure SM9RatePairing(F: TCnFP12; Q: TCnFP2AffinePoint; P: TCnEccPoint);
{* ���� SM9 ָ���� BN ���ߵĲ����Լ�ָ������� R-ate �ԣ�����Ϊһ�� BN �����ϵĵ㼰
   һ�� FP2 �ϵ� XYZ ��������㣬���Ϊһ�� FP12 ֵ��

   ������
     F: TCnFP12                           - �������ɽ���Ķ����������ϵ��Ԫ�ض���
     Q: TCnFP2AffinePoint                 - ���������
     P: TCnEccPoint                       - BN �����ϵ������

   ����ֵ�����ޣ�
}

// ===================== SM9 ����ʵ�ֺ�����ǩ������֤ ==========================

function CnSM9KGCGenerateSignatureMasterKey(SignatureMasterKey:
  TCnSM9SignatureMasterKey; SM9: TCnSM9 = nil): Boolean;
{* �� KCG ���ã�����ǩ������Կ��

   ������
     SignatureMasterKey: TCnSM9SignatureMasterKey         - �����ɵ� SM9 ǩ������Կ
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - �����Ƿ����ɳɹ�
}

function CnSM9KGCGenerateSignatureUserKey(SignatureMasterPrivateKey:
  TCnSM9SignatureMasterPrivateKey; const AUserID: AnsiString;
  OutSignatureUserPrivateKey: TCnSM9SignatureUserPrivateKey; SM9: TCnSM9 = nil): Boolean;
{* �� KCG ���ã������û� ID �����û�ǩ��˽Կ��

   ������
     SignatureMasterPrivateKey: TCnSM9SignatureMasterPrivateKey           - ���������û�ǩ��˽Կ�� SM9 ǩ������Կ
     const AUserID: AnsiString                                            - �û���ʶ
     OutSignatureUserPrivateKey: TCnSM9SignatureUserPrivateKey            - �����ɵ� SM9 �û�ǩ��˽Կ
     SM9: TCnSM9                                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                                        - �����Ƿ����ɳɹ�
}

function CnSM9UserSignData(SignatureMasterPublicKey: TCnSM9SignatureMasterPublicKey;
  SignatureUserPrivateKey: TCnSM9SignatureUserPrivateKey; PlainData: Pointer;
  DataByteLen: Integer; OutSignature: TCnSM9Signature; SM9: TCnSM9 = nil; const RandHex: string = ''): Boolean;
{* �����û�ǩ��˽Կ���û� ID �����ݽ���ǩ�������سɹ����ǩ��ֵ���� OutSignature �С�
   ע�������û�˽Կ���ڣ��û� ID �������ǩ����

   ������
     SignatureMasterPublicKey: TCnSM9SignatureMasterPublicKey             - ����ǩ���� SM9 ǩ������Կ
     SignatureUserPrivateKey: TCnSM9SignatureUserPrivateKey               - ����ǩ���� SM9 �û�ǩ��˽Կ
     PlainData: Pointer                                                   - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                                 - ��ǩ�����������ݿ��ֽڳ���
     OutSignature: TCnSM9Signature                                        - �����ǩ��ֵ
     SM9: TCnSM9                                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��
     const RandHex: string                                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                                        - ����ǩ���Ƿ�ɹ�
}

function CnSM9UserVerifyData(const AUserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  InSignature: TCnSM9Signature; SignatureMasterPublicKey: TCnSM9SignatureMasterPublicKey;
  SM9: TCnSM9 = nil): Boolean;
{* ���ù�����ǩ����Կ���û� ID ��������ǩ��������֤��������֤ǩ���ɹ����
   ע���û� ID ��Ҫ����ǩ����֤��

   ������
     const AUserID: AnsiString                                            - �û���ʶ
     PlainData: Pointer                                                   - ����֤���������ݿ��ַ
     DataByteLen: Integer                                                 - ����֤���������ݿ��ֽڳ���
     InSignature: TCnSM9Signature                                         - ����֤��ǩ��ֵ
     SignatureMasterPublicKey: TCnSM9SignatureMasterPublicKey             - ������֤�� SM9 ǩ������Կ
     SM9: TCnSM9                                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                                        - ������֤�Ƿ�ɹ�
}

// ================== SM9 ����ʵ�ֺ������ӽ�������Կ��װ =======================

function CnSM9KGCGenerateEncryptionMasterKey(EncryptionMasterKey:
  TCnSM9EncryptionMasterKey; SM9: TCnSM9 = nil): Boolean;
{* �� KCG ���ã����ɼ�������Կ�������ڼӽ��ܻ���Կ��װ��

   ������
     EncryptionMasterKey: TCnSM9EncryptionMasterKey       - �����ɵ� SM9 ��������Կ
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - �����Ƿ����ɳɹ�
}

function CnSM9KGCGenerateEncryptionUserKey(EncryptionMasterPrivateKey:
  TCnSM9EncryptionMasterPrivateKey; const AUserID: AnsiString;
  OutEncryptionUserKey: TCnSM9EncryptionUserPrivateKey; SM9: TCnSM9 = nil): Boolean;
{* �� KCG ���ã������û� ID �����û�����˽Կ�������ڼӽ��ܻ���Կ��װ��

   ������
     EncryptionMasterPrivateKey: TCnSM9EncryptionMasterPrivateKey         - ���������û�����˽Կ�� SM9 ��������Կ
     const AUserID: AnsiString                                            - �û���ʶ
     OutEncryptionUserKey: TCnSM9EncryptionUserPrivateKey                 - �����ɵ� SM9 �û�����˽Կ
     SM9: TCnSM9                                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                                        - �����Ƿ����ɳɹ�
}

// ====================== SM9 ����ʵ�ֺ�������Կ��װ ===========================

function CnSM9UserSendKeyEncapsulation(const DestUserID: AnsiString; KeyByteLength: Integer;
  EncryptionPublicKey: TCnSM9EncryptionMasterPublicKey;
  OutKeyEncapsulation: TCnSM9KeyEncapsulation; SM9: TCnSM9 = nil; const RandHex: string = ''): Boolean;
{* ��ͨ�û�����Ŀ���û��� ID ���������Կ������ KeyLength ���ȵ��ֽڴ���Կ��װ���ݣ�
   ���ط�װ�Ƿ�ɹ���

   ������
     const DestUserID: AnsiString                         - Ŀ���û���ʶ
     KeyByteLength: Integer                               - ����װ����Կ�ֽڳ���
     EncryptionPublicKey: TCnSM9EncryptionMasterPublicKey - ������Կ��װ�� SM9 ��������Կ
     OutKeyEncapsulation: TCnSM9KeyEncapsulation          - ���ɵ��ֽڴ���Կ��װ���ݣ��贫����Է�
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��
     const RandHex: string                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                        - ���ط�װ�Ƿ�ɹ�
}

function CnSM9UserReceiveKeyEncapsulation(const DestUserID: AnsiString;
  EncryptionUserKey: TCnSM9EncryptionUserPrivateKey; KeyByteLength: Integer;
  InKeyEncapsulationC: TCnSM9KeyEncapsulationCode; out Key: TBytes; SM9: TCnSM9 = nil): Boolean;
{* Ŀ���û���������� ID ���Լ����û�����˽Կ���� KeyEncapsulation �����л�ԭ KeyLength
   ���ȵ��ֽڴ���Կ��װ���ݷ��� Key �У����ؽ���Ƿ�ɹ���

   ������
     const DestUserID: AnsiString                         - Ŀ���û���ʶ
     EncryptionUserKey: TCnSM9EncryptionUserPrivateKey    - ������Կ��װ�� SM9 �û�����˽Կ
     KeyByteLength: Integer                               - ����װ����Կ�ֽڳ���
     InKeyEncapsulationC: TCnSM9KeyEncapsulationCode      - �ɶԷ����ɲ�����������ֽڴ���Կ��װ����
     out Key: TBytes                                      - ����Ľ����Կ
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ؽ���Ƿ�ɹ�
}

// ======================= SM9 ����ʵ�ֺ������ӽ��� ============================

function CnSM9UserEncryptData(const DestUserID: AnsiString;
  EncryptionPublicKey: TCnSM9EncryptionMasterPublicKey; PlainData: Pointer;
  DataByteLen: Integer; K1ByteLength: Integer; K2ByteLength: Integer; OutStream: TStream;
  EncryptionMode: TCnSM9EncrytionMode = semSM4; SM9: TCnSM9 = nil; const RandHex: string = ''): Boolean;
{* ʹ�ü�������Կ��Ŀ���û��� ID �������ݲ�д���������ؼ����Ƿ�ɹ���
   EncryptionMode �� SM4 ʱ K1Length ����ֵ���ԣ��ڲ��̶�Ϊ 16 �ֽڣ�
   SM4 ʹ�� ECB ģʽ�� PKCS7 ���롣

   ������
     const DestUserID: AnsiString                         - �û���ʶ
     EncryptionPublicKey: TCnSM9EncryptionMasterPublicKey - ���ڼ��ܵ� SM9 ��������Կ
     PlainData: Pointer                                   - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     K1ByteLength: Integer                                - ��һ����Կ���ֽڳ���
     K2ByteLength: Integer                                - �ڶ�����Կ���ֽڳ���
     OutStream: TStream                                   - �����������
     EncryptionMode: TCnSM9EncrytionMode                  - ����ģʽ
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��
     const RandHex: string                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                        - ���ؼ����Ƿ�ɹ�
}

function CnSM9UserDecryptData(const DestUserID: AnsiString;
  EncryptionUserKey: TCnSM9EncryptionUserPrivateKey; EnData: Pointer;
  DataByteLen: Integer; K2ByteLength: Integer; OutStream: TStream;
  EncryptionMode: TCnSM9EncrytionMode = semSM4; SM9: TCnSM9 = nil): Boolean;
{* ʹ���û�����˽Կ�������ݲ�д���������ؽ����Ƿ�ɹ���

   ������
     const DestUserID: AnsiString                         - �û���ʶ
     EncryptionUserKey: TCnSM9EncryptionUserPrivateKey    - ���ڽ��ܵ� SM9 �û�����˽Կ
     EnData: Pointer                                      - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     K2ByteLength: Integer                                - �ڶ�����Կ���ֽڳ���
     OutStream: TStream                                   - �����������
     EncryptionMode: TCnSM9EncrytionMode                  - ����ģʽ
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ؽ����Ƿ�ɹ�
}

// ====================== SM9 ����ʵ�ֺ�������Կ���� ===========================

function CnSM9KGCGenerateKeyExchangeMasterKey(KeyExchangeMasterKey:
  TCnSM9KeyExchangeMasterKey; SM9: TCnSM9 = nil): Boolean;
{* �� KCG ���ã����ɼ�������Կ����������Կ��������Ϊ��ͬ�� CnSM9KGCGenerateEncryptionMasterKey��

   ������
     KeyExchangeMasterKey: TCnSM9KeyExchangeMasterKey     - �����ɵ� SM9 ��Կ������������Կ
     SM9: TCnSM9                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - �����Ƿ����ɳɹ�
}

function CnSM9KGCGenerateKeyExchangeUserKey(KeyExchangeMasterPrivateKey:
  TCnSM9KeyExchangeMasterPrivateKey; const AUserID: AnsiString;
  OutKeyExchangeUserKey: TCnSM9KeyExchangeUserPrivateKey; SM9: TCnSM9 = nil): Boolean;
{* �� KCG ���ã������û� ID ����������Կ�������û�����˽Կ��

   ������
     KeyExchangeMasterPrivateKey: TCnSM9KeyExchangeMasterPrivateKey       - ������Կ������ SM9 ��������Կ
     const AUserID: AnsiString                                            - �û���ʶ
     OutKeyExchangeUserKey: TCnSM9KeyExchangeUserPrivateKey               - �����ɵ�������Կ�������û�����˽Կ
     SM9: TCnSM9                                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                                        - �����Ƿ����ɳɹ�
}

function CnSM9UserKeyExchangeAStep1(const BUserID: AnsiString; KeyByteLength: Integer;
  KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey; OutRA: TCnEccPoint;
  OutRandA: TCnBigNumber; SM9: TCnSM9 = nil; const RandHex: string = ''): Boolean;
{* ��Կ������һ����A �� B �� ID �Լ���������Կ����һ����Բ���ߵ� RA �� B��
   ͬʱ��¼�м������ OutRandA����Ҫ�ⲿ���뱣����ֵ���ڵ�������ʹ�á�

   ������
     const BUserID: AnsiString                                            - B �����û���ʶ
     KeyByteLength: Integer                                               - �����ɵ���Կ�ֽڳ���
     KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey               - ������Կ������ SM9 ��������Կ
     OutRA: TCnEccPoint                                                   - ���ɵ��м�������� R�����ڱ��ν����Ự�б������贫���� B ��
     OutRandA: TCnBigNumber                                               - ���ɵ��м�������������ڱ��ν����Ự�б��������ܴ���� B ��
     SM9: TCnSM9                                                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��
     const RandHex: string                                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                                        - �����Ƿ����ɳɹ�
}

function CnSM9UserKeyExchangeBStep1(const AUserID: AnsiString; const BUserID: AnsiString;
  KeyByteLength: Integer; KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey;
  KeyExchangeBUserKey: TCnSM9KeyExchangeUserPrivateKey; InRA: TCnEccPoint;
  OutRB: TCnEccPoint; out KeyB: TBytes; out OutOptionalSB: TCnSM3Digest;
  OutG1: TCnFP12; OutG2: TCnFP12; OutG3: TCnFP12; SM9: TCnSM9 = nil; const RandHex: string = ''): Boolean;
{* ��Կ�����ڶ�����B �� A��B �� ID �Լ���������Կ���Լ���˽Կ����������Կ������ RA
   ����Э����Կ KeyB������������һ����Բ���ߵ� RB �ټ���һ����ѡ��У���� SB �� A��
   ͬʱ��¼ OutG1, OutG2, OutG3 �����м����������Ҫ�ⲿ���뱣����ֵ���ڵ��Ĳ���ʹ�á�

   ������
     const AUserID: AnsiString                                      - A �����û���ʶ
     const BUserID: AnsiString                                      - B �����û���ʶ
     KeyByteLength: Integer                                         - �����ɵ���Կ�ֽڳ���
     KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey         - ������Կ������ SM9 ��������Կ
     KeyExchangeBUserKey: TCnSM9KeyExchangeUserPrivateKey           - ������Կ������ B �û� SM9 ������˽Կ
     InRA: TCnEccPoint                                              - �� A �����ɲ�����������м�������� R
     OutRB: TCnEccPoint                                             - ���ɵ��м�������� R���贫��� A ��
     out KeyB: TBytes                                               - B ���ɵ�Э����Կ
     out OutOptionalSB: TCnSM3Digest                                - ����Ŀ�ѡУ���Ӵ�ֵ
     OutG1: TCnFP12                                                 - ����м������ G1 �����Ĳ�У��
     OutG2: TCnFP12                                                 - ����м������ G2 �����Ĳ�У��
     OutG3: TCnFP12                                                 - ����м������ G3 �����Ĳ�У��
     SM9: TCnSM9                                                    - ���Դ��� SM9 ʵ����Ĭ��Ϊ��
     const RandHex: string                                          - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                                  - �����Ƿ�Э�̳ɹ�
}

function CnSM9UserKeyExchangeAStep2(const AUserID: AnsiString; const BUserID: AnsiString;
  KeyByteLength: Integer; KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey;
  KeyExchangeAUserKey: TCnSM9KeyExchangeUserPrivateKey; InRandA: TCnBigNumber;
  InRA: TCnEccPoint; InRB: TCnEccPoint; InOptionalSB: TCnSM3Digest; out KeyA: TBytes;
  out OutOptionalSA: TCnSM3Digest; SM9: TCnSM9 = nil): Boolean;
{* ��Կ������������A �� B �� ID �Լ���������Կ���Լ���˽Կ����������Կ������ RA��RB
   ����Э����Կ KeyA���Լ�һ����ѡ��У���� SA �� B���˴� KeyA Ӧ������ KeyB��

   ������
     const AUserID: AnsiString                                      - A �����û���ʶ
     const BUserID: AnsiString                                      - B �����û���ʶ
     KeyByteLength: Integer                                         - �����ɵ���Կ�ֽڳ���
     KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey         - ������Կ������ SM9 ��������Կ
     KeyExchangeAUserKey: TCnSM9KeyExchangeUserPrivateKey           - ������Կ������ A �û� SM9 ������˽Կ
     InRandA: TCnBigNumber                                          - A ����һ�ε���ʱ���ɵ��м��������
     InRA: TCnEccPoint                                              - A ����һ�ε���ʱ���ɵ��м�������� R
     InRB: TCnEccPoint                                              - �� B �����ɲ�����������м�������� R
     InOptionalSB: TCnSM3Digest                                     - �� B �����ɲ���������Ŀ�ѡУ���Ӵ�ֵ
     out KeyA: TBytes                                               - A ���ɵ�Э����Կ
     out OutOptionalSA: TCnSM3Digest                                - ����Ŀ�ѡУ���Ӵ�ֵ
     SM9: TCnSM9                                                    - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                                  - �����Ƿ�Э�̳ɹ�
}

function CnSM9UserKeyExchangeBStep2(const AUserID: AnsiString; const BUserID: AnsiString;
  InRA: TCnEccPoint; InRB: TCnEccPoint; InOptionalSA: TCnSM3Digest; InG1: TCnFP12;
  InG2: TCnFP12; InG3: TCnFP12; SM9: TCnSM9 = nil): Boolean;
{* ��Կ�������Ĳ�����ѡ��B �� A��B �� ID �Լ��ڶ����е������м��������� RA��RB
   �����У�������� InOptionalSA �Ƚϣ���ͨ����У��ʧ�ܡ�

   ������
     const AUserID: AnsiString            - A �����û���ʶ
     const BUserID: AnsiString            - B �����û���ʶ
     InRA: TCnEccPoint                    - �� A �����ɲ�����������м�������� R
     InRB: TCnEccPoint                    - B ����һ�ε���ʱ���ɵ��м�������� R
     InOptionalSA: TCnSM3Digest           - �� A �����ɲ���������Ŀ�ѡУ���Ӵ�ֵ
     InG1: TCnFP12                        - B ����һ�ε���ʱ���ɵ��м������ G1
     InG2: TCnFP12                        - B ����һ�ε���ʱ���ɵ��м������ G2
     InG3: TCnFP12                        - B ����һ�ε���ʱ���ɵ��м������ G3
     SM9: TCnSM9                          - ���Դ��� SM9 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - �����Ƿ�У��ɹ�
}

// =================== SM9 ����ʵ�ֺ����������Ӵ��㷨 ========================

function CnSM9Hash1(Res: TCnBigNumber; Data: Pointer; DataByteLen: Integer;
  N: TCnBigNumber): Boolean;
{* SM9 �й涨�ĵ�һ�����뺯�����ڲ�ʹ�� SM3��256 λ���Ӵպ�����
   ����Ϊ���ش� Data ����� N�����Ϊ 1 �� N - 1 �������ڵĴ�����N Ӧ�ô� SM9.Order��

   ������
     Res: TCnBigNumber                    - �������ɽ���Ĵ�������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���
     N: TCnBigNumber                      - Ӧ���� SM9 �� Order

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function CnSM9Hash2(Res: TCnBigNumber; Data: Pointer; DataByteLen: Integer;
  N: TCnBigNumber): Boolean;
{* SM9 �й涨�ĵڶ������뺯�����ڲ�ʹ�� SM3��256 λ���Ӵպ�����
   ����Ϊ���ش� Data ����� N�����Ϊ 1 �� N - 1 �������ڵĴ�����N Ӧ�ô� SM9.Order��

   ������
     Res: TCnBigNumber                    - �������ɽ���Ĵ�������
     Data: Pointer                        - ����������ݿ��ַ
     DataByteLen: Integer                 - ����������ݿ��ֽڳ���
     N: TCnBigNumber                      - Ӧ���� SM9 �� Order

   ����ֵ��Boolean                        - �����Ƿ����ɹ�
}

function SM9Mac(Key: Pointer; KeyByteLength: Integer; Z: Pointer; ZByteLength: Integer): TCnSM3Digest;
{* ������Կ Key ����Ϣ Z������Ϣ��֤�룬ʵ������ƴһ������� SM3 �Ӵ�ֵ��

   ������
     Key: Pointer                         - ��Կ���ݿ��ַ
     KeyByteLength: Integer               - ��Կ���ݿ��ֽڳ���
     Z: Pointer                           - ��Ϣ���ݿ��ַ
     ZByteLength: Integer                 - ��Ϣ���ݿ��ֽڳ���

   ����ֵ��TCnSM3Digest                   - �����Ӵ�ֵ
}

implementation

uses
  CnKDF, CnSM4, CnPemUtils;

resourcestring
  SCnErrorSM9AffinePointZError = 'Affine Point Z Must be 1';
  SCnErrorSM9ListIndexError = 'List Index Out of Bounds (%d)';
  SCnErrorSM9MacParams = 'Error Mac Params';

const
  CRLF = #13#10;

  CN_SM9_HASH_PREFIX_1 = 1;
  CN_SM9_HASH_PREFIX_2 = 2;

  CN_SM3_DIGEST_BITS = SizeOf(TCnSM3Digest) * 8;

var
  FLocalBigNumberPool: TCnBigNumberPool = nil;
  FLocalFP2Pool: TCnFP2Pool = nil;
  FLocalFP4Pool: TCnFP4Pool = nil;
  FLocalFP12Pool: TCnFP12Pool = nil;
  FLocalFP2AffinePointPool: TCnFP2AffinePointPool = nil;

  // SM9 �������س���
  FSM9FiniteFieldSize: TCnBigNumber = nil;
  FSM9Order: TCnBigNumber = nil;

  FSM9G1P1X: TCnBigNumber = nil;
  FSM9G1P1Y: TCnBigNumber = nil;
  FSM9G2P2X0: TCnBigNumber = nil;
  FSM9G2P2X1: TCnBigNumber = nil;
  FSM9G2P2Y0: TCnBigNumber = nil;
  FSM9G2P2Y1: TCnBigNumber = nil;
  FSM96TPlus2: TCnBigNumber = nil;
  FSM9FastExpP3: TCnBigNumber = nil;
  FFP12FastExpPW20: TCnBigNumber = nil;
  FFP12FastExpPW21: TCnBigNumber = nil;
  FFP12FastExpPW22: TCnBigNumber = nil;
  FFP12FastExpPW23: TCnBigNumber = nil;

// ====================== �����������ϵ��Ԫ�����㺯�� =========================

function FP2New: TCnFP2;
begin
  Result := TCnFP2.Create;
end;

procedure FP2Free(FP2: TCnFP2);
begin
  FP2.Free;
end;

function FP2IsZero(FP2: TCnFP2): Boolean;
begin
  Result := FP2[0].IsZero and FP2[1].IsZero;
end;

function FP2IsOne(FP2: TCnFP2): Boolean;
begin
  Result := FP2[0].IsOne and FP2[1].IsZero;
end;

procedure FP2SetZero(FP2: TCnFP2);
begin
  FP2[0].SetZero;
  FP2[1].SetZero;
end;

procedure FP2SetOne(FP2: TCnFP2);
begin
  FP2[0].SetOne;
  FP2[1].SetZero;
end;

function FP2SetU(FP2: TCnFP2): Boolean;
begin
  Result := False;
  if not FP2[0].SetZero then Exit;
  if not FP2[1].SetOne then Exit;
  Result := True;
end;

function FP2SetBigNumber(FP2: TCnFP2; Num: TCnBigNumber): Boolean;
begin
  Result := False;
  if BigNumberCopy(FP2[0], Num) = nil then Exit;
  if not FP2[1].SetZero then Exit;
  Result := True;
end;

function FP2SetBigNumbers(FP2: TCnFP2; Num0, Num1: TCnBigNumber): Boolean;
begin
  Result := False;
  if BigNumberCopy(FP2[0], Num0) = nil then Exit;
  if BigNumberCopy(FP2[1], Num1) = nil then Exit;
  Result := True;
end;

function FP2SetHex(FP2: TCnFP2; const S0, S1: string): Boolean;
begin
  Result := False;
  if not FP2[0].SetHex(AnsiString(S0)) then Exit;
  if not FP2[1].SetHex(AnsiString(S1)) then Exit;
  Result := True;
end;

function FP2ToString(FP2: TCnFP2): string;
begin
  Result := FP2[1].ToHex + ',' + FP2[0].ToHex;
end;

procedure FP2SetWord(FP2: TCnFP2; Value: Cardinal);
begin
  FP2[0].SetWord(Value);
  FP2[1].SetZero;
end;

procedure FP2SetWords(FP2: TCnFP2; Value0, Value1: Cardinal);
begin
  FP2[0].SetWord(Value0);
  FP2[1].SetWord(Value1);
end;

function FP2Equal(F1, F2: TCnFP2): Boolean;
begin
  Result := BigNumberEqual(F1[0], F2[0]) and BigNumberEqual(F1[1], F2[1]);
end;

function FP2Copy(Dst, Src: TCnFP2): TCnFP2;
begin
  Result := nil;
  if BigNumberCopy(Dst[0], Src[0]) = nil then Exit;
  if BigNumberCopy(Dst[1], Src[1]) = nil then Exit;
  Result := Dst;
end;

procedure FP2Negate(Res: TCnFP2; F: TCnFP2; Prime: TCnBigNumber);
begin
  BigNumberSub(Res[0], Prime, F[0]);
  BigNumberSub(Res[1], Prime, F[1]);
  BigNumberNonNegativeMod(Res[0], Res[0], Prime);
  BigNumberNonNegativeMod(Res[1], Res[1], Prime);
end;

procedure FP2Add(Res: TCnFP2; F1, F2: TCnFP2; Prime: TCnBigNumber);
begin
  BigNumberAdd(Res[0], F1[0], F2[0]);
  BigNumberAdd(Res[1], F1[1], F2[1]);
  BigNumberNonNegativeMod(Res[0], Res[0], Prime);
  BigNumberNonNegativeMod(Res[1], Res[1], Prime);
end;

procedure FP2Sub(Res: TCnFP2; F1, F2: TCnFP2; Prime: TCnBigNumber);
begin
  BigNumberSub(Res[0], F1[0], F2[0]);
  BigNumberSub(Res[1], F1[1], F2[1]);
  BigNumberNonNegativeMod(Res[0], Res[0], Prime);
  BigNumberNonNegativeMod(Res[1], Res[1], Prime);
end;

procedure FP2Mul(Res: TCnFP2; F1, F2: TCnFP2; Prime: TCnBigNumber);
var
  T0, T1, R0: TCnBigNumber;
begin
  // r0 = a0 * b0 - 2 * a1 * b1
  // r1 = a0 * b1 + a1 * b0
  T0 := nil;
  T1 := nil;
  R0 := nil;

  try
    T0 := FLocalBigNumberPool.Obtain;
    T1 := FLocalBigNumberPool.Obtain;
    R0 := FLocalBigNumberPool.Obtain;

    BigNumberMul(T0, F1[0], F2[0]);
    BigNumberMul(T1, F1[1], F2[1]);
    BigNumberAdd(T1, T1, T1);
    BigNumberSub(T0, T0, T1);
    BigNumberNonNegativeMod(R0, T0, Prime); // ����ֱ�Ӹ� Res[0] ��ֵ����һ F1 �� Res ��ͬ�����ǰӰ�� F0

    BigNumberMul(T0, F1[0], F2[1]);
    BigNumberMul(T1, F1[1], F2[0]);
    BigNumberAdd(T1, T0, T1);
    BigNumberNonNegativeMod(Res[1], T1, Prime);

    BigNumberCopy(Res[0], R0);
  finally
    FLocalBigNumberPool.Recycle(R0);
    FLocalBigNumberPool.Recycle(T1);
    FLocalBigNumberPool.Recycle(T0);
  end;
end;

procedure FP2Mul3(Res: TCnFP2; F: TCnFP2; Prime: TCnBigNumber);
var
  T: TCnFP2;
begin
  T := FLocalFP2Pool.Obtain;
  try
    FP2Add(T, F, F, Prime);
    FP2Add(Res, T, F, Prime);
  finally
    FLocalFP2Pool.Recycle(T);
  end;
end;

procedure FP2MulU(Res: TCnFP2; F1, F2: TCnFP2; Prime: TCnBigNumber);
var
  T0, T1: TCnBigNumber;
begin
  // r0 = -2 * (a0 * b1 + a1 * b0)
  // r1 = a0 * b0 - 2 * a1 * b1
  T0 := nil;
  T1 := nil;

  try
    T0 := FLocalBigNumberPool.Obtain;
    T1 := FLocalBigNumberPool.Obtain;

    BigNumberMul(T0, F1[0], F2[1]);
    BigNumberMul(T1, F1[1], F2[0]);
    BigNumberAdd(T0, T0, T1);
    T0.MulWord(2);
    T0.Negate;
    BigNumberNonNegativeMod(Res[0], T0, Prime);

    BigNumberMul(T0, F1[0], F2[0]);
    BigNumberMul(T1, F1[1], F2[1]);
    T1.MulWord(2);
    BigNumberSub(T1, T0, T1);
    BigNumberNonNegativeMod(Res[1], T1, Prime);
  finally
    FLocalBigNumberPool.Recycle(T1);
    FLocalBigNumberPool.Recycle(T0);
  end;
end;

procedure FP2Mul(Res: TCnFP2; F: TCnFP2; Num: TCnBigNumber; Prime: TCnBigNumber);
begin
  BigNumberMul(Res[0], F[0], Num);
  BigNumberMul(Res[1], F[1], Num);
  BigNumberNonNegativeMod(Res[0], Res[0], Prime);
  BigNumberNonNegativeMod(Res[1], Res[1], Prime);
end;

procedure FP2Inverse(Res: TCnFP2; F: TCnFP2; Prime: TCnBigNumber);
var
  K, T: TCnBigNumber;
begin
  if F[0].IsZero then
  begin
    if not Res[0].SetZero then Exit;
    K := nil;

    // r1 = -((2 * a1)^-1) */
    BigNumberAdd(Res[1], F[1], F[1]);
    try
      K := FLocalBigNumberPool.Obtain;
      BigNumberModularInverse(K, Res[1], Prime);
      BigNumberCopy(Res[1], K);

      BigNumberNonNegativeMod(Res[1], Res[1], Prime);
      BigNumberSub(Res[1], Prime, Res[1]);
    finally
      FLocalBigNumberPool.Recycle(K);
    end;
  end
  else if F[1].IsZero then
  begin
    Res[1].SetZero;
    // r0 = a0^-1
    BigNumberModularInverse(Res[0], F[0], Prime);
  end
  else
  begin
    // k = (a[0]^2 + 2 * a[1]^2)^-1
    // r[0] = a[0] * k
    // r[1] = -a[1] * k
    K := nil;
    T := nil;

    try
      K := FLocalBigNumberPool.Obtain;
      T := FLocalBigNumberPool.Obtain;

      BigNumberMul(T, F[1], F[1]);
      T.MulWord(2);
      BigNumberMul(K, F[0], F[0]);
      BigNumberAdd(K, T, K);
      BigNumberModularInverse(T, K, Prime);
      BigNumberCopy(K, T);

      BigNumberMul(Res[0], F[0], K);
      BigNumberNonNegativeMod(Res[0], Res[0], Prime);

      BigNumberMul(Res[1], F[1], K);
      BigNumberNonNegativeMod(Res[1], Res[1], Prime);
      BigNumberSub(Res[1], Prime, Res[1]);
    finally
      FLocalBigNumberPool.Recycle(T);
      FLocalBigNumberPool.Recycle(K);
    end;
  end;
end;

procedure FP2Div(Res: TCnFP2; F1, F2: TCnFP2; Prime: TCnBigNumber);
var
  Inv: TCnFP2;
begin
  if F2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  if F1 = F2 then
    Res.SetOne
  else
  begin
    Inv := FLocalFP2Pool.Obtain;
    try
      FP2Inverse(Inv, F2, Prime);
      FP2Mul(Res, F1, Inv, Prime);
    finally
      FLocalFP2Pool.Recycle(Inv);
    end;
  end;
end;

function FP2ToStream(FP2: TCnFP2; Stream: TStream; FixedLen: Integer): Integer;
begin
  Result := BigNumberWriteBinaryToStream(FP2[1], Stream, FixedLen)
    + BigNumberWriteBinaryToStream(FP2[0], Stream, FixedLen);
end;

// ====================== �Ĵ��������ϵ��Ԫ�����㺯�� =========================

function FP4New: TCnFP4;
begin
  Result := TCnFP4.Create;
end;

procedure FP4Free(FP4: TCnFP4);
begin
  FP4.Free;
end;

function FP4IsZero(FP4: TCnFP4): Boolean;
begin
  Result := FP4[0].IsZero and FP4[1].IsZero;
end;

function FP4IsOne(FP4: TCnFP4): Boolean;
begin
  Result := FP4[0].IsOne and FP4[1].IsZero;
end;

procedure FP4SetZero(FP4: TCnFP4);
begin
  FP4[0].SetZero;
  FP4[1].SetZero;
end;

procedure FP4SetOne(FP4: TCnFP4);
begin
  FP4[1].SetZero;
  FP4[0].SetOne;
end;

procedure FP4SetU(FP4: TCnFP4);
begin
  FP4[1].SetZero;
  FP4[0].SetU;
end;

procedure FP4SetV(FP4: TCnFP4);
begin
  FP4[0].SetZero;
  FP4[1].SetOne;
end;

procedure FP4SetBigNumber(FP4: TCnFP4; Num: TCnBigNumber);
begin
  FP4[1].SetZero;
  FP4[0].SetBigNumber(Num);
end;

procedure FP4SetBigNumbers(FP4: TCnFP4; Num0, Num1: TCnBigNumber);
begin
  FP4[0].SetBigNumber(Num0);
  FP4[1].SetBigNumber(Num1);
end;

procedure FP4SetFP2(FP4: TCnFP4; FP2: TCnFP2);
begin
  FP4[1].SetZero;
  FP2Copy(FP4[0], FP2);
end;

procedure FP4Set2FP2S(FP4: TCnFP4; FP20, FP21: TCnFP2);
begin
  FP2Copy(FP4[0], FP20);
  FP2Copy(FP4[1], FP21);
end;

procedure FP4SetHex(FP4: TCnFP4; const S0, S1, S2, S3: string);
begin
  FP4[1].SetHex(S2, S3);
  FP4[0].SetHex(S0, S1);
end;

function FP4ToString(FP4: TCnFP4): string;
begin
  Result := FP4[1].ToString + CRLF + FP4[0].ToString;
end;

procedure FP4SetWord(FP4: TCnFP4; Value: Cardinal);
begin
  FP4[1].SetZero;
  FP4[0].SetWord(Value);
end;

procedure FP4SetWords(FP4: TCnFP4; Value0, Value1, Value2, Value3: Cardinal);
begin
  FP4[0].SetWords(Value0, Value1);
  FP4[1].SetWords(Value2, Value3);
end;

function FP4Equal(F1, F2: TCnFP4): Boolean;
begin
  Result := FP2Equal(F1[0], F2[0]) and FP2Equal(F1[1], F2[1]);
end;

function FP4Copy(Dst, Src: TCnFP4): TCnFP4;
begin
  Result := nil;
  if FP2Copy(Dst[0], Src[0]) = nil then Exit;
  if FP2Copy(Dst[1], Src[1]) = nil then Exit;
  Result := Dst;
end;

procedure FP4Negate(Res: TCnFP4; F: TCnFP4; Prime: TCnBigNumber);
begin
  FP2Negate(Res[0], F[0], Prime);
  FP2Negate(Res[1], F[1], Prime);
end;

procedure FP4Add(Res: TCnFP4; F1, F2: TCnFP4; Prime: TCnBigNumber);
begin
  FP2Add(Res[0], F1[0], F2[0], Prime);
  FP2Add(Res[1], F1[1], F2[1], Prime);
end;

procedure FP4Sub(Res: TCnFP4; F1, F2: TCnFP4; Prime: TCnBigNumber);
begin
  FP2Sub(Res[0], F1[0], F2[0], Prime);
  FP2Sub(Res[1], F1[1], F2[1], Prime);
end;

procedure FP4Mul(Res: TCnFP4; F1, F2: TCnFP4; Prime: TCnBigNumber);
var
  T, R0, R1: TCnFP2;
begin
  // r0 = a0 * b0 + a1 * b1 * u
  // r1 = a0 * b1 + a1 * b0
  T := nil;
  R0 := nil;
  R1 := nil;

  try
    T := FLocalFP2Pool.Obtain;
    R0 := FLocalFP2Pool.Obtain;
    R1 := FLocalFP2Pool.Obtain;

    FP2Mul(R0, F1[0], F2[0], Prime);
    FP2MulU(T, F1[1], F2[1], Prime);
    FP2Add(R0, R0, T, Prime);

    FP2Mul(R1, F1[0], F2[1], Prime);
    FP2Mul(T, F1[1], F2[0], Prime);
    FP2Add(Res[1], R1, T, Prime);

    FP2Copy(Res[0], R0);
  finally
    FLocalFP2Pool.Recycle(R1);
    FLocalFP2Pool.Recycle(R0);
    FLocalFP2Pool.Recycle(T);
  end;
end;

procedure FP4Mul3(Res: TCnFP4; F: TCnFP4; Prime: TCnBigNumber);
var
  T: TCnFP4;
begin
  T := FLocalFP4Pool.Obtain;
  try
    FP4Add(T, F, F, Prime);
    FP4Add(Res, T, F, Prime);
  finally
    FLocalFP4Pool.Recycle(T);
  end;
end;

procedure FP4MulV(Res: TCnFP4; F1, F2: TCnFP4; Prime: TCnBigNumber);
var
  T, R0, R1: TCnFP2;
begin
  // r0 = a0 * b1 * u + a1 * b0 * u
  // r1 = a0 * b0 + a1 * b1 * u
  T := nil;
  R0 := nil;
  R1 := nil;

  try
    T := FLocalFP2Pool.Obtain;
    R0 := FLocalFP2Pool.Obtain;
    R1 := FLocalFP2Pool.Obtain;

    FP2MulU(R0, F1[0], F2[1], Prime);
    FP2MulU(T, F1[1], F2[0], Prime);
    FP2Add(R0, R0, T, Prime);

    FP2Mul(R1, F1[0], F2[0], Prime);
    FP2MulU(T, F1[1], F2[1], Prime);
    FP2Add(Res[1], R1, T, Prime);

    FP2Copy(Res[0], R0);
  finally
    FLocalFP2Pool.Recycle(R1);
    FLocalFP2Pool.Recycle(R0);
    FLocalFP2Pool.Recycle(T);
  end;
end;

procedure FP4Inverse(Res: TCnFP4; F: TCnFP4; Prime: TCnBigNumber);
var
  R0, R1, K: TCnFP2;
begin
  // k = (f1^2 * u - f0^2)^-1
  // r0 = -(f0 * k)
  // r1 = f1 * k
  K := nil;
  R0 := nil;
  R1 := nil;

  try
    K := FLocalFP2Pool.Obtain;
    R0 := FLocalFP2Pool.Obtain;
    R1 := FLocalFP2Pool.Obtain;

    FP2MulU(K, F[1], F[1], Prime);
    FP2Mul(R0, F[0], F[0], Prime);
    FP2Sub(K, K, R0, Prime);
    FP2Inverse(R0, K, Prime);
    FP2Copy(K, R0);

    FP2Mul(R0, F[0], K, Prime);
    FP2Negate(R0, R0, Prime);

    FP2Mul(R1, F[1], K, Prime);

    FP2Copy(Res[0], R0);
    FP2Copy(Res[1], R1);
  finally
    FLocalFP2Pool.Recycle(R1);
    FLocalFP2Pool.Recycle(R0);
    FLocalFP2Pool.Recycle(K);
  end;
end;

procedure FP4Div(Res: TCnFP4; F1, F2: TCnFP4; Prime: TCnBigNumber);
var
  Inv: TCnFP4;
begin
  if F2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  if F1 = F2 then
    Res.SetOne
  else
  begin
    Inv := FLocalFP4Pool.Obtain;
    try
      FP4Inverse(Inv, F2, Prime);
      FP4Mul(Res, F1, Inv, Prime);
    finally
      FLocalFP4Pool.Recycle(Inv);
    end;
  end;
end;

function FP4ToStream(FP4: TCnFP4; Stream: TStream; FixedLen: Integer): Integer;
begin
  Result := FP2ToStream(FP4[1], Stream, FixedLen) + FP2ToStream(FP4[0], Stream, FixedLen);
end;

// ===================== ʮ�����������ϵ��Ԫ�����㺯�� ========================

function FP12New: TCnFP12;
begin
  Result := TCnFP12.Create;
end;

procedure FP12Free(FP12: TCnFP12);
begin
  FP12.Free;
end;

function FP12IsZero(FP12: TCnFP12): Boolean;
begin
  Result := FP12[0].IsZero and FP12[1].IsZero and FP12[2].IsZero;
end;

function FP12IsOne(FP12: TCnFP12): Boolean;
begin
  Result := FP12[0].IsOne and FP12[1].IsZero and FP12[2].IsZero;
end;

procedure FP12SetZero(FP12: TCnFP12);
begin
  FP12[0].SetZero;
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetOne(FP12: TCnFP12);
begin
  FP12[0].SetOne;
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetU(FP12: TCnFP12);
begin
  FP12[0].SetU;
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetV(FP12: TCnFP12);
begin
  FP12[0].SetV;
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetW(FP12: TCnFP12);
begin
  FP12[0].SetZero;
  FP12[1].SetOne;
  FP12[2].SetZero;
end;

procedure FP12SetWSqr(FP12: TCnFP12);
begin
  FP12[0].SetZero;
  FP12[1].SetZero;
  FP12[2].SetOne;
end;

procedure FP12SetBigNumber(FP12: TCnFP12; Num: TCnBigNumber);
begin
  FP12[0].SetBigNumber(Num);
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetBigNumbers(FP12: TCnFP12; Num0, Num1, Num2: TCnBigNumber);
begin
  FP12[0].SetBigNumber(Num0);
  FP12[1].SetBigNumber(Num1);
  FP12[2].SetBigNumber(Num2);
end;

procedure FP12SetFP4(FP12: TCnFP12; FP4: TCnFP4);
begin
  FP4Copy(FP12[0], FP4);
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12Set3FP4S(FP12: TCnFP12; FP40, FP41, FP42: TCnFP4);
begin
  FP4Copy(FP12[0], FP40);
  FP4Copy(FP12[1], FP41);
  FP4Copy(FP12[2], FP42);
end;

procedure FP12SetFP2(FP12: TCnFP12; FP2: TCnFP2);
begin
  FP4SetFP2(FP12[0], FP2);
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetHex(FP12: TCnFP12; const S0, S1, S2, S3, S4, S5, S6, S7, S8,
  S9, S10, S11: string);
begin
  FP12[0].SetHex(S0, S1, S2, S3);
  FP12[1].SetHex(S4, S5, S6, S7);
  FP12[2].SetHex(S8, S9, S10, S11);
end;

function FP12ToString(FP12: TCnFP12): string;
begin
  Result := FP12[2].ToString + CRLF + FP12[1].ToString + CRLF + FP12[0].ToString;
end;

procedure FP12SetWord(FP12: TCnFP12; Value: Cardinal);
begin
  FP4SetWord(FP12[0], Value);
  FP12[1].SetZero;
  FP12[2].SetZero;
end;

procedure FP12SetWords(FP12: TCnFP12; Value0, Value1, Value2, Value3, Value4,
  Value5, Value6, Value7, Value8, Value9, Value10, Value11: Cardinal);
begin
  FP12[0].SetWords(Value0, Value1, Value2, Value3);
  FP12[1].SetWords(Value4, Value5, Value6, Value7);
  FP12[2].SetWords(Value8, Value9, Value10, Value11);
end;

function FP12Equal(F1, F2: TCnFP12): Boolean;
begin
  Result := FP4Equal(F1[0], F2[0]) and FP4Equal(F1[1], F2[1]) and FP4Equal(F1[2], F2[2]);
end;

function FP12Copy(Dst, Src: TCnFP12): TCnFP12;
begin
  Result := nil;
  if FP4Copy(Dst[0], Src[0]) = nil then Exit;
  if FP4Copy(Dst[1], Src[1]) = nil then Exit;
  if FP4Copy(Dst[2], Src[2]) = nil then Exit;
  Result := Dst;
end;

procedure FP12Negate(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
begin
  FP4Negate(Res[0], F[0], Prime);
  FP4Negate(Res[1], F[1], Prime);
  FP4Negate(Res[2], F[2], Prime);
end;

procedure FP12Add(Res: TCnFP12; F1, F2: TCnFP12; Prime: TCnBigNumber);
begin
  FP4Add(Res[0], F1[0], F2[0], Prime);
  FP4Add(Res[1], F1[1], F2[1], Prime);
  FP4Add(Res[2], F1[2], F2[2], Prime);
end;

procedure FP12Sub(Res: TCnFP12; F1, F2: TCnFP12; Prime: TCnBigNumber);
begin
  FP4Sub(Res[0], F1[0], F2[0], Prime);
  FP4Sub(Res[1], F1[1], F2[1], Prime);
  FP4Sub(Res[2], F1[2], F2[2], Prime);
end;

procedure FP12Mul(Res: TCnFP12; F1, F2: TCnFP12; Prime: TCnBigNumber);
var
  T, R0, R1, R2: TCnFP4;
begin
  // r0 = a0 * b0 + a1 * b2 * v + a2 * b1 * v
  // r1 = a0 * b1 + a1 * b0 + a2 * b2 *v
  // r2 = a0 * b2 + a1 * b1 + a2 * b0
  T := nil;
  R0 := nil;
  R1 := nil;
  R2 := nil;

  try
    T := FLocalFP4Pool.Obtain;
    R0 := FLocalFP4Pool.Obtain;
    R1 := FLocalFP4Pool.Obtain;
    R2 := FLocalFP4Pool.Obtain;

    FP4Mul(R0, F1[0], F2[0], Prime);
    FP4MulV(T, F1[1], F2[2], Prime);
    FP4Add(R0, R0, T, Prime);
    FP4MulV(T, F1[2], F2[1], Prime);
    FP4Add(R0, R0, T, Prime);

    FP4Mul(R1, F1[0], F2[1], Prime);
    FP4Mul(T, F1[1], F2[0], Prime);
    FP4Add(R1, R1, T, Prime);
    FP4MulV(T, F1[2], F2[2], Prime);
    FP4Add(R1, R1, T, Prime);

    FP4Mul(R2, F1[0], F2[2], Prime);
    FP4Mul(T, F1[1], F2[1], Prime);
    FP4Add(R2, R2, T, Prime);
    FP4Mul(T, F1[2], F2[0], Prime);
    FP4Add(R2, R2, T, Prime);

    FP4Copy(Res[0], R0);
    FP4Copy(Res[1], R1);
    FP4Copy(Res[2], R2);
  finally
    FLocalFP4Pool.Recycle(R2);
    FLocalFP4Pool.Recycle(R1);
    FLocalFP4Pool.Recycle(R0);
    FLocalFP4Pool.Recycle(T);
  end;
end;

procedure FP12Mul3(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
var
  T: TCnFP12;
begin
  T := FLocalFP12Pool.Obtain;
  try
    FP12Add(T, F, F, Prime);
    FP12Add(Res, T, F, Prime);
  finally
    FLocalFP12Pool.Recycle(T);
  end;
end;

procedure FP12Inverse(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
var
  K, T, T0, T1, T2, T3: TCnFP4;
begin
  if FP4IsZero(F[2]) then // �ֿ�����
  begin
    // k = (f0^3 + f1^3 * v)^-1
    // r2 = f1^2 * k
    // r1 = -(f0 * f1 * k)
    // r0 = f0^2 * k
    K := nil;
    T := nil;

    try
      K := FLocalFP4Pool.Obtain;
      T := FLocalFP4Pool.Obtain;

      FP4Mul(K, F[0], F[0], Prime);
      FP4Mul(K, K, F[0], Prime);
      FP4MulV(T, F[1], F[1], Prime);
      FP4Mul(T, T, F[1], Prime);
      FP4Add(K, K, T, Prime);
      FP4Inverse(K, K, Prime);

      FP4Mul(T, F[1], F[1], Prime);
      FP4Mul(Res[2], T, K, Prime);

      FP4Mul(T, F[0], F[1], Prime);
      FP4Mul(T, T, K, Prime);
      FP4Negate(Res[1], T, Prime);

      FP4Mul(T, F[0], F[0], Prime);
      FP4Mul(Res[0], T, K, Prime);
    finally
      FLocalFP4Pool.Recycle(T);
      FLocalFP4Pool.Recycle(K);
    end;
  end
  else
  begin
    T := nil;
    T0 := nil;
    T1 := nil;
    T2 := nil;
    T3 := nil;

    try
      T := FLocalFP4Pool.Obtain;
      T0 := FLocalFP4Pool.Obtain;
      T1 := FLocalFP4Pool.Obtain;
      T2 := FLocalFP4Pool.Obtain;
      T3 := FLocalFP4Pool.Obtain;

      // t0 = f1^2 - f0 * f2
      // t1 = f0 * f1 - f2^2 * v
      // t2 = f0^2 - f1 * f2 * v
      // t3 = f2 * (t1^2 - t0 * t2)^-1
      FP4Mul(T0, F[1], F[1], Prime);
      FP4Mul(T1, F[0], F[2], Prime);
      FP4Sub(T0, T0, T1, Prime);

      FP4Mul(T1, F[0], F[1], Prime);
      FP4MulV(T2, F[2], F[2], Prime);
      FP4Sub(T1, T1, T2, Prime);

      FP4Mul(T2, F[0], F[0], Prime);
      FP4MulV(T3, F[1], F[2], Prime);
      FP4Sub(T2, T2, T3, Prime);

      FP4Mul(T3, T1, T1, Prime);
      FP4Mul(T, T0, T2, Prime);
      FP4Sub(T3, T3, T, Prime);
      FP4Inverse(T3, T3, Prime);
      FP4Mul(T3, F[2], T3, Prime);

      // r0 = t2 * t3
      // r1 = -(t1 * t3)
      // r2 = t0 * t3
      FP4Mul(Res[0], T2, T3, Prime);

      FP4Mul(Res[1], T1, T3, Prime);
      FP4Negate(Res[1], Res[1], Prime);

      FP4Mul(Res[2], T0, T3, Prime);
    finally
      FLocalFP4Pool.Recycle(T3);
      FLocalFP4Pool.Recycle(T2);
      FLocalFP4Pool.Recycle(T1);
      FLocalFP4Pool.Recycle(T0);
      FLocalFP4Pool.Recycle(T);
    end;
  end;
end;

procedure FP12Div(Res: TCnFP12; F1, F2: TCnFP12; Prime: TCnBigNumber);
var
  Inv: TCnFP12;
begin
  if F2.IsZero then
    raise EDivByZero.Create(SDivByZero);

  if F1 = F2 then
    Res.SetOne
  else
  begin
    Inv := FLocalFP12Pool.Obtain;
    try
      FP12Inverse(Inv, F2, Prime);
      FP12Mul(Res, F1, Inv, Prime);
    finally
      FLocalFP12Pool.Recycle(Inv);
    end;
  end;
end;

procedure FP12Power(Res: TCnFP12; F: TCnFP12; Exponent: TCnBigNumber;
  Prime: TCnBigNumber);
var
  I, N: Integer;
  T: TCnFP12;
begin
  if Exponent.IsZero then
  begin
    Res.SetOne;
    Exit;
  end
  else if Exponent.IsOne then
  begin
    FP12Copy(Res, F);
    Exit;
  end;

  N := Exponent.GetBitsCount;
  if Res = F then
    T := FLocalFP12Pool.Obtain
  else
    T := Res;

  FP12Copy(T, F);

  try
    for I := N - 2 downto 0 do  // ָ�������� 6 �� 13 ��֤���ƺ��ǶԵ�
    begin
      FP12Mul(T, T, T, Prime);
      if Exponent.IsBitSet(I) then
        FP12Mul(T, T, F, Prime);
    end;

    if Res = F then
      FP12Copy(Res, T);
  finally
    if Res = F then
      FLocalFP12Pool.Recycle(T);
  end;
end;

function FP12ToStream(FP12: TCnFP12; Stream: TStream; FixedLen: Integer): Integer;
begin
  Result := FP4ToStream(FP12[2], Stream, FixedLen) + FP4ToStream(FP12[1], Stream, FixedLen)
    + FP4ToStream(FP12[0], Stream, FixedLen);
end;

// ===================== ��������ϵ�����Ԫ������㺯�� ========================

function FP2AffinePointNew: TCnFP2AffinePoint;
begin
  Result := TCnFP2AffinePoint.Create;
end;

procedure AffinePointFree(P: TCnFP2AffinePoint);
begin
  P.Free;
end;

procedure FP2AffinePointSetZero(P: TCnFP2AffinePoint);
begin
  P.X.SetZero;
  P.Y.SetZero;
  P.Z.SetZero;
end;

function FP2AffinePointToString(P: TCnFP2AffinePoint): string;
begin
  Result := 'X: ' + P.X.ToString + CRLF + 'Y: ' + P.Y.ToString + CRLF + 'Z: ' + P.Z.ToString;
end;

function FP2AffinePointEqual(P1, P2: TCnFP2AffinePoint): Boolean;
begin
  Result := FP2Equal(P1.X, P2.X) and FP2Equal(P1.Y, P2.Y) and FP2Equal(P1.Z, P2.Z);
end;

function FP2AffinePointCopy(Dst, Src: TCnFP2AffinePoint): TCnFP2AffinePoint;
begin
  Result := nil;
  if FP2Copy(Dst.X, Src.X) = nil then Exit;
  if FP2Copy(Dst.Y, Src.Y) = nil then Exit;
  if FP2Copy(Dst.Z, Src.Z) = nil then Exit;
  Result := Dst;
end;

function FP2AffinePointIsAtInfinity(P: TCnFP2AffinePoint): Boolean;
begin
  Result := FP2IsZero(P.X) and FP2IsOne(P.Y) and FP2IsZero(P.Z);
end;

procedure FP2AffinePointSetToInfinity(P: TCnFP2AffinePoint);
begin
  P.X.SetZero;
  P.Y.SetOne;
  P.Z.SetZero;
end;

procedure FP2AffinePointGetCoordinates(P: TCnFP2AffinePoint; FP2X, FP2Y: TCnFP2);
begin
  if P.Z.IsOne then
  begin
    FP2Copy(FP2X, P.X);
    FP2Copy(FP2Y, P.Y);
  end
  else
    raise ECnSM9Exception.Create(SCnErrorSM9AffinePointZError);
end;

procedure FP2AffinePointSetCoordinates(P: TCnFP2AffinePoint; FP2X, FP2Y: TCnFP2);
begin
  FP2Copy(P.X, FP2X);
  FP2Copy(P.Y, FP2Y);
  FP2SetOne(P.Z);
end;

procedure FP2AffinePointSetCoordinatesHex(P: TCnFP2AffinePoint;
  const SX0, SX1, SY0, SY1: string);
begin
  FP2SetHex(P.X, SX0, SX1);
  FP2SetHex(P.Y, SY0, SY1);
  FP2SetOne(P.Z);
end;

procedure FP2AffinePointSetCoordinatesBigNumbers(P: TCnFP2AffinePoint;
  X0, X1, Y0, Y1: TCnBigNumber);
begin
  FP2SetBigNumbers(P.X, X0, X1);
  FP2SetBigNumbers(P.Y, X1, Y1);
  FP2SetOne(P.Z);
end;

procedure FP2AffinePointGetJacobianCoordinates(P: TCnFP2AffinePoint;
  FP12X, FP12Y: TCnFP12; Prime: TCnBigNumber);
var
  X, Y: TCnFP2;
  W: TCnFP12;
begin
  X := nil;
  Y := nil;
  W := nil;

  try
    X := FLocalFP2Pool.Obtain;
    Y := FLocalFP2Pool.Obtain;
    W := FLocalFP12Pool.Obtain;

    FP2AffinePointGetCoordinates(P, X, Y);
    FP12SetFP2(FP12X, X);
    FP12SetFP2(FP12Y, Y);

    // x = x * w^-2
    FP12SetWSqr(W);
    FP12Inverse(W, W, Prime);
    FP12Mul(FP12X, FP12X, W, Prime);

    // y = y * w^-3
    FP12SetV(W);
    FP12Inverse(W, W, Prime);
    FP12Mul(FP12Y, FP12Y, W, Prime);
  finally
    FLocalFP2Pool.Recycle(Y);
    FLocalFP2Pool.Recycle(X);
    FLocalFP12Pool.Recycle(W);
  end;
end;

procedure FP2AffinePointSetJacobianCoordinates(P: TCnFP2AffinePoint;
  FP12X, FP12Y: TCnFP12; Prime: TCnBigNumber);
var
  TX, TY: TCnFP12;
begin
  TX := nil;
  TY := nil;

  try
    TX := FLocalFP12Pool.Obtain;
    TY := FLocalFP12Pool.Obtain;

    FP12SetWSqr(TX);
    FP12SetV(TY);
    FP12Mul(TX, FP12X, TX, Prime);
    FP12Mul(TY, FP12Y, TY, Prime);

    FP2AffinePointSetCoordinates(P, TX[0][0], TY[0][0]);
  finally
    FLocalFP12Pool.Recycle(TY);
    FLocalFP12Pool.Recycle(TX);
  end;
end;

function FP2AffinePointIsOnCurve(P: TCnFP2AffinePoint; Prime: TCnBigNumber): Boolean;
var
  X, Y, B, T: TCnFP2;
begin
  X := nil;
  Y := nil;
  B := nil;
  T := nil;

  try
    X := FLocalFP2Pool.Obtain;
    Y := FLocalFP2Pool.Obtain;
    B := FLocalFP2Pool.Obtain;
    T := FLocalFP2Pool.Obtain;

    B[0].SetZero;
    B[1].SetWord(CN_SM9_ECC_B);   // B �� 5

    FP2AffinePointGetCoordinates(P, X, Y);

    // X^3 + 5 u
    FP2Mul(T, X, X, Prime);
    FP2Mul(X, X, T, Prime);
    FP2Add(X, X, B, Prime);

    // Y^2
    FP2Mul(Y, Y, Y, Prime);

    Result := FP2Equal(X, Y);
  finally
    FLocalFP2Pool.Recycle(T);
    FLocalFP2Pool.Recycle(B);
    FLocalFP2Pool.Recycle(Y);
    FLocalFP2Pool.Recycle(X);
  end;
end;

procedure FP2AffinePointNegate(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
begin
  FP2Copy(Res.X, P.X);
  FP2Negate(Res.Y, P.Y, Prime);
  FP2Copy(Res.Z, P.Z);
end;

procedure FP2AffinePointDouble(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
var
  L, T, X1, Y1, X2, Y2: TCnFP2;
begin
  if P.IsAtInfinity then
  begin
    Res.SetToInfinity;
    Exit;
  end;

  L := nil;
  T := nil;
  X1 := nil;
  Y1 := nil;
  X2 := nil;
  Y2 := nil;

  try
    L := FLocalFP2Pool.Obtain;
    T := FLocalFP2Pool.Obtain;
    X1 := FLocalFP2Pool.Obtain;
    Y1 := FLocalFP2Pool.Obtain;
    X2 := FLocalFP2Pool.Obtain;
    Y2 := FLocalFP2Pool.Obtain;

    FP2AffinePointGetCoordinates(P, X1, Y1);

    // L := 3 * x1^2 / (2 * y1)
    FP2Mul(L, X1, X1, Prime);
    FP2Mul3(L, L, Prime);
    FP2Add(T, Y1, Y1, Prime);
    FP2Inverse(T, T, Prime);
    FP2Mul(L, L, T, Prime);

    // X2 = L^2 - 2 * X1
    FP2Mul(X2, L, L, Prime);
    FP2Add(T, X1, X1, Prime);
    FP2Sub(X2, X2, T, Prime);

    // Y2 = L * (X1 - X2) - Y1
    FP2Sub(Y2, X1, X2, Prime);
    FP2Mul(Y2, L, Y2, Prime);
    FP2Sub(Y2, Y2, Y1, Prime);

    FP2AffinePointSetCoordinates(Res, X2, Y2);
  finally
    FLocalFP2Pool.Recycle(Y2);
    FLocalFP2Pool.Recycle(X2);
    FLocalFP2Pool.Recycle(Y1);
    FLocalFP2Pool.Recycle(X1);
    FLocalFP2Pool.Recycle(T);
    FLocalFP2Pool.Recycle(L);
  end;
end;

procedure FP2AffinePointAdd(Res: TCnFP2AffinePoint; P, Q: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
var
  X1, Y1, X2, Y2, X3, Y3, L, T: TCnFP2;
begin
  if FP2AffinePointIsAtInfinity(P) then
    FP2AffinePointCopy(Res, Q)
  else if FP2AffinePointIsAtInfinity(Q) then
    FP2AffinePointCopy(Res, P)
  else if FP2AffinePointEqual(P, Q) then
    FP2AffinePointDouble(P, Q, Prime)
  else
  begin
    T := nil;
    L := nil;
    X1 := nil;
    Y1 := nil;
    X2 := nil;
    Y2 := nil;
    X3 := nil;
    Y3 := nil;

    try
      T := FLocalFP2Pool.Obtain;
      L := FLocalFP2Pool.Obtain;
      X1 := FLocalFP2Pool.Obtain;
      Y1 := FLocalFP2Pool.Obtain;
      X2 := FLocalFP2Pool.Obtain;
      Y2 := FLocalFP2Pool.Obtain;
      X3 := FLocalFP2Pool.Obtain;
      Y3 := FLocalFP2Pool.Obtain;

      FP2AffinePointGetCoordinates(P, X1, Y1);
      FP2AffinePointGetCoordinates(Q, X2, Y2);
      FP2Add(T, Y1, Y2, Prime);

      if T.IsZero and FP2Equal(X1, X2) then // ������
      begin
        Res.SetToInfinity; // ��Ϊ 0
        Exit;
      end;

      // L = (Y2 - Y1)/(X2 - X1)
      FP2Sub(L, Y2, Y1, Prime);
      FP2Sub(T, X2, X1, Prime);
      FP2Inverse(T, T, Prime);
      FP2Mul(L, L, T, Prime);

      // X3 = L^2 - X1 - X2
      FP2Mul(X3, L, L, Prime);
      FP2Sub(X3, X3, X1, Prime);
      FP2Sub(X3, X3, X2, Prime);

      // Y3 = L * (X1 - X3) - Y1
      FP2Sub(Y3, X1, X3, Prime);
      FP2Mul(Y3, L, Y3, Prime);
      FP2Sub(Y3, Y3, Y1, Prime);

      FP2AffinePointSetCoordinates(Res, X3, Y3);
    finally
      FLocalFP2Pool.Recycle(Y3);
      FLocalFP2Pool.Recycle(X3);
      FLocalFP2Pool.Recycle(Y2);
      FLocalFP2Pool.Recycle(X2);
      FLocalFP2Pool.Recycle(Y1);
      FLocalFP2Pool.Recycle(X1);
      FLocalFP2Pool.Recycle(L);
      FLocalFP2Pool.Recycle(T);
    end;
  end;
end;

procedure FP2AffinePointSub(Res: TCnFP2AffinePoint; P, Q: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
var
  T: TCnFP2AffinePoint;
begin
  T := FLocalFP2AffinePointPool.Obtain;
  try
    FP2AffinePointNegate(T, Q, Prime);
    FP2AffinePointAdd(Res, P, T, Prime);
  finally
    FLocalFP2AffinePointPool.Recycle(T);
  end;
end;

procedure FP2AffinePointMul(Res: TCnFP2AffinePoint; P: TCnFP2AffinePoint;
  Num: TCnBigNumber; Prime: TCnBigNumber);
var
  I, N: Integer;
  T: TCnFP2AffinePoint;
begin
  if Num.IsZero then
    FP2AffinePointSetToInfinity(Res)
  else if Num.IsOne then
    FP2AffinePointCopy(Res, P)
  else  // �˶��ڼӣ���ͬ���ݶ��ڳˣ����Ժ� Power �㷨����
  begin
    N := Num.GetBitsCount;
    if Res = P then
      T := FLocalFP2AffinePointPool.Obtain
    else
      T := Res;
        
    try
      FP2AffinePointCopy(T, P);
      for I := N - 2 downto 0 do
      begin
        FP2AffinePointDouble(T, T, Prime);
        if Num.IsBitSet(I) then
          FP2AffinePointAdd(T, T, P, Prime);
      end;

      if Res = P then
        FP2AffinePointCopy(Res, T);
    finally
      if Res = P then
        FLocalFP2AffinePointPool.Recycle(T);
    end;
  end;
end;

procedure FP2AffinePointFrobenius(Res: TCnFP2AffinePoint;
  P: TCnFP2AffinePoint; Prime: TCnBigNumber);
var
  X, Y: TCnFP12;
begin
  X := nil;
  Y := nil;

  try
    X := FLocalFP12Pool.Obtain;
    Y := FLocalFP12Pool.Obtain;

    FP2AffinePointGetJacobianCoordinates(P, X, Y, Prime);
    FP12Power(X, X, Prime, Prime);
    FP12Power(Y, Y, Prime, Prime);
    FP2AffinePointSetJacobianCoordinates(Res, X, Y, Prime);
  finally
    FLocalFP12Pool.Recycle(Y);
    FLocalFP12Pool.Recycle(X);
  end;
end;

function FP2PointToString(P: TCnFP2Point): string;
begin
  Result := 'X: ' + P.X.ToString + CRLF + 'Y: ' + P.Y.ToString;
end;

procedure FP2AffinePointToFP2Point(FP2P: TCnFP2Point; FP2AP: TCnFP2AffinePoint;
  Prime: TCnBigNumber);
var
  V: TCnFP2;
begin
  // X := X/Z   Y := Y/Z
  if FP2AP.Z.IsZero then
    raise EDivByZero.Create(SDivByZero);

  V := FLocalFP2Pool.Obtain;
  try
    FP2Inverse(V, FP2AP.Z, Prime);
    FP2Mul(FP2P.X, FP2AP.X, V, Prime);
    FP2Mul(FP2P.Y, FP2AP.Y, V, Prime);
  finally
    FLocalFP2Pool.Recycle(V);
  end;
end;

procedure FP2PointToFP2AffinePoint(FP2AP: TCnFP2AffinePoint; FP2P: TCnFP2Point);
begin
  FP2Copy(FP2AP.X, FP2P.X);
  FP2Copy(FP2AP.Y, FP2P.Y);

  if FP2AP.X.IsZero and FP2AP.Y.IsZero then
    FP2AP.Z.SetZero
  else
    FP2AP.Z.SetOne;
end;

// ============================ ˫���ԶԼ��㺯�� ===============================

// ��һ������
procedure Tangent(Res: TCnFP12; T: TCnFP2AffinePoint;
  XP, YP: TCnBigNumber; Prime: TCnBigNumber);
var
  X, Y, XT, YT, L, Q: TCnFP12;
begin
  X := nil;
  Y := nil;
  XT := nil;
  YT := nil;
  L := nil;
  Q := nil;

  try
    X := FLocalFP12Pool.Obtain;
    Y := FLocalFP12Pool.Obtain;
    XT := FLocalFP12Pool.Obtain;
    YT := FLocalFP12Pool.Obtain;
    L := FLocalFP12Pool.Obtain;
    Q := FLocalFP12Pool.Obtain;

    FP2AffinePointGetJacobianCoordinates(T, XT, YT, Prime);

    FP12SetBigNumber(X, XP);
    FP12SetBigNumber(Y, YP);

    // L = (3 * YT^2)/(2 * YT)
    FP12Mul(L, XT, XT, Prime);
    FP12Mul3(L, L, Prime);
    FP12Add(Q, YT, YT, Prime);
    FP12Inverse(Q, Q, Prime);
    FP12Mul(L, L, Q, Prime);

    // r = lambda * (x - xT) - y + yT
    FP12Sub(Res, X, XT, Prime);
    FP12Mul(Res, L, Res, Prime);
    FP12Sub(Res, Res, Y, Prime);
    FP12Add(Res, Res, YT, Prime);
  finally
    FLocalFP12Pool.Recycle(Q);
    FLocalFP12Pool.Recycle(L);
    FLocalFP12Pool.Recycle(YT);
    FLocalFP12Pool.Recycle(XT);
    FLocalFP12Pool.Recycle(Y);
    FLocalFP12Pool.Recycle(X);
  end;
end;

// ���������
procedure Secant(Res: TCnFP12; T, Q: TCnFP2AffinePoint;
  XP, YP: TCnBigNumber; Prime: TCnBigNumber);
var
  X, Y, L, M, XT, YT, XQ, YQ: TCnFP12;
begin
  X := nil;
  Y := nil;
  L := nil;
  M := nil;
  XT := nil;
  YT := nil;
  XQ := nil;
  YQ := nil;

  try
    X := FLocalFP12Pool.Obtain;
    Y := FLocalFP12Pool.Obtain;
    L := FLocalFP12Pool.Obtain;
    M := FLocalFP12Pool.Obtain;
    XT := FLocalFP12Pool.Obtain;
    YT := FLocalFP12Pool.Obtain;
    XQ := FLocalFP12Pool.Obtain;
    YQ := FLocalFP12Pool.Obtain;

    FP2AffinePointGetJacobianCoordinates(T, XT, YT, Prime);
    FP2AffinePointGetJacobianCoordinates(Q, XQ, YQ, Prime);

    FP12SetBigNumber(X, XP);
    FP12SetBigNumber(Y, YP);

    // L = (yT - yQ)/(xT - xQ)
    FP12Sub(L, YT, YQ, Prime);
    FP12Sub(M, XT, XQ, Prime);
    FP12Inverse(M, M, Prime);
    FP12Mul(L, L, M, Prime);

    // r = L * (x - xQ) - y + yQ
    FP12Sub(Res, X, XQ, Prime);
    FP12Mul(Res, L, Res, Prime);
    FP12Sub(Res, Res, Y, Prime);
    FP12Add(Res, Res, YQ, Prime);
  finally
    FLocalFP12Pool.Recycle(YQ);
    FLocalFP12Pool.Recycle(XQ);
    FLocalFP12Pool.Recycle(YT);
    FLocalFP12Pool.Recycle(XT);
    FLocalFP12Pool.Recycle(M);
    FLocalFP12Pool.Recycle(L);
    FLocalFP12Pool.Recycle(Y);
    FLocalFP12Pool.Recycle(X);
  end;
end;

procedure FP12FastExp1(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
begin
  FP2Copy(Res[0][0], F[0][0]);
  FP2Negate(Res[0][1], F[0][1], Prime);
  FP2Negate(Res[1][0], F[1][0], Prime);
  FP2Copy(Res[1][1], F[1][1]);
  FP2Copy(Res[2][0], F[2][0]);
  FP2Negate(Res[2][1], F[2][1], Prime);
end;

procedure FP12FastExp2(Res: TCnFP12; F: TCnFP12; Prime: TCnBigNumber);
begin
  FP2Copy(Res[0][0], F[0][0]);
  FP2Negate(Res[0][1], F[0][1], Prime);
  FP2Mul(Res[1][0], F[1][0], FFP12FastExpPW20, Prime);
  FP2Mul(Res[1][1], F[1][1], FFP12FastExpPW21, Prime);
  FP2Mul(Res[2][0], F[2][0], FFP12FastExpPW22, Prime);
  FP2Mul(Res[2][1], F[2][1], FFP12FastExpPW23, Prime);
end;

procedure FinalFastExp(Res: TCnFP12; F: TCnFP12; K: TCnBigNumber;
  Prime: TCnBigNumber);
var
  I, N: Integer;
  T, T0: TCnFP12;
begin
  T := nil;
  T0 := nil;

  try
    T := FLocalFP12Pool.Obtain;
    T0 := FLocalFP12Pool.Obtain;

    FP12Copy(T, F);

    FP12Inverse(T0, T, Prime);
    FP12FastExp1(T, T, Prime);
    FP12Mul(T, T0, T, Prime);
    FP12Copy(T0, T);

    FP12FastExp2(T, T, Prime);
    FP12Mul(T, T0, T, Prime);
    FP12Copy(T0, T);

    N := K.GetBitsCount;
    for I := N - 2 downto 0 do
    begin
      FP12Mul(T, T, T, Prime);
      if K.IsBitSet(I) then
        FP12Mul(T, T, T0, Prime);
    end;

    FP12Copy(Res, T);
  finally
    FLocalFP12Pool.Recycle(T0);
    FLocalFP12Pool.Recycle(T);
  end;
end;

procedure Rate(F: TCnFP12; Q: TCnFP2AffinePoint; XP, YP: TCnBigNumber;
  A: TCnBigNumber; K: TCnBigNumber; Prime: TCnBigNumber);
var
  I, N: Integer;
  T, Q1, Q2: TCnFP2AffinePoint;
  G: TCnFP12;
begin
  T := nil;
  Q1 := nil;
  Q2 := nil;
  G := nil;

  try
    T := FLocalFP2AffinePointPool.Obtain;
    Q1 := FLocalFP2AffinePointPool.Obtain;
    Q2 := FLocalFP2AffinePointPool.Obtain;
    G := FLocalFP12Pool.Obtain;

    FP12SetOne(F);
    FP2AffinePointCopy(T, Q);
    N := A.GetBitsCount;

    for I := N - 2 downto 0 do
    begin
      Tangent(G, T, XP, YP, Prime);
      FP12Mul(F, F, F, Prime);
      FP12Mul(F, F, G, Prime);

      FP2AffinePointDouble(T, T, Prime);

      if A.IsBitSet(I) then
      begin
        Secant(G, T, Q, XP, YP, Prime);
        FP12Mul(F, F, G, Prime);
        FP2AffinePointAdd(T, T, Q, Prime);
      end;
    end;

    FP2AffinePointFrobenius(Q1, Q, Prime);

    FP2AffinePointFrobenius(Q2, Q, Prime);
    FP2AffinePointFrobenius(Q2, Q2, Prime);

    Secant(G, T, Q1, XP, YP, Prime);
    FP12Mul(F, F, G, Prime);

    FP2AffinePointAdd(T, T, Q1, Prime);

    FP2AffinePointNegate(Q2, Q2, Prime);
    Secant(G, T, Q2, XP, YP, Prime);
    FP12Mul(F, F, G, Prime);

    FP2AffinePointAdd(T, T, Q2, Prime);

    FinalFastExp(F, F, K, Prime);
  finally
    FLocalFP12Pool.Recycle(G);
    FLocalFP2AffinePointPool.Recycle(Q2);
    FLocalFP2AffinePointPool.Recycle(Q1);
    FLocalFP2AffinePointPool.Recycle(T);
  end;
end;

procedure SM9RatePairing(F: TCnFP12; Q: TCnFP2AffinePoint; P: TCnEccPoint);
var
  XP, YP: TCnBigNumber; // P �����������
  AQ: TCnFP2AffinePoint;   // Q �����������
begin
  if P <> nil then
  begin
    XP := P.X;
    YP := P.Y;
  end
  else // ��� P �� nil����ʹ�� SM9 �����ߵ� G1 ��
  begin
    XP := FSM9G1P1X;
    YP := FSM9G1P1Y;
  end;

  if Q = nil then // ��� Q �� nil����ʹ�� SM9 ���ߵ� G2 ��
  begin
    AQ := FLocalFP2AffinePointPool.Obtain;
    AQ.SetCoordinatesBigNumbers(FSM9G2P2X0, FSM9G2P2X1, FSM9G2P2Y0, FSM9G2P2Y1);
  end
  else
    AQ := Q;

  // ���� R-ate �Ե�ֵ
  Rate(F, AQ, XP, YP, FSM96TPlus2, FSM9FastExpP3, FSM9FiniteFieldSize);

  if Q = nil then
    FLocalFP2AffinePointPool.Recycle(AQ);
end;

{ TCnFP2 }

constructor TCnFP2.Create;
begin
  inherited;
  F0 := TCnBigNumber.Create;
  F1 := TCnBigNumber.Create;
end;

destructor TCnFP2.Destroy;
begin
  F1.Free;
  F0.Free;
  inherited;
end;

function TCnFP2.GetItems(Index: Integer): TCnBigNumber;
begin
  if Index = 0 then
    Result := F0
  else if Index = 1 then
    Result := F1
  else
    raise ECnSM9Exception.CreateFmt(SCnErrorSM9ListIndexError, [Index]);
end;

function TCnFP2.IsOne: Boolean;
begin
  Result := FP2IsOne(Self);
end;

function TCnFP2.IsZero: Boolean;
begin
  Result := FP2IsZero(Self);
end;

procedure TCnFP2.SetBigNumber(Num: TCnBigNumber);
begin
  FP2SetBigNumber(Self, Num);
end;

procedure TCnFP2.SetHex(const S0, S1: string);
begin
  FP2SetHex(Self, S0, S1);
end;

procedure TCnFP2.SetOne;
begin
  FP2SetOne(Self);
end;

procedure TCnFP2.SetU;
begin
  FP2SetU(Self);
end;

procedure TCnFP2.SetWord(Value: Cardinal);
begin
  FP2SetWord(Self, Value);
end;

procedure TCnFP2.SetWords(Value0, Value1: Cardinal);
begin
  FP2SetWords(Self, Value0, Value1);
end;

procedure TCnFP2.SetZero;
begin
  FP2SetZero(Self);
end;

function TCnFP2.ToString: string;
begin
  Result := FP2ToString(Self);
end;

{ TCnFP4 }

constructor TCnFP4.Create;
begin
  inherited;
  F0 := TCnFP2.Create;
  F1 := TCnFP2.Create;
end;

destructor TCnFP4.Destroy;
begin
  F1.Free;
  F0.Free;
  inherited;
end;

function TCnFP4.GetItems(Index: Integer): TCnFP2;
begin
  if Index = 0 then
    Result := F0
  else if Index = 1 then
    Result := F1
  else
    raise ECnSM9Exception.CreateFmt(SCnErrorSM9ListIndexError, [Index]);
end;

function TCnFP4.IsOne: Boolean;
begin
  Result := FP4IsOne(Self);
end;

function TCnFP4.IsZero: Boolean;
begin
  Result := FP4IsZero(Self);
end;

procedure TCnFP4.SetBigNumber(Num: TCnBigNumber);
begin
  FP4SetBigNumber(Self, Num);
end;

procedure TCnFP4.SetBigNumbers(Num0, Num1: TCnBigNumber);
begin
  FP4SetBigNumbers(Self, Num0, Num1);
end;

procedure TCnFP4.SetHex(const S0, S1, S2, S3: string);
begin
  FP4SetHex(Self, S0, S1, S2, S3);
end;

procedure TCnFP4.SetOne;
begin
  FP4SetOne(Self);
end;

procedure TCnFP4.SetU;
begin
  FP4SetU(Self);
end;

procedure TCnFP4.SetV;
begin
  FP4SetV(Self);
end;

procedure TCnFP4.SetWord(Value: Cardinal);
begin
  FP4SetWord(Self, Value);
end;

procedure TCnFP4.SetWords(Value0, Value1, Value2,
  Value3: Cardinal);
begin
  FP4SetWords(Self, Value0, Value1, Value2, Value3);
end;

procedure TCnFP4.SetZero;
begin
  FP4SetZero(Self);
end;

function TCnFP4.ToString: string;
begin
  Result := FP4ToString(Self);
end;

{ TCnFP12 }

constructor TCnFP12.Create;
begin
  inherited;
  F0 := TCnFP4.Create;
  F1 := TCnFP4.Create;
  F2 := TCnFP4.Create;
end;

destructor TCnFP12.Destroy;
begin
  F2.Free;
  F1.Free;
  F0.Free;
  inherited;
end;

function TCnFP12.GetItems(Index: Integer): TCnFP4;
begin
  if Index = 0 then
    Result := F0
  else if Index = 1 then
    Result := F1
  else if Index = 2 then
    Result := F2
  else
    raise ECnSM9Exception.CreateFmt(SCnErrorSM9ListIndexError, [Index]);
end;

function TCnFP12.IsOne: Boolean;
begin
  Result := FP12IsOne(Self);
end;

function TCnFP12.IsZero: Boolean;
begin
  Result := FP12IsZero(Self);
end;

procedure TCnFP12.SetBigNumber(Num: TCnBigNumber);
begin
  FP12SetBigNumber(Self, Num);
end;

procedure TCnFP12.SetBigNumbers(Num0, Num1, Num2: TCnBigNumber);
begin
  FP12SetBigNumbers(Self, Num0, Num1, Num2);
end;

procedure TCnFP12.SetHex(const S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10,
  S11: string);
begin
  FP12SetHex(Self, S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11);
end;

procedure TCnFP12.SetOne;
begin
  FP12SetOne(Self);
end;

procedure TCnFP12.SetU;
begin
  FP12SetU(Self);
end;

procedure TCnFP12.SetV;
begin
  FP12SetV(Self);
end;

procedure TCnFP12.SetW;
begin
  FP12SetW(Self);
end;

procedure TCnFP12.SetWord(Value: Cardinal);
begin
  FP12SetWord(Self, Value);
end;

procedure TCnFP12.SetWords(Value0, Value1, Value2, Value3, Value4, Value5,
  Value6, Value7, Value8, Value9, Value10, Value11: Cardinal);
begin
  FP12SetWords(Self, Value0, Value1, Value2, Value3, Value4, Value5,
    Value6, Value7, Value8, Value9, Value10, Value11);
end;

procedure TCnFP12.SetWSqr;
begin
  FP12SetWSqr(Self);
end;

procedure TCnFP12.SetZero;
begin
  FP12SetZero(Self);
end;

function TCnFP12.ToString: string;
begin
  Result := FP12ToString(Self);
end;

{ TCnFP2Pool }

function TCnFP2Pool.CreateObject: TObject;
begin
  Result := TCnFP2.Create;
end;

function TCnFP2Pool.Obtain: TCnFP2;
begin
  Result := TCnFP2(inherited Obtain);
  Result.SetZero;
end;

procedure TCnFP2Pool.Recycle(Num: TCnFP2);
begin
  inherited Recycle(Num);
end;

{ TCnFP4Pool }

function TCnFP4Pool.CreateObject: TObject;
begin
  Result := TCnFP4.Create;
end;

function TCnFP4Pool.Obtain: TCnFP4;
begin
  Result := TCnFP4(inherited Obtain);
  Result.SetZero;
end;

procedure TCnFP4Pool.Recycle(Num: TCnFP4);
begin
  inherited Recycle(Num);
end;

{ TCnFP12Pool }

function TCnFP12Pool.CreateObject: TObject;
begin
  Result := TCnFP12.Create;
end;

function TCnFP12Pool.Obtain: TCnFP12;
begin
  Result := TCnFP12(inherited Obtain);
  Result.SetZero;
end;

procedure TCnFP12Pool.Recycle(Num: TCnFP12);
begin
  inherited Recycle(Num);
end;

{ TCnFP2AffinePoint }

constructor TCnFP2AffinePoint.Create;
begin
  inherited;
  FX := TCnFP2.Create;
  FY := TCnFP2.Create;
  FZ := TCnFP2.Create;
end;

destructor TCnFP2AffinePoint.Destroy;
begin
  FZ.Free;
  FY.Free;
  FX.Free;
  inherited;
end;

procedure TCnFP2AffinePoint.GetCoordinatesFP2(FP2X, FP2Y: TCnFP2);
begin
  FP2AffinePointGetCoordinates(Self, FP2X, FP2Y);
end;

procedure TCnFP2AffinePoint.GetJacobianCoordinatesFP12(FP12X, FP12Y: TCnFP12;
  Prime: TCnBigNumber);
begin
  FP2AffinePointGetJacobianCoordinates(Self, FP12X, FP12Y, Prime);
end;

function TCnFP2AffinePoint.IsAtInfinity: Boolean;
begin
  Result := FP2AffinePointIsAtInfinity(Self);
end;

function TCnFP2AffinePoint.IsOnCurve(Prime: TCnBigNumber): Boolean;
begin
  Result := FP2AffinePointIsOnCurve(Self, Prime);
end;

procedure TCnFP2AffinePoint.SetCoordinatesBigNumbers(X0, X1, Y0,
  Y1: TCnBigNumber);
begin
  FP2AffinePointSetCoordinatesBigNumbers(Self, X0, X1, Y0, Y1);
end;

procedure TCnFP2AffinePoint.SetCoordinatesFP2(FP2X, FP2Y: TCnFP2);
begin
  FP2AffinePointSetCoordinates(Self, FP2X, FP2Y);
end;

procedure TCnFP2AffinePoint.SetCoordinatesHex(const SX0, SX1, SY0,
  SY1: string);
begin
  FP2AffinePointSetCoordinatesHex(Self, SX0, SX1, SY0, SY1);
end;

procedure TCnFP2AffinePoint.SetJacobianCoordinatesFP12(FP12X, FP12Y: TCnFP12;
  Prime: TCnBigNumber);
begin
  FP2AffinePointSetJacobianCoordinates(Self, FP12X, FP12Y, Prime);
end;

procedure TCnFP2AffinePoint.SetToInfinity;
begin
  FP2AffinePointSetToInfinity(Self);
end;

procedure TCnFP2AffinePoint.SetZero;
begin
  FP2AffinePointSetZero(Self);
end;

function TCnFP2AffinePoint.ToString: string;
begin
  Result := FP2AffinePointToString(Self);
end;

{ TCnFP2AffinePointPool }

function TCnFP2AffinePointPool.CreateObject: TObject;
begin
  Result := TCnFP2AffinePoint.Create;
end;

function TCnFP2AffinePointPool.Obtain: TCnFP2AffinePoint;
begin
  Result := TCnFP2AffinePoint(inherited Obtain);
//  Result.SetZero;
end;

procedure TCnFP2AffinePointPool.Recycle(Num: TCnFP2AffinePoint);
begin
  inherited Recycle(Num);
end;

procedure InitSM9Consts;
begin
  FSM9FiniteFieldSize := TCnBigNumber.FromHex(CN_SM9_FINITE_FIELD);
  FSM9Order := TCnBigNumber.FromHex(CN_SM9_ORDER);
  FSM9G1P1X := TCnBigNumber.FromHex(CN_SM9_G1_P1X);
  FSM9G1P1Y := TCnBigNumber.FromHex(CN_SM9_G1_P1Y);
  FSM9G2P2X0 := TCnBigNumber.FromHex(CN_SM9_G2_P2X0);
  FSM9G2P2X1 := TCnBigNumber.FromHex(CN_SM9_G2_P2X1);
  FSM9G2P2Y0 := TCnBigNumber.FromHex(CN_SM9_G2_P2Y0);
  FSM9G2P2Y1 := TCnBigNumber.FromHex(CN_SM9_G2_P2Y1);
  FSM96TPlus2 := TCnBigNumber.FromHex(CN_SM9_6T_PLUS_2);
  FSM9FastExpP3 := TCnBigNumber.FromHex(CN_SM9_FAST_EXP_P3);
  FFP12FastExpPW20 := TCnBigNumber.FromHex(CN_SM9_FAST_EXP_PW20);
  FFP12FastExpPW21 := TCnBigNumber.FromHex(CN_SM9_FAST_EXP_PW21);
  FFP12FastExpPW22 := TCnBigNumber.FromHex(CN_SM9_FAST_EXP_PW22);
  FFP12FastExpPW23 := TCnBigNumber.FromHex(CN_SM9_FAST_EXP_PW23);
end;

procedure FreeSM9Consts;
begin
  FSM9FiniteFieldSize.Free;
  FSM9Order.Free;
  FSM9G1P1X.Free;
  FSM9G1P1Y.Free;
  FSM9G2P2X0.Free;
  FSM9G2P2X1.Free;
  FSM9G2P2Y0.Free;
  FSM9G2P2Y1.Free;
  FSM96TPlus2.Free;
  FSM9FastExpP3.Free;
  FFP12FastExpPW20.Free;
  FFP12FastExpPW21.Free;
  FFP12FastExpPW22.Free;
  FFP12FastExpPW23.Free;
end;

function CnSM9KGCGenerateSignatureMasterKey(SignatureMasterKey:
  TCnSM9SignatureMasterKey; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  AP: TCnFP2AffinePoint;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  AP := nil;
  try
    if not BigNumberRandRange(SignatureMasterKey.PrivateKey, SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_RANDOM_ERROR);
      Exit;
    end;

    if SignatureMasterKey.PrivateKey.IsZero then
      SignatureMasterKey.PrivateKey.SetOne;

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);

    FP2AffinePointMul(AP, AP, SignatureMasterKey.PrivateKey, SM9.FiniteFieldSize);
    FP2AffinePointToFP2Point(SignatureMasterKey.PublicKey, AP, SM9.FiniteFieldSize);

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    AP.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9KGCGenerateSignatureUserKey(SignatureMasterPrivateKey: TCnSM9SignatureMasterPrivateKey;
  const AUserID: AnsiString; OutSignatureUserPrivateKey: TCnSM9SignatureUserPrivateKey; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  T1, T2: TCnBigNumber;
  S: AnsiString;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  T1 := nil;
  T2 := nil;

  try
    T1 := TCnBigNumber.Create;
    T2 := TCnBigNumber.Create;

    // ���� T1 := Hash1(ID��hid��SM9Order) + MasterPrivateKey��ע�����µ������������� Order �ף������ǻ��� P
    S := AUserID + AnsiChar(CN_SM9_SIGNATURE_USER_HID);
    if not CnSM9Hash1(T1, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    BigNumberAddMod(T1, T1, SignatureMasterPrivateKey, SM9.Order);

    if T1.IsZero then
    begin
      _CnSetLastError(ECN_SM9_SIGN_MASTERKEY_ZERO_ERROR);
      Exit;
    end;

    // ���� T2 = PrivateKey / T1
    if not BigNumberModularInverse(T2, T1, SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_BIGNUMBER_ERROR);
      Exit;
    end;

    BigNumberDirectMulMod(T2, SignatureMasterPrivateKey, T2, SM9.Order);

    OutSignatureUserPrivateKey.Assign(SM9.Generator);
    SM9.MultiplePoint(T2, OutSignatureUserPrivateKey); // ������������� SM9 �� P
    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    T2.Free;
    T1.Free;

    if C then
      SM9.Free;
  end;
end;

function CnSM9UserSignData(SignatureMasterPublicKey: TCnSM9SignatureMasterPublicKey;
  SignatureUserPrivateKey: TCnSM9SignatureUserPrivateKey; PlainData: Pointer;
  DataByteLen: Integer; OutSignature: TCnSM9Signature; SM9: TCnSM9; const RandHex: string): Boolean;
var
  C: Boolean;
  G: TCnFP12;
  AP: TCnFP2AffinePoint;
  R, L: TCnBigNumber;
  HexSet: Boolean;
  Stream: TMemoryStream;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  G := nil;
  AP := nil;
  R := nil;
  Stream := nil;
  L := nil;

  try
    G := TCnFP12.Create;
    AP := TCnFP2AffinePoint.Create;

    // ���ù�Կ�����һ�����Զ� FP12
    FP2PointToFP2AffinePoint(AP, SignatureMasterPublicKey);
    SM9RatePairing(G, AP, SM9.Generator);

    R := TCnBigNumber.Create;
    Stream := TMemoryStream.Create;
    L := TCnBigNumber.Create;
    HexSet := False;

    repeat
      if RandHex <> '' then
      begin
        R.SetHex(AnsiString(RandHex));
        HexSet := True;
      end
      else
      begin
        // ������� R
        if not BigNumberRandRange(R, SM9.Order) then
        begin
          _CnSetLastError(ECN_SM9_RANDOM_ERROR);
          Exit;
        end;
      end;

      if R.IsZero then
        R.SetOne;   // ȷ����Χ�� [1, N-1]

      // ���� G^R �η�
      FP12Power(G, G, R, SM9.FiniteFieldSize);

      Stream.Clear;
      Stream.Write(PlainData^, DataByteLen);
      FP12ToStream(G, Stream, SM9.BytesCount);

      if not CnSM9Hash2(OutSignature.H, Stream.Memory, Stream.Size, SM9.Order) then
      begin
        _CnSetLastError(ECN_SM9_HASH_ERROR);
        Exit;
      end;

      BigNumberSub(L, R, OutSignature.H);
      BigNumberNonNegativeMod(L, L, SM9.Order);

      if HexSet and L.IsZero then // �ⲿ����Ĺ̶���������� L Ϊ 0������Ҳû�����ˣ�ֱ�ӳ����˳�
        Exit;
    until not L.IsZero;

    // ������� L �� H���ٳ�˽Կ��õ�ǩ��
    OutSignature.S.Assign(SignatureUserPrivateKey);
    SM9.MultiplePoint(L, OutSignature.S);
    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    L.Free;
    Stream.Free;
    R.Free;
    AP.Free;
    G.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserVerifyData(const AUserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  InSignature: TCnSM9Signature; SignatureMasterPublicKey: TCnSM9SignatureMasterPublicKey;
  SM9: TCnSM9): Boolean;
var
  C: Boolean;
  G, W: TCnFP12;
  AP, TP: TCnFP2AffinePoint;
  S: AnsiString;
  H: TCnBigNumber;
  Stream: TMemoryStream;
begin
  Result := False;
  if InSignature.H.IsZero or InSignature.H.IsNegative then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    Exit;
  end;

  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  G := nil;
  AP := nil;
  H := nil;
  TP := nil;
  W := nil;
  Stream := nil;

  try
    if BigNumberCompare(InSignature.H, SM9.Order) >= 0 then Exit;
    if not SM9.IsPointOnCurve(InSignature.S) then Exit;

    G := TCnFP12.Create;
    AP := TCnFP2AffinePoint.Create;

    // ���ù�Կ�����һ�����Զ� FP12
    FP2PointToFP2AffinePoint(AP, SignatureMasterPublicKey);
    SM9RatePairing(G, AP, SM9.Generator);

    // ���� FP12 ����
    FP12Power(G, G, InSignature.H, SM9.FiniteFieldSize);

    H := TCnBigNumber.Create;
    // ���� H1
    S := AUserID + AnsiChar(CN_SM9_SIGNATURE_USER_HID);
    if not CnSM9Hash1(H, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    // ���� G2 ���ϵ� H1*P2
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);
    FP2AffinePointMul(AP, AP, H, SM9.FiniteFieldSize);

    // ������ Pub������� TP ��
    TP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(TP, SignatureMasterPublicKey);
    FP2AffinePointAdd(TP, AP, TP, SM9.FiniteFieldSize);

    // �ټ���һ��˫���Զ� e(S, P)
    W := TCnFP12.Create;
    SM9RatePairing(W, TP, InSignature.S);

    // W �ٺ� G ���
    FP12Mul(W, W, G, SM9.FiniteFieldSize);

    Stream := TMemoryStream.Create;
    Stream.Write(PlainData^, DataByteLen);
    FP12ToStream(W, Stream, SM9.BytesCount);

    // �ٴ�ƴ��ԭ���� FP12 ���� Hash2 ���ȶ�
    if not CnSM9Hash2(H, Stream.Memory, Stream.Size, SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    Result := BigNumberEqual(H, InSignature.H);
  finally
    Stream.Free;
    W.Free;
    TP.Free;
    H.Free;
    AP.Free;
    G.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9KGCGenerateEncryptionMasterKey(EncryptionMasterKey:
  TCnSM9EncryptionMasterKey; SM9: TCnSM9): Boolean;
var
  C: Boolean;
begin
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  try
    BigNumberRandRange(EncryptionMasterKey.PrivateKey, SM9.Order);
    if EncryptionMasterKey.PrivateKey.IsZero then
      EncryptionMasterKey.PrivateKey.SetOne;

    EncryptionMasterKey.PublicKey.Assign(SM9.Generator);
    SM9.MultiplePoint(EncryptionMasterKey.PrivateKey, EncryptionMasterKey.PublicKey);

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    if C then
      SM9.Free;
  end;
end;

function CnSM9KGCGenerateEncryptionUserKey(EncryptionMasterPrivateKey: TCnSm9EncryptionMasterPrivateKey;
  const AUserID: AnsiString; OutEncryptionUserKey: TCnSM9EncryptionUserPrivateKey; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  S: AnsiString;
  T1, T2: TCnBigNumber;
  AP: TCnFP2AffinePoint;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  T1 := nil;
  T2 := nil;
  AP := nil;

  try
    S := AUserID + AnsiChar(CN_SM9_KEY_ENCAPSULATION_USER_HID);

    T1 := TCnBigNumber.Create;
    if not CnSM9Hash1(T1, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    BigNumberAdd(T1, T1, EncryptionMasterPrivateKey);

    if T1.IsZero then
    begin
      _CnSetLastError(ECN_SM9_ENCRYPT_MASTERKEY_ZERO_ERROR);
      Exit;
    end;

    T2 := TCnBigNumber.Create;
    if not BigNumberModularInverse(T2, T1, SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_BIGNUMBER_ERROR);
      Exit;
    end;
    BigNumberCopy(T1, T2);

    BigNumberDirectMulMod(T1, T1, EncryptionMasterPrivateKey, SM9.Order);

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);
    FP2AffinePointMul(AP, AP, T1, SM9.FiniteFieldSize);
    FP2AffinePointToFP2Point(OutEncryptionUserKey, AP, SM9.FiniteFieldSize);

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    AP.Free;
    T2.Free;
    T1.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserSendKeyEncapsulation(const DestUserID: AnsiString; KeyByteLength: Integer;
  EncryptionPublicKey: TCnSM9EncryptionMasterPublicKey;
  OutKeyEncapsulation: TCnSM9KeyEncapsulation; SM9: TCnSM9; const RandHex: string): Boolean;
var
  C: Boolean;
  S: AnsiString;
  H, R: TCnBigNumber;
  AP: TCnFP2AffinePoint;
  G: TCnFP12;
  Stream: TMemoryStream;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  H := nil;
  R := nil;
  AP := nil;
  G := nil;
  Stream := nil;

  try
    S := DestUserID + AnsiChar(CN_SM9_KEY_ENCAPSULATION_USER_HID);
    H := TCnBigNumber.Create;

    if not CnSM9Hash1(H, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    OutKeyEncapsulation.Code.Assign(SM9.Generator);
    SM9.MultiplePoint(H, OutKeyEncapsulation.Code);
    SM9.PointAddPoint(EncryptionPublicKey, OutKeyEncapsulation.Code, OutKeyEncapsulation.Code);

    R := TCnBigNumber.Create;
    if RandHex <> '' then
      R.SetHex(AnsiString(RandHex))
    else
    begin
      if not BigNumberRandRange(R, SM9.Order) then
      begin
        _CnSetLastError(ECN_SM9_RANDOM_ERROR);
        Exit;
      end;
    end;

    if R.IsZero then
      R.SetOne;

    SM9.MultiplePoint(R, OutKeyEncapsulation.Code); // �õ���װ���� C

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);

    G := TCnFP12.Create;
    SM9RatePairing(G, AP, EncryptionPublicKey);
    FP12Power(G, G, R, SM9.FiniteFieldSize);

    Stream := TMemoryStream.Create;
    CnEccPointToStream(OutKeyEncapsulation.Code, Stream, SM9.BytesCount);
    FP12ToStream(G, Stream, SM9.BytesCount);
    Stream.Write(DestUserID[1], Length(DestUserID));

    OutKeyEncapsulation.Key := CnSM9KDFBytes(Stream.Memory, Stream.Size, KeyByteLength); // �õ���װ��Կ K
    Result := KeyByteLength = Length(OutKeyEncapsulation.Key);
  finally
    Stream.Free;
    G.Free;
    AP.Free;
    R.Free;
    H.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserReceiveKeyEncapsulation(const DestUserID: AnsiString;
  EncryptionUserKey: TCnSM9EncryptionUserPrivateKey; KeyByteLength: Integer;
  InKeyEncapsulationC: TCnSM9KeyEncapsulationCode; out Key: TBytes; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  W: TCnFP12;
  AP: TCnFP2AffinePoint;
  Stream: TMemoryStream;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  W := nil;
  AP := nil;
  Stream := nil;

  try
    if not SM9.IsPointOnCurve(InKeyEncapsulationC) then
    begin
      _CnSetLastError(ECN_SM9_INVALID_INPUT);
      Exit;
    end;

    W := TCnFP12.Create;
    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, EncryptionUserKey);
    SM9RatePairing(W, AP, InKeyEncapsulationC);

    Stream := TMemoryStream.Create;
    CnEccPointToStream(InKeyEncapsulationC, Stream, SM9.BytesCount);
    FP12ToStream(W, Stream, SM9.BytesCount);
    Stream.Write(DestUserID[1], Length(DestUserID));

    Key := CnSM9KDFBytes(Stream.Memory, Stream.Size, KeyByteLength);
    Result := Length(Key) > 0;

    if Result then
      _CnSetLastError(ECN_SM9_OK)
    else
      _CnSetLastError(ECN_SM9_KDF_ERROR);
  finally
    Stream.Free;
    AP.Free;
    W.Free;
    if C then
      SM9.Free;
  end;
end;

{
   C1 ��һ�� EccPoint������Ϊ���� 32 �ֽڹ� 64 �ֽ�
   C2 ������ֵ��XOR ģʽ�³��ȵ�������ֵ��SM4 ģʽ�³��ȵ������ĵ� PKCS7 ���볤��
   C3 ��һ�� Mac ֵ���� SM3 ���㣬���� 32 �ֽ�
   ����Ϊ��C1��C3��C2
}
function CnSM9UserEncryptData(const DestUserID: AnsiString;
  EncryptionPublicKey: TCnSM9EncryptionMasterPublicKey; PlainData: Pointer;
  DataByteLen: Integer; K1ByteLength, K2ByteLength: Integer; OutStream: TStream;
  EncryptionMode: TCnSM9EncrytionMode; SM9: TCnSM9; const RandHex: string): Boolean;
var
  C: Boolean;
  S, KDFKey: AnsiString;
  H, R: TCnBigNumber;
  Q: TCnEccPoint;
  AP: TCnFP2AffinePoint;
  G: TCnFP12;
  Stream: TMemoryStream;
  I, KLen: Integer;
  P2, C2: TBytes;
  PD: PByteArray;
  Mac: TCnSM3Digest;
begin
  Result := False;
  if (DestUserID = '') or (PlainData = nil) or (DataByteLen <= 0) or (K1ByteLength <= 0)
    or (K2ByteLength <= 0) then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    Exit;
  end;

  // SM4 �� Key ����ֻ�� 16
  if EncryptionMode = semSM4 then
    K1ByteLength := CN_SM4_KEYSIZE;

  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  H := nil;
  Q := nil;
  R := nil;
  AP := nil;
  G := nil;
  Stream := nil;
  C2 := nil;
  P2 := nil;

  try
    S := DestUserID + AnsiChar(CN_SM9_ENCRYPTION_USER_HID);
    H := TCnBigNumber.Create;

    if not CnSM9Hash1(H, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    Q := TCnEccPoint.Create;
    Q.Assign(SM9.Generator);
    SM9.MultiplePoint(H, Q);
    SM9.PointAddPoint(EncryptionPublicKey, Q, Q);

    R := TCnBigNumber.Create;
    if RandHex <> '' then
      R.SetHex(AnsiString(RandHex))
    else
    begin
      if not BigNumberRandRange(R, SM9.Order) then
      begin
        _CnSetLastError(ECN_SM9_RANDOM_ERROR);
        Exit;
      end;
    end;

    if R.IsZero then
      R.SetOne;

    SM9.MultiplePoint(R, Q); // Q �õ� C1

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);

    G := TCnFP12.Create;
    SM9RatePairing(G, AP, EncryptionPublicKey);
    FP12Power(G, G, R, SM9.FiniteFieldSize); // G �õ��� w

    Stream := TMemoryStream.Create;
    CnEccPointToStream(Q, Stream, SM9.BytesCount);
    FP12ToStream(G, Stream, SM9.BytesCount);
    Stream.Write(DestUserID[1], Length(DestUserID));

    KLen := 0; // ��ʼ��һ��
    if EncryptionMode = semSM4 then
    begin
      KLen := K1ByteLength + K2ByteLength;
      KDFKey := CnSM9KDF(Stream.Memory, Stream.Size, KLen);

      SetLength(P2, DataByteLen);
      Move(PlainData^, P2[0], DataByteLen);
      BytesAddPKCS7Padding(P2, CN_SM4_BLOCKSIZE); // ����ԭʼ���ݲ���β�����ϼ������� PKCS7 ����

      SetLength(C2, Length(P2));

      // ʹ�� KDFKey �� 1 �� K1Length ��Ϊ������ SM4 ���ܶ��������Ĳ��ŵ� C2 ��
      SM4Encrypt(@KDFKey[1], @P2[0], @C2[0], Length(P2));
    end
    else if EncryptionMode = semKDF then
    begin
      KLen := DataByteLen + K2ByteLength;
      KDFKey := CnSM9KDF(Stream.Memory, Stream.Size, KLen);

      // KDFKey �� 1 �� DataLen ���������õ� C2��ע�� KDFKey ���±�� 1 ��ʼ
      PD := PByteArray(PlainData);
      SetLength(C2, DataByteLen);

      for I := 0 to DataByteLen - 1 do
        C2[I] := Byte(KDFKey[I + 1]) xor PD^[I];
    end;

    Mac := SM9Mac(@(KDFKey[KLen - K2ByteLength + 1]), K2ByteLength, @C2[0], Length(C2)); // �� K2 �� C2 ��� C3

    CnEccPointToStream(Q, OutStream, SM9.BytesCount);    // д C1
    OutStream.Write(Mac[0], SizeOf(TCnSM3Digest));       // д C3
    OutStream.Write(C2[0], Length(C2));                  // д C2

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    SetLength(P2, 0);
    SetLength(C2, 0);
    Stream.Free;
    G.Free;
    AP.Free;
    R.Free;
    Q.Free;
    H.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserDecryptData(const DestUserID: AnsiString;
  EncryptionUserKey: TCnSM9EncryptionUserPrivateKey; EnData: Pointer;
  DataByteLen: Integer; K2ByteLength: Integer; OutStream: TStream;
  EncryptionMode: TCnSM9EncrytionMode; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  C1: TCnEccPoint;
  C3, Mac: TCnSM3Digest;
  P: PByteArray;
  PC: PAnsiChar;
  AP: TCnFP2AffinePoint;
  W: TCnFP12;
  Stream: TMemoryStream;
  KLen, I, MLen: Integer;
  KDFKey: AnsiString;
  C2: TBytes;
begin
  Result := False;
  if (EnData = nil) or (K2ByteLength <= 0) or (DataByteLen <= 0) then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    Exit;
  end;

  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  if DataByteLen <= (SM9.BitsCount div 4) + SizeOf(TCnSM3Digest) then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    if C then
      SM9.Free;
    Exit;
  end;

  C1 := nil;
  AP := nil;
  W := nil;
  Stream := nil;
  C2 := nil;

  // ����ǰ 2 * SM9.BitsCount div 8 ���ֽ��� C1 ��� EccPoint �Ķ�������ʽ

  try
    PC := PAnsiChar(EnData);
    C1 := TCnEccPoint.Create;
    C1.X.SetBinary(PC, SM9.BitsCount div 8);
    Inc(PC, SM9.BitsCount div 8);
    C1.Y.SetBinary(PC, SM9.BitsCount div 8);

    // ���ж��Ƿ���������
    if not SM9.IsPointOnCurve(C1) then
    begin
      _CnSetLastError(ECN_SM9_INVALID_INPUT);
      Exit;
    end;

    Inc(PC, SM9.BitsCount div 8);
    Move(PC^, C3[0], SizeOf(TCnSM3Digest)); // ȡ�� C3 �Ա��Ƚ�
    Inc(PC, SizeOf(TCnSM3Digest));  // PC ����ָ������ C2

    P := PByteArray(PC);
    MLen := DataByteLen - SM9.BitsCount div 4 - SizeOf(TCnSM3Digest); // MLen ���ĳ���

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, EncryptionUserKey);
    W := TCnFP12.Create;
    SM9RatePairing(W, AP, C1);

    Stream := TMemoryStream.Create;
    CnEccPointToStream(C1, Stream, SM9.BytesCount);
    FP12ToStream(W, Stream, SM9.BytesCount);
    Stream.Write(DestUserID[1], Length(DestUserID));

    SetLength(C2, MLen);
    if EncryptionMode = semSM4 then
    begin
      KLen := CN_SM4_KEYSIZE + K2ByteLength;
      KDFKey := CnSM9KDF(Stream.Memory, Stream.Size, KLen);
      Mac := SM9Mac(@(KDFKey[KLen - K2ByteLength + 1]), K2ByteLength, @P[0], MLen); // �� K2 �� C2 ��� C3

      // SK4 ������ĵ� C2
      SM4Decrypt(@KDFKey[1], @P[0], @C2[0], Length(C2));
      // ȥ�� C2 β���� PKCS7 ���ݼ�Ϊ����
      BytesRemovePKCS7Padding(C2);
    end
    else if EncryptionMode = semKDF then
    begin
      KLen := MLen + K2ByteLength;
      KDFKey := CnSM9KDF(Stream.Memory, Stream.Size, KLen);
      Mac := SM9Mac(@(KDFKey[KLen - K2ByteLength + 1]), K2ByteLength, @P[0], MLen); // �� K2 �� C2 ��� C3

      // KDFKey ��ǰ�沿�ֵĳ�������������ȣ�XOR �������Ϊ����
      for I := 0 to Length(C2) - 1 do
        C2[I] := Byte(KDFKey[I + 1]) xor P^[I];
    end;

    if CompareMem(@C3[0], @Mac[0], SizeOf(TCnSM3Digest)) then
    begin
      OutStream.Write(C2[0], Length(C2));

      Result := True;
      _CnSetLastError(ECN_SM9_OK);
    end;
  finally
    SetLength(C2, 0);
    Stream.Free;
    W.Free;
    AP.Free;
    C1.Free;
    if C then
      SM9.Free;
  end;
end;

// ====================== SM9 ����ʵ�ֺ�������ԿЭ�� ===========================

function CnSM9KGCGenerateKeyExchangeMasterKey(KeyExchangeMasterKey:
  TCnSM9KeyExchangeMasterKey; SM9: TCnSM9): Boolean;
var
  C: Boolean;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  try
    if not BigNumberRandRange(KeyExchangeMasterKey.PrivateKey, SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_RANDOM_ERROR);
      Exit;
    end;

    if KeyExchangeMasterKey.PrivateKey.IsZero then
      KeyExchangeMasterKey.PrivateKey.SetOne;

    KeyExchangeMasterKey.PublicKey.Assign(SM9.Generator);
    SM9.MultiplePoint(KeyExchangeMasterKey.PrivateKey, KeyExchangeMasterKey.PublicKey);

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    if C then
      SM9.Free;
  end;
end;

function CnSM9KGCGenerateKeyExchangeUserKey(KeyExchangeMasterPrivateKey:
  TCnSM9KeyExchangeMasterPrivateKey; const AUserID: AnsiString;
  OutKeyExchangeUserKey: TCnSM9KeyExchangeUserPrivateKey; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  S: AnsiString;
  T1, T2: TCnBigNumber;
  AP: TCnFP2AffinePoint;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  T1 := nil;
  T2 := nil;
  AP := nil;

  try
    S := AUserID + AnsiChar(CN_SM9_KEY_EXCHANGE_USER_HID);

    T1 := TCnBigNumber.Create;
    if not CnSM9Hash1(T1, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    BigNumberAdd(T1, T1, KeyExchangeMasterPrivateKey);

    if T1.IsZero then
    begin
      _CnSetLastError(ECN_SM9_ENCRYPT_MASTERKEY_ZERO_ERROR);
      Exit;
    end;

    T2 := TCnBigNumber.Create;
    if not BigNumberModularInverse(T2, T1, SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_BIGNUMBER_ERROR);
      Exit;
    end;
    BigNumberCopy(T1, T2);

    BigNumberDirectMulMod(T1, T1, KeyExchangeMasterPrivateKey, SM9.Order);

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);
    FP2AffinePointMul(AP, AP, T1, SM9.FiniteFieldSize);
    FP2AffinePointToFP2Point(OutKeyExchangeUserKey, AP, SM9.FiniteFieldSize);

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    AP.Free;
    T2.Free;
    T1.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserKeyExchangeAStep1(const BUserID: AnsiString; KeyByteLength: Integer;
  KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey; OutRA: TCnEccPoint;
  OutRandA: TCnBigNumber; SM9: TCnSM9; const RandHex: string): Boolean;
var
  C: Boolean;
  S: AnsiString;
  T: TCnBigNumber;
begin
  Result := False;
  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  T := nil;

  try
    S := BUserID + AnsiChar(CN_SM9_KEY_EXCHANGE_USER_HID);
    T := TCnBigNumber.Create;
    if not CnSM9Hash1(T, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    OutRA.Assign(SM9.Generator);
    SM9.MultiplePoint(T, OutRA);
    SM9.PointAddPoint(OutRA, KeyExchangePublicKey, OutRA);

    if RandHex <> '' then
      OutRandA.SetHex(AnsiString(RandHex))
    else
    begin
      if not BigNumberRandRange(OutRandA, SM9.Order) then
      begin
        _CnSetLastError(ECN_SM9_RANDOM_ERROR);
        Exit;
      end;
    end;

    if OutRandA.IsZero then
      OutRandA.SetOne;

    SM9.MultiplePoint(OutRandA, OutRA);
    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    T.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserKeyExchangeBStep1(const AUserID, BUserID: AnsiString;
  KeyByteLength: Integer; KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey;
  KeyExchangeBUserKey: TCnSM9KeyExchangeUserPrivateKey; InRA: TCnEccPoint;
  OutRB: TCnEccPoint; out KeyB: TBytes; out OutOptionalSB: TCnSM3Digest;
  OutG1, OutG2, OutG3: TCnFP12; SM9: TCnSM9; const RandHex: string): Boolean;
var
  C: Boolean;
  S: AnsiString;
  R, T: TCnBigNumber;
  AP: TCnFP2AffinePoint;
  Stream: TMemoryStream;
  B: Byte;
  D: TCnSM3Digest;
begin
  Result := False;

  if (InRA = nil) or (KeyByteLength <= 0) or
    (OutG1 = nil) or (OutG2 = nil) or (OutG3 = nil) then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    Exit;
  end;

  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  T := nil;
  R := nil;
  AP := nil;
  Stream := nil;

  try
    if not SM9.IsPointOnCurve(InRA) then
    begin
      _CnSetLastError(ECN_SM9_INVALID_INPUT);
      Exit;
    end;

    S := AUserID + AnsiChar(CN_SM9_KEY_EXCHANGE_USER_HID);
    T := TCnBigNumber.Create;
    if not CnSM9Hash1(T, @S[1], Length(S), SM9.Order) then
    begin
      _CnSetLastError(ECN_SM9_HASH_ERROR);
      Exit;
    end;

    OutRB.Assign(SM9.Generator);
    SM9.MultiplePoint(T, OutRB);
    SM9.PointAddPoint(OutRB, KeyExchangePublicKey, OutRB);

    R := TCnBigNumber.Create;
    if RandHex <> '' then
      R.SetHex(AnsiString(RandHex))
    else
    begin
      if not BigNumberRandRange(R, SM9.Order) then
      begin
        _CnSetLastError(ECN_SM9_RANDOM_ERROR);
        Exit;
      end;
    end;

    if R.IsZero then
      R.SetOne;

    SM9.MultiplePoint(R, OutRB);

    AP := TCnFP2AffinePoint.Create;

    FP2PointToFP2AffinePoint(AP, KeyExchangeBUserKey);
    SM9RatePairing(OutG1, AP, InRA);

    FP2PointToFP2AffinePoint(AP, SM9.Generator2);
    SM9RatePairing(OutG2, AP, KeyExchangePublicKey);
    FP12Power(OutG2, OutG2, R, SM9.FiniteFieldSize);

    FP12Power(OutG3, OutG1, R, SM9.FiniteFieldSize); // ��������� G

    Stream := TMemoryStream.Create;
    Stream.Write(AUserID[1], Length(AUserID));
    Stream.Write(BUserID[1], Length(BUserID));
    CnEccPointToStream(InRA, Stream, SM9.BytesCount);
    CnEccPointToStream(OutRB, Stream, SM9.BytesCount);
    FP12ToStream(OutG1, Stream, SM9.BytesCount);
    FP12ToStream(OutG2, Stream, SM9.BytesCount);
    FP12ToStream(OutG3, Stream, SM9.BytesCount);

    KeyB := CnSM9KDFBytes(Stream.Memory, Stream.Size, KeyByteLength); // ������Э����Կ

    // �ټ����ѡ��У��ֵ
    Stream.Clear;
    FP12ToStream(OutG2, Stream, SM9.BytesCount);
    FP12ToStream(OutG3, Stream, SM9.BytesCount);
    Stream.Write(AUserID[1], Length(AUserID));
    Stream.Write(BUserID[1], Length(BUserID));
    CnEccPointToStream(InRA, Stream, SM9.BytesCount);
    CnEccPointToStream(OutRB, Stream, SM9.BytesCount);
    D := SM3(Stream.Memory, Stream.Size);  // ��һ���Ӵ�

    Stream.Clear;
    B := CN_SM9_KEY_EXCHANGE_HASHID1;
    Stream.Write(B, 1);
    FP12ToStream(OutG1, Stream, SM9.BytesCount);
    Stream.Write(D[0], SizeOf(TCnSM3Digest));
    OutOptionalSB := SM3(Stream.Memory, Stream.Size); // �ڶ����Ӵ�

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    Stream.Free;
    AP.Free;
    R.Free;
    T.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserKeyExchangeAStep2(const AUserID, BUserID: AnsiString; KeyByteLength: Integer;
  KeyExchangePublicKey: TCnSM9KeyExchangeMasterPublicKey;
  KeyExchangeAUserKey: TCnSM9KeyExchangeUserPrivateKey; InRandA: TCnBigNumber;
  InRA, InRB: TCnEccPoint; InOptionalSB: TCnSM3Digest; out KeyA: TBytes;
  out OutOptionalSA: TCnSM3Digest; SM9: TCnSM9): Boolean;
var
  C: Boolean;
  G1, G2, G3: TCnFP12;
  AP: TCnFP2AffinePoint;
  Stream: TMemoryStream;
  B: Byte;
  D: TCnSM3Digest;
begin
  Result := False;
  if (InRA = nil) or (InRB = nil) or (InRandA = nil) then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    Exit;
  end;

  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  AP := nil;
  G1 := nil;
  G2 := nil;
  G3 := nil;
  Stream := nil;

  try
    if not SM9.IsPointOnCurve(InRB) then
    begin
      _CnSetLastError(ECN_SM9_INVALID_INPUT);
      Exit;
    end;

    AP := TCnFP2AffinePoint.Create;
    FP2PointToFP2AffinePoint(AP, SM9.Generator2);

    G1 := TCnFP12.Create;
    SM9RatePairing(G1, AP, KeyExchangePublicKey);
    FP12Power(G1, G1, InRandA, SM9.FiniteFieldSize);

    G2 := TCnFP12.Create;
    FP2PointToFP2AffinePoint(AP, KeyExchangeAUserKey);
    SM9RatePairing(G2, AP, InRB);

    G3 := TCnFP12.Create;
    FP12Power(G3, G2, InRandA, SM9.FiniteFieldSize); // Ҳ��������� G

    Stream := TMemoryStream.Create;
    FP12ToStream(G2, Stream, SM9.BytesCount);
    FP12ToStream(G3, Stream, SM9.BytesCount);
    Stream.Write(AUserID[1], Length(AUserID));
    Stream.Write(BUserID[1], Length(BUserID));
    CnEccPointToStream(InRA, Stream, SM9.BytesCount);
    CnEccPointToStream(InRB, Stream, SM9.BytesCount);
    D := SM3(Stream.Memory, Stream.Size); // ��һ���Ӵ�

    Stream.Clear;
    B := CN_SM9_KEY_EXCHANGE_HASHID1;
    Stream.Write(B, 1);
    FP12ToStream(G1, Stream, SM9.BytesCount);
    Stream.Write(D[0], SizeOf(TCnSM3Digest));
    D := SM3(Stream.Memory, Stream.Size); // �ڶ����Ӵ�

    if not CompareMem(@D[0], @InOptionalSB[0], SizeOf(TCnSM3Digest)) then
    begin
      _CnSetLastError(ECN_SM9_INVALID_INPUT);
      Exit;
    end;

    // У�� SA SB ͨ���󣬿�ʼ������Կ
    Stream.Clear;
    Stream.Write(AUserID[1], Length(AUserID));
    Stream.Write(BUserID[1], Length(BUserID));
    CnEccPointToStream(InRA, Stream, SM9.BytesCount);
    CnEccPointToStream(InRB, Stream, SM9.BytesCount);
    FP12ToStream(G1, Stream, SM9.BytesCount);
    FP12ToStream(G2, Stream, SM9.BytesCount);
    FP12ToStream(G3, Stream, SM9.BytesCount);

    KeyA := CnSM9KDFBytes(Stream.Memory, Stream.Size, KeyByteLength); // ������Э����Կ

    // ��ѡ������һ��У��
    Stream.Clear;
    FP12ToStream(G2, Stream, SM9.BytesCount);
    FP12ToStream(G3, Stream, SM9.BytesCount);
    Stream.Write(AUserID[1], Length(AUserID));
    Stream.Write(BUserID[1], Length(BUserID));
    CnEccPointToStream(InRA, Stream, SM9.BytesCount);
    CnEccPointToStream(InRB, Stream, SM9.BytesCount);
    D := SM3(Stream.Memory, Stream.Size); // ��һ���Ӵ�

    Stream.Clear;
    B := CN_SM9_KEY_EXCHANGE_HASHID2;
    Stream.Write(B, 1);
    FP12ToStream(G1, Stream, SM9.BytesCount);
    Stream.Write(D[0], SizeOf(TCnSM3Digest));
    OutOptionalSA := SM3(Stream.Memory, Stream.Size); // �ڶ����Ӵ�

    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    Stream.Free;
    AP.Free;
    G3.Free;
    G2.Free;
    G1.Free;
    if C then
      SM9.Free;
  end;
end;

function CnSM9UserKeyExchangeBStep2(const AUserID, BUserID: AnsiString;
  InRA, InRB: TCnEccPoint; InOptionalSA: TCnSM3Digest; InG1, InG2, InG3: TCnFP12;
  SM9: TCnSM9): Boolean;
var
  C: Boolean;
  D: TCnSM3Digest;
  Stream: TMemoryStream;
  B: Byte;
begin
  Result := False;

  if (InRA = nil) or (InRB = nil) or
    (InG1 = nil) or (InG2 = nil) or (InG3 = nil) then
  begin
    _CnSetLastError(ECN_SM9_INVALID_INPUT);
    Exit;
  end;

  C := SM9 = nil;
  if C then
    SM9 := TCnSM9.Create;

  Stream := nil;

  try
    Stream := TMemoryStream.Create;

    FP12ToStream(InG2, Stream, SM9.BytesCount);
    FP12ToStream(InG3, Stream, SM9.BytesCount);
    Stream.Write(AUserID[1], Length(AUserID));
    Stream.Write(BUserID[1], Length(BUserID));
    CnEccPointToStream(InRA, Stream, SM9.BytesCount);
    CnEccPointToStream(InRB, Stream, SM9.BytesCount);

    D := SM3(Stream.Memory, Stream.Size);
    Stream.Clear;
    B := CN_SM9_KEY_EXCHANGE_HASHID2;

    Stream.Write(B, 1);
    FP12ToStream(InG1, Stream, SM9.BytesCount);
    Stream.Write(D[0], SizeOf(TCnSM3Digest));

    // �ڶ����Ӵ�
    D := SM3(Stream.Memory, Stream.Size);
    Result := CompareMem(@D[0], @InOptionalSA[0], SizeOf(TCnSM3Digest));

    if Result then
      _CnSetLastError(ECN_SM9_OK)
    else
    begin
      _CnSetLastError(ECN_SM9_INVALID_INPUT);
      Exit;
    end;
  finally
    Stream.Free;
    if C then
      SM9.Free;
  end;
end;

function SM9Hash(const Res: TCnBigNumber; Prefix: Byte; Data: Pointer; DataByteLen: Integer;
  N: TCnBigNumber): Boolean;
var
  CT, SCT, HLen: Cardinal;
  I, CeilLen: Integer;
  IsInt: Boolean;
  DArr, Ha: TBytes; // Ha �� HLen Bits
  SM3D: TCnSM3Digest;
  BH, BN: TCnBigNumber;
begin
  Result := False;
  if (Data = nil) or (DataByteLen <= 0) then
    Exit;

  DArr := nil;
  Ha := nil;
  BH := nil;
  BN := nil;

  // �� N �� 256 Bits ʱ

  try
    CT := 1;
    HLen := ((N.GetBitsCount * 5 + 31) div 32);
    HLen := 8 * HLen;
    // HLen ��һ�� Bits ����������� Ha �ı��س��ȣ������� SM9 ��Ӧ���ܱ� 8 ����Ҳ���Ƿ������ֽ���
    // N = 256 Bits ʱ HLen = 320

    IsInt := HLen mod CN_SM3_DIGEST_BITS = 0;
    CeilLen := (HLen + CN_SM3_DIGEST_BITS - 1) div CN_SM3_DIGEST_BITS;

    // CeilLen = 2��FloorLen = 1

    SetLength(DArr, DataByteLen + SizeOf(Byte) + SizeOf(Cardinal)); // 1 Byte Prefix + 4 Byte Cardinal CT
    DArr[0] := Prefix;
    Move(Data^, DArr[1], DataByteLen);

    SetLength(Ha, HLen div 8);

    for I := 1 to CeilLen do
    begin
      SCT := UInt32HostToNetwork(CT);  // ��Ȼ�ĵ���û˵����Ҫ����һ��
      Move(SCT, DArr[DataByteLen + 1], SizeOf(Cardinal));
      SM3D := SM3(@DArr[0], Length(DArr));

      if (I = CeilLen) and not IsInt then
      begin
        // �����һ����������ʱֻ�ƶ�һ����
        Move(SM3D[0], Ha[(I - 1) * SizeOf(TCnSM3Digest)], (HLen mod CN_SM3_DIGEST_BITS) div 8);
      end
      else
        Move(SM3D[0], Ha[(I - 1) * SizeOf(TCnSM3Digest)], SizeOf(TCnSM3Digest));

      Inc(CT);
    end;

    BN := BigNumberDuplicate(N);
    BN.SubWord(1);

    BH := TCnBigNumber.FromBinary(PAnsiChar(@Ha[0]), Length(Ha));
    BigNumberNonNegativeMod(Res, BH, BN);
    Res.AddWord(1);
    Result := True;
    _CnSetLastError(ECN_SM9_OK);
  finally
    BN.Free;
    BH.Free;
    SetLength(Ha, 0);
    SetLength(DArr, 0);
  end;
end;

function CnSM9Hash1(Res: TCnBigNumber; Data: Pointer; DataByteLen: Integer;
  N: TCnBigNumber): Boolean;
begin
  Result := SM9Hash(Res, CN_SM9_HASH_PREFIX_1, Data, DataByteLen, N);
end;

function CnSM9Hash2(Res: TCnBigNumber; Data: Pointer; DataByteLen: Integer;
  N: TCnBigNumber): Boolean;
begin
  Result := SM9Hash(Res, CN_SM9_HASH_PREFIX_2, Data, DataByteLen, N);
end;

function SM9Mac(Key: Pointer; KeyByteLength: Integer; Z: Pointer; ZByteLength: Integer): TCnSM3Digest;
var
  Arr: TBytes;
begin
  if (Key = nil) or (KeyByteLength <= 0) or (Z = nil) or (ZByteLength <= 0) then
    raise ECnSM9Exception.Create(SCnErrorSM9MacParams);

  SetLength(Arr, KeyByteLength + ZByteLength);
  Move(Z^, Arr[0], ZByteLength);
  Move(Key^, Arr[ZByteLength], KeyByteLength);
  Result := SM3(@Arr[0], Length(Arr));
  SetLength(Arr, 0);
end;

{ TCnSM9EncryptionMasterKey }

constructor TCnSM9EncryptionMasterKey.Create;
begin
  inherited;
  FPrivateKey := TCnSM9EncryptionMasterPrivateKey.Create;
  FPublicKey := TCnSM9EncryptionMasterPublicKey.Create;
end;

destructor TCnSM9EncryptionMasterKey.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

{ TCnSM9SignatureMasterKey }

constructor TCnSM9SignatureMasterKey.Create;
begin
  inherited;
  FPrivateKey := TCnSM9SignatureMasterPrivateKey.Create;
  FPublicKey := TCnSM9SignatureMasterPublicKey.Create;
end;

destructor TCnSM9SignatureMasterKey.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

{ TCnFP2Point }

procedure TCnFP2Point.Assign(Source: TPersistent);
begin
  if Source is TCnFP2Point then
  begin
    FP2Copy(FX, (Source as TCnFP2Point).X);
    FP2Copy(FY, (Source as TCnFP2Point).Y);
  end
  else
    inherited;
end;

constructor TCnFP2Point.Create;
begin
  inherited;
  FX := TCnFP2.Create;
  FY := TCnFP2.Create;
end;

destructor TCnFP2Point.Destroy;
begin
  FY.Free;
  FX.Free;
  inherited;
end;

function TCnFP2Point.ToString: string;
begin
  Result := FP2PointToString(Self);
end;

{ TCnSM9 }

constructor TCnSM9.Create;
begin
  inherited Create(ctSM9Bn256v1);
  FGenerator2 := TCnFP2Point.Create;

  FGenerator2.X.SetHex(CN_SM9_G2_P2X0, CN_SM9_G2_P2X1);
  FGenerator2.Y.SetHex(CN_SM9_G2_P2Y0, CN_SM9_G2_P2Y1);
end;

destructor TCnSM9.Destroy;
begin
  FGenerator2.Free;
  inherited;
end;

{ TCnSM9Signature }

constructor TCnSM9Signature.Create;
begin
  inherited;
  FH := TCnBigNumber.Create;
  FS := TCnEccPoint.Create;
end;

destructor TCnSM9Signature.Destroy;
begin
  FS.Free;
  FH.Free;
  inherited;
end;

function TCnSM9Signature.ToString: string;
begin
  Result := FH.ToHex + CRLF + FS.ToHex;
end;

{ TCnSM9KeyEncapsulation }

constructor TCnSM9KeyEncapsulation.Create;
begin
  inherited;
  FCode := TCnSM9KeyEncapsulationCode.Create;
end;

destructor TCnSM9KeyEncapsulation.Destroy;
begin
  FCode.Free;
  inherited;
end;

function TCnSM9KeyEncapsulation.ToString: string;
begin
  Result := DataToHex(PAnsiChar(FKey), Length(FKey)) + CRLF + FCode.ToHex;
end;

{ TCnSM9KeyExchangeMasterKey }

constructor TCnSM9KeyExchangeMasterKey.Create;
begin
  FPrivateKey := TCnSM9KeyExchangeMasterPrivateKey.Create;
  FPublicKey := TCnSM9KeyExchangeMasterPublicKey.Create;
end;

destructor TCnSM9KeyExchangeMasterKey.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

initialization
  FLocalBigNumberPool := TCnBigNumberPool.Create;
  FLocalFP2Pool := TCnFP2Pool.Create;
  FLocalFP4Pool := TCnFP4Pool.Create;
  FLocalFP12Pool := TCnFP12Pool.Create;
  FLocalFP2AffinePointPool := TCnFP2AffinePointPool.Create;

  InitSM9Consts;

finalization
  FLocalFP2AffinePointPool.Free;
  FLocalFP12Pool.Free;
  FLocalFP4Pool.Free;
  FLocalFP2Pool.Free;
  FLocalBigNumberPool.Free;

  FreeSM9Consts;

end.
