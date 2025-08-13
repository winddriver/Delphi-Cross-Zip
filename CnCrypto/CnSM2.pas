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

unit CnSM2;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ������������� SM2 ��Բ�����㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���� GM/T 0003.x-2012��SM2��Բ���߹�Կ�����㷨��
*           �淶�еĻ��� SM2 �����ݼӽ��ܡ�ǩ����ǩ����Կ�������Լ�Эͬ��Կ���ɡ�Эͬǩ����Эͬ���ܵȡ�
*
*           ע�� SM2 ǩ���淶��ȫ��ͬ�� OpenSSL �е� ECC ǩ���������Ӵպ���ֻ��ʹ�� SM3��
*           ע��ǩ��ʱ�� UserId ����ʱ�ڲ�Ĭ�ϻ�ʹ���ַ��� 1234567812345678 �Է���
*           ��GM/T 0009-2012 SM2�����㷨ʹ�ù淶���� 10 �ڵ�Ҫ��
*
*           ���⣬ǩ��ʱ����� Za ֵ�� SM3(EntLen��UserID��a��b��xG��yG��xA��yA)
*           ���� EntLen �� UserID ��λ���ȣ�Ҳ�����ֽڳ��� * 8��������˳���ֽڱ�ʾ��
*
*           ���⣬ע�� SM2 ��Բ����ǩ���޷���ǩ����ԭʼֵ�лָ���Կ��
*           ��Ȼ�� PublicKey = (s + r)^-1 * (k*G - s*G)
*           �Ҿ��� k ����δ֪�� k*G ������ x1 �ǿ��� r ���Ƴ�������Ϊ r <= (e + x1) mod n
*           ���� x1 <= (r - e) mod n����� y1 Ҳ����������� e ʹ���˹�Կ���Ӵ�ֵ��
*           ���³��������е��������м������⡣
*
* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ�Win7 + XE
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2024.01.12 V2.3
*               SM2 ��Կ��֧���ڲ��� SM2 ʵ��ʱ����ѹ����ʽ�Ĺ�Կ
*           2023.04.29 V2.2
*               ����Կ�����������Կ��ʽ�� AnsiString ��Ϊ TBytes �Ա�������
*           2023.04.10 V2.1
*               ������������ֵ��С������µļӽ��ܶ�������
*           2023.03.25 V2.0
*               ������ǩ��ʱ�������ָ��������������������ʮ�������ַ���
*           2022.12.15 V1.9
*               ����ǩ��ʱ����ʡ��ǰ�� 0 ����ǩ��������������
*           2022.11.01 V1.8
*               ǩ��ʱ����Կ�� nil���ڲ�ͨ��˽Կ�������Կ����ǩ��
*           2022.08.31 V1.7
*               ����˫��Эͬǩ���������������Эͬǩ�����Ʋ�ʵ�֣���˳��ʵ������Эͬ����
*           2022.06.18 V1.6
*               ʹ��Ԥ���� 2 ���ݵ��Լ����� 16 �Ĺ̶��������� SM2 �� G ������˼���
*               ʹ�� NAF ������ SM2 �ķ� G ������˼���
*           2022.06.01 V1.5
*               ���Ӽ��׵�Эͬ������ǩ����ʵ��
*           2022.05.27 V1.4
*               �����ļ��ӽ��ܵ�ʵ��
*           2022.05.26 V1.3
*               ���ӷǽ���ʽ Schnorr ��֪ʶ֤����֤���̵�ʵ��
*           2022.03.30 V1.2
*               ���ݼӽ��ܵ� C1C3C2 �� C1C2C3 ����ģʽ�Լ�ǰ���ֽ� 04
*           2021.11.25 V1.1
*               ���ӷ�װ�� SignFile �� VerifyFile ����
*           2020.04.04 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, Contnrs, CnNative, CnECC, CnBigNumber, CnConsts, CnSM3;

const
  CN_SM2_FINITEFIELD_BYTESIZE = 32;
  {* SM2 ��Բ���ߵ�����λ����256 Bits��Ҳ�ǵ�������ֵλ��}

  CN_SM2_MIN_ENCRYPT_BYTESIZE = SizeOf(TCnSM3Digest) + CN_SM2_FINITEFIELD_BYTESIZE * 2;
  {* ��С�� SM2 ���ܽ�����ȣ����������һ�� SM3 ժҪ���ȣ��� 96 �ֽ�}

  // ������
  ECN_SM2_OK                           = ECN_OK;
  {* SM2 ϵ�д����룺�޴���ֵΪ 0}

  ECN_SM2_ERROR_BASE                   = ECN_CUSTOM_ERROR_BASE + $200;
  {* SM2 ϵ�д�����Ļ�׼��ʼֵ��Ϊ ECN_CUSTOM_ERROR_BASE ���� $200}

  ECN_SM2_INVALID_INPUT                = ECN_SM2_ERROR_BASE + 1;
  {* SM2 ������֮����Ϊ�ջ򳤶ȴ���}
  ECN_SM2_RANDOM_ERROR                 = ECN_SM2_ERROR_BASE + 2;
  {* SM2 ������֮�������ش���}
  ECN_SM2_BIGNUMBER_ERROR              = ECN_SM2_ERROR_BASE + 3;
  {* SM2 ������֮�����������}
  ECN_SM2_DECRYPT_INFINITE_ERROR       = ECN_SM2_ERROR_BASE + 4;
  {* SM2 ������֮����ʱ��������Զ��}
  ECN_SM2_KEYEXCHANGE_INFINITE_ERROR   = ECN_SM2_ERROR_BASE + 5;
  {* SM2 ������֮��Կ������������Զ��}

type
  TCnSM2PrivateKey = TCnEccPrivateKey;
  {* SM2 ��˽Կ������ͨ��Բ���ߵ�˽Կ�������� ECC �е���Ӧ Load/Save ��������}

  TCnSM2PublicKey = class(TCnEccPublicKey)
  {* SM2 �Ĺ�Կ������ͨ��Բ���ߵĹ�Կ�������� ECC �е���Ӧ Load/Save ��������}
  public
    procedure SetHex(const Buf: AnsiString); reintroduce;
    {* ��ʮ�������ַ����м�������㣬�ڲ��� 02 03 04 ǰ׺�Ĵ���
       ����� 02 03 04 ǰ׺��԰������ֱ�ֵ�� X �� Y
       ���ǰ׺�� 02 �� 03��˵������ֻ�� X ���꣬��ʱ�ڲ��� SM2 ��������ʵ�������� Y ���ꡣ

       ������
         const Buf: AnsiString            - ʮ�������ַ���

       ����ֵ�����ޣ�
    }
  end;

  TCnSM2 = class(TCnEcc)
  {* SM2 ��Բ���������࣬����󲿷�ʵ����ָ���������͵Ļ��� TCnEcc ��}
  public
    constructor Create; override;
    {* ���캯��}

    procedure AffineMultiplePoint(K: TCnBigNumber; Point: TCnEcc3Point); override;
    {* ʹ��Ԥ����ķ����������������˷����١�

       ������
         K: TCnBigNumber                  - ��������ʽΪ����
         Point: TCnEcc3Point              - ������������

       ����ֵ�����ޣ�
    }
  end;

  TCnSM2Signature = class(TCnEccSignature);
  {* SM2 ��Բ����ǩ�������ݾ�����ͨ��Բ���ߵ�ǩ�������ݣ�ע���� ECC ���㷨���ļ���ʽ��ͬ��}

  TCnSM2CryptSequenceType = (cstC1C3C2, cstC1C2C3);
  {* SM2 ��������ʱ��ƴ�ӷ�ʽ���������� C1C3C2�����������뵱Ȼ�� C1C2C3 �汾���ʴ˱���Ԫ������}

  TCnSM2CollaborativePrivateKey = TCnSM2PrivateKey;
  {* SM2 Эͬ˽Կ������ͨ��Բ���ߵ�˽Կ��������������}

  TCnSM2CollaborativePublicKey = TCnSM2PublicKey;
  {* SM2 Эͬ˽Կ������ͨ��Բ���ߵĹ�Կ��ͬ����һ��}

// ========================== SM2 ��Բ������Կ���� =============================

function CnSM2GenerateKeys(PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2 = nil): Boolean;
{* ����һ�� SM2 ��˽Կ��

   ������
     PrivateKey: TCnSM2PrivateKey         - �����ɵ� SM2 ˽Կ
     PublicKey: TCnSM2PublicKey           - �����ɵ� SM2 ��Կ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnSM2CheckKeys(PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2 = nil): Boolean;
{* ����һ�� SM2 ��˽Կ�Ƿ�Ϸ���

   ������
     PrivateKey: TCnSM2PrivateKey         - ������� SM2 ˽Կ
     PublicKey: TCnSM2PublicKey           - ������� SM2 ��Կ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ���ؼ����Ƿ�Ϸ�
}

// ========================= SM2 ��Բ���߼ӽ����㷨 ============================

function CnSM2EncryptData(PlainData: Pointer; DataByteLen: Integer; OutStream:
  TStream; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2;
  IncludePrefixByte: Boolean = True; const RandHex: string = ''): Boolean; overload;
{* �ù�Կ�����ݿ���м��ܣ��ο� GM/T0003.4-2012��SM2��Բ���߹�Կ�����㷨
   ��4����:��Կ�����㷨���е�������򣬲�ͬ����ͨ ECC �� RSA �Ķ������
   SequenceType ����ָ���ڲ�ƴ�Ӳ���Ĭ�Ϲ���� C1C3C2 �����뵱Ȼ�� C1C2C3��
   IncludePrefixByte ���������Ƿ���� C1 ǰ���� $04 һ�ֽڣ�Ĭ�ϰ�����
   ���ؼ����Ƿ�ɹ������ܽ��д�� OutStream �С�

   ������
     PlainData: Pointer                                   - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     OutStream: TStream                                   - �����������
     PublicKey: TCnSM2PublicKey                           - �����õ� SM2 ��Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - ������ĵ��ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2
     IncludePrefixByte: Boolean                           - �Ƿ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���
     const RandHex: string                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                        - ���ؼ����Ƿ�ɹ�
}

function CnSM2EncryptData(PlainData: TBytes; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2;
  IncludePrefixByte: Boolean = True; const RandHex: string = ''): TBytes; overload;
{* �ù�Կ���ֽ�������м��ܣ��ο� GM/T0003.4-2012��SM2��Բ���߹�Կ�����㷨
   ��4����:��Կ�����㷨���е�������򣬲�ͬ����ͨ ECC �� RSA �Ķ������
   SequenceType ����ָ���ڲ�ƴ�Ӳ���Ĭ�Ϲ���� C1C3C2 �����뵱Ȼ�� C1C2C3��
   IncludePrefixByte ���������Ƿ���� C1 ǰ���� $04 һ�ֽڣ�Ĭ�ϰ�����
   ���������ֽ����飬�������ʧ���򷵻ؿա�

   ������
     PlainData: TBytes                                    - �����ܵ������ֽ�����
     PublicKey: TCnSM2PublicKey                           - �����õ� SM2 ��Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - ������ĵ��ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2
     IncludePrefixByte: Boolean                           - ����������Ƿ�Ҫ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���
     const RandHex: string                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��TBytes                                         - ����ɹ��򷵻������ֽ����飬ʧ���򷵻ؿ�
}

function CnSM2DecryptData(EnData: Pointer; DataByteLen: Integer; OutStream: TStream;
  PrivateKey: TCnSM2PrivateKey; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2): Boolean; overload;
{* ��˽Կ�����ݿ���н��ܣ��ο� GM/T0003.4-2012��SM2��Բ���߹�Կ�����㷨
   ��4����:��Կ�����㷨���е�������򣬲�ͬ����ͨ ECC �� RSA �Ķ������
   SequenceType ����ָ���ڲ�ƴ�Ӳ���Ĭ�Ϲ���� C1C3C2 �����뵱Ȼ�� C1C2C3��
   ���� IncludePrefixByte �������ڲ��Զ�����
   ���ؽ����Ƿ�ɹ������������д�� OutStream �С�

   ������
     EnData: Pointer                                      - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     OutStream: TStream                                   - �����������
     PrivateKey: TCnSM2PrivateKey                         - �����õ� SM2 ˽Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2��������ĵ�ʵ�����һ��

   ����ֵ��Boolean                                        - ���ؽ����Ƿ�ɹ�
}

function CnSM2DecryptData(EnData: TBytes; PrivateKey: TCnSM2PrivateKey;
  SM2: TCnSM2 = nil; SequenceType: TCnSM2CryptSequenceType = cstC1C3C2): TBytes; overload;
{* ��˽Կ�����ݿ���н��ܣ��ο� GM/T0003.4-2012��SM2��Բ���߹�Կ�����㷨
   ��4����:��Կ�����㷨���е�������򣬲�ͬ����ͨ ECC �� RSA �Ķ������
   SequenceType ����ָ���ڲ�ƴ�Ӳ���Ĭ�Ϲ���� C1C3C2 �����뵱Ȼ�� C1C2C3��
   ���� IncludePrefixByte �������ڲ��Զ�����
   ���ؽ��ܺ�������ֽ����飬�������ʧ���򷵻ؿա�

   ������
     EnData: TBytes                                       - �����ܵ������ֽ�����
     PrivateKey: TCnSM2PrivateKey                         - �����õ� SM2 ˽Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2��������ĵ�ʵ�����һ��

   ����ֵ��TBytes                                         - ����ɹ��򷵻������ֽ����飬ʧ���򷵻ؿ�
}

function CnSM2EncryptFile(const InFile: string; const OutFile: string; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2 = nil; SequenceType: TCnSM2CryptSequenceType = cstC1C3C2;
  IncludePrefixByte: Boolean = True; const RandHex: string = ''): Boolean;
{* �ù�Կ���� InFile �ļ����ݣ����ܽ���� OutFile ������Ƿ���ܳɹ���
   SequenceType ����ָ���ڲ�ƴ�Ӳ���Ĭ�Ϲ���� C1C3C2 �����뵱Ȼ�� C1C2C3��
   IncludePrefixByte ���������Ƿ���� C1 ǰ���� $04 һ�ֽڣ�Ĭ�ϰ�����

   ������
     const InFile: string                                 - �����ܵ�����ԭʼ�ļ���
     const OutFile: string                                - ���������Ŀ���ļ���
     PublicKey: TCnSM2PublicKey                           - �����õ� SM2 ��Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - ������ĵ��ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2
     IncludePrefixByte: Boolean                           - ����������Ƿ�Ҫ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���
     const RandHex: string                                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                                        - ���ؼ����Ƿ�ɹ�
}

function CnSM2DecryptFile(const InFile: string; const OutFile: string; PrivateKey: TCnSM2PrivateKey;
  SM2: TCnSM2 = nil; SequenceType: TCnSM2CryptSequenceType = cstC1C3C2): Boolean;
{* ��˽Կ���� InFile �ļ����ݣ����ܽ���� OutFile ������Ƿ���ܳɹ���
   SequenceType ����ָ���ڲ�ƴ�Ӳ���Ĭ�Ϲ���� C1C3C2 �����뵱Ȼ�� C1C2C3��
   ���� IncludePrefixByte �������ڲ��Զ�����

   ������
     const InFile: string                                 - �����ܵ������ļ���
     const OutFile: string                                - ���������Ŀ���ļ���
     PrivateKey: TCnSM2PrivateKey                         - �����õ� SM2 ˽Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2��������ĵ�ʵ�����һ��

   ����ֵ��Boolean                                        - ���ؽ����Ƿ�ɹ�
}

function CnSM2CryptToAsn1(EnData: TBytes; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2; IncludePrefixByte: Boolean = True): TBytes; overload;
{* �� EnData ���ֽ�������ʽ��ԭʼ��������ת��Ϊ ASN1/BER ��ʽ���ֽ����顣

   ������
     EnData: TBytes                                       - ��ת���������ֽ�����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - ���ĵ��ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2
     IncludePrefixByte: Boolean                           - �������Ƿ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���

   ����ֵ��TBytes                                         - ����ת������ֽ�����
}

function CnSM2CryptToAsn1(EnStream: TStream; OutStream: TStream; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2; IncludePrefixByte: Boolean = True): Boolean; overload;
{* �� EnStream ������ʽ��ԭʼ��������ת��Ϊ ASN1/BER ��ʽ��д�� OutStream ���С�

   ������
     EnStream: TStream                                    - ��ת����������
     OutStream: TStream                                   - ת�����Ŀ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - ���ĵ��ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2
     IncludePrefixByte: Boolean                           - �������Ƿ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���

   ����ֵ��Boolean                                        - ����ת���Ƿ�ɹ�
}

function CnSM2CryptFromAsn1(Asn1Data: TBytes; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2; IncludePrefixByte: Boolean = True): TBytes; overload;
{* �� Asn1Data �� ASN1/BER ��ʽ���ֽ�������ʽ�ļ�������ת��Ϊԭʼ�ֽ�����

   ������
     Asn1Data: TBytes                                     - ��ת���� ASN1 ��ʽ�������ֽ�����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2����� ASN1 ��ʽ�������ֽ������ʵ�����һ��
     IncludePrefixByte: Boolean                           - ������ֽ��������Ƿ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���

   ����ֵ��TBytes                                         - ����ת������ֽ�����
}

function CnSM2CryptFromAsn1(Asn1Stream: TStream; OutStream: TStream; SM2: TCnSM2 = nil;
  SequenceType: TCnSM2CryptSequenceType = cstC1C3C2; IncludePrefixByte: Boolean = True): Boolean; overload;
{* �� Asn1Stream �� ASN1/BER ��ʽ���ļ�������ת��Ϊԭʼ�������ݲ�д�� OutStream ����

   ������
     Asn1Stream: TStream                                  - ��ת���� ASN1 ��ʽ��������
     OutStream: TStream                                   - �����ԭʼ������
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2����� ASN1 ��ʽ����������ʵ�����һ��
     IncludePrefixByte: Boolean                           - ����������Ƿ���� C1 ��ǰ���ֽ� $04��Ĭ�ϰ���

   ����ֵ��Boolean                                        - ����ת���Ƿ�ɹ�
}

// ====================== SM2 ��Բ��������ǩ����֤�㷨 =========================

function CnSM2SignData(const UserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  OutSignature: TCnSM2Signature; PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey = nil;
  SM2: TCnSM2 = nil; const RandHex: string = ''): Boolean; overload;
{* ˽Կ�����ݿ�ǩ������ GM/T0003.2-2012��SM2��Բ���߹�Կ�����㷨��2����:����ǩ���㷨��
   �е��������Ҫ����ǩ������������Ϣ�Լ���Կ������ժҪ������ǩ���Ƿ�ɹ���

   ������
     const UserID: AnsiString             - ����ǩ�����û���ʶ
     PlainData: Pointer                   - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                 - ��ǩ�����������ݿ��ֽڳ���
     OutSignature: TCnSM2Signature        - �����ǩ��ֵ
     PrivateKey: TCnSM2PrivateKey         - ����ǩ���� SM2 ˽Կ
     PublicKey: TCnSM2PublicKey           - ����ǩ���� SM2 ��Կ���ɴ� nil���ڲ���ʹ�� PrivateKey ���¼���� PublickKey ����ǩ��
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     const RandHex: string                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnSM2SignData(const UserID: AnsiString; PlainData: TBytes;
  OutSignature: TCnSM2Signature; PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey = nil;
  SM2: TCnSM2 = nil; const RandHex: string = ''): Boolean; overload;
{* ˽Կ���ֽ�����ǩ������ GM/T0003.2-2012��SM2��Բ���߹�Կ�����㷨��2����:����ǩ���㷨��
   �е��������Ҫ����ǩ������������Ϣ�Լ���Կ������ժҪ������ǩ���Ƿ�ɹ���

   ������
     const UserID: AnsiString             - ����ǩ�����û���ʶ
     PlainData: TBytes                    - ��ǩ���������ֽ�����
     OutSignature: TCnSM2Signature        - �����ǩ��ֵ
     PrivateKey: TCnSM2PrivateKey         - ����ǩ���� SM2 ˽Կ
     PublicKey: TCnSM2PublicKey           - ����ǩ���� SM2 ��Կ���ɴ� nil���ڲ���ʹ�� PrivateKey ���¼���� PublickKey ����ǩ��
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     const RandHex: string                - ���ⲿָ���������ʮ�������ַ�����Ĭ��Ϊ�գ������ڲ�����

   ����ֵ��Boolean                        - ����ǩ���Ƿ�ɹ�
}

function CnSM2VerifyData(const UserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  InSignature: TCnSM2Signature; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil): Boolean; overload;
{* ��Կ��֤���ݿ��ǩ������ GM/T0003.2-2012��SM2��Բ���߹�Կ�����㷨
   ��2����:����ǩ���㷨���е����������

   ������
     const UserID: AnsiString             - ������֤ǩ�����û���ʶ�����ǩ�����û���ʶ����һ��
     PlainData: Pointer                   - ����֤���������ݿ��ַ
     DataByteLen: Integer                 - ����֤���������ݿ��ֽڳ���
     InSignature: TCnSM2Signature         - ����֤��ǩ��ֵ
     PublicKey: TCnSM2PublicKey           - ������֤�� SM2 ��Կ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnSM2VerifyData(const UserID: AnsiString; PlainData: TBytes;
  InSignature: TCnSM2Signature; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil): Boolean; overload;
{* ��Կ��֤�ֽ������ǩ������ GM/T0003.2-2012��SM2��Բ���߹�Կ�����㷨
   ��2����:����ǩ���㷨���е����������

   ������
     const UserID: AnsiString             - ������֤ǩ�����û���ʶ�����ǩ�����û���ʶ����һ��
     PlainData: TBytes                    - ����֤�������ֽ�����
     InSignature: TCnSM2Signature         - ����֤��ǩ��ֵ
     PublicKey: TCnSM2PublicKey           - ������֤�� SM2 ��Կ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

function CnSM2SignFile(const UserID: AnsiString; const FileName: string;
  PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey = nil; SM2: TCnSM2 = nil): string;
{* ��װ��˽Կ���ļ�ǩ������������ǩ��ֵ��ʮ�������ַ�����ע���ڲ������ǽ��ļ�ȫ���������ڴ棬
  ��ǩ�������򷵻ؿ��ַ�����

   ������
     const UserID: AnsiString             - ����ǩ�����û���ʶ
     const FileName: string               - ��ǩ�����ļ���
     PrivateKey: TCnSM2PrivateKey         - ����ǩ���� SM2 ˽Կ
     PublicKey: TCnSM2PublicKey           - ����ǩ���� SM2 ��Կ���ɴ� nil���ڲ���ʹ�� PrivateKey ���¼���� PublickKey ����ǩ��
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��string                         - ����ǩ��ֵ��ʮ�������ַ���
}

function CnSM2VerifyFile(const UserID: AnsiString; const FileName: string;
  const InHexSignature: string; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil): Boolean;
{* ��װ�Ĺ�Կ��֤���ݿ��ǩ����������ǩ��ֵ��ʮ�������ַ�����ע���ڲ������ǽ��ļ�ȫ���������ڴ档

   ������
     const UserID: AnsiString             - ������֤ǩ�����û���ʶ�����ǩ�����û���ʶ����һ��
     const FileName: string               - ����֤���ļ���
     const InHexSignature: string         - ����֤��ʮ�����Ƶ�ǩ��ֵ
     PublicKey: TCnSM2PublicKey           - ������֤�� SM2 ��Կ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

// ======================== SM2 ��Բ������Կ�����㷨 ===========================

{
  SM2 ��Կ����ǰ�᣺A B ˫���������� ID �빫˽Կ������֪���Է��� ID ��Է��Ĺ�Կ
}
function CnSM2KeyExchangeAStep1(const AUserID: AnsiString; const BUserID: AnsiString;
  KeyByteLength: Integer; APrivateKey: TCnSM2PrivateKey; APublicKey: TCnSM2PublicKey;
  BPublicKey: TCnSM2PublicKey; OutARand: TCnBigNumber; OutRA: TCnEccPoint; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ����Կ����Э�飬��һ�� A �û���������� RA�������� B��
   ���룺A B ���û������������볤�ȡ��Լ���˽Կ��˫���Ĺ�Կ��
   ��������ֵ OutARand�����ɵ������ RA������ B��

   ������
     const AUserID: AnsiString            - A �����û���ʶ
     const BUserID: AnsiString            - B �����û���ʶ
     KeyByteLength: Integer               - ��Ҫ��������Կ�ֽڳ���
     APrivateKey: TCnSM2PrivateKey        - A ���� SM2 ˽Կ
     APublicKey: TCnSM2PublicKey          - A ���� SM2 ��Կ
     BPublicKey: TCnSM2PublicKey          - B ���� SM2 ˽Կ
     OutARand: TCnBigNumber               - ���ɵ��м�������������ڱ��ν����Ự�б��������ܴ���� B ��
     OutRA: TCnEccPoint                   - ���ɵ��м�������� R�����ڱ��ν����Ự�б��������贫��� B ��
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnSM2KeyExchangeBStep1(const AUserID: AnsiString; const BUserID: AnsiString;
  KeyByteLength: Integer; BPrivateKey: TCnSM2PrivateKey; APublicKey: TCnSM2PublicKey;
  BPublicKey: TCnSM2PublicKey; InRA: TCnEccPoint; out OutKeyB: TBytes; OutRB: TCnEccPoint;
  out OutOptionalSB: TCnSM3Digest; out OutOptionalS2: TCnSM3Digest; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ����Կ����Э�飬�ڶ��� B �û��յ� A �����ݣ����� Kb�����ѿ�ѡ����֤������� A��
   ���룺A B ���û������������볤�ȡ��Լ���˽Կ��˫���Ĺ�Կ��A ������ RA��
   ���������ɹ��Ĺ�����Կ Kb�����ɵ������ RB������ A������ѡ��У���Ӵ� SB������ A ��֤������ѡ��У���Ӵ� S2��

   ������
     const AUserID: AnsiString            - A �����û���ʶ
     const BUserID: AnsiString            - B �����û���ʶ
     KeyByteLength: Integer               - ��Ҫ��������Կ�ֽڳ���
     BPrivateKey: TCnSM2PrivateKey        - B ���� SM2 ˽Կ
     APublicKey: TCnSM2PublicKey          - A ���� SM2 ��Կ
     BPublicKey: TCnSM2PublicKey          - B ���� SM2 ˽Կ
     InRA: TCnEccPoint                    - �� A �����ɲ��������������� R
     out OutKeyB: TBytes                  - B �������������Կ�ֽ����飬ֵӦ��������� OutKeyA
     OutRB: TCnEccPoint                   - ���ɵ��м�������� R���贫��� A ��
     out OutOptionalSB: TCnSM3Digest      - ���ɵ�У���Ӵ�ֵ S���ɴ���� A ������֤
     out OutOptionalS2: TCnSM3Digest      - ���ɵ�У���Ӵ�ֵ S2�����ڱ��ν����Ự�б��������ܴ���� A ��
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ���ؽ����Ƿ�ɹ�
}

function CnSM2KeyExchangeAStep2(const AUserID: AnsiString; const BUserID: AnsiString;
  KeyByteLength: Integer; APrivateKey: TCnSM2PrivateKey; APublicKey: TCnSM2PublicKey;
  BPublicKey: TCnSM2PublicKey; MyRA: TCnEccPoint; InRB: TCnEccPoint; MyARand: TCnBigNumber;
  out OutKeyA: TBytes; InOptionalSB: TCnSM3Digest; out OutOptionalSA: TCnSM3Digest; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ����Կ����Э�飬������ A �û��յ� B �����ݼ��� Ka�����ѿ�ѡ����֤������� B������Э�̺� Ka = Kb
  ���룺A B ���û������������볤�ȡ��Լ���˽Կ��˫���Ĺ�Կ��B ������ RB ���ѡ�� SB���Լ��ĵ� RA���Լ������ֵ MyARand
  ���������ɹ��Ĺ�����Կ Ka����ѡ��У���Ӵ� SA������ B ��֤����

   ������
     const AUserID: AnsiString            - A �����û���ʶ
     const BUserID: AnsiString            - B �����û���ʶ
     KeyByteLength: Integer               - ��Ҫ��������Կ�ֽڳ���
     APrivateKey: TCnSM2PrivateKey        - A ���� SM2 ˽Կ
     APublicKey: TCnSM2PublicKey          - A ���� SM2 ��Կ
     BPublicKey: TCnSM2PublicKey          - B ���� SM2 ��Կ
     MyRA: TCnEccPoint                    - A ����һ�ε���ʱ���ɵ��м�������� R
     InRB: TCnEccPoint                    - �� B �����ɲ�����������м�������� R
     MyARand: TCnBigNumber                - A ����һ�ε���ʱ���ɵ��м��������
     out OutKeyA: TBytes                  - A �������������Կ�ֽ����飬ֵӦ��������� OutKeyB
     InOptionalSB: TCnSM3Digest           - �� B �����ɲ����������У���Ӵ�ֵ S ����֤
     out OutOptionalSA: TCnSM3Digest      - ���ɵ�У���Ӵ�ֵ S
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ���ؽ����Ƿ�ɹ�
}

function CnSM2KeyExchangeBStep2(const AUserID: AnsiString; const BUserID: AnsiString;
  KeyByteLength: Integer; BPrivateKey: TCnSM2PrivateKey; APublicKey: TCnSM2PublicKey;
  BPublicKey: TCnSM2PublicKey; InOptionalSA: TCnSM3Digest; MyOptionalS2: TCnSM3Digest;
  SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ����Կ����Э�飬���Ĳ� B �û��յ� A �����ݼ�����У�飬Э����ϣ��˲���ѡ��
   ʵ����ֻ�Ա� B �ڶ������ɵ� S2 �� A ������������ SA�������������ʹ�á�

   ������
     const AUserID: AnsiString            - A �����û���ʶ
     const BUserID: AnsiString            - B �����û���ʶ
     KeyByteLength: Integer               - ��Ҫ��������Կ�ֽڳ���
     BPrivateKey: TCnSM2PrivateKey        - B ���� SM2 ˽Կ
     APublicKey: TCnSM2PublicKey          - A ���� SM2 ��Կ
     BPublicKey: TCnSM2PublicKey          - B ���� SM2 ��Կ
     InOptionalSA: TCnSM3Digest           - �� A �����ɲ����������У���Ӵ�ֵ S ����֤
     MyOptionalS2: TCnSM3Digest           - B ���ڶ��ε���ʱ���ɵ�У���Ӵ�ֵ���� S �Ա�
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ����У���Ƿ�ɹ�
}

// =============== ���� SM2/SM3 �ķǽ���ʽ Schnorr ��֪ʶ֤�� ==================

function CnSM2SchnorrProve(PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  OutR: TCnEccPoint; OutZ: TCnBigNumber; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2/SM3 �ķǽ���ʽ Schnorr ��֪ʶ֤������һ����˽Կӵ���ߵ��á�
  ˽Կӵ�������� R �� Z�����������Ƿ�ɹ���
  �ú������� SM2 ˽Կӵ����֤���Լ�ӵ�ж�Ӧ��Կ��˽Կ�����蹫����˽Կ��

   ������
     PrivateKey: TCnSM2PrivateKey         - ���� Schnorr ��֪ʶ֤���� SM2 ˽Կ
     PublicKey: TCnSM2PublicKey           - ���� Schnorr ��֪ʶ֤���� SM2 ��Կ
     OutR: TCnEccPoint                    - SM2 ˽Կӵ�������ɵ� R �����
     OutZ: TCnBigNumber                   - SM2 ˽Կӵ�������ɵ� Z ����ֵ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

function CnSM2SchnorrCheck(PublicKey: TCnSM2PublicKey; InR: TCnEccPoint;
  InZ: TCnBigNumber; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2/SM3 �ķǽ���ʽ Schnorr ��֪ʶ֤������������õ���Կ����֤
   ��֤�Է������� R �� Z������ɹ���˵���Է�ӵ�иù�Կ��Ӧ��˽Կ
   �ú���������֤�Է��Ƿ�ӵ��ĳ SM2 ��Կ��Ӧ��˽Կ

   ������
     PublicKey: TCnSM2PublicKey           - ������֤ Schnorr ��֪ʶ֤���� SM2 ��Կ
     InR: TCnEccPoint                     - Schnorr ��֪ʶ֤�������ɵ� R �����
     InZ: TCnBigNumber                    - Schnorr ��֪ʶ֤�������ɵ� Z ����ֵ
     SM2: TCnSM2                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                        - ������֤�Ƿ�ɹ�
}

// ========== SM2 ��Բ����˫���������εļ���Эͬ�㷨֮Эͬ��Կ���� =============

{
  ��Эͬģʽ�£�A B ˫���������Σ�������ԶԷ�����֤�����������ŶԷ����������ݡ�
  ���У���Կ = ��˽Կ����A * ˽Կ����B - 1��* G
}
function CnSM2CollaborativeGenerateKeyAStep1(PrivateKeyA: TCnSM2CollaborativePrivateKey;
  OutPointToB: TCnEccPoint; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ�㷨��A ��һ�������Լ���˽Կ���� PrivateKeyA���������м��� OutPointToB��
   �õ�ֵ��Ҫ������ B�������Ƿ����ɳɹ���

   ������
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� A �����ɵ� SM2 ˽Կ������A ���豣��
     OutPointToB: TCnEccPoint                             - ˫��Эͬģʽ�����ɵ��м�������㣬�贫��� B ��
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2CollaborativeGenerateKeyBStep1(PrivateKeyB: TCnSM2CollaborativePrivateKey;
  InPointFromA: TCnEccPoint; PublicKey: TCnSM2CollaborativePublicKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ�㷨��B �ڶ��������Լ���˽Կ���� PrivateKeyB�������� A �������м��� InPointFromA��
   ���ɹ��õĹ�Կ PublicKey�������Ƿ����ɳɹ�����Կ PublicKey ������Ҫ���� A ��������ȥ��

   ������
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� B �����ɵ� SM2 ˽Կ������B ���豣��
     InPointFromA: TCnEccPoint                            - ˫��Эͬģʽ���� A �����ɲ�����������м��������
     PublicKey: TCnSM2CollaborativePublicKey              - ˫��Эͬģʽ�����ɵĹ�ͬ�� SM2 ��Կ���ɹ���������� A ��
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

// =============== SM2 ��Բ����˫���������εļ���Эͬǩ���㷨 ==================

function CnSM2CollaborativeSignAStep1(const UserID: AnsiString; PlainData: Pointer;
  DataByteLen: Integer; OutHashEToB: TCnBigNumber; OutQToB: TCnEccPoint; OutRandKA: TCnBigNumber;
  PrivateKeyA: TCnSM2CollaborativePrivateKey; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬǩ����A ��һ������ԭʼ����ǩ���м�ֵ E �� Q�����͸� B�����ظò�ǩ���Ƿ�ɹ�
   ע�� OutRandK ��Ҫ���� B�����⣬ע��ò� PrivateKeyA δʹ�á�

   ������
     const UserID: AnsiString                             - ˫��Эͬģʽ������ǩ���Ĺ�ͬ���û���ʶ
     PlainData: Pointer                                   - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     OutHashEToB: TCnBigNumber                            - ˫��Эͬģʽ�� A ��������м�ֵ E ����ֵ���贫��� B ��
     OutQToB: TCnEccPoint                                 - ˫��Эͬģʽ�� A ��������м�ֵ Q ����㣬�贫��� B ��
     OutRandKA: TCnBigNumber                              - ˫��Эͬģʽ�� A ��������м����ֵ K��A ���豣��
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� A ���� SM2 ˽Կ�������ò��ڲ���δʹ��
     PublicKey: TCnSM2PublicKey                           - ˫��Эͬģʽ�¹�ͬ�� SM2 ��Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ظ� A ���ĵ�һ��ǩ���Ƿ�ɹ�
}

function CnSM2CollaborativeSignBStep1(InHashEFromA: TCnBigNumber; InQFromA: TCnEccPoint;
  OutRToA: TCnBigNumber; OutS1ToA: TCnBigNumber; OutS2ToA: TCnBigNumber;
  PrivateKeyB: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬǩ����B �ڶ������� A ǩ�����м�ֵ E �� Q��
   ��� PrivateKeyB ���� R S1 S2 ���ͻ� A�����ظò�ǩ���Ƿ�ɹ���

   ������
     InHashEFromA: TCnBigNumber                           - ˫��Эͬģʽ���� A ���ڵ�һ�����ɲ���������� E ����ֵ
     InQFromA: TCnEccPoint                                - ˫��Эͬģʽ���� A ���ڵ�һ�����ɲ���������� Q �����
     OutRToA: TCnBigNumber                                - ˫��Эͬģʽ�� B �����ɵ��м�ֵ R ����ֵ���贫��� A ��
     OutS1ToA: TCnBigNumber                               - ˫��Эͬģʽ�� B �����ɵ��м�ֵ S1 ����ֵ���贫��� A ��
     OutS2ToA: TCnBigNumber                               - ˫��Эͬģʽ�� B �����ɵ��м�ֵ S2 ����ֵ���贫��� A ��
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� B ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ظ� B ���ĵڶ���ǩ���Ƿ�ɹ�
}

function CnSM2CollaborativeSignAStep2(InRandKA: TCnBigNumber; InRFromB: TCnBigNumber;
  InS1FromB: TCnBigNumber; InS2FromB: TCnBigNumber; OutSignature: TCnSM2Signature;
  PrivateKeyA: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬǩ����A ���������� A ��һ���� OutRandK ���ֵ�� B ǩ�����м�ֵ R S1 S2��
   ��� PrivateKeyA ��������ǩ�������ظò�ǩ���Ƿ�ɹ���

   ������
     InRandKA: TCnBigNumber                               - A ����һ��ǩ�������ɵ��м����ֵ K
     InRFromB: TCnBigNumber                               - ˫��Эͬģʽ���� B ���ڵڶ������ɲ���������� R ����ֵ
     InS1FromB: TCnBigNumber                              - ˫��Эͬģʽ���� B ���ڵڶ������ɲ���������� S1 ����ֵ
     InS2FromB: TCnBigNumber                              - ˫��Эͬģʽ���� B ���ڵڶ������ɲ���������� S2 ����ֵ
     OutSignature: TCnSM2Signature                        - ���������ǩ��ֵ
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� A ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ظ� A ���ĵ�����Ҳ�������ղ�ǩ���Ƿ�ɹ�
}

// =============== SM2 ��Բ����˫���������εļ���Эͬ�����㷨 ==================

function CnSM2CollaborativeDecryptAStep1(EnData: Pointer; DataByteLen: Integer;
  OutTToB: TCnEccPoint; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ���ܣ�A ��һ���������Ľ���м�ֵ T�����͸� B�����ظò������Ƿ�ɹ���

   ������
     EnData: Pointer                                      - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     OutTToB: TCnEccPoint                                 - ˫��Эͬģʽ�� A �����ɵ��м�������� T���贫��� B ��
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� A ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���� A ���ĵ�һ�������Ƿ�ɹ�
}

function CnSM2CollaborativeDecryptBStep1(InTFromA: TCnEccPoint; OutTToA: TCnEccPoint;
  PrivateKeyB: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ���ܣ�B �ڶ������� A ������м�ֵ T��������һ���м�ֵ T ���ͻ� A��
   ���ظò������Ƿ�ɹ���

   ������
     InTFromA: TCnEccPoint                                - ˫��Эͬģʽ���� A �����ɲ�����������м�������� T
     OutTToA: TCnEccPoint                                 - ˫��Эͬģʽ�� B �����ɵ��м�������� T���贫��� A ��
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� B ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���� B ���ĵڶ��������Ƿ�ɹ�
}

function CnSM2CollaborativeDecryptAStep2(EnData: Pointer; DataByteLen: Integer;
  InTFromB: TCnEccPoint; OutStream: TStream; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil; SequenceType: TCnSM2CryptSequenceType = cstC1C3C2): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ���ܣ�A ���������� B ������м�ֵ T ������ս��ܽ��д�� Stream��
  ���ظò����ս����Ƿ�ɹ�
  ע�������� SequenceType �뱣�ֺ� AStep1 �е���ȫһ��

   ������
     EnData: Pointer                                      - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     InTFromB: TCnEccPoint                                - ˫��Эͬģʽ���� B �����ɲ�����������м�������� T
     OutStream: TStream                                   - �����������
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - ˫��Эͬģʽ�� A ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2��������ĵ�ʵ�����һ��

   ����ֵ��Boolean                                        - ���� A ���ĵ�����Ҳ�������ղ��Ľ����Ƿ�ɹ�
}

// ======== SM2 ��Բ������������෽�������εļ���Эͬ�㷨֮Эͬ��Կ���� =======
{
  ��Эͬģʽ�£�A B C ��������෽�������Σ�������ԶԷ�����֤�����������ŶԷ����������ݡ�
  �෽ģʽ�£������м�ķ�ͷβ������ CnSM2Collaborative3 * BStep1 ������ý��ж��
  �ڲ������ϵ�ͬ��˫��Эͬ��ֻ���м䲽����� 0 �� �� �ಽ֮��

  ���У���Կ = ��˽Կ����A * ˽Կ����B * ˽Կ����C - 1��* G
}
function CnSM2Collaborative3GenerateKeyAStep1(PrivateKeyA: TCnSM2CollaborativePrivateKey;
  OutPointToB: TCnEccPoint; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬ�㷨��A ��һ�������Լ���˽Կ���� PrivateKeyA���������м��� OutPointToB��
   �õ�ֵ��Ҫ������ B�������Ƿ����ɳɹ���

   ������
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� A �����ɵ� SM2 ˽Կ����
     OutPointToB: TCnEccPoint                             - �෽Эͬģʽ�� A �����ɵ��м�������㣬�贫��� B ��
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2Collaborative3GenerateKeyBStep1(PrivateKeyB: TCnSM2CollaborativePrivateKey;
  InPointFromA: TCnEccPoint; OutPointToC: TCnEccPoint; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬ�㷨��B �ڶ��������Լ���˽Կ���� PrivateKeyB�������� A �������м��� InPointFromA��
   �����м��� OutPointToC���õ�ֵ��Ҫ������ C�������Ƿ����ɳɹ���
   ������෽��C Ҳ����ñ��������ɸ� D �ģ��Դ����ơ�

   ������
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� B ���������м䷽���ɵ� SM2 ˽Կ����
     InPointFromA: TCnEccPoint                            - �෽Эͬģʽ���� A ������һ�����ɲ�����������м��������
     OutPointToC: TCnEccPoint                             - �෽Эͬģʽ�� B ���������м䷽���ɵ��м�������㣬��Ҫ�������һ��
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2Collaborative3GenerateKeyCStep1(PrivateKeyC: TCnSM2CollaborativePrivateKey;
  InPointFromB: TCnEccPoint; PublicKey: TCnSM2CollaborativePublicKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬ�㷨��C �����������Լ���˽Կ���� PrivateKeyC�������� B �������м��� InPointFromB��
   ���ɹ��õĹ�Կ PublicKey�������Ƿ����ɳɹ���������෽�������������һλ���õġ�
   ��Կ PublicKey ������Ҫ���� A��B ��������ȥ��

   ������
     PrivateKeyC: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� C �������һ�����ɵ� SM2 ˽Կ����
     InPointFromB: TCnEccPoint                            - �෽Эͬģʽ���� B ������һ�����ɲ�����������м��������
     PublicKey: TCnSM2CollaborativePublicKey              - �෽Эͬģʽ�� C �������һ�����ɵ� SM2 ��Կ���ɹ���������� A B ��ÿһ��
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

// =========== SM2 ��Բ������������෽�������εļ���Эͬǩ���㷨 ==============
{
  ���Ĺ����� A -> B (-> B') -> C (-> B') -> B  -> A����ͷ���Ϊ��һ�����ұ�Ϊ��һ��
}

function CnSM2Collaborative3SignAStep1(const UserID: AnsiString; PlainData: Pointer;
  DataByteLen: Integer; OutHashEToBC: TCnBigNumber; OutQToB: TCnEccPoint; OutRandKA: TCnBigNumber;
  PrivateKeyA: TCnSM2CollaborativePrivateKey; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬǩ����A ��һ������ԭʼ����ǩ���м�ֵ E �� Qa�����͸� B�����ظò�ǩ���Ƿ�ɹ���
   OutHashEToBC Ҫ������һ�� B �Լ����²� C����Ӧ InHashEFromA��OutQToB Ҫ������һ�� B����Ӧ InQFromA��
   ע�� OutRandKA Ҫ��������岽���ã���Ҫ����ȥ��

   ������
     const UserID: AnsiString                             - �෽Эͬģʽ������ǩ���Ĺ�ͬ���û���ʶ
     PlainData: Pointer                                   - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     OutHashEToBC: TCnBigNumber                           - �෽Эͬģʽ�� A �����ɵ��Ӵ�ֵ����Ҫ����������ÿһ��
     OutQToB: TCnEccPoint                                 - �෽Эͬģʽ�� A �����ɵ��м�������� Q����Ҫ����� B ��
     OutRandKA: TCnBigNumber                              - �෽Эͬģʽ�� A �����ɵ��м����ֵ K��A ���豣��
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� A ���� SM2 ˽Կ����
     PublicKey: TCnSM2PublicKey                           - �෽Эͬģʽ�µ� SM2 ��Կ
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2Collaborative3SignBStep1(InHashEFromA: TCnBigNumber; InQFromA: TCnEccPoint;
  OutQToC: TCnEccPoint; OutRandKB: TCnBigNumber; PrivateKeyB: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬǩ����B �ڶ������� A ��һ��ǩ�����м�ֵ E �� Qa������ Qb �� E һ�𷢸� C�����ظò�ǩ���Ƿ�ɹ���
   InHashEFromA ��Դ����һ���� OutHashEToBC��InQFromA ��Դ����һ���� OutQToB��OutQToC Ҫ������һ�� C����Ӧ InQFromB��
   ע�� OutRandKB Ҫ��������Ĳ����ã���Ҫ����ȥ��

   ������
     InHashEFromA: TCnBigNumber                           - �෽Эͬģʽ���� A �����ɲ�����������Ӵ�ֵ
     InQFromA: TCnEccPoint                                - �෽Эͬģʽ���� A ������һ�����ɲ�����������м�������� Q
     OutQToC: TCnEccPoint                                 - �෽Эͬģʽ�� B �����ɵ��м�������� Q���贫��� C ������һ��
     OutRandKB: TCnBigNumber                              - �෽Эͬģʽ�� B �����ɵ��м����ֵ K��B ���豣��
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� B ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2Collaborative3SignCStep1(InHashEFromA: TCnBigNumber; InQFromB: TCnEccPoint;
  OutRToBA: TCnBigNumber; OutS1ToB: TCnBigNumber; OutS2ToB: TCnBigNumber;
  PrivateKeyC: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬǩ����C ���������� B �ڶ���ǩ�����м�ֵ E �� Qb������ R S1 S2 ���ͻ� B�����ظò�ǩ���Ƿ�ɹ�
   InHashEFromA ��Դ����һ���� OutHashEToBC��InQFromB ��Դ����һ���� OutQToC��OutRToBA Ҫ������һ�� B �Լ����²� A����Ӧ InRFromC��
   OutS1ToB Ҫ������һ�� B����Ӧ InS1FromC��OutS2ToB Ҫ������һ�� B����Ӧ InS2FromC��

   ������
     InHashEFromA: TCnBigNumber                           - �෽Эͬģʽ���� A �����ɲ�����������Ӵ�ֵ
     InQFromB: TCnEccPoint                                - �෽Эͬģʽ���� B ������һ�����ɲ�����������м�������� Q
     OutRToBA: TCnBigNumber                               - �෽Эͬģʽ�� C �������һ�����ɵ��м�ֵ R���贫���ǰ�����
     OutS1ToB: TCnBigNumber                               - �෽Эͬģʽ�� C �������һ�����ɵ��м�ǩ��ֵ S1���贫�����һ��
     OutS2ToB: TCnBigNumber                               - �෽Эͬģʽ�� C �������һ�����ɵ��м�ǩ��ֵ S2���贫�����һ��
     PrivateKeyC: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� C �������һ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2Collaborative3SignBStep2(InRandKB: TCnBigNumber; InRFromC: TCnBigNumber;
  InS1FromC: TCnBigNumber; InS2FromC: TCnBigNumber; OutS1ToA: TCnBigNumber;
  OutS2ToA: TCnBigNumber; PrivateKeyB: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬǩ����B ���Ĳ����� C ������ǩ�����м�ֵ�����µ� S1 S2 �� R ���� A�����ظò�ǩ���Ƿ�ɹ�
   InRandKB �ǵڶ����е� OutRandKB��InRFromC ��Դ����һ���� OutRToBA��InS1FromC ��Դ����һ���� OutS1ToB��
   InS2FromC ��Դ����һ���� OutS2ToB��OutS1ToA Ҫ������һ�� A����Ӧ InS1FromB��OutS2ToA Ҫ������һ�� A����Ӧ InS2FromB��

   ������
     InRandKB: TCnBigNumber                               - �෽Эͬģʽ���� B ����ǰһ�������ɵ��м����ֵ K
     InRFromC: TCnBigNumber                               - �෽Эͬģʽ���� C �������һ�����ɲ�����������м�ֵ R
     InS1FromC: TCnBigNumber                              - �෽Эͬģʽ���� C �������һ�����ɲ�����������м�ǩ��ֵ S1
     InS2FromC: TCnBigNumber                              - �෽Эͬģʽ���� C �������һ�����ɲ�����������м�ǩ��ֵ S2
     OutS1ToA: TCnBigNumber                               - �෽Эͬģʽ�����ɵ��м�ǩ��ֵ S1���贫��� A ������һ��
     OutS2ToA: TCnBigNumber                               - �෽Эͬģʽ�����ɵ��м�ǩ��ֵ S2���贫��� A ������һ��
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� B ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

function CnSM2Collaborative3SignAStep2(InRandKA: TCnBigNumber; InRFromC: TCnBigNumber;
  InS1FromB: TCnBigNumber; InS2FromB: TCnBigNumber; OutSignature: TCnSM2Signature;
  PrivateKeyA: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬǩ����A ���岽���� OutRandKA ���ֵ�� B ���Ĳ���ǩ�����м�ֵ S1 S2 ��ԭʼ R��
   ��������ǩ�������ظò�ǩ���Ƿ�ɹ���InRandKA �ǵ�һ���е� OutRandKA��InRFromC ��Դ�����ϲ��� OutRToBA��
   InS1FromB ��Դ����һ���� OutS1ToA��InS2FromB ��Դ����һ���� OutS2ToA������ǩ��ֵ�� OutSignature �С�

   ������
     InRandKA: TCnBigNumber                               - �෽Эͬģʽ���� A ���ڵ�һ�������ɵ��м����ֵ K
     InRFromC: TCnBigNumber                               - �෽Эͬģʽ���� C �������һ�����ɲ�����������м����ֵ R
     InS1FromB: TCnBigNumber                              - �෽Эͬģʽ���� B ������һ�����ɲ�����������м�ǩ��ֵ S1
     InS2FromB: TCnBigNumber                              - �෽Эͬģʽ���� B ������һ�����ɲ�����������м�ǩ��ֵ S2
     OutSignature: TCnSM2Signature                        - ���������ǩ��ֵ
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� A ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ����ǩ���Ƿ�ɹ�
}

// =========== SM2 ��Բ������������෽�������εļ���Эͬ�����㷨 ==============
{
  ԭ���ǩ���򵥶��ˣ�A B C �����������˽Կ�������ӳ�һ���㣬C ����󷵻ظ� A ���ܼ��ɣ������ٴι� B
}
function CnSM2Collaborative3DecryptAStep1(EnData: Pointer; DataByteLen: Integer;
  OutTToB: TCnEccPoint; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬ���ܣ�A ��һ���������Ľ���м�ֵ T�����͸� B�����ظò������Ƿ�ɹ���

   ������
     EnData: Pointer                                      - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     OutTToB: TCnEccPoint                                 - �෽Эͬģʽ�� A �����ɵ��м�������� T����Ҫ����� B ��
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� A ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ؼ����Ƿ�ɹ�
}

function CnSM2Collaborative3DecryptBStep1(InTFromA: TCnEccPoint; OutTToC: TCnEccPoint;
  PrivateKeyB: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�����Эͬ���ܣ�B �ڶ������� A �������м�ֵ T ����Լ����м�ֵ T�����͸� C�����ظò������Ƿ�ɹ���

   ������
     InTFromA: TCnEccPoint                                - �෽Эͬģʽ���� A �����ɲ�����������м�������� T
     OutTToC: TCnEccPoint                                 - �෽Эͬģʽ�� B �����ɵ��м�������� T����Ҫ����� C ����һ��
     PrivateKeyB: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� B ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ؼ����Ƿ�ɹ�
}

function CnSM2Collaborative3DecryptCStep1(InTFromB: TCnEccPoint; OutTToA: TCnEccPoint;
  PrivateKeyC: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ���ܣ�C ���������� B ������м�ֵ T����������ֵ T ���ͻ� A����ע�ⲻ�ù� B �ˣ���
   ���ظò������Ƿ�ɹ���

   ������
     InTFromB: TCnEccPoint                                - �෽Эͬģʽ���� B ������һ�����ɲ�����������м�������� T
     OutTToA: TCnEccPoint                                 - �෽Эͬģʽ�� C �����ɵ��м�������� T����Ҫ����� A
     PrivateKeyC: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� C ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��

   ����ֵ��Boolean                                        - ���ؼ����Ƿ�ɹ�
}

function CnSM2Collaborative3DecryptAStep2(EnData: Pointer; DataByteLen: Integer;
  InTFromC: TCnEccPoint; OutStream: TStream; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil; SequenceType: TCnSM2CryptSequenceType = cstC1C3C2): Boolean;
{* ���� SM2 ��Բ���ߵ�˫��Эͬ���ܣ�A ���Ĳ����� C ������м�ֵ T ������ս��ܽ��д�� Stream��
   ���ظò����ս����Ƿ�ɹ���ע�������� SequenceType �뱣�ֺ� AStep1 �е���ȫһ�¡�

   ������
     EnData: Pointer                                      - �����ܵ��������ݿ��ַ
     DataByteLen: Integer                                 - �����ܵ��������ݿ��ֽڳ���
     InTFromC: TCnEccPoint                                - �෽Эͬģʽ���� C �����ɲ�����������м�������� T
     OutStream: TStream                                   - �����������
     PrivateKeyA: TCnSM2CollaborativePrivateKey           - �෽Эͬģʽ�� A ���� SM2 ˽Կ����
     SM2: TCnSM2                                          - ���Դ��� SM2 ʵ����Ĭ��Ϊ��
     SequenceType: TCnSM2CryptSequenceType                - �ڲ�ƴ��˳��Ĭ�Ϲ���� C1C3C2��������ĵ�ʵ�����һ��

   ����ֵ��Boolean                                        - ���ؽ����Ƿ�ɹ�
}

implementation

uses
  CnKDF, CnBerUtils;

const
  CN_SM2_DEF_UID: array[0..15] of Byte =
    ($31, $32, $33, $34, $35, $36, $37, $38, $31, $32, $33, $34, $35, $36, $37, $38);

var
  FLocalSM2Generator: TCnEccPoint = nil;     // SM2 �� G �㹩�Ƚ���
  FSM2AffineGPower2KList: TObjectList = nil; // SM2 �� G ���Ԥ�������꣬�� n ����ʾ 2^n �η�����
  FSM2AffinePreMatrix: TCnEcc3Matrix = nil;  // SM2 �� G ��� 2^4 �̶���Ԥ�������꣬�� Row �е� Col �е�ֵ�� Col * (2^4)^Row ����

{* X <= 2^W + (x and (2^W - 1) ��ʾ�� x �ĵ� W λ�� 1���� W + 1 ������ȫ�� 0
   �����֮����ȡ X �ĵ� W λ����֤��һλ�ĵ� W λ�� 1��λ�� 0 ��ʼ��
  ���� W �� N �� BitsCount ��һ���ٵ�����ú���������Կ����
  ע�⣺���� CnECC �е�ͬ���������ܲ�ͬ}
procedure BuildShortXValue(X: TCnBigNumber; Order: TCnBigNumber);
var
  I, W: Integer;
begin
  W := (Order.GetBitsCount + 1) div 2 - 1;
  BigNumberSetBit(X, W);
  for I := W + 1 to X.GetBitsCount - 1 do
    BigNumberClearBit(X, I);
end;

{ TCnSM2PublicKey }

procedure TCnSM2PublicKey.SetHex(const Buf: AnsiString);
var
  SM2: TCnSM2;
begin
  SM2 := TCnSM2.Create;
  try
    inherited SetHex(Buf, SM2);
  finally
    SM2.Free;
  end;
end;

{ TCnSM2 }

procedure TCnSM2.AffineMultiplePoint(K: TCnBigNumber; Point: TCnEcc3Point);
var
  I, C, Row, Col: Integer;
  E, R: TCnEcc3Point;
  IsG: Boolean;
  M: TCnBigNumber;
  Naf: TShortInts;
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

  // ���ж��Ƿ��׼ SM2 ���ߵ� G �㣬�����Ǳ����ߵ� G ��
  IsG := Point.Z.IsOne and BigNumberEqual(Point.X, FLocalSM2Generator.X) and
    BigNumberEqual(Point.Y, FLocalSM2Generator.Y);

  R := nil;
  E := nil;
  M := nil;
  Naf := nil;

  try
    R := TCnEcc3Point.Create;
    E := TCnEcc3Point.Create;

    E.X := Point.X;
    E.Y := Point.Y;
    E.Z := Point.Z;

    C := BigNumberGetBitsCount(K);
    if IsG then // ע�⣬���²��˷��Ż����뱣֤�������� SM2 ��׼����
    begin
      // �ж��� G ��Ļ������Բ����ٳ˷���ӷ�����
      if C <= BitsCount then
      begin
        // С�� 256 �ĳ�����ֱ�ӹ̶������ӣ���� 64 �μӷ�
        Row := 0;

        M := TCnBigNumber.Create;
        BigNumberCopy(M, K);

        while not M.IsZero do
        begin
          Col := BigNumberAndWordTo(M, $000F); // ���������λ
          AffinePointAddPoint(R, FSM2AffinePreMatrix[Row, Col], R);
          // �ڼ��飬���ڼ�����λ������Ԫ�أ��ۼ�

          BigNumberShiftRight(M, M, 4);
          Inc(Row);
        end;
      end
      else // ���� 256 �ģ���ÿ�� 2 ���ݲ����
      begin
        for I := 0 to C - 1 do
        begin
          if BigNumberIsBitSet(K, I) then
            AffinePointAddPoint(R, E, R);

          // P �� G �㣬�����ӣ�ֱ��ȡ��
          if I < FSM2AffineGPower2KList.Count - 1 then
            E.Assign(TCnEcc3Point(FSM2AffineGPower2KList[I + 1]))
          else if I < C - 1 then // ����˴�û��Ԥ�õ㣬�� E �Լӣ����һ�ֲ����Լ�
            AffinePointAddPoint(E, E, E);
        end;
      end;
    end
    else // ���� G �㣬����ӣ���֤ǩ��ʱ���ã����� NAF ���٣����������֮һ�ĵ�ӷ���
    begin
      // R ��ʼΪ 0��E ��ԭʼ��
      Naf := BigNumberNonAdjanceFormWidth(K);
      for I := High(Naf) downto Low(Naf) do
      begin
        AffinePointAddPoint(R, R, R);
        if Naf[I] = 1 then
          AffinePointAddPoint(R, E, R)
        else if Naf[I] = -1 then
          AffinePointSubPoint(R, E, R)
      end;

//      ԭʼ���ƽ��һ�룬���� NAF ��С����� 1/3
//      for I := 0 to C - 1 do
//      begin
//        if BigNumberIsBitSet(K, I) then
//          AffinePointAddPoint(R, E, R);
//
//        if I < C - 1 then // ���һ�ֲ����Լ�
//          AffinePointAddPoint(E, E, E);
//      end;
    end;

    Point.X := R.X;
    Point.Y := R.Y;
    Point.Z := R.Z;
  finally
    SetLength(Naf, 0);
    M.Free;
    E.Free;
    R.Free;
  end;
end;

constructor TCnSM2.Create;
begin
  inherited;
  Load(ctSM2);
end;

function CnSM2GenerateKeys(PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKey = nil) or (PublicKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    SM2.GenerateKeys(PrivateKey, PublicKey);
    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2CheckKeys(PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2 = nil): Boolean;
var
  SM2IsNil: Boolean;
  Pub: TCnSM2PublicKey;
begin
  Result := False;
  if (PrivateKey = nil) or (PublicKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;
  Pub := nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    Pub := TCnSM2PublicKey.Create;
    Pub.Assign(SM2.Generator);
    SM2.MultiplePoint(PrivateKey, Pub);

    Result := CnEccPointsEqual(Pub, PublicKey);
    _CnSetLastError(ECN_SM2_OK);
  finally
    Pub.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  �������� M���� MLen �ֽڣ�������� k������

  C1 = k * G => (x1, y1)         // ��ѹ���洢������Ϊ��������λ���� 1���� SM2 ��Ҳ���� 32 * 2 + 1 = 65 �ֽ�

  k * PublicKey => (x2, y2)
  t <= KDF(x2��y2, MLen)
  C2 <= M xor t                  // ���� MLen

  C3 <= SM3(x2��M��y2)           // ���� 32 �ֽ�

  ����Ϊ��C1��C3��C2             // �ܳ� MLen + 97 �ֽ�
}
function CnSM2EncryptData(PlainData: Pointer; DataByteLen: Integer; OutStream:
  TStream; PublicKey: TCnSM2PublicKey; SM2: TCnSM2; SequenceType: TCnSM2CryptSequenceType;
  IncludePrefixByte: Boolean; const RandHex: string): Boolean;
var
  Py, P1, P2: TCnEccPoint;
  K: TCnBigNumber;
  B: Byte;
  M: PAnsiChar;
  I: Integer;
  Buf, T, KDFB: TBytes;
  C3H: AnsiString;
  Sm3Dig: TCnSM3Digest;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PlainData = nil) or (DataByteLen <= 0) or (OutStream = nil) or (PublicKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  Py := nil;
  P1 := nil;
  P2 := nil;
  K := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    K := TCnBigNumber.Create;

    // ȷ����Կ X Y ������
    if PublicKey.Y.IsZero then
    begin
      Py := TCnEccPoint.Create;
      if not SM2.PlainToPoint(PublicKey.X, Py) then
        Exit;
      BigNumberCopy(PublicKey.Y, Py.Y);
    end;

    // ʹ��ָ�� K�� ������һ����� K
    if RandHex <> '' then
      K.SetHex(AnsiString(RandHex))
    else
    begin
      if not BigNumberRandRange(K, SM2.Order) then
      begin
        _CnSetLastError(ECN_SM2_RANDOM_ERROR);
        Exit;
      end;
    end;

    P1 := TCnEccPoint.Create;
    P1.Assign(SM2.Generator);
    SM2.MultiplePoint(K, P1);  // ����� K * G �õ� X1 Y1

    OutStream.Position := 0;
    if IncludePrefixByte then
    begin
      B := 4;
      OutStream.Write(B, 1);
    end;

    SetLength(Buf, CN_SM2_FINITEFIELD_BYTESIZE);
    P1.X.ToBinary(@Buf[0], CN_SM2_FINITEFIELD_BYTESIZE);
    OutStream.Write(Buf[0], CN_SM2_FINITEFIELD_BYTESIZE);
    SetLength(Buf, CN_SM2_FINITEFIELD_BYTESIZE);
    P1.Y.ToBinary(@Buf[0], CN_SM2_FINITEFIELD_BYTESIZE);
    OutStream.Write(Buf[0], CN_SM2_FINITEFIELD_BYTESIZE);    // ƴ�� C1

    P2 := TCnEccPoint.Create;
    P2.Assign(PublicKey);
    SM2.MultiplePoint(K, P2); // ����� K * PublicKey �õ� X2 Y2

    SetLength(KDFB, CN_SM2_FINITEFIELD_BYTESIZE * 2);
    P2.X.ToBinary(@KDFB[0], CN_SM2_FINITEFIELD_BYTESIZE);
    P2.Y.ToBinary(@KDFB[CN_SM2_FINITEFIELD_BYTESIZE], CN_SM2_FINITEFIELD_BYTESIZE);
    T := CnSM2KDFBytes(KDFB, DataByteLen);

    M := PAnsiChar(PlainData);
    for I := 1 to DataByteLen do
      T[I - 1] := Byte(T[I - 1]) xor Byte(M[I - 1]);         // T ���� C2�����Ȳ���д

    SetLength(C3H, CN_SM2_FINITEFIELD_BYTESIZE * 2 + DataByteLen);
    P2.X.ToBinary(@C3H[1], CN_SM2_FINITEFIELD_BYTESIZE);
    Move(M[0], C3H[CN_SM2_FINITEFIELD_BYTESIZE + 1], DataByteLen);
    P2.Y.ToBinary(@C3H[CN_SM2_FINITEFIELD_BYTESIZE + DataByteLen + 1], CN_SM2_FINITEFIELD_BYTESIZE); // ƴ���� C3 ��
    Sm3Dig := SM3(@C3H[1], Length(C3H));                     // ��� C3

    if SequenceType = cstC1C3C2 then
    begin
      OutStream.Write(Sm3Dig[0], SizeOf(TCnSM3Digest));      // д�� C3
      OutStream.Write(T[0], DataByteLen);                    // д�� C2
    end
    else
    begin
      OutStream.Write(T[0], DataByteLen);                    // д�� C2
      OutStream.Write(Sm3Dig[0], SizeOf(TCnSM3Digest));      // д�� C3
    end;

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    P2.Free;
    P1.Free;
    Py.Free;
    K.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2EncryptData(PlainData: TBytes; PublicKey: TCnSM2PublicKey; SM2: TCnSM2;
  SequenceType: TCnSM2CryptSequenceType; IncludePrefixByte: Boolean; const RandHex: string): TBytes;
var
  Stream: TMemoryStream;
begin
  Result := nil;
  Stream := TMemoryStream.Create;
  try
    if CnSM2EncryptData(@PlainData[0], Length(PlainData), Stream, PublicKey, SM2,
      SequenceType, IncludePrefixByte, RandHex) then
    begin
      SetLength(Result, Stream.Size);
      Move(Stream.Memory^, Result[0], Stream.Size);
    end;
  finally
    Stream.Free;
  end;
end;

{
  MLen <= DataLen - SM3DigLength - 2 * Sm2ByteLength - 1�������õ� C1 C2 C3

  PrivateKey * C1 => (x2, y2)

  t <= KDF(x2��y2, Mlen)

  M' <= C2 xor t

  ���ɶԱ� SM3(x2��M��y2) Hash �Ƿ��� C3 ���
}
function CnSM2DecryptData(EnData: Pointer; DataByteLen: Integer; OutStream: TStream;
  PrivateKey: TCnSM2PrivateKey; SM2: TCnSM2; SequenceType: TCnSM2CryptSequenceType): Boolean;
var
  MLen: Integer;
  M: PAnsiChar;
  MP: AnsiString;
  KDFB, T: TBytes;
  C3H: AnsiString;
  SM2IsNil: Boolean;
  P2: TCnEccPoint;
  I, PrefixLen: Integer;
  Sm3Dig: TCnSM3Digest;
begin
  Result := False;
  if (EnData = nil) or (DataByteLen <= 0) or (OutStream = nil) or (PrivateKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  P2 := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    MLen := DataByteLen - CN_SM2_MIN_ENCRYPT_BYTESIZE;
    if MLen <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    P2 := TCnEccPoint.Create;
    M := PAnsiChar(EnData);
    if M^ = #$04 then  // �������ܵ�ǰ���ֽ� $04
    begin
      Dec(MLen);
      if MLen <= 0 then
      begin
        _CnSetLastError(ECN_SM2_INVALID_INPUT);
        Exit;
      end;

      PrefixLen := 1;
      Inc(M);
    end
    else
      PrefixLen := 0;

    // ���� C1
    P2.X.SetBinary(M, CN_SM2_FINITEFIELD_BYTESIZE);
    Inc(M, CN_SM2_FINITEFIELD_BYTESIZE);
    P2.Y.SetBinary(M, CN_SM2_FINITEFIELD_BYTESIZE);
    if P2.IsZero then
    begin
      _CnSetLastError(ECN_SM2_DECRYPT_INFINITE_ERROR);
      Exit;
    end;

    SM2.MultiplePoint(PrivateKey, P2);

    SetLength(KDFB, CN_SM2_FINITEFIELD_BYTESIZE * 2);
    P2.X.ToBinary(@KDFB[0], CN_SM2_FINITEFIELD_BYTESIZE);
    P2.Y.ToBinary(@KDFB[CN_SM2_FINITEFIELD_BYTESIZE], CN_SM2_FINITEFIELD_BYTESIZE);
    T := CnSM2KDFBytes(KDFB, MLen);

    if SequenceType = cstC1C3C2 then
    begin
      SetLength(MP, MLen);
      M := PAnsiChar(EnData);
      Inc(M, SizeOf(TCnSM3Digest) + CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen); // ���� C3 ָ�� C2
      for I := 1 to MLen do
        MP[I] := AnsiChar(Byte(M[I - 1]) xor Byte(T[I - 1]));  // �� KDF ������� MP ��õ�����

      SetLength(C3H, CN_SM2_FINITEFIELD_BYTESIZE * 2 + MLen);
      P2.X.ToBinary(@C3H[1], CN_SM2_FINITEFIELD_BYTESIZE);
      Move(MP[1], C3H[CN_SM2_FINITEFIELD_BYTESIZE + 1], MLen);
      P2.Y.ToBinary(@C3H[CN_SM2_FINITEFIELD_BYTESIZE + MLen + 1], CN_SM2_FINITEFIELD_BYTESIZE);    // ƴ���� C3 ��
      Sm3Dig := SM3(@C3H[1], Length(C3H));                     // ��� C3

      M := PAnsiChar(EnData);
      Inc(M, CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen);     // M ָ�� C3
      if CompareMem(@Sm3Dig[0], M, SizeOf(TCnSM3Digest)) then  // �ȶ��Ӵ�ֵ�Ƿ����
      begin
        OutStream.Write(MP[1], Length(MP));

        Result := True;
        _CnSetLastError(ECN_SM2_OK);
      end;
    end
    else // C1C2C3 ������
    begin
      SetLength(MP, MLen);
      M := PAnsiChar(EnData);
      Inc(M, CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen);     // ָ�� C2

      for I := 1 to MLen do
        MP[I] := AnsiChar(Byte(M[I - 1]) xor Byte(T[I - 1]));  // �� KDF ������� MP ��õ�����

      SetLength(C3H, CN_SM2_FINITEFIELD_BYTESIZE * 2 + MLen);
      P2.X.ToBinary(@C3H[1], CN_SM2_FINITEFIELD_BYTESIZE);
      Move(MP[1], C3H[CN_SM2_FINITEFIELD_BYTESIZE + 1], MLen);
      P2.Y.ToBinary(@C3H[CN_SM2_FINITEFIELD_BYTESIZE + MLen + 1], CN_SM2_FINITEFIELD_BYTESIZE);    // ƴ���� C3 ��
      Sm3Dig := SM3(@C3H[1], Length(C3H));                     // ��� C3

      M := PAnsiChar(EnData);
      Inc(M, CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen + MLen);      // ָ�� C3
      if CompareMem(@Sm3Dig[0], M, SizeOf(TCnSM3Digest)) then  // �ȶ��Ӵ�ֵ�Ƿ����
      begin
        OutStream.Write(MP[1], Length(MP));

        Result := True;
        _CnSetLastError(ECN_SM2_OK);
      end;
    end;
  finally
    P2.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2DecryptData(EnData: TBytes; PrivateKey: TCnSM2PrivateKey;
  SM2: TCnSM2; SequenceType: TCnSM2CryptSequenceType): TBytes;
var
  Stream: TMemoryStream;
begin
  Result := nil;
  Stream := TMemoryStream.Create;
  try
    if CnSM2DecryptData(@EnData[0], Length(EnData), Stream, PrivateKey, SM2,
      SequenceType) then
    begin
      SetLength(Result, Stream.Size);
      Move(Stream.Memory^, Result[0], Stream.Size);
    end;
  finally
    Stream.Free;
  end;
end;

function CnSM2EncryptFile(const InFile, OutFile: string; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2; SequenceType: TCnSM2CryptSequenceType; IncludePrefixByte: Boolean;
  const RandHex: string): Boolean;
var
  Stream: TMemoryStream;
  F: TFileStream;
begin
  Stream := nil;
  F := nil;

  try
    Stream := TMemoryStream.Create;
    Stream.LoadFromFile(InFile);

    F := TFileStream.Create(OutFile, fmCreate);
    Result := CnSM2EncryptData(Stream.Memory, Stream.Size, F, PublicKey, SM2,
      SequenceType, IncludePrefixByte, RandHex);
  finally
    F.Free;
    Stream.Free;
  end;
end;

function CnSM2DecryptFile(const InFile, OutFile: string; PrivateKey: TCnSM2PrivateKey;
  SM2: TCnSM2; SequenceType: TCnSM2CryptSequenceType): Boolean;
var
  Stream: TMemoryStream;
  F: TFileStream;
begin
  Stream := nil;
  F := nil;

  try
    Stream := TMemoryStream.Create;
    Stream.LoadFromFile(InFile);

    F := TFileStream.Create(OutFile, fmCreate);
    Result := CnSM2DecryptData(Stream.Memory, Stream.Size, F, PrivateKey, SM2, SequenceType);
  finally
    F.Free;
    Stream.Free;
  end;
end;

function CnSM2CryptToAsn1(EnData: TBytes; SM2: TCnSM2;
  SequenceType: TCnSM2CryptSequenceType; IncludePrefixByte: Boolean): TBytes;
var
  P: Pointer;
  MLen: Integer;
  Num: TCnBigNumber;
  Writer: TCnBerWriter;
  Root: TCnBerWriteNode;
begin
  Result := nil;
  MLen := Length(EnData) - CN_SM2_MIN_ENCRYPT_BYTESIZE;
  if MLen <= 0 then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  if IncludePrefixByte then
  begin
    if (MLen <= 1) or (EnData[0] <> 04) then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;
    P := @EnData[1]; // ����ǰ���ֽ� 04
    Dec(MLen);
  end
  else
    P := @EnData[0];

  Writer := nil;
  Num := nil;

  try
    Writer := TCnBerWriter.Create;
    Root := Writer.AddContainerNode(CN_BER_TAG_SEQUENCE);

    Num := TCnBigNumber.Create;

    // P ��ָ�� C1��д C1 �е� X
    Num.SetBinary(P, CN_SM2_FINITEFIELD_BYTESIZE);
    AddBigNumberToWriter(Writer, Num, Root);
    P := Pointer(TCnNativeUInt(P) + CN_SM2_FINITEFIELD_BYTESIZE);

    // д C1 �е� Y
    Num.SetBinary(P, CN_SM2_FINITEFIELD_BYTESIZE);
    AddBigNumberToWriter(Writer, Num, Root);
    P := Pointer(TCnNativeUInt(P) + CN_SM2_FINITEFIELD_BYTESIZE);

    // C1 д�꣬�������ʹ��� C3C2 �� C2C3
    if SequenceType = cstC1C3C2 then
    begin
      Writer.AddBasicNode(CN_BER_TAG_OCTET_STRING, P, SizeOf(TCnSM3Digest)); // д C3 У��
      P := Pointer(TCnIntAddress(P) + SizeOf(TCnSM3Digest));
      Writer.AddBasicNode(CN_BER_TAG_OCTET_STRING, P, MLen);                 // д C2 ����
    end
    else
    begin
      Writer.AddBasicNode(CN_BER_TAG_OCTET_STRING, P, MLen);                 // д C2 ����
      P := Pointer(TCnIntAddress(P) + MLen);
      Writer.AddBasicNode(CN_BER_TAG_OCTET_STRING, P, SizeOf(TCnSM3Digest)); // д C3 У��
    end;

    SetLength(Result, Writer.TotalSize);
    Writer.SaveTo(@Result[0]);
  finally
    Num.Free;
    Writer.Free;
  end;
end;

function CnSM2CryptToAsn1(EnStream: TStream; OutStream: TStream; SM2: TCnSM2;
  SequenceType: TCnSM2CryptSequenceType; IncludePrefixByte: Boolean): Boolean;
var
  R: TBytes;
begin
  Result := False;
  R := CnSM2CryptToAsn1(StreamToBytes(EnStream), SM2, SequenceType, IncludePrefixByte);
  if R <> nil then
    Result := BytesToStream(R, OutStream) > 0;
end;

function CnSM2CryptFromAsn1(Asn1Data: TBytes; SM2: TCnSM2;
  SequenceType: TCnSM2CryptSequenceType; IncludePrefixByte: Boolean): TBytes;
var
  Idx: Integer;
  Reader: TCnBerReader;
  X, Y: TCnBigNumber;
begin
  Result := nil;
  if Length(Asn1Data) < CN_SM2_MIN_ENCRYPT_BYTESIZE + 4 then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  Reader := nil;
  X := nil;
  Y := nil;

  try
    Reader := TCnBerReader.Create(@Asn1Data[0], Length(Asn1Data));
    Reader.ParseToTree;

    if Reader.TotalCount <> 5 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    if (Reader.Items[1].BerDataLength > CN_SM2_FINITEFIELD_BYTESIZE + 1)
      or ((Reader.Items[2].BerDataLength > CN_SM2_FINITEFIELD_BYTESIZE + 1)) then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    X := TCnBigNumber.Create;
    PutIndexedBigIntegerToBigNumber(Reader.Items[1], X);
    if X.GetBytesCount > CN_SM2_FINITEFIELD_BYTESIZE then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    Y := TCnBigNumber.Create;
    PutIndexedBigIntegerToBigNumber(Reader.Items[2], Y);
    if Y.GetBytesCount > CN_SM2_FINITEFIELD_BYTESIZE then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    if SequenceType = cstC1C3C2 then
    begin
      if Reader.Items[3].BerDataLength <> SizeOf(TCnSM3Digest) then // β���ϵ� C3 ���ȱ����� 32 �ֽ�
      begin
        _CnSetLastError(ECN_SM2_INVALID_INPUT);
       Exit;
      end;
    end
    else
    begin
      if Reader.Items[4].BerDataLength <> SizeOf(TCnSM3Digest) then // β���ϵ� C3 ���ȱ����� 32 �ֽ�
      begin
        _CnSetLastError(ECN_SM2_INVALID_INPUT);
       Exit;
      end;
    end;

    Idx := CN_SM2_FINITEFIELD_BYTESIZE * 2 + Reader.Items[3].BerDataLength
      + Reader.Items[4].BerDataLength;
    if IncludePrefixByte then
      Inc(Idx);

    SetLength(Result, Idx);
    Idx := 0;
    if IncludePrefixByte then
    begin
      Result[0] := 04;
      Inc(Idx);
    end;
    X.ToBinary(@Result[Idx], CN_SM2_FINITEFIELD_BYTESIZE);
    Inc(Idx, CN_SM2_FINITEFIELD_BYTESIZE);
    Y.ToBinary(@Result[Idx], CN_SM2_FINITEFIELD_BYTESIZE);

    Inc(Idx, CN_SM2_FINITEFIELD_BYTESIZE);

    // ���� 3 �� C3��4 �� C2������ 3 �� C2��4 �� C3��������ôд
    Reader.Items[3].CopyDataTo(@Result[Idx]);
    Inc(Idx, Reader.Items[3].BerDataLength);
    Reader.Items[4].CopyDataTo(@Result[Idx]);
  finally
    Y.Free;
    X.Free;
    Reader.Free;
  end;
end;

function CnSM2CryptFromAsn1(Asn1Stream: TStream; OutStream: TStream; SM2: TCnSM2;
  SequenceType: TCnSM2CryptSequenceType; IncludePrefixByte: Boolean): Boolean;
var
  R: TBytes;
begin
  Result := False;
  R := CnSM2CryptFromAsn1(StreamToBytes(Asn1Stream), SM2, SequenceType, IncludePrefixByte);
  if R <> nil then
    Result := BytesToStream(R, OutStream) > 0;
end;

// ���� Za ֵҲ���� Hash(EntLen��UserID��a��b��xG��yG��xA��yA)
// ���� EntLen �� UserID ��λ���ȣ�Ҳ�����ֽڳ��� * 8��������˳���ֽڱ�ʾ
function CalcSM2UserHash(const UserID: AnsiString; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2): TCnSM3Digest;
var
  Stream: TMemoryStream;
  Len: Integer;
  ULen: Word;
begin
  Stream := TMemoryStream.Create;
  try
    if UserID <> '' then
    begin
      Len := Length(UserID) * 8;
      ULen := UInt16HostToNetwork(Len); // ת�������ֽ�˳��

      Stream.Write(ULen, SizeOf(ULen));
      if ULen > 0 then
        Stream.Write(UserID[1], Length(UserID));
    end
    else // UserID Ϊ��ʱ���淶ʹ���ַ��� 1234567812345678
    begin
      Len := SizeOf(CN_SM2_DEF_UID) * 8;
      ULen := UInt16HostToNetwork(Len); // ת�������ֽ�˳��

      Stream.Write(ULen, SizeOf(ULen));
      if ULen > 0 then
        Stream.Write(CN_SM2_DEF_UID[0], SizeOf(CN_SM2_DEF_UID));
    end;

    BigNumberWriteBinaryToStream(SM2.CoefficientA, Stream);
    BigNumberWriteBinaryToStream(SM2.CoefficientB, Stream);
    BigNumberWriteBinaryToStream(SM2.Generator.X, Stream);
    BigNumberWriteBinaryToStream(SM2.Generator.Y, Stream);
    BigNumberWriteBinaryToStream(PublicKey.X, Stream, SM2.BytesCount);
    BigNumberWriteBinaryToStream(PublicKey.Y, Stream, SM2.BytesCount);

    Result := SM3(PAnsiChar(Stream.Memory), Stream.Size);  // ��� ZA
  finally
    Stream.Free;
  end;
end;

// ���� Za �������ٴμ����Ӵ�ֵ e
function CalcSM2SignatureHash(const UserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  PublicKey: TCnSM2PublicKey; SM2: TCnSM2): TCnSM3Digest;
var
  Stream: TMemoryStream;
  Sm3Dig: TCnSM3Digest;
begin
  Stream := TMemoryStream.Create;
  try
    Sm3Dig := CalcSM2UserHash(UserID, PublicKey, SM2);
    Stream.Write(Sm3Dig[0], SizeOf(TCnSM3Digest));
    Stream.Write(PlainData^, DataByteLen);

    Result := SM3(PAnsiChar(Stream.Memory), Stream.Size);  // �ٴ�����Ӵ�ֵ e
  finally
    Stream.Free;
  end;
end;

{
  ZA <= Hash(EntLen��UserID��a��b��xG��yG��xA��yA)
  e <= Hash(ZA��M)

  k * G => (x1, y1)

  ���ǩ�� r <= (e + x1) mod n

  ���ǩ�� s <= ((1 + PrivateKey)^-1 * (k - r * PrivateKey)) mod n

}
function CnSM2SignData(const UserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  OutSignature: TCnSM2Signature; PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2; const RandHex: string): Boolean;
var
  K, R, E: TCnBigNumber;
  P: TCnEccPoint;
  SM2IsNil: Boolean;
  PubIsNil: Boolean;
  HexSet: Boolean;
  Sm3Dig: TCnSM3Digest;
begin
  Result := False;
  if (PlainData = nil) or (DataByteLen <= 0) or (OutSignature = nil) or
    (PrivateKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  K := nil;
  P := nil;
  E := nil;
  R := nil;
  SM2IsNil := SM2 = nil;
  PubIsNil := PublicKey = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if PubIsNil then
    begin
      PublicKey := TCnSM2PublicKey.Create;
      PublicKey.Assign(SM2.Generator);
      SM2.MultiplePoint(PrivateKey, PublicKey);
    end;

    Sm3Dig := CalcSM2SignatureHash(UserID, PlainData, DataByteLen, PublicKey, SM2); // �Ӵ�ֵ e

    P := TCnEccPoint.Create;
    E := TCnBigNumber.Create;
    R := TCnBigNumber.Create;
    K := TCnBigNumber.Create;
    HexSet := False;

    while True do
    begin
      // ʹ��ָ�� K��������һ����� K
      if RandHex <> '' then
      begin
        K.SetHex(AnsiString(RandHex));
        HexSet := True;
      end
      else
      begin
        if not BigNumberRandRange(K, SM2.Order) then
        begin
          _CnSetLastError(ECN_SM2_RANDOM_ERROR);
          Exit;
        end;
      end;

      P.Assign(SM2.Generator);
      SM2.MultiplePoint(K, P);

      // ���� R = (e + x) mod N
      E.SetBinary(@Sm3Dig[0], SizeOf(TCnSM3Digest));
      BigNumberAdd(E, E, P.X);
      BigNumberMod(R, E, SM2.Order); // ��� R �� E ������

      if R.IsZero then  // R ����Ϊ 0
      begin
        if HexSet then // ���ʹ�õ������������Ҫ��
        begin
          _CnSetLastError(ECN_SM2_RANDOM_ERROR);
          Exit;
        end;
        Continue;
      end;

      BigNumberAdd(E, R, K);
      if BigNumberCompare(E, SM2.Order) = 0 then // R + K = N Ҳ����
      begin
        if HexSet then // ���ʹ�õ������������Ҫ��
        begin
          _CnSetLastError(ECN_SM2_RANDOM_ERROR);
          Exit;
        end;
        Continue;
      end;

      BigNumberCopy(OutSignature.R, R);  // �õ�һ��ǩ��ֵ R

      BigNumberCopy(E, PrivateKey);
      BigNumberAddWord(E, 1);
      BigNumberModularInverse(R, E, SM2.Order);      // ����Ԫ�õ� (1 + PrivateKey)^-1������ R ��

      // �� K - R * PrivateKey�������� E ��
      BigNumberMul(E, OutSignature.R, PrivateKey);
      BigNumberSub(E, K, E);
      BigNumberMul(R, E, R); // (1 + PrivateKey)^-1 * (K - R * PrivateKey) ���� R ��
      BigNumberNonNegativeMod(OutSignature.S, R, SM2.Order); // ע����������Ϊ��

      Result := True;
      _CnSetLastError(ECN_SM2_OK);

      Break;
    end;
  finally
    K.Free;
    P.Free;
    R.Free;
    E.Free;
    if PubIsNil then
      PublicKey.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2SignData(const UserID: AnsiString; PlainData: TBytes;
  OutSignature: TCnSM2Signature; PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  SM2: TCnSM2; const RandHex: string): Boolean;
begin
  Result := CnSM2SignData(UserID, @PlainData[0], Length(PlainData), OutSignature,
    PrivateKey, PublicKey, SM2, RandHex);
end;

{
  s �� r ��ǩ��ֵ
  ZA = Hash(EntLen��UserID��a��b��xG��yG��xA��yA)
  e <= Hash(ZA��M)

  t <= (r + s) mod n
  P <= s * G + t * PublicKey
  r' <= (e + P.x) mod n
  �ȶ� r' �� r

  ���У�P ������õ� k*G
  P = s*G + t*d*G = [s + d(r + s)] *G = ((1+d)*s + dr)*G
  ��Ϊ s = (k-rd)/(1+d) ������ʽ = (k - rd + rd) * G = k*G

  �� P ��� x ֵ�� e ����õ� r
}
function CnSM2VerifyData(const UserID: AnsiString; PlainData: Pointer; DataByteLen: Integer;
  InSignature: TCnSM2Signature; PublicKey: TCnSM2PublicKey; SM2: TCnSM2): Boolean;
var
  K, R, E: TCnBigNumber;
  P, Q: TCnEccPoint;
  SM2IsNil: Boolean;
  Sm3Dig: TCnSM3Digest;
begin
  Result := False;
  if (PlainData = nil) or (DataByteLen <= 0) or (InSignature = nil) or (PublicKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  K := nil;
  P := nil;
  Q := nil;
  E := nil;
  R := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if BigNumberCompare(InSignature.R, SM2.Order) >= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    if BigNumberCompare(InSignature.S, SM2.Order) >= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    Sm3Dig := CalcSM2SignatureHash(UserID, PlainData, DataByteLen, PublicKey, SM2); // �Ӵ�ֵ e

    P := TCnEccPoint.Create;
    Q := TCnEccPoint.Create;
    E := TCnBigNumber.Create;
    R := TCnBigNumber.Create;
    K := TCnBigNumber.Create;

    BigNumberAdd(K, InSignature.R, InSignature.S);
    BigNumberNonNegativeMod(R, K, SM2.Order);
    if R.IsZero then  // (r + s) mod n = 0 ��ʧ�ܣ����� R �����е� T
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    P.Assign(SM2.Generator);
    SM2.MultiplePoint(InSignature.S, P);
    Q.Assign(PublicKey);
    SM2.MultiplePoint(R, Q);
    SM2.PointAddPoint(P, Q, P);   // s * G + t * PublicKey => P

    E.SetBinary(@Sm3Dig[0], SizeOf(TCnSM3Digest));
    BigNumberAdd(E, E, P.X);

    BigNumberNonNegativeMod(R, E, SM2.Order);

    Result := BigNumberCompare(R, InSignature.R) = 0;
    _CnSetLastError(ECN_SM2_OK); // ��������У�飬��ʹУ�鲻ͨ��Ҳ��մ�����
  finally
    K.Free;
    P.Free;
    Q.Free;
    R.Free;
    E.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2VerifyData(const UserID: AnsiString; PlainData: TBytes;
  InSignature: TCnSM2Signature; PublicKey: TCnSM2PublicKey; SM2: TCnSM2): Boolean;
begin
  Result := CnSM2VerifyData(UserID, @PlainData[0], Length(PlainData), InSignature, PublicKey, SM2);
end;

function CnSM2SignFile(const UserID: AnsiString; const FileName: string;
  PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey; SM2: TCnSM2): string;
var
  OutSign: TCnSM2Signature;
  Stream: TMemoryStream;
begin
  Result := '';
  if not FileExists(FileName) then
  begin
    _CnSetLastError(ECN_FILE_NOT_FOUND);
    Exit;
  end;

  OutSign := nil;
  Stream := nil;

  try
    OutSign := TCnSM2Signature.Create;
    Stream := TMemoryStream.Create;

    Stream.LoadFromFile(FileName);
    if CnSM2SignData(UserID, Stream.Memory, Stream.Size, OutSign, PrivateKey, PublicKey, SM2) then
      Result := OutSign.ToHex(SM2.BytesCount);
  finally
    Stream.Free;
    OutSign.Free;
  end;
end;

function CnSM2VerifyFile(const UserID: AnsiString; const FileName: string;
  const InHexSignature: string; PublicKey: TCnSM2PublicKey; SM2: TCnSM2): Boolean;
var
  InSign: TCnSM2Signature;
  Stream: TMemoryStream;
begin
  Result := False;
  if not FileExists(FileName) then
  begin
    _CnSetLastError(ECN_FILE_NOT_FOUND);
    Exit;
  end;

  InSign := nil;
  Stream := nil;

  try
    InSign := TCnSM2Signature.Create;
    InSign.SetHex(AnsiString(InHexSignature));

    Stream := TMemoryStream.Create;
    Stream.LoadFromFile(FileName);

    Result := CnSM2VerifyData(UserID, Stream.Memory, Stream.Size, InSign, PublicKey, SM2);
  finally
    Stream.Free;
    InSign.Free;
  end;
end;

{
  ���㽻��������Կ��KDF(Xuv��Yuv��Za��Zb, kLen)
}
function CalcSM2ExchangeKey(UV: TCnEccPoint; Za, Zb: TCnSM3Digest; KeyByteLength: Integer): TBytes;
var
  Stream: TMemoryStream;
  S: TBytes;
begin
  Stream := TMemoryStream.Create;
  try
    BigNumberWriteBinaryToStream(UV.X, Stream);
    BigNumberWriteBinaryToStream(UV.Y, Stream);
    Stream.Write(Za[0], SizeOf(TCnSM3Digest));
    Stream.Write(Zb[0], SizeOf(TCnSM3Digest));

    SetLength(S, Stream.Size);
    Stream.Position := 0;
    Stream.Read(S[0], Stream.Size);

    Result := CnSM2KDFBytes(S, KeyByteLength);
  finally
    SetLength(S, 0);
    Stream.Free;
  end;
end;

{
  Hash(0x02��Yuv��Hash(Xuv��Za��Zb��X1��Y1��X2��Y2))
       0x03
}
function CalcSM2OptionalSig(UV, P1, P2: TCnEccPoint; Za, Zb: TCnSM3Digest; Step2or3: Boolean): TCnSM3Digest;
var
  Stream: TMemoryStream;
  Sm3Dig: TCnSM3Digest;
  B: Byte;
begin
  if Step2or3 then
    B := 2
  else
    B := 3;

  Stream := TMemoryStream.Create;
  try
    BigNumberWriteBinaryToStream(UV.X, Stream);
    Stream.Write(Za[0], SizeOf(TCnSM3Digest));
    Stream.Write(Zb[0], SizeOf(TCnSM3Digest));
    BigNumberWriteBinaryToStream(P1.X, Stream);
    BigNumberWriteBinaryToStream(P1.Y, Stream);
    BigNumberWriteBinaryToStream(P2.X, Stream);
    BigNumberWriteBinaryToStream(P2.Y, Stream);
    Sm3Dig := SM3(PAnsiChar(Stream.Memory), Stream.Size);

    Stream.Clear;
    Stream.Write(B, 1);
    BigNumberWriteBinaryToStream(UV.Y, Stream);
    Stream.Write(Sm3Dig[0], SizeOf(TCnSM3Digest));

    Result := SM3(PAnsiChar(Stream.Memory), Stream.Size);
  finally
    Stream.Free;
  end;
end;

{
  ���ֵ rA * G => RA ���� B
}
function CnSM2KeyExchangeAStep1(const AUserID, BUserID: AnsiString; KeyByteLength: Integer;
  APrivateKey: TCnSM2PrivateKey; APublicKey, BPublicKey: TCnSM2PublicKey;
  OutARand: TCnBigNumber; OutRA: TCnEccPoint; SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
begin
  Result := False;
  if (KeyByteLength <= 0) or (APrivateKey = nil) or (APublicKey = nil) or (OutRA = nil)
    or (OutARand = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;
  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not BigNumberRandRange(OutARand, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;

    OutRA.Assign(SM2.Generator);
    SM2.MultiplePoint(OutARand, OutRA);
    Result := True;
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  ���ֵ * G => RB
  x2 <= RB.X
  X2 <= 2^W + (x2 and (2^W - 1) ��ʾ�� x2 �ĵ� W λ�� 1��W + 1 ����ȫ�� 0
  T <= (BPrivateKey + ���ֵ * X2) mod N

  x1 <= RA.X
  X1 <= 2^W + (x1 and (2^W - 1)
  KB <= (h * T) * (APublicKey + X1 * RA)

  ע�� BigNumber �� BitCount Ϊ 2 Ϊ�׵Ķ�������ȡ��
}
function CnSM2KeyExchangeBStep1(const AUserID, BUserID: AnsiString; KeyByteLength: Integer;
  BPrivateKey: TCnSM2PrivateKey; APublicKey, BPublicKey: TCnSM2PublicKey; InRA: TCnEccPoint;
  out OutKeyB: TBytes; OutRB: TCnEccPoint; out OutOptionalSB: TCnSM3Digest;
  out OutOptionalS2: TCnSM3Digest; SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
  R, X, T: TCnBigNumber;
  V: TCnEccPoint;
  Za, Zb: TCnSM3Digest;
begin
  Result := False;
  if (KeyByteLength <= 0) or (BPrivateKey = nil) or (APublicKey = nil) or
    (BPublicKey = nil) or (InRA = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;
  R := nil;
  X := nil;
  T := nil;
  V := nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not SM2.IsPointOnCurve(InRA) then // ��֤�������� RA �Ƿ����㷽��
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    R := TCnBigNumber.Create;
    if not BigNumberRandRange(R, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;

    OutRB.Assign(SM2.Generator);
    SM2.MultiplePoint(R, OutRB);

    X := TCnBigNumber.Create;
    BigNumberCopy(X, OutRB.X);

    // 2^W �η���ʾ�� W λ 1��λ�� 0 ��ʼ�㣩 ��2^W - 1 ���ʾ 0 λ�� W - 1 λȫ�� 1
    // X2 = 2^W + (x2 and (2^W - 1) ��ʾ�� x2 �ĵ� W λ�� 1��W + 1 ����ȫ�� 0��x2 �� RB.X
    BuildShortXValue(X, SM2.Order);

    BigNumberMul(X, R, X);
    BigNumberAdd(X, X, BPrivateKey);

    T := TCnBigNumber.Create;
    BigNumberNonNegativeMod(T, X, SM2.Order); // T = (BPrivateKey + ���ֵ * X2) mod N

    BigNumberCopy(X, InRA.X);
    BuildShortXValue(X, SM2.Order);

    // ���� XV YV�� (h * t) * (APublicKey + X * RA)
    V := TCnEccPoint.Create;
    V.Assign(InRA);
    SM2.MultiplePoint(X, V);
    SM2.PointAddPoint(V, APublicKey, V);
    SM2.MultiplePoint(T, V);

    if V.X.IsZero or V.Y.IsZero then // ���������Զ����Э��ʧ��
    begin
      _CnSetLastError(ECN_SM2_KEYEXCHANGE_INFINITE_ERROR);
      Exit;
    end;

    // Э�̳����ɹ������� KB
    Za := CalcSM2UserHash(AUserID, APublicKey, SM2);
    Zb := CalcSM2UserHash(BUserID, BPublicKey, SM2);
    OutKeyB := CalcSM2ExchangeKey(V, Za, Zb, KeyByteLength); // ������ԿЭ�̳ɹ���

    // Ȼ����� SB �� A �˶�
    OutOptionalSB := CalcSM2OptionalSig(V, InRA, OutRB, Za, Zb, True);

    // ˳����� S2 �� A ���� SA ʱ�˶�
    OutOptionalS2 := CalcSM2OptionalSig(V, InRA, OutRB, Za, Zb, False);
    Result := True;
  finally
    V.Free;
    T.Free;
    X.Free;
    R.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2KeyExchangeAStep2(const AUserID, BUserID: AnsiString; KeyByteLength: Integer;
  APrivateKey: TCnSM2PrivateKey; APublicKey, BPublicKey: TCnSM2PublicKey; MyRA, InRB: TCnEccPoint;
  MyARand: TCnBigNumber; out OutKeyA: TBytes; InOptionalSB: TCnSM3Digest;
  out OutOptionalSA: TCnSM3Digest; SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
  X, T: TCnBigNumber;
  U: TCnEccPoint;
  Za, Zb: TCnSM3Digest;
begin
  Result := False;
  if (KeyByteLength <= 0) or (APrivateKey = nil) or (APublicKey = nil) or
    (BPublicKey = nil) or (MyRA = nil) or (InRB = nil) or (MyARand = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;
  X := nil;
  T := nil;
  U := nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not SM2.IsPointOnCurve(InRB) then // ��֤�������� RB �Ƿ����㷽��
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    X := TCnBigNumber.Create;
    BigNumberCopy(X, MyRA.X);
    BuildShortXValue(X, SM2.Order);     // �� RA ������ X1

    BigNumberMul(X, MyARand, X);
    BigNumberAdd(X, X, APrivateKey);

    T := TCnBigNumber.Create;
    BigNumberNonNegativeMod(T, X, SM2.Order); // T = (APrivateKey + ���ֵ * X1) mod N

    BigNumberCopy(X, InRB.X);
    BuildShortXValue(X, SM2.Order);

    // ���� XU YU�� (h * t) * (BPublicKey + X * RB)
    U := TCnEccPoint.Create;
    U.Assign(InRB);
    SM2.MultiplePoint(X, U);
    SM2.PointAddPoint(U, BPublicKey, U);
    SM2.MultiplePoint(T, U);

    if U.X.IsZero or U.Y.IsZero then // ���������Զ����Э��ʧ��
    begin
      _CnSetLastError(ECN_SM2_KEYEXCHANGE_INFINITE_ERROR);
      Exit;
    end;

    // Э�̳����ɹ������� KA
    Za := CalcSM2UserHash(AUserID, APublicKey, SM2);
    Zb := CalcSM2UserHash(BUserID, BPublicKey, SM2);
    OutKeyA := CalcSM2ExchangeKey(U, Za, Zb, KeyByteLength); // ������ԿЭ�̳ɹ���

    // Ȼ����� SB �˶�
    OutOptionalSA := CalcSM2OptionalSig(U, MyRA, InRB, Za, Zb, True);
    if not CompareMem(@OutOptionalSA[0], @InOptionalSB[0], SizeOf(TCnSM3Digest)) then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    // Ȼ����� SA �� B �˶�
    OutOptionalSA := CalcSM2OptionalSig(U, MyRA, InRB, Za, Zb, False);
    Result := True;
  finally
    U.Free;
    T.Free;
    X.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2KeyExchangeBStep2(const AUserID, BUserID: AnsiString; KeyByteLength: Integer;
  BPrivateKey: TCnSM2PrivateKey; APublicKey, BPublicKey: TCnSM2PublicKey;
  InOptionalSA: TCnSM3Digest; MyOptionalS2: TCnSM3Digest; SM2: TCnSM2): Boolean;
begin
  Result := CompareMem(@InOptionalSA[0], @MyOptionalS2[0], SizeOf(TCnSM3Digest));
end;

{
  ���ȡ r
  �� R <= r * G
  �� c <= Hash(PublicKey, R)
  �� z <= r + c * PrivateKey
}
function CnSM2SchnorrProve(PrivateKey: TCnSM2PrivateKey; PublicKey: TCnSM2PublicKey;
  OutR: TCnEccPoint; OutZ: TCnBigNumber; SM2: TCnSM2): Boolean;
var
  R: TCnBigNumber;
  Dig: TCnSM3Digest;
  SM2IsNil: Boolean;
  Stream: TMemoryStream;
begin
  Result := False;
  if (PrivateKey = nil) or (PublicKey = nil) or (OutR = nil) or (OutZ = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  R := nil;
  Stream := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    R := TCnBigNumber.Create;
    if not BigNumberRandBytes(R, CN_SM2_FINITEFIELD_BYTESIZE) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;

    OutR.Assign(SM2.Generator);
    SM2.MultiplePoint(R, OutR);

    Stream := TMemoryStream.Create;
    if CnEccPointToStream(PublicKey, Stream, CN_SM2_FINITEFIELD_BYTESIZE) <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    if CnEccPointToStream(OutR, Stream, CN_SM2_FINITEFIELD_BYTESIZE) <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    Dig := SM3(Stream.Memory, Stream.Size);

    OutZ.SetBinary(@Dig[0], SizeOf(TCnSM3Digest));

    // ע�⣬�˴�����Ҳ���� mod P��
    BigNumberMul(OutZ, OutZ, PrivateKey);
    BigNumberAdd(OutZ, OutZ, R);

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    Stream.Free;
    R.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  �� c <= Hash(PublicKey, R)
  �� z * G ?= R + c * PublicKey
}
function CnSM2SchnorrCheck(PublicKey: TCnSM2PublicKey; InR: TCnEccPoint;
  InZ: TCnBigNumber; SM2: TCnSM2): Boolean;
var
  C: TCnBigNumber;
  Dig: TCnSM3Digest;
  SM2IsNil: Boolean;
  Stream: TMemoryStream;
  P1, P2: TCnEccPoint;
begin
  Result := False;
  if (PublicKey = nil) or (InR = nil) or (InZ = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  Stream := nil;
  C := nil;
  P1 := nil;
  P2 := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    Stream := TMemoryStream.Create;
    if CnEccPointToStream(PublicKey, Stream, CN_SM2_FINITEFIELD_BYTESIZE) <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    if CnEccPointToStream(InR, Stream, CN_SM2_FINITEFIELD_BYTESIZE) <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    Dig := SM3(Stream.Memory, Stream.Size);

    C := TCnBigNumber.Create;
    C.SetBinary(@Dig[0], SizeOf(TCnSM3Digest));

    P1 := TCnEccPoint.Create;
    P1.Assign(SM2.Generator);
    SM2.MultiplePoint(InZ, P1);

    P2 := TCnEccPoint.Create;
    P2.Assign(PublicKey);
    SM2.MultiplePoint(C, P2);
    SM2.PointAddPoint(P2, InR, P2);

    Result := CnEccPointsEqual(P1, P2);
    _CnSetLastError(ECN_SM2_OK);
  finally
    P2.Free;
    P1.Free;
    C.Free;
    Stream.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

// ========== SM2 ��Բ����˫���������εļ���Эͬ�㷨֮Эͬ��Կ���� =============

function CnSM2CollaborativeGenerateKeyAStep1(PrivateKeyA: TCnSM2CollaborativePrivateKey;
  OutPointToB: TCnEccPoint; SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyA = nil) or (OutPointToB = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not BigNumberRandRange(PrivateKeyA, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;
    if PrivateKeyA.IsZero then // ��һ���õ� 0���ͼ� 1
      PrivateKeyA.SetOne;

    OutPointToB.Assign(SM2.Generator);
    SM2.MultiplePoint(PrivateKeyA, OutPointToB); // ����� PrivateKeyA �θ� B

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2CollaborativeGenerateKeyBStep1(PrivateKeyB: TCnSM2CollaborativePrivateKey;
  InPointFromA: TCnEccPoint; PublicKey: TCnSM2CollaborativePublicKey; SM2: TCnSM2): Boolean;
var
  P: TCnEccPoint;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyB = nil) or (InPointFromA = nil) or (PublicKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  P := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not BigNumberRandRange(PrivateKeyB, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;
    if PrivateKeyB.IsZero then // ��һ���õ� 0���ͼ� 1
      PrivateKeyB.SetOne;

    PublicKey.Assign(InPointFromA);
    SM2.MultiplePoint(PrivateKeyB, PublicKey); // �õ��� PublicKey ��Ҫ�� G

    P := TCnEccPoint.Create;
    P.Assign(SM2.Generator);
    SM2.PointInverse(P);
    SM2.PointAddPoint(PublicKey, P, PublicKey);

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    P.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

// =============== SM2 ��Բ����˫���������εļ���Эͬǩ���㷨 ==================
{
  A ��������� ka��������� ka*G �� B��Ҳ���Ӵ�ֵ e �� B
}
function CnSM2CollaborativeSignAStep1(const UserID: AnsiString; PlainData: Pointer;
  DataByteLen: Integer; OutHashEToB: TCnBigNumber; OutQToB: TCnEccPoint; OutRandKA: TCnBigNumber;
  PrivateKeyA: TCnSM2CollaborativePrivateKey; PublicKey: TCnSM2PublicKey; SM2: TCnSM2): Boolean;
var
  Sm3Dig: TCnSM3Digest;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyA = nil) or (OutHashEToB = nil) or (OutQToB = nil) or
    (OutRandKA = nil) or (PublicKey = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    Sm3Dig := CalcSM2SignatureHash(UserID, PlainData, DataByteLen, PublicKey, SM2); // �Ӵ�ֵ e Ҫ�� B
    OutHashEToB.SetBinary(@Sm3Dig[0], SizeOf(TCnSM3Digest));

    if not BigNumberRandRange(OutRandKA, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;
    if OutRandKA.IsZero then               // ��һ���õ� 0���ͼ� 1
      OutRandKA.SetOne;

    OutQToB.Assign(SM2.Generator);
    SM2.MultiplePoint(OutRandKA, OutQToB); // K Ҫ���Ÿ� A ǩ������һ����ע������û��ʹ�� PrivateKeyA

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  B ��������� k2 ȥ���� ka*G��������������� k1�������Ҫ�� (ka*k2+k1)*G���õ�ĺ����� r
  ����� S1 = k2/dB    S2 = (k1+r)/dB
}
function CnSM2CollaborativeSignBStep1(InHashEFromA: TCnBigNumber; InQFromA: TCnEccPoint;
  OutRToA, OutS1ToA, OutS2ToA: TCnBigNumber; PrivateKeyB: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2): Boolean;
var
  K1, K2, Inv: TCnBigNumber;
  P, Q: TCnEccPoint;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyB = nil) or (InHashEFromA = nil) or (InQFromA = nil)
    or (OutRToA = nil) or (OutS1ToA = nil) or (OutS2ToA = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  K1 := nil;
  K2 := nil;
  Q := nil;
  P := nil;
  Inv := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    K1 := TCnBigNumber.Create;
    K2 := TCnBigNumber.Create;
    Q := TCnEccPoint.Create;
    P := TCnEccPoint.Create;
    Inv := TCnBigNumber.Create;

    while True do
    begin
      if not BigNumberRandRange(K1, SM2.Order) then
      begin
        _CnSetLastError(ECN_SM2_RANDOM_ERROR);
        Exit;
      end;
      if K1.IsZero then // ��һ���õ� 0���ͼ� 1
        K1.SetOne;

      Q.Assign(SM2.Generator);
      SM2.MultiplePoint(K1, Q); // �ȼ����һ���Լ��� Q ��

      // ������һ����� K
      if not BigNumberRandRange(K2, SM2.Order) then
      begin
        _CnSetLastError(ECN_SM2_RANDOM_ERROR);
        Exit;
      end;
      if K2.IsZero then // ��һ���õ� 0���ͼ� 1
        K2.SetOne;

      P.Assign(InQFromA);
      SM2.MultiplePoint(K2, P);   // �Է��� Q ������Լ��� K
      SM2.PointAddPoint(P, Q, Q); // �ټ����Լ��� Q

      // r = (Q.x + e) mod N
      BigNumberAddMod(OutRToA, Q.X, InHashEFromA, SM2.Order);

      if OutRToA.IsZero then                               // ע�⵽��Ϊֹ PrivateKeyB δ������
        Continue;

      BigNumberModularInverse(Inv, PrivateKeyB, SM2.Order);
      BigNumberDirectMulMod(OutS1ToA, Inv, K2, SM2.Order); // ��� s1 = k2 / PrivateKeyB
      BigNumberAddMod(K1, K1, OutRToA, SM2.Order);         // K1 + r
      BigNumberDirectMulMod(OutS2ToA, K1, Inv, SM2.Order); // K1 + r / PrivateKeyB

      Result := True;
      _CnSetLastError(ECN_SM2_OK);

      Break;
    end;
  finally
    Inv.Free;
    P.Free;
    Q.Free;
    K2.Free;
    K1.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;
{
  A �õ� B �������� S1 S2 ����� S = (ka*k2/dA*dB) + T -r
  ������ʱ���� T = S2/dA

           (ka*k2 + k1) + (dA*dB - 1)*r
  �õ� S = -----------------------------  Ϊ��������� k = (ka*k2 + k1)
                      dA*dB

  ��֤ʱͬ������ P = s*G + (r+s)*PublicKey = s+(r+s)(dA*dB-1)*G
  ���� r+s = (k-r)(dA*dB-1)/dAdB ��չ����ȥ�� r*dA*dB�������뻯��
  ���չ���õ� P = (k *dA*dB/dA*dB)*G = k*G���ɹ���
}
function CnSM2CollaborativeSignAStep2(InRandKA, InRFromB, InS1FromB, InS2FromB: TCnBigNumber;
  OutSignature: TCnSM2Signature; PrivateKeyA: TCnSM2CollaborativePrivateKey; SM2: TCnSM2): Boolean;
var
  Inv, T: TCnBigNumber;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyA = nil) or (OutSignature = nil) or
    (InRFromB = nil) or (InS1FromB = nil) or (InS2FromB = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  Inv := nil;
  T := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    Inv := TCnBigNumber.Create;
    BigNumberModularInverse(Inv, PrivateKeyA, SM2.Order);

    T := TCnBigNumber.Create;
    BigNumberDirectMulMod(T, Inv, InS2FromB, SM2.Order); // T := S2 / PrivateKeyA
    BigNumberDirectMulMod(OutSignature.S, InRandKA, Inv, SM2.Order); // Ka / PrivateKeyA
    BigNumberDirectMulMod(OutSignature.S, OutSignature.S, InS1FromB, SM2.Order); // K * S1 / PrivateKeyA

    BigNumberAddMod(OutSignature.S, OutSignature.S, T, SM2.Order);
    BigNumberSubMod(OutSignature.S, OutSignature.S, InRFromB, SM2.Order);

    if not OutSignature.S.IsZero then
    begin
      BigNumberAdd(T, OutSignature.S, InRFromB);

      if not BigNumberEqual(T, SM2.Order) then
      begin
        if BigNumberCopy(OutSignature.R, InRFromB) = nil then
        begin
          _CnSetLastError(ECN_SM2_BIGNUMBER_ERROR);
          Exit;
        end;
      end;

      Result := True;
      _CnSetLastError(ECN_SM2_OK);
    end;
  finally
    T.Free;
    Inv.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

// =============== SM2 ��Բ����˫���������εļ���Эͬ�����㷨 ==================

function CnSM2CollaborativeDecryptAStep1(EnData: Pointer; DataByteLen: Integer;
  OutTToB: TCnEccPoint; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2): Boolean;
var
  MLen: Integer;
  M: PAnsiChar;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (EnData = nil) or (DataByteLen <= 0) or (PrivateKeyA = nil)
    or (OutTToB = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    MLen := DataByteLen - CN_SM2_MIN_ENCRYPT_BYTESIZE;
    if MLen <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    M := PAnsiChar(EnData);
    if M^ = #$04 then  // �������ܵ�ǰ���ֽ� $04
    begin
      Dec(MLen);
      if MLen <= 0 then
      begin
        _CnSetLastError(ECN_SM2_INVALID_INPUT);
        Exit;
      end;

      Inc(M);
    end;

    // ���� C1
    OutTToB.X.SetBinary(M, SM2.BitsCount div 8);
    Inc(M, SM2.BitsCount div 8);
    OutTToB.Y.SetBinary(M, SM2.BitsCount div 8);
    if OutTToB.IsZero then
    begin
      _CnSetLastError(ECN_SM2_DECRYPT_INFINITE_ERROR);
      Exit;
    end;

    SM2.MultiplePoint(PrivateKeyA, OutTToB); // C1 ���˽Կ���� B

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2CollaborativeDecryptBStep1(InTFromA: TCnEccPoint; OutTToA: TCnEccPoint;
  PrivateKeyB: TCnSM2CollaborativePrivateKey; SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyB = nil) or (InTFromA = nil) or (OutTToA = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    OutTToA.Assign(InTFromA);
    SM2.MultiplePoint(PrivateKeyB, OutTToA);

     Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

function CnSM2CollaborativeDecryptAStep2(EnData: Pointer; DataByteLen: Integer;
  InTFromB: TCnEccPoint; OutStream: TStream; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2; SequenceType: TCnSM2CryptSequenceType): Boolean;
var
  MLen: Integer;
  M: PAnsiChar;
  MP: AnsiString;
  KDFB, T: TBytes;
  C3H: AnsiString;
  P2: TCnEccPoint;
  I, PrefixLen: Integer;
  Sm3Dig: TCnSM3Digest;
  SM2IsNil: Boolean;
begin
  Result := False;
  if (EnData = nil) or (DataByteLen <= 0) or (PrivateKeyA = nil)
    or (InTFromB = nil) or (OutStream = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    MLen := DataByteLen - CN_SM2_MIN_ENCRYPT_BYTESIZE;
    if MLen <= 0 then
    begin
      _CnSetLastError(ECN_SM2_INVALID_INPUT);
      Exit;
    end;

    P2 := TCnEccPoint.Create;
    M := PAnsiChar(EnData);
    if M^ = #$04 then  // �������ܵ�ǰ���ֽ� $04
    begin
      Dec(MLen);
      if MLen <= 0 then
      begin
        _CnSetLastError(ECN_SM2_INVALID_INPUT);
        Exit;
      end;

      PrefixLen := 1;
      Inc(M);
    end
    else
      PrefixLen := 0;

    // ���� C1
    P2.X.SetBinary(M, SM2.BitsCount div 8);
    Inc(M, SM2.BitsCount div 8);
    P2.Y.SetBinary(M, SM2.BitsCount div 8);
    if P2.IsZero then
    begin
      _CnSetLastError(ECN_SM2_DECRYPT_INFINITE_ERROR);
      Exit;
    end;

    // P2 <= InTFromB - C1
    SM2.PointSubPoint(InTFromB, P2, P2);

    // ����ͬ�������

    SetLength(KDFB, CN_SM2_FINITEFIELD_BYTESIZE * 2);
    P2.X.ToBinary(@KDFB[0], CN_SM2_FINITEFIELD_BYTESIZE);
    P2.Y.ToBinary(@KDFB[CN_SM2_FINITEFIELD_BYTESIZE], CN_SM2_FINITEFIELD_BYTESIZE);
    T := CnSM2KDFBytes(KDFB, MLen);

    if SequenceType = cstC1C3C2 then
    begin
      SetLength(MP, MLen);
      M := PAnsiChar(EnData);
      Inc(M, SizeOf(TCnSM3Digest) + CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen); // ���� C3 ָ�� C2
      for I := 1 to MLen do
        MP[I] := AnsiChar(Byte(M[I - 1]) xor Byte(T[I - 1]));    // �� KDF ������� MP ��õ�����

      SetLength(C3H, CN_SM2_FINITEFIELD_BYTESIZE * 2 + MLen);
      P2.X.ToBinary(@C3H[1], CN_SM2_FINITEFIELD_BYTESIZE);
      Move(MP[1], C3H[CN_SM2_FINITEFIELD_BYTESIZE + 1], MLen);
      P2.Y.ToBinary(@C3H[CN_SM2_FINITEFIELD_BYTESIZE + MLen + 1], CN_SM2_FINITEFIELD_BYTESIZE);    // ƴ���� C3 ��
      Sm3Dig := SM3(@C3H[1], Length(C3H));                   // ��� C3

      M := PAnsiChar(EnData);
      Inc(M, CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen);             // M ָ�� C3
      if CompareMem(@Sm3Dig[0], M, SizeOf(TCnSM3Digest)) then  // �ȶ��Ӵ�ֵ�Ƿ����
      begin
        OutStream.Write(MP[1], Length(MP));

        Result := True;
        _CnSetLastError(ECN_SM2_OK);
      end;
    end
    else // C1C2C3 ������
    begin
      SetLength(MP, MLen);
      M := PAnsiChar(EnData);
      Inc(M, CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen);             // ָ�� C2

      for I := 1 to MLen do
        MP[I] := AnsiChar(Byte(M[I - 1]) xor Byte(T[I - 1]));    // �� KDF ������� MP ��õ�����

      SetLength(C3H, CN_SM2_FINITEFIELD_BYTESIZE * 2 + MLen);
      P2.X.ToBinary(@C3H[1], CN_SM2_FINITEFIELD_BYTESIZE);
      Move(MP[1], C3H[CN_SM2_FINITEFIELD_BYTESIZE + 1], MLen);
      P2.Y.ToBinary(@C3H[CN_SM2_FINITEFIELD_BYTESIZE + MLen + 1], CN_SM2_FINITEFIELD_BYTESIZE);    // ƴ���� C3 ��
      Sm3Dig := SM3(@C3H[1], Length(C3H));                   // ��� C3

      M := PAnsiChar(EnData);
      Inc(M, CN_SM2_FINITEFIELD_BYTESIZE * 2 + PrefixLen + MLen);      // ָ�� C3
      if CompareMem(@Sm3Dig[0], M, SizeOf(TCnSM3Digest)) then  // �ȶ��Ӵ�ֵ�Ƿ����
      begin
        OutStream.Write(MP[1], Length(MP));

        Result := True;
        _CnSetLastError(ECN_SM2_OK);
      end;
    end;
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

procedure CheckPrePoints;
const
  M_WIDTH = 4;
var
  SM2: TCnSM2;
  P, Q: TCnEcc3Point;
  R, C, I: Integer;
  MRows, MCols: Integer;
begin
  if FSM2AffineGPower2KList.Count > 0 then
    Exit;

  FLocalSM2Generator := TCnEccPoint.Create;
  SM2 := TCnSM2.Create;
  try
    FLocalSM2Generator.Assign(SM2.Generator);

    // ����Ԥ����� 2^n �б�
    P := TCnEcc3Point.Create;
    CnEccPointToEcc3Point(SM2.Generator, P);

    FSM2AffineGPower2KList.Add(P);      // �� 0 ���� 2 �� 0 �η�Ҳ���� 1 ����������
    for I := 1 to 255 do
    begin
      Q := TCnEcc3Point.Create;
      SM2.AffinePointAddPoint(P, P, Q); // Q ��� 2P
      FSM2AffineGPower2KList.Add(Q);    // �����б�
      P.Assign(Q);                      // P ��� 2P ׼���´�ѭ��
    end;

    // ����Ԥ����Ĺ̶�������
    if FSM2AffinePreMatrix <> nil then
      Exit;

    MRows := SM2.BitsCount div M_WIDTH;
    MCols := 1 shl M_WIDTH;

    FSM2AffinePreMatrix := TCnEcc3Matrix.Create(MRows, MCols);
    CnEccPointToEcc3Point(SM2.Generator, P); // P �õ���Ӱ G
    FSM2AffinePreMatrix.ValueObject[0, 0].SetZero;

    // ��� 0 �еı���
    for C := 0 to MCols - 2 do
      SM2.AffinePointAddPoint(FSM2AffinePreMatrix.ValueObject[0, C], P,
        FSM2AffinePreMatrix.ValueObject[0, C + 1]);

    for R := 1 to MRows - 1 do
    begin
      for C := 0 to MCols - 1 do
      begin
        SM2.AffinePointAddPoint(FSM2AffinePreMatrix.ValueObject[R - 1, C],
          FSM2AffinePreMatrix.ValueObject[R - 1, C], FSM2AffinePreMatrix.ValueObject[R, C]);
        for I := 1 to M_WIDTH - 1 do
          SM2.AffinePointAddPoint(FSM2AffinePreMatrix.ValueObject[R, C],
            FSM2AffinePreMatrix.ValueObject[R, C], FSM2AffinePreMatrix.ValueObject[R, C]);
          // �ԼӶ��� = ���� 4���Լ��Ĵ� = ���� 16
      end;
    end;
  finally
    SM2.Free;
  end;
end;

// ======== SM2 ��Բ������������෽�������εļ���Эͬ�㷨֮Эͬ��Կ���� =======
{
  dA * G => B
}
function CnSM2Collaborative3GenerateKeyAStep1(PrivateKeyA: TCnSM2CollaborativePrivateKey;
  OutPointToB: TCnEccPoint; SM2: TCnSM2): Boolean;
begin
  Result := CnSM2CollaborativeGenerateKeyAStep1(PrivateKeyA, OutPointToB, SM2);
end;

{
  dA * dB * G => C
}
function CnSM2Collaborative3GenerateKeyBStep1(PrivateKeyB: TCnSM2CollaborativePrivateKey;
  InPointFromA: TCnEccPoint; OutPointToC: TCnEccPoint; SM2: TCnSM2): Boolean;
var
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyB = nil) or (OutPointToC = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not BigNumberRandRange(PrivateKeyB, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;
    if PrivateKeyB.IsZero then // ��һ���õ� 0���ͼ� 1
      PrivateKeyB.SetOne;

    OutPointToC.Assign(InPointFromA);
    SM2.MultiplePoint(PrivateKeyB, OutPointToC); // A �ĵ�� PrivateKeyB �θ� C

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  (dA * dB * dC - 1) * G
}
function CnSM2Collaborative3GenerateKeyCStep1(PrivateKeyC: TCnSM2CollaborativePrivateKey;
  InPointFromB: TCnEccPoint; PublicKey: TCnSM2CollaborativePublicKey; SM2: TCnSM2): Boolean;
begin
  Result := CnSM2CollaborativeGenerateKeyBStep1(PrivateKeyC, InPointFromB, PublicKey, SM2); // �м�һ����
end;

{
  ka * G => B
  e => B
}
function CnSM2Collaborative3SignAStep1(const UserID: AnsiString; PlainData: Pointer;
  DataByteLen: Integer; OutHashEToBC: TCnBigNumber; OutQToB: TCnEccPoint; OutRandKA: TCnBigNumber;
  PrivateKeyA: TCnSM2CollaborativePrivateKey; PublicKey: TCnSM2PublicKey; SM2: TCnSM2 = nil): Boolean;
begin
  Result := CnSM2CollaborativeSignAStep1(UserID, PlainData, DataByteLen, OutHashEToBC,
    OutQToB, OutRandKA, PrivateKeyA, PublicKey, SM2);
end;

{
  kb * ka * G => C
  e => C
}
function CnSM2Collaborative3SignBStep1(InHashEFromA: TCnBigNumber; InQFromA: TCnEccPoint;
  OutQToC: TCnEccPoint; OutRandKB: TCnBigNumber; PrivateKeyB: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
var
  SM2IsNil: Boolean;
begin
  Result := False;
  if (PrivateKeyB = nil) or (InHashEFromA = nil) or (InQFromA = nil)
    or (OutQToC = nil) or (OutRandKB = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    if not BigNumberRandRange(OutRandKB, SM2.Order) then
    begin
      _CnSetLastError(ECN_SM2_RANDOM_ERROR);
      Exit;
    end;
    if OutRandKB.IsZero then                // ��һ���õ� 0���ͼ� 1
      OutRandKB.SetOne;

    // Kb * Qa => Qb
    OutQToC.Assign(InQFromA);
    SM2.MultiplePoint(OutRandKB, OutQToC);   // �ּ����һ���Լ��� Q ��

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  Q = kc * kb * ka * G + k1 * G���� x ���� + e => r��r ��ԱȽϹ̶��ش��ݸ� A �� B
  S1 = kc / dC         => B
  S2 = (k1 + r) / dC   => B
}
function CnSM2Collaborative3SignCStep1(InHashEFromA: TCnBigNumber; InQFromB: TCnEccPoint;
  OutRToBA, OutS1ToB, OutS2ToB: TCnBigNumber; PrivateKeyC: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
var
  SM2IsNil: Boolean;
  Inv, K1, RandKC: TCnBigNumber;
  P, Q: TCnEccPoint;
begin
  Result := False;
  if (PrivateKeyC = nil) or (InHashEFromA = nil) or (InQFromB = nil)  then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  K1 := nil;
  RandKC := nil;
  P := nil;
  Q := nil;
  Inv := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    K1 := TCnBigNumber.Create;
    RandKC := TCnBigNumber.Create;
    P := TCnEccPoint.Create;
    Q := TCnEccPoint.Create;
    Inv := TCnBigNumber.Create;

    while True do
    begin
      if not BigNumberRandRange(K1, SM2.Order) then
      begin
        _CnSetLastError(ECN_SM2_RANDOM_ERROR);
        Exit;
      end;
      if K1.IsZero then // ��һ���õ� 0���ͼ� 1
        K1.SetOne;

      Q.Assign(SM2.Generator);
      SM2.MultiplePoint(K1, Q); // �ȼ����һ���Լ��� Q ��

      // ������һ����� K
      if not BigNumberRandRange(RandKC, SM2.Order) then
      begin
        _CnSetLastError(ECN_SM2_RANDOM_ERROR);
        Exit;
      end;
      if RandKC.IsZero then // ��һ���õ� 0���ͼ� 1
        RandKC.SetOne;

      P.Assign(InQFromB);
      SM2.MultiplePoint(RandKC, P);   // �Է��� Q ������Լ��� RandKC������ KC �� A B �е� RandKA RandKB ��λ��ͬ
      SM2.PointAddPoint(P, Q, Q); // �ټ����Լ��� Q���õ���Ҫ�� Q

      // r = (Q.x + e) mod N
      BigNumberAddMod(OutRToBA, Q.X, InHashEFromA, SM2.Order);

      if OutRToBA.IsZero then                               // ע�⵽��Ϊֹ PrivateKeyC δ������
        Continue;

      BigNumberModularInverse(Inv, PrivateKeyC, SM2.Order);
      BigNumberDirectMulMod(OutS1ToB, Inv, RandKC, SM2.Order); // ��� S1 = RandKC / PrivateKeyC
      BigNumberAddMod(K1, K1, OutRToBA, SM2.Order);            // K1 + r
      BigNumberDirectMulMod(OutS2ToB, K1, Inv, SM2.Order);     // ��� S2 = K1 + r / PrivateKeyC

      Result := True;
      _CnSetLastError(ECN_SM2_OK);

      Break;
    end;
  finally
    Inv.Free;
    Q.Free;
    P.Free;
    RandKC.Free;
    K1.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  S1 = (kc * kb) / (dC * dB)  => A
  S2 = (k1 + r) / (dC * dB)   => A
}
function CnSM2Collaborative3SignBStep2(InRandKB, InRFromC, InS1FromC, InS2FromC: TCnBigNumber;
  OutS1ToA, OutS2ToA: TCnBigNumber; PrivateKeyB: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
var
  SM2IsNil: Boolean;
  Inv, K2: TCnBigNumber;
begin
  Result := False;
  if (PrivateKeyB = nil) or (InRandKB = nil) or (InRFromC = nil) or (InS1FromC = nil)
     or (InS2FromC = nil) or (OutS1ToA = nil) or (OutS2ToA = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  K2 := nil;
  Inv := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    K2 := TCnBigNumber.Create;
    Inv := TCnBigNumber.Create;

    // S1 = S1 * Kb / dB mod N
    BigNumberModularInverse(Inv, PrivateKeyB, SM2.Order);           // �õ� PrivateKeyB^-1
    BigNumberDirectMulMod(OutS1ToA, InS1FromC, Inv, SM2.Order);     // S1c / PrivateKeyB
    BigNumberDirectMulMod(OutS1ToA, OutS1ToA, InRandKB, SM2.Order); // (Kb * S1c) / PrivateKeyB

    // S2 := S2 / dB
    BigNumberDirectMulMod(OutS2ToA, InS2FromC, Inv, SM2.Order);     // S2 / PrivateKeyB

    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    Inv.Free;
    K2.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

{
  S1 = (kc * kb * ka) / (dC * dB * dA)
  S2 = (k1 + r) / (dC * dB * dA)

  S = S1 + S2 - r

  ��֤ S �Ĺ��������� P �ļ��㻯��
  Ϊ�򻯣��� k = (k1 + ka*kb*kc)  �� d = dA*dB*dC
  ��Ϊ P = [s +(r+s)(d-1)]*G
  ���� s = (k+r-dr)/d   �õ� s+r = (k+r)/d
  ��� P ��չ���õ������� k*G = (k1 + ka*kb*kc)*G
}
function CnSM2Collaborative3SignAStep2(InRandKA, InRFromC, InS1FromB, InS2FromB: TCnBigNumber;
  OutSignature: TCnSM2Signature; PrivateKeyA: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
var
  SM2IsNil: Boolean;
  Inv, S1, S2: TCnBigNumber;
begin
  Result := False;
  if (PrivateKeyA = nil) or (InRandKA = nil) or (InRFromC = nil) or (InS1FromB = nil)
    or (InS2FromB = nil) or (OutSignature = nil) then
  begin
    _CnSetLastError(ECN_SM2_INVALID_INPUT);
    Exit;
  end;

  S1 := nil;
  S2 := nil;
  Inv := nil;
  SM2IsNil := SM2 = nil;

  try
    if SM2IsNil then
      SM2 := TCnSM2.Create;

    S1 := TCnBigNumber.Create;
    S2 := TCnBigNumber.Create;
    Inv := TCnBigNumber.Create;

    // S1 = S1 * Ka / dA mod N
    BigNumberModularInverse(Inv, PrivateKeyA, SM2.Order);     // �õ� PrivateKeyA^-1
    BigNumberDirectMulMod(S1, InS1FromB, Inv, SM2.Order);     // S1b / PrivateKeyA
    BigNumberDirectMulMod(S1, S1, InRandKA, SM2.Order);       // (Ka * S1b) / PrivateKeyA

    // S2 := S2 / dA
    BigNumberDirectMulMod(S2, InS2FromB, Inv, SM2.Order);     // S2b / PrivateKeyB

    // S := S1 + S2 - R
    BigNumberAddMod(OutSignature.S, S1, S2, SM2.Order);
    BigNumberSubMod(OutSignature.S, OutSignature.S, InRFromC, SM2.Order);

    BigNumberCopy(OutSignature.R, InRFromC);                  // R S Ϊ����ǩ��
    Result := True;
    _CnSetLastError(ECN_SM2_OK);
  finally
    Inv.Free;
    S2.Free;
    S1.Free;
    if SM2IsNil then
      SM2.Free;
  end;
end;

// =========== SM2 ��Բ������������෽�������εļ���Эͬ�����㷨 ==============

function CnSM2Collaborative3DecryptAStep1(EnData: Pointer; DataByteLen: Integer;
  OutTToB: TCnEccPoint; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil): Boolean;
begin
  Result := CnSM2CollaborativeDecryptAStep1(EnData, DataByteLen, OutTToB, PrivateKeyA, SM2);
end;

function CnSM2Collaborative3DecryptBStep1(InTFromA: TCnEccPoint; OutTToC: TCnEccPoint;
  PrivateKeyB: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
begin
  Result := CnSM2CollaborativeDecryptBStep1(InTFromA, OutTToC, PrivateKeyB, SM2);
end;

function CnSM2Collaborative3DecryptCStep1(InTFromB: TCnEccPoint; OutTToA: TCnEccPoint;
  PrivateKeyC: TCnSM2CollaborativePrivateKey; SM2: TCnSM2 = nil): Boolean;
begin
  Result := CnSM2CollaborativeDecryptBStep1(InTFromB, OutTToA, PrivateKeyC, SM2);
end;

function CnSM2Collaborative3DecryptAStep2(EnData: Pointer; DataByteLen: Integer;
  InTFromC: TCnEccPoint; OutStream: TStream; PrivateKeyA: TCnSM2CollaborativePrivateKey;
  SM2: TCnSM2 = nil; SequenceType: TCnSM2CryptSequenceType = cstC1C3C2): Boolean;
begin
  Result := CnSM2CollaborativeDecryptAStep2(EnData, DataByteLen, InTFromC, OutStream,
    PrivateKeyA, SM2, SequenceType);
end;

procedure InitSM2;
begin
  FSM2AffineGPower2KList := TObjectList.Create(True);
  CheckPrePoints;
end;

procedure FintSM2;
begin
  FLocalSM2Generator.Free;
  FSM2AffinePreMatrix.Free;
  FSM2AffineGPower2KList.Free;
end;

initialization
  InitSM2;

finalization
  FintSM2;

end.

