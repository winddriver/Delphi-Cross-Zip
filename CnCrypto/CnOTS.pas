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

unit CnOTS;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�һ�����Ӵ�ǩ���㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
* ��    ע������Ԫʵ���˻��� SM3 �� SHA256 �� OTS/M-OTS/W-OTS һ�����Ӵ�ǩ���㷨
*           ��Hash Based One Time Signature�����������ȵ��Ӵ��㷨��δʵ�֡�
* ����ƽ̨��Win7 + Delphi 5.0
* ���ݲ��ԣ���δ����
* �� �� �����õ�Ԫ���豾�ػ�����
* �޸ļ�¼��2023.11.25 V1.0
*               ������Ԫ��ʵ�ֹ���
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative, CnBits, CnRandom, CnSM3, CnSHA2;

type

// ================ Lamport �����ĳ��� OTS����� SM3 �Ӵ��㷨 ==================

  TCnOTSSM3PrivateKey = array[0..(SizeOf(TCnSM3Digest) * 8 * 2) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨��һ�����Ӵ�ǩ��˽Կ��Ϊ 256 * 2 �����ֵ��Ϊһ��������������ֵ����ȡ SM3 �Ľ������}

  TCnOTSSM3PublicKey = array[0..(SizeOf(TCnSM3Digest) * 8 * 2) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨��һ�����Ӵ�ǩ����Կ��Ϊ 256 * 2 �����ֵ�� SM3 �Ӵ�ֵ}

  TCnOTSSM3Signature = array[0..(SizeOf(TCnSM3Digest) * 8) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨��һ�����Ӵ�ǩ��ֵ��ʵ������ 256 �� SM3 �Ӵ�ֵ}

  TCnOTSSM3VerificationKey = array[0..(SizeOf(TCnSM3Digest) * 8) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨��һ�����Ӵ�ǩ����֤��Կ��ʵ�����Ǵ�˽Կ�г�ȡ�� 256 �����ֵ}

// =============== Lamport �����ĳ��� OTS����� SHA256 �Ӵ��㷨 ================

  TCnOTSSHA256PrivateKey = array[0..(SizeOf(TCnSHA256Digest) * 8 * 2) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨��һ�����Ӵ�ǩ��˽Կ��Ϊ 256 * 2 �����ֵ��Ϊһ��������������ֵ����ȡ SHA256 �Ľ������}

  TCnOTSSHA256PublicKey = array[0..(SizeOf(TCnSHA256Digest) * 8 * 2) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨��һ�����Ӵ�ǩ����Կ��Ϊ 256 * 2 �����ֵ�� SHA256 �Ӵ�ֵ}

  TCnOTSSHA256Signature = array[0..(SizeOf(TCnSHA256Digest) * 8) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨��һ�����Ӵ�ǩ��ֵ��ʵ������ 256 �� SHA256 �Ӵ�ֵ}

  TCnOTSSHA256VerificationKey = array[0..(SizeOf(TCnSHA256Digest) * 8) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨��һ�����Ӵ�ǩ����֤��Կ��ʵ�����Ǵ�˽Կ�г�ȡ�� 256 �����ֵ}

// ========== Merkle ������ M-OTS��У�� 0 �ĸ�������� SM3 �Ӵ��㷨 ============

  TCnMOTSSM3PrivateKey = array[0..((SizeOf(TCnSM3Digest) + 1) * 8) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨�� M-OTS ˽Կ��Ϊ 256 �����ֵ����һ�����ֽ�У��ͣ�Ϊһ��������������ֵ����ȡ SM3 �Ľ������}

  TCnMOTSSM3PublicKey = array[0..((SizeOf(TCnSM3Digest)+ 1) * 8) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨�� M-OTS ��Կ��Ϊ 256 �����ֵ����һ�����ֽ�У��͵� SM3 �Ӵ�ֵ}

  TCnMOTSSM3Signature = array[0..((SizeOf(TCnSM3Digest) + 1) * 8) - 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨�� M-OTS ǩ����ʵ������ 256 �� SM3 �Ӵ�ֵ����һ�����ֽ�У��ͣ����� 0 ��Ӧȫ 0}

// ========== Merkle ������ M-OTS��У�� 0 �ĸ�������� SHA256 �Ӵ��㷨 ============

  TCnMOTSSHA256PrivateKey = array[0..((SizeOf(TCnSHA256Digest) + 1) * 8) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨�� M-OTS ˽Կ��Ϊ 256 �����ֵ����һ�����ֽ�У��ͣ�Ϊһ��������������ֵ����ȡ SHA256 �Ľ������}

  TCnMOTSSHA256PublicKey = array[0..((SizeOf(TCnSHA256Digest)+ 1) * 8) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨�� M-OTS ��Կ��Ϊ 256 �����ֵ����һ�����ֽ�У��͵� SHA256 �Ӵ�ֵ}

  TCnMOTSSHA256Signature = array[0..((SizeOf(TCnSHA256Digest) + 1) * 8) - 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨�� M-OTS ǩ����ʵ������ 256 �� SHA256 �Ӵ�ֵ����һ�����ֽ�У��ͣ����� 0 ��Ӧȫ 0}

// ===== Winternitz �Ľ��� W-OTS��ȡ n = 8 Ҳ�� 1 �ֽڣ���� SM3 �Ӵ��㷨 ======

  TCnWOTSSM3PrivateKey = array[0..SizeOf(TCnSM3Digest) + 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨�� W-OTS ˽Կ��Ϊ 32 �����ֵ����һ��˫�ֽ�У��ͣ�Ϊһ��������������ֵ����ȡ SM3 �Ľ������}

  TCnWOTSSM3PublicKey = array[0..SizeOf(TCnSM3Digest) + 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨�� W-OTS ��Կ��Ϊ 32 �����ֵ����һ��˫�ֽ�У��͸����� 256 �εõ��� SM3 �Ӵ�ֵ}

  TCnWOTSSM3Signature = array[0..SizeOf(TCnSM3Digest) + 1] of TCnSM3Digest;
  {* ���� SM3 �Ӵ��㷨�� W-OTS ǩ����Ϊ 32 �� SM3 �Ӵ�ֵ����һ��˫�ֽ�У��ͣ�ע��˫�ֽڰ�����˳��洢}

// ==== Winternitz �Ľ��� W-OTS��ȡ n = 8 Ҳ�� 1 �ֽڣ���� SHA256 �Ӵ��㷨 ====

  TCnWOTSSHA256PrivateKey = array[0..SizeOf(TCnSHA256Digest) + 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨�� W-OTS ˽Կ��Ϊ 32 �����ֵ����һ��˫�ֽ�У��ͣ�Ϊһ��������������ֵ����ȡ SHA256 �Ľ������}

  TCnWOTSSHA256PublicKey = array[0..SizeOf(TCnSHA256Digest) + 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨�� W-OTS ��Կ��Ϊ 32 �����ֵ����һ��˫�ֽ�У��͸����� 256 �εõ��� SHA256 �Ӵ�ֵ}

  TCnWOTSSHA256Signature = array[0..SizeOf(TCnSHA256Digest) + 1] of TCnSHA256Digest;
  {* ���� SHA256 �Ӵ��㷨�� W-OTS ǩ����Ϊ 32 �� SHA256 �Ӵ�ֵ����һ��˫�ֽ�У��ͣ�ע��˫�ֽڰ�����˳��洢}

// ================ Lamport �����ĳ��� OTS����� SM3 �Ӵ��㷨 ==================

function CnOTSSM3GenerateKeys(var PrivateKey: TCnOTSSM3PrivateKey;
  var PublicKey: TCnOTSSM3PublicKey): Boolean;
{* ����һ�Ի��� SM3 �Ӵ��㷨�� OTS һ�����Ӵ�ǩ����˽Կ�����������Ƿ�ɹ���

   ������
     var PrivateKey: TCnOTSSM3PrivateKey  - ���ɵĻ��� SM3 ��һ�����Ӵ�ǩ��˽Կ
     var PublicKey: TCnOTSSM3PublicKey    - ���ɵĻ��� SM3 ��һ�����Ӵ�ǩ����Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

procedure CnOTSSM3SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnOTSSM3PrivateKey; PublicKey: TCnOTSSM3PublicKey;
  var OutSignature: TCnOTSSM3Signature; var OutVerifyKey: TCnOTSSM3VerificationKey);
{* ���ݹ�˽Կ����ָ�����ݿ�� OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤��������֤��Կ��
   ��֤��Կʵ������˽Կ��һ���֣������֤��Կ�������ͬ��ֻ����֤��һ�Σ�
   ������������˽Կ�������Ϣǩ���ˣ�������һ����ǩ���ĺ��塣

   ������
     Data: Pointer                                        - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     PrivateKey: TCnOTSSM3PrivateKey                      - ����ǩ���Ļ��� SM3 ��һ�����Ӵ�ǩ��˽Կ
     PublicKey: TCnOTSSM3PublicKey                        - ����ǩ���Ļ��� SM3 ��һ�����Ӵ�ǩ����Կ
     var OutSignature: TCnOTSSM3Signature                 - �����ǩ��ֵ
     var OutVerifyKey: TCnOTSSM3VerificationKey           - �������֤��Կ

   ����ֵ�����ޣ�
}

function CnOTSSM3VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnOTSSM3Signature; PublicKey: TCnOTSSM3PublicKey;
  VerifyKey: TCnOTSSM3VerificationKey): Boolean;
{* �������ġ���������֤��Կ�빫Կ��ָ֤�����ݿ�� OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���
   ע��淶�� Signature δ������֤����ʹ�� VerifyKey ���С�

   ������
     Data: Pointer                        - ����֤���������ݿ��ַ
     DataByteLen: Integer                 - ����֤���������ݿ��ֽڳ���
     Signature: TCnOTSSM3Signature        - ����֤��ǩ��ֵ
     PublicKey: TCnOTSSM3PublicKey        - ������֤�Ļ��� SM3 ��һ�����Ӵ�ǩ����Կ
     VerifyKey: TCnOTSSM3VerificationKey  - ������֤����֤��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

procedure CnOTSSM3SignBytes(Data: TBytes; PrivateKey: TCnOTSSM3PrivateKey;
  PublicKey: TCnOTSSM3PublicKey; var OutSignature: TCnOTSSM3Signature;
  var OutVerifyKey: TCnOTSSM3VerificationKey);
{* ���ݹ�˽Կ�����ֽ������ OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤��������֤��Կ��
   ��֤��Կʵ������˽Կ��һ���֣������֤��Կ�������ͬ��ֻ����֤��һ�Σ�
   ������������˽Կ�������Ϣǩ���ˣ�������һ����ǩ���ĺ��塣

   ������
     Data: TBytes                                         - ��ǩ���������ֽ�����
     PrivateKey: TCnOTSSM3PrivateKey                      - ����ǩ���Ļ��� SM3 ��һ�����Ӵ�ǩ��˽Կ
     PublicKey: TCnOTSSM3PublicKey                        - ����ǩ���Ļ��� SM3 ��һ�����Ӵ�ǩ����Կ
     var OutSignature: TCnOTSSM3Signature                 - �����ǩ��ֵ
     var OutVerifyKey: TCnOTSSM3VerificationKey           - �������֤��Կ

   ����ֵ�����ޣ�
}

function CnOTSSM3VerifyBytes(Data: TBytes; Signature: TCnOTSSM3Signature;
  PublicKey: TCnOTSSM3PublicKey; VerifyKey: TCnOTSSM3VerificationKey): Boolean;
{* �������ġ���������֤��Կ�빫Կ��֤�ֽ������ OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���
   ע��淶�� Signature δ������֤����ʹ�� VerifyKey ���С�

   ������
     Data: TBytes                         - ����֤�������ֽ�����
     Signature: TCnOTSSM3Signature        - ����֤��ǩ��ֵ
     PublicKey: TCnOTSSM3PublicKey        - ������֤�Ļ��� SM3 ��һ�����Ӵ�ǩ����Կ
     VerifyKey: TCnOTSSM3VerificationKey  - ������֤����֤��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

// =============== Lamport �����ĳ��� OTS����� SHA256 �Ӵ��㷨 ================

function CnOTSSHA256GenerateKeys(var PrivateKey: TCnOTSSHA256PrivateKey;
  var PublicKey: TCnOTSSHA256PublicKey): Boolean;
{* ����һ�Ի��� SHA256 �Ӵ��㷨�� OTS һ�����Ӵ�ǩ����˽Կ�����������Ƿ�ɹ���

   ������
     var PrivateKey: TCnOTSSHA256PrivateKey               - ���ɵĻ��� SHA256 ��һ�����Ӵ�ǩ��˽Կ
     var PublicKey: TCnOTSSHA256PublicKey                 - ���ɵĻ��� SHA256 ��һ�����Ӵ�ǩ����Կ

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

procedure CnOTSSHA256SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnOTSSHA256PrivateKey; PublicKey: TCnOTSSHA256PublicKey;
  var OutSignature: TCnOTSSHA256Signature; var OutVerifyKey: TCnOTSSHA256VerificationKey);
{* ���ݹ�˽Կ����ָ�����ݿ�� OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤��������֤��Կ��
   ��֤��Կʵ������˽Կ��һ���֣������֤��Կ�������ͬ��ֻ����֤��һ�Σ�
   ������������˽Կ�������Ϣǩ���ˣ�������һ����ǩ���ĺ��塣

   ������
     Data: Pointer                                        - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     PrivateKey: TCnOTSSHA256PrivateKey                   - ����ǩ���Ļ��� SHA256 ��һ�����Ӵ�ǩ��˽Կ
     PublicKey: TCnOTSSHA256PublicKey                     - ����ǩ���Ļ��� SHA256 ��һ�����Ӵ�ǩ����Կ
     var OutSignature: TCnOTSSHA256Signature              - �����ǩ��ֵ
     var OutVerifyKey: TCnOTSSHA256VerificationKey        - �������֤��Կ

   ����ֵ�����ޣ�
}

function CnOTSSHA256VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnOTSSHA256Signature; PublicKey: TCnOTSSHA256PublicKey;
  VerifyKey: TCnOTSSHA256VerificationKey): Boolean;
{* �������ġ���������֤��Կ�빫Կ��ָ֤�����ݿ�� OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���
   ע��淶�� Signature δ������֤����ʹ�� VerifyKey ���С�

   ������
     Data: Pointer                                        - ����֤���������ݿ��ַ
     DataByteLen: Integer                                 - ����֤���������ݿ��ֽڳ���
     Signature: TCnOTSSHA256Signature                     - ����֤��ǩ��ֵ
     PublicKey: TCnOTSSHA256PublicKey                     - ������֤�Ļ��� SHA256 ��һ�����Ӵ�ǩ����Կ
     VerifyKey: TCnOTSSHA256VerificationKey               - ������֤����֤��Կ

   ����ֵ��Boolean                                        - ������֤ǩ���Ƿ�ɹ�
}

procedure CnOTSSHA256SignBytes(Data: TBytes; PrivateKey: TCnOTSSHA256PrivateKey;
  PublicKey: TCnOTSSHA256PublicKey; var OutSignature: TCnOTSSHA256Signature;
  var OutVerifyKey: TCnOTSSHA256VerificationKey);
{* ���ݹ�˽Կ�����ֽ������ OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤��������֤��Կ��
   ��֤��Կʵ������˽Կ��һ���֣������֤��Կ�������ͬ��ֻ����֤��һ�Σ�
   ������������˽Կ�������Ϣǩ���ˣ�������һ����ǩ���ĺ��塣

   ������
     Data: TBytes                                         - ��ǩ���������ֽ�����
     PrivateKey: TCnOTSSHA256PrivateKey                   - ����ǩ���Ļ��� SHA256 ��һ�����Ӵ�ǩ��˽Կ
     PublicKey: TCnOTSSHA256PublicKey                     - ����ǩ���Ļ��� SHA256 ��һ�����Ӵ�ǩ����Կ
     var OutSignature: TCnOTSSHA256Signature              - �����ǩ��ֵ
     var OutVerifyKey: TCnOTSSHA256VerificationKey        - �������֤��Կ

   ����ֵ�����ޣ�
}

function CnOTSSHA256VerifyBytes(Data: TBytes; Signature: TCnOTSSHA256Signature;
  PublicKey: TCnOTSSHA256PublicKey; VerifyKey: TCnOTSSHA256VerificationKey): Boolean;
{* �������ġ���������֤��Կ�빫Կ��֤�ֽ������ OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ�
   ע��淶�� Signature δ������֤����ʹ�� VerifyKey ���С�

   ������
     Data: TBytes                                         - ����֤�������ֽ�����
     Signature: TCnOTSSHA256Signature                     - ����֤��ǩ��ֵ
     PublicKey: TCnOTSSHA256PublicKey                     - ������֤�Ļ��� SHA256 ��һ�����Ӵ�ǩ����Կ
     VerifyKey: TCnOTSSHA256VerificationKey               - ������֤����֤��Կ

   ����ֵ��Boolean                                        - ������֤ǩ���Ƿ�ɹ�
}

// ========== Merkle �Ľ��� M-OTS��У�� 0 �ĸ�������� SM3 �Ӵ��㷨 ============

function CnMOTSSM3GenerateKeys(var PrivateKey: TCnMOTSSM3PrivateKey;
  var PublicKey: TCnMOTSSM3PublicKey): Boolean;
{* ����һ�Ի��� SM3 �Ӵ��㷨�� M-OTS ��˽Կ�����������Ƿ�ɹ�

   ������
     var PrivateKey: TCnMOTSSM3PrivateKey - ���� SM3 �Ӵ��㷨�� M-OTS ˽Կ
     var PublicKey: TCnMOTSSM3PublicKey   - ���� SM3 �Ӵ��㷨�� M-OTS ��Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

procedure CnMOTSSM3SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnMOTSSM3PrivateKey; var OutSignature: TCnMOTSSM3Signature);
{* ����˽Կ����ָ�����ݿ�� M-OTS һ�����Ӵ�ǩ����
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤������˽Կ��

   ������
     Data: Pointer                                        - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     PrivateKey: TCnMOTSSM3PrivateKey                     - ����ǩ���Ļ��� SM3 �� M-OTS ˽Կ
     var OutSignature: TCnMOTSSM3Signature                - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnMOTSSM3VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnMOTSSM3Signature; PublicKey: TCnMOTSSM3PublicKey): Boolean;
{* ���������빫Կ��ָ֤�����ݿ�� M-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: Pointer                        - ����֤���������ݿ��ַ
     DataByteLen: Integer                 - ����֤���������ݿ��ֽڳ���
     Signature: TCnMOTSSM3Signature       - ����֤��ǩ��ֵ
     PublicKey: TCnMOTSSM3PublicKey       - ������֤�Ļ��� SM3 �� M-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

procedure CnMOTSSM3SignBytes(Data: TBytes; PrivateKey: TCnMOTSSM3PrivateKey;
  var OutSignature: TCnMOTSSM3Signature);
{* ����˽Կ�����ֽ������ M-OTS һ�����Ӵ�ǩ����
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤������˽Կ��

   ������
     Data: TBytes                                         - ��ǩ���������ֽ�����
     PrivateKey: TCnMOTSSM3PrivateKey                     - ����ǩ���Ļ��� SM3 �� M-OTS ˽Կ
     var OutSignature: TCnMOTSSM3Signature                - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnMOTSSM3VerifyBytes(Data: TBytes; Signature: TCnMOTSSM3Signature;
  PublicKey: TCnMOTSSM3PublicKey): Boolean;
{* ���������빫Կ��֤�ֽ������ M-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: TBytes                         - ����֤�������ֽ�����
     Signature: TCnMOTSSM3Signature       - ����֤��ǩ��ֵ
     PublicKey: TCnMOTSSM3PublicKey       - ������֤�Ļ��� SM3 �� M-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

// ========== Merkle �Ľ��� M-OTS��У�� 0 �ĸ�������� SHA256 �Ӵ��㷨 ============

function CnMOTSSHA256GenerateKeys(var PrivateKey: TCnMOTSSHA256PrivateKey;
  var PublicKey: TCnMOTSSHA256PublicKey): Boolean;
{* ����һ�Ի��� SHA256 �Ӵ��㷨�� M-OTS ǩ����˽Կ�����������Ƿ�ɹ���

   ������
     var PrivateKey: TCnMOTSSHA256PrivateKey              - ���� SHA256 �Ӵ��㷨�� M-OTS ˽Կ
     var PublicKey: TCnMOTSSHA256PublicKey                - ���� SHA256 �Ӵ��㷨�� M-OTS ��Կ

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

procedure CnMOTSSHA256SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnMOTSSHA256PrivateKey; var OutSignature: TCnMOTSSHA256Signature);
{* ����˽Կ����ָ�����ݿ�� M-OTS һ�����Ӵ�ǩ����
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤������˽Կ��

   ������
     Data: Pointer                                        - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     PrivateKey: TCnMOTSSHA256PrivateKey                  - ����ǩ���Ļ��� SHA256 �Ӵ��㷨�� M-OTS ˽Կ
     var OutSignature: TCnMOTSSHA256Signature             - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnMOTSSHA256VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnMOTSSHA256Signature; PublicKey: TCnMOTSSHA256PublicKey): Boolean;
{* ���������빫Կ��ָ֤�����ݿ�� M-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ�

   ������
     Data: Pointer                        - ����֤���������ݿ��ַ
     DataByteLen: Integer                 - ����֤���������ݿ��ֽڳ���
     Signature: TCnMOTSSHA256Signature    - ����֤��ǩ��ֵ
     PublicKey: TCnMOTSSHA256PublicKey    - ������֤�Ļ��� SHA256 �Ӵ��㷨�� M-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

procedure CnMOTSSHA256SignBytes(Data: TBytes; PrivateKey: TCnMOTSSHA256PrivateKey;
  var OutSignature: TCnMOTSSHA256Signature);
{* ����˽Կ�����ֽ������ M-OTS һ�����Ӵ�ǩ����
   ƽʱ�������ġ�ǩ��ֵ�빫Կ������֤����ʱ������֤������˽Կ��

   ������
     Data: TBytes                                         - ��ǩ���������ֽ�����
     PrivateKey: TCnMOTSSHA256PrivateKey                  - ����ǩ���Ļ��� SHA256 �Ӵ��㷨�� M-OTS ˽Կ
     var OutSignature: TCnMOTSSHA256Signature             - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnMOTSSHA256VerifyBytes(Data: TBytes; Signature: TCnMOTSSHA256Signature;
  PublicKey: TCnMOTSSHA256PublicKey): Boolean;
{* ���������빫Կ��֤�ֽ������ M-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: TBytes                         - ����֤�������ֽ�����
     Signature: TCnMOTSSHA256Signature    - ����֤��ǩ��ֵ
     PublicKey: TCnMOTSSHA256PublicKey    - ������֤�Ļ��� SHA256 �Ӵ��㷨�� M-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

// ===== Winternitz �Ľ��� W-OTS��ȡ n = 8 Ҳ�� 1 �ֽڣ���� SM3 �Ӵ��㷨 ======

function CnWOTSSM3GenerateKeys(var PrivateKey: TCnWOTSSM3PrivateKey;
  var PublicKey: TCnWOTSSM3PublicKey): Boolean;
{* ����һ�Ի��� SM3 �Ӵ��㷨�� W-OTS һ�����Ӵ�ǩ����˽Կ�����������Ƿ�ɹ���

   ������
     var PrivateKey: TCnWOTSSM3PrivateKey - ���� SM3 �Ӵ��㷨�� W-OTS ˽Կ
     var PublicKey: TCnWOTSSM3PublicKey   - ���� SM3 �Ӵ��㷨�� W-OTS ��Կ

   ����ֵ��Boolean                        - ���������Ƿ�ɹ�
}

procedure CnWOTSSM3SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnWOTSSM3PrivateKey; var OutSignature: TCnWOTSSM3Signature);
{* ����˽Կ����ָ�����ݿ�� W-OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ������֤����ʱ������֤��������Կ��

   ������
     Data: Pointer                                        - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     PrivateKey: TCnWOTSSM3PrivateKey                     - ����ǩ���Ļ��� SM3 �Ӵ��㷨�� W-OTS ˽Կ
     var OutSignature: TCnWOTSSM3Signature                - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnWOTSSM3VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnWOTSSM3Signature; PublicKey: TCnWOTSSM3PublicKey): Boolean;
{* �������ġ������Ĺ�Կ��ָ֤�����ݿ�� W-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: Pointer                        - ����֤���������ݿ��ַ
     DataByteLen: Integer                 - ����֤���������ݿ��ֽڳ���
     Signature: TCnWOTSSM3Signature       - ����֤��ǩ��ֵ
     PublicKey: TCnWOTSSM3PublicKey       - ������֤�Ļ��� SM3 �Ӵ��㷨�� W-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

procedure CnWOTSSM3SignBytes(Data: TBytes; PrivateKey: TCnWOTSSM3PrivateKey;
  var OutSignature: TCnWOTSSM3Signature);
{* ����˽Կ�����ֽ������ W-OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ������֤����ʱ������֤��������Կ��

   ������
     Data: TBytes                                         - ��ǩ���������ֽ�����
     PrivateKey: TCnWOTSSM3PrivateKey                     - ����ǩ���Ļ��� SM3 �Ӵ��㷨�� W-OTS ˽Կ
     var OutSignature: TCnWOTSSM3Signature                - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnWOTSSM3VerifyBytes(Data: TBytes; Signature: TCnWOTSSM3Signature;
  PublicKey: TCnWOTSSM3PublicKey): Boolean;
{* �������ġ������Ĺ�Կ��ָ֤�����ݿ�� W-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: TBytes                         - ����֤�������ֽ�����
     Signature: TCnWOTSSM3Signature       - ����֤��ǩ��ֵ
     PublicKey: TCnWOTSSM3PublicKey       - ������֤�Ļ��� SM3 �Ӵ��㷨�� W-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

// ==== Winternitz �Ľ��� W-OTS��ȡ n = 8 Ҳ�� 1 �ֽڣ���� SHA256 �Ӵ��㷨 ====

function CnWOTSSHA256GenerateKeys(var PrivateKey: TCnWOTSSHA256PrivateKey;
  var PublicKey: TCnWOTSSHA256PublicKey): Boolean;
{* ����һ�Ի��� SHA256 �Ӵ��㷨�� W-OTS һ�����Ӵ�ǩ����˽Կ�����������Ƿ�ɹ���

   ������
     var PrivateKey: TCnWOTSSHA256PrivateKey              - ���� SHA256 �Ӵ��㷨�� W-OTS ˽Կ
     var PublicKey: TCnWOTSSHA256PublicKey                - ���� SHA256 �Ӵ��㷨�� W-OTS ��Կ

   ����ֵ��Boolean                                        - ���������Ƿ�ɹ�
}

procedure CnWOTSSHA256SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnWOTSSHA256PrivateKey; var OutSignature: TCnWOTSSHA256Signature);
{* ����˽Կ����ָ�����ݿ�� W-OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ������֤����ʱ������֤��������Կ��

   ������
     Data: Pointer                                        - ��ǩ�����������ݿ��ַ
     DataByteLen: Integer                                 - ��ǩ�����������ݿ��ֽڳ���
     PrivateKey: TCnWOTSSHA256PrivateKey                  - ����ǩ���Ļ��� SHA256 �Ӵ��㷨�� W-OTS ˽Կ
     var OutSignature: TCnWOTSSHA256Signature             - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnWOTSSHA256VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnWOTSSHA256Signature; PublicKey: TCnWOTSSHA256PublicKey): Boolean;
{* �������ġ������Ĺ�Կ��ָ֤�����ݿ�� W-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: Pointer                        - ����֤���������ݿ��ַ
     DataByteLen: Integer                 - ����֤���������ݿ��ֽڳ���
     Signature: TCnWOTSSHA256Signature    - ������֤�Ļ��� SHA256 �Ӵ��㷨�� W-OTS ��Կ
     PublicKey: TCnWOTSSHA256PublicKey    - ����֤��ǩ��ֵ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

procedure CnWOTSSHA256SignBytes(Data: TBytes; PrivateKey: TCnWOTSSHA256PrivateKey;
  var OutSignature: TCnWOTSSHA256Signature);
{* ����˽Կ�����ֽ������ W-OTS һ�����Ӵ�ǩ������֤���ǩ������Կ��
   ƽʱ�������ġ�ǩ��ֵ������֤����ʱ������֤��������Կ��

   ������
     Data: TBytes                                         - ��ǩ���������ֽ�����
     PrivateKey: TCnWOTSSHA256PrivateKey                  - ����ǩ���Ļ��� SHA256 �Ӵ��㷨�� W-OTS ˽Կ
     var OutSignature: TCnWOTSSHA256Signature             - �����ǩ��ֵ

   ����ֵ�����ޣ�
}

function CnWOTSSHA256VerifyBytes(Data: TBytes; Signature: TCnWOTSSHA256Signature;
  PublicKey: TCnWOTSSHA256PublicKey): Boolean;
{* �������ġ������Ĺ�Կ��ָ֤�����ݿ�� W-OTS ǩ���Ƿ���ȷ��������֤�Ƿ�ɹ���

   ������
     Data: TBytes                         - ����֤�������ֽ�����
     Signature: TCnWOTSSHA256Signature    - ����֤��ǩ��ֵ
     PublicKey: TCnWOTSSHA256PublicKey    - ������֤�Ļ��� SHA256 �Ӵ��㷨�� W-OTS ��Կ

   ����ֵ��Boolean                        - ������֤ǩ���Ƿ�ɹ�
}

implementation

const
  CN_WOTS_ROUND = 256;

function CnOTSSM3GenerateKeys(var PrivateKey: TCnOTSSM3PrivateKey;
  var PublicKey: TCnOTSSM3PublicKey): Boolean;
var
  I: Integer;
begin
  Result := CnRandomFillBytes(@PrivateKey[0], SizeOf(TCnOTSSM3PrivateKey));
  if Result then
    for I := Low(TCnOTSSM3PublicKey) to High(TCnOTSSM3PublicKey) do
      PublicKey[I] := SM3(@PrivateKey[I], SizeOf(TCnSM3Digest));
end;

procedure CnOTSSM3SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnOTSSM3PrivateKey; PublicKey: TCnOTSSM3PublicKey;
  var OutSignature: TCnOTSSM3Signature; var OutVerifyKey: TCnOTSSM3VerificationKey);
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig: TCnSM3Digest;
begin
  Dig := SM3(PAnsiChar(Data), DataByteLen);
  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSM3Digest));

    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // �� 1
      begin
        OutSignature[I] := PublicKey[I * 2 + 1];
        OutVerifyKey[I] := PrivateKey[I * 2 + 1];
      end
      else
      begin
        OutSignature[I] := PublicKey[I * 2];
        OutVerifyKey[I] := PrivateKey[I * 2];
      end;
    end;
  finally
    Bits.Free;
  end;
end;

function CnOTSSM3VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnOTSSM3Signature; PublicKey: TCnOTSSM3PublicKey;
  VerifyKey: TCnOTSSM3VerificationKey): Boolean;
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig, Cmp: TCnSM3Digest;
begin
  Result := False;
  Dig := SM3(PAnsiChar(Data), DataByteLen);
  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSM3Digest));

    for I := 0 to Bits.BitLength - 1 do
    begin
      Cmp := SM3(@VerifyKey[I], SizeOf(TCnSM3Digest)); // ����˽Կ���Ӵ�ֵ
      if Bits.Bit[I] then 
        Result := SM3Match(Cmp, PublicKey[I * 2 + 1])  // ��λ�� 1���Ƚ� 1 ��Ӧ�Ĺ�Կ
      else
        Result := SM3Match(Cmp, PublicKey[I * 2]);     // ��λ�� 0���Ƚ� 0 ��Ӧ�Ĺ�Կ

      if not Result then
        Exit;
    end;
  finally
    Bits.Free;
  end;
end;

procedure CnOTSSM3SignBytes(Data: TBytes; PrivateKey: TCnOTSSM3PrivateKey;
  PublicKey: TCnOTSSM3PublicKey; var OutSignature: TCnOTSSM3Signature;
  var OutVerifyKey: TCnOTSSM3VerificationKey);
begin
  if Length(Data) = 0 then
    CnOTSSM3SignData(nil, 0, PrivateKey, PublicKey, OutSignature, OutVerifyKey)
  else
    CnOTSSM3SignData(@Data[0], Length(Data), PrivateKey, PublicKey, OutSignature, OutVerifyKey);
end;

function CnOTSSM3VerifyBytes(Data: TBytes; Signature: TCnOTSSM3Signature;
  PublicKey: TCnOTSSM3PublicKey; VerifyKey: TCnOTSSM3VerificationKey): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnOTSSM3VerifyData(nil, 0, Signature, PublicKey, VerifyKey)
  else
    Result := CnOTSSM3VerifyData(@Data[0], Length(Data), Signature, PublicKey, VerifyKey);
end;

function CnOTSSHA256GenerateKeys(var PrivateKey: TCnOTSSHA256PrivateKey;
  var PublicKey: TCnOTSSHA256PublicKey): Boolean;
var
  I: Integer;
  P: Pointer;
begin
  Result := CnRandomFillBytes(@PrivateKey[0], SizeOf(TCnOTSSHA256PrivateKey));
  if Result then
  begin
    for I := Low(TCnOTSSHA256PublicKey) to High(TCnOTSSHA256PublicKey) do
    begin
      P := @PrivateKey[I];
      PublicKey[I] := SHA256Buffer(P, SizeOf(TCnSHA256Digest));
    end;
  end;
end;

procedure CnOTSSHA256SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnOTSSHA256PrivateKey; PublicKey: TCnOTSSHA256PublicKey;
  var OutSignature: TCnOTSSHA256Signature; var OutVerifyKey: TCnOTSSHA256VerificationKey);
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig: TCnSHA256Digest;
begin
  Dig := SHA256Buffer(PAnsiChar(Data), DataByteLen);
  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSHA256Digest));

    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // �� 1
      begin
        OutSignature[I] := PublicKey[I * 2 + 1];
        OutVerifyKey[I] := PrivateKey[I * 2 + 1];
      end
      else
      begin
        OutSignature[I] := PublicKey[I * 2];
        OutVerifyKey[I] := PrivateKey[I * 2];
      end;
    end;
  finally
    Bits.Free;
  end;
end;

function CnOTSSHA256VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnOTSSHA256Signature; PublicKey: TCnOTSSHA256PublicKey;
  VerifyKey: TCnOTSSHA256VerificationKey): Boolean;
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig, Cmp: TCnSHA256Digest;
  P: Pointer;
begin
  Result := False;
  Dig := SHA256Buffer(PAnsiChar(Data), DataByteLen);
  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSHA256Digest));

    for I := 0 to Bits.BitLength - 1 do
    begin
      P := @VerifyKey[I];
      Cmp := SHA256Buffer(P, SizeOf(TCnSHA256Digest));    // ����˽Կ���Ӵ�ֵ
      if Bits.Bit[I] then 
        Result := SHA256Match(Cmp, PublicKey[I * 2 + 1])  // ��λ�� 1���Ƚ� 1 ��Ӧ�Ĺ�Կ
      else
        Result := SHA256Match(Cmp, PublicKey[I * 2]);     // ��λ�� 0���Ƚ� 0 ��Ӧ�Ĺ�Կ

      if not Result then
        Exit;
    end;
  finally
    Bits.Free;
  end;
end;

procedure CnOTSSHA256SignBytes(Data: TBytes; PrivateKey: TCnOTSSHA256PrivateKey;
  PublicKey: TCnOTSSHA256PublicKey; var OutSignature: TCnOTSSHA256Signature;
  var OutVerifyKey: TCnOTSSHA256VerificationKey);
begin
  if Length(Data) = 0 then
    CnOTSSHA256SignData(nil, 0, PrivateKey, PublicKey, OutSignature, OutVerifyKey)
  else
    CnOTSSHA256SignData(@Data[0], Length(Data), PrivateKey, PublicKey, OutSignature, OutVerifyKey);
end;

function CnOTSSHA256VerifyBytes(Data: TBytes; Signature: TCnOTSSHA256Signature;
  PublicKey: TCnOTSSHA256PublicKey; VerifyKey: TCnOTSSHA256VerificationKey): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnOTSSHA256VerifyData(nil, 0, Signature, PublicKey, VerifyKey)
  else
    Result := CnOTSSHA256VerifyData(@Data[0], Length(Data), Signature, PublicKey, VerifyKey);
end;

function CnMOTSSM3GenerateKeys(var PrivateKey: TCnMOTSSM3PrivateKey;
  var PublicKey: TCnMOTSSM3PublicKey): Boolean;
var
  I: Integer;
begin
  Result := CnRandomFillBytes(@PrivateKey[0], SizeOf(TCnMOTSSM3PrivateKey));
  if Result then
    for I := Low(TCnMOTSSM3PublicKey) to High(TCnMOTSSM3PublicKey) do
      PublicKey[I] := SM3(@PrivateKey[I], SizeOf(TCnSM3Digest));
end;

procedure CnMOTSSM3SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnMOTSSM3PrivateKey; var OutSignature: TCnMOTSSM3Signature);
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig: TCnSM3Digest;
  Cnt: Byte;
begin
  FillChar(OutSignature[0], SizeOf(TCnMOTSSM3Signature), 0);
  Dig := SM3(PAnsiChar(Data), DataByteLen);

  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSM3Digest));

    Cnt := 0;
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // �Ӵ�ֵ�Ķ�Ӧλ�� 1��ǩ����˽Կ
        OutSignature[I] := PrivateKey[I]
      else
        Inc(Cnt);         // �Ӵղ���ȫ 0 ���Բ������
    end;

    Bits.Clear;
    Bits.AppendByte(Cnt);
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // У��͵Ķ�Ӧλ�� 1��ǩ��������˽Կ
        OutSignature[(SizeOf(TCnSM3Digest) * 8) + I] := PrivateKey[(SizeOf(TCnSM3Digest) * 8) + I];
    end;
  finally
    Bits.Free;
  end;
end;

function CnMOTSSM3VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnMOTSSM3Signature; PublicKey: TCnMOTSSM3PublicKey): Boolean;
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig, Zero, Cmp: TCnSM3Digest;
  Cnt: Byte;
begin
  Result := False;
  FillChar(Zero[0], SizeOf(TCnSM3Digest), 0);
  Dig := SM3(PAnsiChar(Data), DataByteLen);

  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSM3Digest));

    Cnt := 0;
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // �Ӵ�ֵ�Ķ�Ӧλ�� 1��ǩ����˽Կ���Ӵ���֤
      begin
        Cmp := SM3(@Signature[I], SizeOf(TCnSM3Digest)); // ����˽Կ���Ӵ�ֵ
        if not SM3Match(Cmp, PublicKey[I]) then
          Exit;
      end
      else
      begin
        if not SM3Match(Signature[I], Zero) then         // ��Ӧλ 0 �ñ�֤ȫ 0
          Exit;
        Inc(Cnt);         // �Ӵղ���ȫ 0 ���Բ������
      end;
    end;

    Bits.Clear;
    Bits.AppendByte(Cnt);
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // У��͵Ķ�Ӧλ�� 1��ǩ��������˽Կ���Ӵ���֤
      begin
        Cmp := SM3(@Signature[(SizeOf(TCnSM3Digest) * 8) + I], SizeOf(TCnSM3Digest));
        if not SM3Match(Cmp, PublicKey[(SizeOf(TCnSM3Digest) * 8) + I]) then
          Exit;
      end
      else
      begin
        if not SM3Match(Signature[(SizeOf(TCnSM3Digest) * 8) + I], Zero) then         // ��Ӧλ 0 �ñ�֤ȫ 0
          Exit;
      end;
    end;
    Result := True;
  finally
    Bits.Free;
  end;
end;

procedure CnMOTSSM3SignBytes(Data: TBytes; PrivateKey: TCnMOTSSM3PrivateKey;
  var OutSignature: TCnMOTSSM3Signature);
begin
  if Length(Data) = 0 then
    CnMOTSSM3SignData(nil, 0, PrivateKey, OutSignature)
  else
    CnMOTSSM3SignData(@Data[0], Length(Data), PrivateKey, OutSignature);
end;

function CnMOTSSM3VerifyBytes(Data: TBytes; Signature: TCnMOTSSM3Signature;
  PublicKey: TCnMOTSSM3PublicKey): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnMOTSSM3VerifyData(nil, 0, Signature, PublicKey)
  else
    Result := CnMOTSSM3VerifyData(@Data[0], Length(Data), Signature, PublicKey);
end;

function CnMOTSSHA256GenerateKeys(var PrivateKey: TCnMOTSSHA256PrivateKey;
  var PublicKey: TCnMOTSSHA256PublicKey): Boolean;
var
  I: Integer;
  P: Pointer;
begin
  Result := CnRandomFillBytes(@PrivateKey[0], SizeOf(TCnMOTSSHA256PrivateKey));
  if Result then
  begin
    for I := Low(TCnMOTSSHA256PublicKey) to High(TCnMOTSSHA256PublicKey) do
    begin
      P := @PrivateKey[I];
      PublicKey[I] := SHA256Buffer(P, SizeOf(TCnSHA256Digest));
    end;
  end;
end;

procedure CnMOTSSHA256SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnMOTSSHA256PrivateKey; var OutSignature: TCnMOTSSHA256Signature);
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig: TCnSHA256Digest;
  Cnt: Byte;
begin
  FillChar(OutSignature[0], SizeOf(TCnMOTSSHA256Signature), 0);
  Dig := SHA256Buffer(PAnsiChar(Data), DataByteLen);

  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSHA256Digest));

    Cnt := 0;
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // �Ӵ�ֵ�Ķ�Ӧλ�� 1��ǩ����˽Կ
        OutSignature[I] := PrivateKey[I]
      else
        Inc(Cnt);         // �Ӵղ���ȫ 0 ���Բ������
    end;

    Bits.Clear;
    Bits.AppendByte(Cnt);
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // У��͵Ķ�Ӧλ�� 1��ǩ��������˽Կ
        OutSignature[(SizeOf(TCnSHA256Digest) * 8) + I] := PrivateKey[(SizeOf(TCnSHA256Digest) * 8) + I];
    end;
  finally
    Bits.Free;
  end;
end;

function CnMOTSSHA256VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnMOTSSHA256Signature; PublicKey: TCnMOTSSHA256PublicKey): Boolean;
var
  I: Integer;
  Bits: TCnBitBuilder;
  Dig, Zero, Cmp: TCnSHA256Digest;
  Cnt: Byte;
  P: Pointer;
begin
  Result := False;
  FillChar(Zero[0], SizeOf(TCnSHA256Digest), 0);
  Dig := SHA256Buffer(PAnsiChar(Data), DataByteLen);

  Bits := TCnBitBuilder.Create;
  try
    Bits.AppendData(@Dig[0], SizeOf(TCnSHA256Digest));

    Cnt := 0;
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // �Ӵ�ֵ�Ķ�Ӧλ�� 1��ǩ����˽Կ���Ӵ���֤
      begin
        P := @Signature[I];
        Cmp := SHA256Buffer(P, SizeOf(TCnSHA256Digest)); // ����˽Կ���Ӵ�ֵ
        if not SHA256Match(Cmp, PublicKey[I]) then
          Exit;
      end
      else
      begin
        if not SHA256Match(Signature[I], Zero) then         // ��Ӧλ 0 �ñ�֤ȫ 0
          Exit;
        Inc(Cnt);         // �Ӵղ���ȫ 0 ���Բ������
      end;
    end;

    Bits.Clear;
    Bits.AppendByte(Cnt);
    for I := 0 to Bits.BitLength - 1 do
    begin
      if Bits.Bit[I] then // У��͵Ķ�Ӧλ�� 1��ǩ��������˽Կ���Ӵ���֤
      begin
        P := @Signature[(SizeOf(TCnSHA256Digest) * 8) + I];
        Cmp := SHA256Buffer(P, SizeOf(TCnSHA256Digest));
        if not SHA256Match(Cmp, PublicKey[(SizeOf(TCnSHA256Digest) * 8) + I]) then
          Exit;
      end
      else
      begin
        if not SHA256Match(Signature[(SizeOf(TCnSHA256Digest) * 8) + I], Zero) then         // ��Ӧλ 0 �ñ�֤ȫ 0
          Exit;
      end;
    end;
    Result := True;
  finally
    Bits.Free;
  end;
end;

procedure CnMOTSSHA256SignBytes(Data: TBytes; PrivateKey: TCnMOTSSHA256PrivateKey;
  var OutSignature: TCnMOTSSHA256Signature);
begin
  if Length(Data) = 0 then
    CnMOTSSHA256SignData(nil, 0, PrivateKey, OutSignature)
  else
    CnMOTSSHA256SignData(@Data[0], Length(Data), PrivateKey, OutSignature);
end;

function CnMOTSSHA256VerifyBytes(Data: TBytes; Signature: TCnMOTSSHA256Signature;
  PublicKey: TCnMOTSSHA256PublicKey): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnMOTSSHA256VerifyData(nil, 0, Signature, PublicKey)
  else
    Result := CnMOTSSHA256VerifyData(@Data[0], Length(Data), Signature, PublicKey);
end;

function CnWOTSSM3GenerateKeys(var PrivateKey: TCnWOTSSM3PrivateKey;
  var PublicKey: TCnWOTSSM3PublicKey): Boolean;
var
  I, J: Integer;
  Dig: TCnSM3Digest;
begin
  Result := CnRandomFillBytes(@PrivateKey[0], SizeOf(TCnWOTSSM3PrivateKey));
  if Result then
  begin
    for I := Low(TCnWOTSSM3PublicKey) to High(TCnWOTSSM3PublicKey) do
    begin
      Dig := PrivateKey[I];
      for J := 0 to CN_WOTS_ROUND - 1 do
        Dig := SM3(@Dig[0], SizeOf(TCnSM3Digest));

      PublicKey[I] := Dig;
    end;
  end;
end;

procedure CnWOTSSM3SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnWOTSSM3PrivateKey; var OutSignature: TCnWOTSSM3Signature);
var
  I, J: Integer;
  Dig, D: TCnSM3Digest;
  P: PByte;
  Sum, B: Word;
begin
  Dig := SM3(PAnsiChar(Data), DataByteLen);
  Sum := 0;

  for I := 0 to SizeOf(TCnSM3Digest) - 1 do
  begin
    D := PrivateKey[I];
    B := CN_WOTS_ROUND - Dig[I];             // ���� Byte �����Ҫ�� Word

    for J := 0 to B - 1 do
      D := SM3(@D[0], SizeOf(TCnSM3Digest)); // �����ֽ�������˽Կ���� 256 - ÿ���ֽڵ��Ӵմ���

    OutSignature[I] := D;
    Sum := Sum + Dig[I];
  end;

  // ����λУ���Ҳͬ������
  Sum := UInt16HostToNetwork(Sum);
  P := PByte(@Sum);

  D := PrivateKey[High(TCnSM3Digest) + 1];
  B := CN_WOTS_ROUND - P^;
  for J := 0 to B - 1 do
    D := SM3(@D[0], SizeOf(TCnSM3Digest));
  OutSignature[High(TCnSM3Digest) + 1] := D;

  Inc(P);
  D := PrivateKey[High(TCnSM3Digest) + 2];
  B := CN_WOTS_ROUND - P^;
  for J := 0 to B - 1 do
    D := SM3(@D[0], SizeOf(TCnSM3Digest));
  OutSignature[High(TCnSM3Digest) + 2] := D;
end;

function CnWOTSSM3VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnWOTSSM3Signature; PublicKey: TCnWOTSSM3PublicKey): Boolean;
var
  I, J: Integer;
  Dig, D: TCnSM3Digest;
  P: PByte;
  Sum, B: Word;
begin
  Result := False;

  Dig := SM3(PAnsiChar(Data), DataByteLen);
  Sum := 0;

  for I := 0 to SizeOf(TCnSM3Digest) - 1 do
  begin
    D := Signature[I];
    B := Dig[I];                             // ���� Byte �����Ҫ�� Word

    for J := 0 to B - 1 do
      D := SM3(@D[0], SizeOf(TCnSM3Digest)); // �����ֽ�������˽Կ����ÿ���ֽڵ��Ӵմ���

    if not SM3Match(D, PublicKey[I]) then
      Exit;

    Sum := Sum + Dig[I];
  end;

  // ����λУ���Ҳͬ������
  Sum := UInt16HostToNetwork(Sum);
  P := PByte(@Sum);

  D := Signature[High(TCnSM3Digest) + 1];
  B := P^;
  for J := 0 to B - 1 do
    D := SM3(@D[0], SizeOf(TCnSM3Digest));

  if not SM3Match(D, PublicKey[High(TCnSM3Digest) + 1]) then
    Exit;

  Inc(P);
  D := Signature[High(TCnSM3Digest) + 2];
  B := P^;
  for J := 0 to B - 1 do
    D := SM3(@D[0], SizeOf(TCnSM3Digest));

  if not SM3Match(D, PublicKey[High(TCnSM3Digest) + 2]) then
    Exit;

  Result := True;
end;

procedure CnWOTSSM3SignBytes(Data: TBytes; PrivateKey: TCnWOTSSM3PrivateKey;
  var OutSignature: TCnWOTSSM3Signature);
begin
  if Length(Data) = 0 then
    CnWOTSSM3SignData(nil, 0, PrivateKey, OutSignature)
  else
    CnWOTSSM3SignData(@Data[0], Length(Data), PrivateKey, OutSignature);
end;

function CnWOTSSM3VerifyBytes(Data: TBytes; Signature: TCnWOTSSM3Signature;
  PublicKey: TCnWOTSSM3PublicKey): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnWOTSSM3VerifyData(nil, 0, Signature, PublicKey)
  else
    Result := CnWOTSSM3VerifyData(@Data[0], Length(Data), Signature, PublicKey);
end;

function CnWOTSSHA256GenerateKeys(var PrivateKey: TCnWOTSSHA256PrivateKey;
  var PublicKey: TCnWOTSSHA256PublicKey): Boolean;
var
  I, J: Integer;
  Dig: TCnSHA256Digest;
  P: Pointer;
begin
  Result := CnRandomFillBytes(@PrivateKey[0], SizeOf(TCnWOTSSHA256PrivateKey));
  if Result then
  begin
    for I := Low(TCnWOTSSHA256PublicKey) to High(TCnWOTSSHA256PublicKey) do
    begin
      Dig := PrivateKey[I];
      for J := 0 to CN_WOTS_ROUND - 1 do
      begin
        P := @Dig[0];
        Dig := SHA256Buffer(P, SizeOf(TCnSHA256Digest));
      end;

      PublicKey[I] := Dig;
    end;
  end;
end;

procedure CnWOTSSHA256SignData(Data: Pointer; DataByteLen: Integer;
  PrivateKey: TCnWOTSSHA256PrivateKey; var OutSignature: TCnWOTSSHA256Signature);
var
  I, J: Integer;
  Dig, D: TCnSHA256Digest;
  P: PByte;
  Sum, B: Word;
  PB: Pointer;
begin
  Dig := SHA256Buffer(PAnsiChar(Data), DataByteLen);
  Sum := 0;

  for I := 0 to SizeOf(TCnSHA256Digest) - 1 do
  begin
    D := PrivateKey[I];
    B := CN_WOTS_ROUND - Dig[I];             // ���� Byte �����Ҫ�� Word

    for J := 0 to B - 1 do
    begin
      PB := @D[0];
      D := SHA256Buffer(PB, SizeOf(TCnSHA256Digest)); // �����ֽ�������˽Կ���� 256 - ÿ���ֽڵ��Ӵմ���
    end;

    OutSignature[I] := D;
    Sum := Sum + Dig[I];
  end;

  // ����λУ���Ҳͬ������
  Sum := UInt16HostToNetwork(Sum);
  P := PByte(@Sum);

  D := PrivateKey[High(TCnSHA256Digest) + 1];
  B := CN_WOTS_ROUND - P^;
  for J := 0 to B - 1 do
  begin
    PB := @D[0];
    D := SHA256Buffer(PB, SizeOf(TCnSHA256Digest));
  end;
  OutSignature[High(TCnSHA256Digest) + 1] := D;

  Inc(P);
  D := PrivateKey[High(TCnSHA256Digest) + 2];
  B := CN_WOTS_ROUND - P^;
  for J := 0 to B - 1 do
  begin
    PB := @D[0];
    D := SHA256Buffer(PB, SizeOf(TCnSHA256Digest));
  end;
  OutSignature[High(TCnSHA256Digest) + 2] := D;
end;

function CnWOTSSHA256VerifyData(Data: Pointer; DataByteLen: Integer;
  Signature: TCnWOTSSHA256Signature; PublicKey: TCnWOTSSHA256PublicKey): Boolean;
var
  I, J: Integer;
  Dig, D: TCnSHA256Digest;
  P: PByte;
  Sum, B: Word;
  PB: Pointer;
begin
  Result := False;

  Dig := SHA256Buffer(PAnsiChar(Data), DataByteLen);
  Sum := 0;

  for I := 0 to SizeOf(TCnSHA256Digest) - 1 do
  begin
    D := Signature[I];
    B := Dig[I];                             // ���� Byte �����Ҫ�� Word

    for J := 0 to B - 1 do
    begin
      PB := @D[0];
      D := SHA256Buffer(PB, SizeOf(TCnSHA256Digest)); // �����ֽ�������˽Կ����ÿ���ֽڵ��Ӵմ���
    end;

    if not SHA256Match(D, PublicKey[I]) then
      Exit;

    Sum := Sum + Dig[I];
  end;

  // ����λУ���Ҳͬ������
  Sum := UInt16HostToNetwork(Sum);
  P := PByte(@Sum);

  D := Signature[High(TCnSHA256Digest) + 1];
  B := P^;
  for J := 0 to B - 1 do
  begin
    PB := @D[0];
    D := SHA256Buffer(PB, SizeOf(TCnSHA256Digest));
  end;

  if not SHA256Match(D, PublicKey[High(TCnSHA256Digest) + 1]) then
    Exit;

  Inc(P);
  D := Signature[High(TCnSHA256Digest) + 2];
  B := P^;
  for J := 0 to B - 1 do
  begin
    PB := @D[0];
    D := SHA256Buffer(PB, SizeOf(TCnSHA256Digest));
  end;

  if not SHA256Match(D, PublicKey[High(TCnSHA256Digest) + 2]) then
    Exit;

  Result := True;
end;

procedure CnWOTSSHA256SignBytes(Data: TBytes; PrivateKey: TCnWOTSSHA256PrivateKey;
  var OutSignature: TCnWOTSSHA256Signature);
begin
  if Length(Data) = 0 then
    CnWOTSSHA256SignData(nil, 0, PrivateKey, OutSignature)
  else
    CnWOTSSHA256SignData(@Data[0], Length(Data), PrivateKey, OutSignature);
end;

function CnWOTSSHA256VerifyBytes(Data: TBytes; Signature: TCnWOTSSHA256Signature;
  PublicKey: TCnWOTSSHA256PublicKey): Boolean;
begin
  if Length(Data) = 0 then
    Result := CnWOTSSHA256VerifyData(nil, 0, Signature, PublicKey)
  else
    Result := CnWOTSSHA256VerifyData(@Data[0], Length(Data), Signature, PublicKey);
end;

end.
