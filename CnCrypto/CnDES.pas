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

unit CnDES;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�DES �ԳƼӽ����㷨ʵ�ֵ�Ԫ
* ��Ԫ���ߣ�CnPack ������ (master@cnpack.org)
*           ������/����������ֲ���������䲿�ֹ��ܡ�
* ��    ע������Ԫʵ���� DES/3DES �ԳƼӽ����㷨���ֿ��С 8 �ֽڣ�������ʵ����
*           ECB/CBC ģʽ����֧������������ģʽ��
*
* ����ƽ̨��PWin2000Pro + Delphi 5.0
* ���ݲ��ԣ�PWin9X/2000/XP + Delphi 5/6
* �� �� �����õ�Ԫ�е��ַ��������ϱ��ػ�����ʽ
* �޸ļ�¼��2024.11.30 V1.7
*               ɾ���������淶�� DESEncryptStrToHex �� DESDecryptStrToHex��
*               ɾ���������淶�� TripleDESEncryptStrToHex �� TripleDESDecryptStrToHex��
*               ���� ECB �汾�����
*               �Ż� PAnsiChar ��ʽ�� Iv �Ĵ���
*           2024.10.12 V1.6
*               ���� 3DES �²���Խ������⣬�Ż��� Key �� Iv �Ķ��봦��
*           2022.08.13 V1.5
*               �Կ����ݼ��ܷ��ؿ�
*           2021.02.07 V1.4
*               ���Ӷ� TBytes ��֧��
*           2020.03.25 V1.3
*               ���� 3DES ��֧��
*           2020.03.24 V1.2
*               ���� ECB/CBC �ַ��������ӽ��ܺ�����ɾ��ԭ�е��ַ������ܺ���
*           2019.04.15 V1.1
*               ֧�� Win32/Win64/MacOS
*           2008.05.30 V1.0
*               ������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative;

const
  CN_DES_KEYSIZE = 8;
  {* DES ����Կ���ȣ�8 �ֽ�}

  CN_DES_BLOCKSIZE = 8;
  {* DES �ļ��ܿ鳤�ȣ�8 �ֽ�}

  CN_TRIPLE_DES_KEYSIZE = CN_DES_KEYSIZE * 3;
  {* 3DES ����Կ���ȣ��� DES ��������24 �ֽ�}

  CN_TRIPLE_DES_BLOCKSIZE = CN_DES_BLOCKSIZE;
  {* 3DES �ļ��ܿ鳤�ȣ����� 8 �ֽ�}

type
  ECnDESException = class(Exception);
  {* DES ����쳣}

  TCnDESKey = array[0..CN_DES_KEYSIZE - 1] of Byte;
  {* DES �ļ��� Key��8 �ֽ�}

  TCnDESBuffer = array[0..CN_DES_BLOCKSIZE - 1] of Byte;
  {* DES �ļ��ܿ飬8 �ֽ�}

  TCnDESIv  = array[0..CN_DES_BLOCKSIZE - 1] of Byte;
  {* DES �� CBC �ĳ�ʼ��������8 �ֽ�}

  TCn3DESKey = array[0..CN_TRIPLE_DES_KEYSIZE - 1] of Byte;
  {* 3DES ����Կ���ȣ��� DES ��������24 �ֽ�}

  TCn3DESBuffer = TCnDESBuffer;
  {* 3DES �ļ��ܿ飬���� DES �ļ��ܿ飬8 �ֽ�}

  TCn3DESIv = TCnDESIv;
  {* 3DES �� CBC �ĳ�ʼ������������ DES �� CBC �ĳ�ʼ��������8 �ֽ�}

// ================================= DES =======================================

function DESGetOutputLengthFromInputLength(InputByteLength: Integer): Integer;
{* �������������ֽڳ��ȼ��� DES ������������ȡ�����ǿ�����������������������������

   ������
     InputByteLength: Integer             - ����������ֽڳ���

   ����ֵ��Integer                        - ���� DES ������ĳ���
}

procedure DESEncryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
{* ��� AnsiString �� DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: AnsiString                      - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0
     const Input: AnsiString              - �����ܵ��ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

procedure DESDecryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
{* ��� AnsiString �� DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: AnsiString                      - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0
     const Input: AnsiString              - �����ܵ��ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

procedure DESEncryptCbcStr(Key: AnsiString; Iv: PAnsiChar; const Input: AnsiString;
  Output: PAnsiChar);
{* ��� AnsiString �� DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: AnsiString                      - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0
     Iv: PAnsiChar                        - 8 �ֽڳ�ʼ��������ע����Ч���ݱ�����ڻ���� 8 �ֽ�
     const Input: AnsiString              - �����ܵ������ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

procedure DESDecryptCbcStr(Key: AnsiString; Iv: PAnsiChar; const Input: AnsiString;
  Output: PAnsiChar);
{* ��� AnsiString �� DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: AnsiString                      - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0
     Iv: PAnsiChar                        - 8 �ֽڳ�ʼ��������ע����Ч���ݱ�����ڻ���� 8 �ֽ�
     const Input: AnsiString              - �����ܵ������ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

function DESEncryptEcbStrToHex(const Str: AnsiString; const Key: AnsiString): AnsiString;
{* ������������� Key��DES ���ܷ���ת����ʮ�����Ƶ����ģ����ʹ�� ECB ģʽ������ĩβ���ܲ� #0��

   ������
     const Str: AnsiString                - �����ܵ������ַ���
     const Key: AnsiString                - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0

   ����ֵ��AnsiString                     - ���ؼ��ܺ��ʮ�����������ַ���
}

function DESDecryptEcbStrFromHex(const HexStr: AnsiString; const Key: AnsiString): AnsiString;
{* ����ʮ�����Ƶ���������� Key��DES ���ܷ������ģ����ʹ�� ECB ģʽ��

   ������
     const HexStr: AnsiString             - �����ܵ�ʮ�����������ַ���
     const Key: AnsiString                - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0

   ����ֵ��AnsiString                     - ���ؽ��ܺ�������ַ���
}

function DESEncryptCbcStrToHex(const Str: AnsiString; const Key: AnsiString; const Iv: AnsiString): AnsiString;
{* ������������� Key �� Iv��DES ���ܷ���ת����ʮ�����Ƶ����ģ����ʹ�� CBC ģʽ������ĩβ���ܲ� #0��

   ������
     const Str: AnsiString                - �����ܵ������ַ���
     const Key: AnsiString                - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0
     const Iv: AnsiString                 - 8 �ֽڳ�ʼ������

   ����ֵ��AnsiString                     - ���ؼ��ܺ��ʮ�����������ַ���
}

function DESDecryptCbcStrFromHex(const HexStr: AnsiString; const Key: AnsiString;
  const Iv: AnsiString): AnsiString;
{* ����ʮ�����Ƶ���������� Key �� Iv��DES ���ܷ������ģ����ʹ�� ECB ģʽ��

   ������
     const HexStr: AnsiString             - �����ܵ�ʮ�����������ַ���
     const Key: AnsiString                - 8 �ֽ� DES ��Կ��̫����ضϣ������� #0
     const Iv: AnsiString                 - 8 �ֽڳ�ʼ������

   ����ֵ��AnsiString                     - ���ؽ��ܺ�������ַ���
}

function DESEncryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: TBytes                          - 8 �ֽ� DES ��Կ��̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ����飬�䳤���粻�� 8 ����������ʱ�ᱻ��� 0 �����ȴﵽ 8 �ı���

   ����ֵ��TBytes                         - ���ؼ��ܺ�������ֽ�����
}

function DESDecryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: TBytes                          - 8 �ֽ� DES ��Կ��̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ����飬�䳤���粻�� 8 ����������ʱ�ᱻ��� 0 �����ȴﵽ 8 �ı���

   ����ֵ��TBytes                         - ���ؽ��ܺ�������ֽ�����
}

function DESEncryptCbcBytes(Key: TBytes; Iv: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: TBytes                          - 8 �ֽ� DES ��Կ��̫����ضϣ������� 0
     Iv: TBytes                           - 8 �ֽڳ�ʼ��������̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ�����

   ����ֵ��TBytes                         - ���ؼ��ܺ�������ֽ�����
}

function DESDecryptCbcBytes(Key: TBytes; Iv: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: TBytes                          - 8 �ֽ� DES ��Կ��̫����ضϣ������� 0
     Iv: TBytes                           - 8 �ֽڳ�ʼ��������̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ�����

   ����ֵ��TBytes                         - ���ؽ��ܺ�������ֽ�����
}

procedure DESEncryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; Dest: TStream); overload;
{* ������� DES ���ܣ����ʹ�� ECB ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCnDESKey                 - 8 �ֽ� DES ��Կ
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

procedure DESDecryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; Dest: TStream); overload;
{* ������� DES ���ܣ����ʹ�� ECB ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCnDESKey                 - 8 �ֽ� DES ��Կ
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

procedure DESEncryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
{* ������� DES ���ܣ����ʹ�� CBC ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCnDESKey                 - 8 �ֽ� DES ��Կ
     const InitVector: TCnDESIv           - 8 �ֽڳ�ʼ������
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

procedure DESDecryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
{* ������� DES ���ܣ����ʹ�� CBC ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCnDESKey                 - 8 �ֽ� DES ��Կ
     const InitVector: TCnDESIv           - 8 �ֽڳ�ʼ������
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

// =========================== 3-DES (Triple DES) ==============================

function TripleDESGetOutputLengthFromInputLength(InputByteLength: Integer): Integer;
{* �������������ֽڳ��ȼ����������������ȡ�����ǿ���������������������������

   ������
     InputByteLength: Integer             - ����������ֽڳ���

   ����ֵ��Integer                        - ���� 3DES ��������ֽڳ���
}

procedure TripleDESEncryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
{* ��� AnsiString �� 3DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: AnsiString                      - 24�ֽ� 3DES ��Կ��̫����ضϣ������� #0
     const Input: AnsiString              - �����ܵ��ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

procedure TripleDESDecryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
{* ��� AnsiString �� 3DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: AnsiString                      - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0
     const Input: AnsiString              - �����ܵ��ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

procedure TripleDESEncryptCbcStr(Key: AnsiString; Iv: PAnsiChar;
  const Input: AnsiString; Output: PAnsiChar);
{* ��� AnsiString �� 3DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: AnsiString                      - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0
     Iv: PAnsiChar                        - 8 �ֽڳ�ʼ��������ע����Ч���ݱ�����ڻ���� 8 �ֽ�
     const Input: AnsiString              - �����ܵ������ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

procedure TripleDESDecryptCbcStr(Key: AnsiString; Iv: PAnsiChar;
  const Input: AnsiString; Output: PAnsiChar);
{* ��� AnsiString �� 3DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: AnsiString                      - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0
     Iv: PAnsiChar                        - 8 �ֽڳ�ʼ��������ע����Ч���ݱ�����ڻ���� 8 �ֽ�
     const Input: AnsiString              - �����ܵ������ַ������䳤���粻�� 8 ����������ʱ�ᱻ��� #0 �����ȴﵽ 8 �ı���
     Output: PAnsiChar                    - ������������䳤�ȱ�����ڻ���� (((Length(Input) - 1) div 8) + 1) * 8

   ����ֵ�����ޣ�
}

function TripleDESEncryptEcbStrToHex(const Str: AnsiString; const Key: AnsiString): AnsiString;
{* ������������� Key��3DES ���ܷ���ת����ʮ�����Ƶ����ģ����ʹ�� ECB ģʽ������ĩβ���ܲ� #0��

   ������
     const Str: AnsiString                - �����ܵ������ַ���
     const Key: AnsiString                - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0

   ����ֵ��AnsiString                     - ���ؼ��ܺ��ʮ�����������ַ���
}

function TripleDESDecryptEcbStrFromHex(const HexStr: AnsiString; const Key: AnsiString): AnsiString;
{* ����ʮ�����Ƶ���������� Key��3DES ���ܷ������ģ����ʹ�� ECB ģʽ��

   ������
     const HexStr: AnsiString             - �����ܵ�ʮ�����������ַ���
     const Key: AnsiString                - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0

   ����ֵ��AnsiString                     - ���ؽ��ܺ�������ַ���
}

function TripleDESEncryptCbcStrToHex(const Str: AnsiString; const Key: AnsiString;
  const Iv: AnsiString): AnsiString;
{* ������������� Key �� Iv��3DES ���ܷ���ת����ʮ�����Ƶ����ģ����ʹ�� CBC ģʽ������ĩβ���ܲ� #0��

   ������
     const Str: AnsiString                - �����ܵ������ַ���
     const Key: AnsiString                - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0
     const Iv: AnsiString                 - 8 �ֽڳ�ʼ������

   ����ֵ��AnsiString                     - ���ؼ��ܺ��ʮ�����������ַ���
}

function TripleDESDecryptCbcStrFromHex(const HexStr: AnsiString;
  const Key: AnsiString; const Iv: AnsiString): AnsiString;
{* ����ʮ�����Ƶ���������� Key �� Iv��3DES ���ܷ������ģ����ʹ�� CBC ģʽ��

   ������
     const HexStr: AnsiString             - �����ܵ�ʮ�����������ַ���
     const Key: AnsiString                - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� #0
     const Iv: AnsiString                 - 8 �ֽڳ�ʼ������

   ����ֵ��AnsiString                     - ���ؽ��ܺ�������ַ���
}

function TripleDESEncryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ 3DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: TBytes                          - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ����飬�䳤���粻�� 8 ����������ʱ�ᱻ��� 0 �����ȴﵽ 8 �ı���

   ����ֵ��TBytes                         - ���ؼ��ܺ�������ֽ�����
}

function TripleDESDecryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ 3DES ���ܣ����ʹ�� ECB ģʽ��

   ������
     Key: TBytes                          - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ����飬�䳤���粻�� 8 ����������ʱ�ᱻ��� 0 �����ȴﵽ 8 �ı���

   ����ֵ��TBytes                         - ���ؽ��ܺ�������ֽ�����
}

function TripleDESEncryptCbcBytes(Key: TBytes; Iv: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ 3DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: TBytes                          - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� 0
     Iv: TBytes                           - 8 �ֽڳ�ʼ��������̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ�����

   ����ֵ��TBytes                         - ���ؼ��ܺ�������ֽ�����
}

function TripleDESDecryptCbcBytes(Key: TBytes; Iv: TBytes; Input: TBytes): TBytes;
{* ����ֽ������ 3DES ���ܣ����ʹ�� CBC ģʽ��

   ������
     Key: TBytes                          - 24 �ֽ� 3DES ��Կ��̫����ضϣ������� 0
     Iv: TBytes                           - 8 �ֽڳ�ʼ��������̫����ضϣ������� 0
     Input: TBytes                        - �����ܵ������ֽ�����

   ����ֵ��TBytes                         - ���ؽ��ܺ�������ֽ�����
}

procedure TripleDESEncryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; Dest: TStream); overload;
{* ������� 3DES ���ܣ����ʹ�� ECB ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCnDESKey                 - 24 �ֽ� 3DES ��Կ
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

procedure TripleDESDecryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; Dest: TStream); overload;
{* ������� 3DES ���ܣ����ʹ�� ECB ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCnDESKey                 - 24 �ֽ� 3DES ��Կ
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

procedure TripleDESEncryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
{* ������� 3DES ���ܣ����ʹ�� CBC ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCn3DESKey                - 24 �ֽ� 3DES ��Կ
     const InitVector: TCnDESIv           - 8 �ֽڳ�ʼ������
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

procedure TripleDESDecryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
{* ������� 3DES ���ܣ����ʹ�� CBC ģʽ��
   Count Ϊ 0 ��ʾ��ͷ����������������ֻ���� Stream ��ǰλ���� Count ���ֽ�����

   ������
     Source: TStream                      - �����ܵ�������
     Count: Cardinal                      - ������ǰλ����Ĵ����ܵ��ֽڳ��ȣ���Ϊ 0����ʾ��ͷ����������
     const Key: TCn3DESKey                - 24 �ֽ� 3DES ��Կ
     const InitVector: TCnDESIv           - 8 �ֽڳ�ʼ������
     Dest: TStream                        - �����������

   ����ֵ�����ޣ�
}

implementation

resourcestring
  SCnErrorDESInvalidInBufSize = 'Invalid Buffer Size for Decryption';
  SCnErrorDESReadError = 'Stream Read Error';
  SCnErrorDESWriteError = 'Stream Write Error';

type
  TKeyByte = array[0..5] of Byte;
  TDesMode = (dmEncry, dmDecry);
  TSubKey = array[0..15] of TKeyByte;

const
  BitIP: array[0..63] of Byte =
  (57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6);

  BitCP: array[0..63] of Byte =
  (39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
    32, 0, 40, 8, 48, 16, 56, 24);

  BitExp: array[0..47] of Integer =
  (31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10,
    11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
    21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0);

  BitPM: array[0..31] of Byte =
  (15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
    1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24);

  sBox: array[0..7] of array[0..63] of Byte =
  ((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),

    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),

    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),

    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),

    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),

    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),

    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),

    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11));

  BitPMC1: array[0..55] of Byte =
  (56, 48, 40, 32, 24, 16, 8,
    0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26,
    18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
    6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3);

  BitPMC2: array[0..47] of Byte =
  (13, 16, 10, 23, 0, 4,
    2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7,
    15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31);

function Min(A, B: Integer): Integer; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

procedure InitPermutation(var InData: array of Byte);
var
  NewData: array[0..7] of Byte;
  I: Integer;
begin
  FillChar(NewData, 8, 0);
  for I := 0 to 63 do
    if (InData[BitIP[I] shr 3] and (1 shl (7 - (BitIP[I] and $07)))) <> 0 then
      NewData[I shr 3] := NewData[I shr 3] or (1 shl (7 - (I and $07)));
  for I := 0 to 7 do InData[I] := NewData[I];
end;

procedure ConversePermutation(var InData: array of Byte);
var
  NewData: array[0..7] of Byte;
  I: Integer;
begin
  FillChar(NewData, 8, 0);
  for I := 0 to 63 do
    if (InData[BitCP[I] shr 3] and (1 shl (7 - (BitCP[I] and $07)))) <> 0 then
      NewData[I shr 3] := NewData[I shr 3] or (1 shl (7 - (I and $07)));
  for I := 0 to 7 do InData[I] := NewData[I];
end;

procedure Expand(const InData: array of Byte; var OutData: array of Byte);
var
  I: Integer;
begin
  FillChar(OutData, 6, 0);
  for I := 0 to 47 do
    if (InData[BitExp[I] shr 3] and (1 shl (7 - (BitExp[I] and $07)))) <> 0 then
      OutData[I shr 3] := OutData[I shr 3] or (1 shl (7 - (I and $07)));
end;

procedure Permutation(var InData: array of Byte);
var
  NewData: array[0..3] of Byte;
  I: Integer;
begin
  FillChar(NewData, 4, 0);
  for I := 0 to 31 do
    if (InData[BitPM[I] shr 3] and (1 shl (7 - (BitPM[I] and $07)))) <> 0 then
      NewData[I shr 3] := NewData[I shr 3] or (1 shl (7 - (I and $07)));
  for I := 0 to 3 do InData[I] := NewData[I];
end;

function Si(S, InByte: Byte): Byte;
var
  c: Byte;
begin
  c := (InByte and $20) or ((InByte and $1E) shr 1) or
    ((InByte and $01) shl 4);
  Result := (sBox[S][c] and $0F);
end;

procedure PermutationChoose1(const InData: array of Byte; var OutData: array of Byte);
var
  I: Integer;
begin
  FillChar(OutData, 7, 0);
  for I := 0 to 55 do
    if (InData[BitPMC1[I] shr 3] and (1 shl (7 - (BitPMC1[I] and $07)))) <> 0 then
      OutData[I shr 3] := OutData[I shr 3] or (1 shl (7 - (I and $07)));
end;

procedure PermutationChoose2(const InData: array of Byte; var OutData: array of Byte);
var
  I: Integer;
begin
  FillChar(OutData, 6, 0);
  for I := 0 to 47 do
    if (InData[BitPMC2[I] shr 3] and (1 shl (7 - (BitPMC2[I] and $07)))) <> 0 then
      OutData[I shr 3] := OutData[I shr 3] or (1 shl (7 - (I and $07)));
end;

procedure CycleMove(var InData: array of Byte; bitMove: Byte);
var
  I: Integer;
begin
  for I := 0 to bitMove - 1 do
  begin
    InData[0] := (InData[0] shl 1) or (InData[1] shr 7);
    InData[1] := (InData[1] shl 1) or (InData[2] shr 7);
    InData[2] := (InData[2] shl 1) or (InData[3] shr 7);
    InData[3] := (InData[3] shl 1) or ((InData[0] and $10) shr 4);
    InData[0] := (InData[0] and $0F);
  end;
end;

procedure MakeKey(const InKey: array of Byte; var OutKey: array of TKeyByte);
const
  bitDisplace: array[0..15] of Byte =
    (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);
var
  OutData56: array[0..6] of Byte;
  Key28l: array[0..3] of Byte;
  Key28r: array[0..3] of Byte;
  Key56o: array[0..6] of Byte;
  I: Integer;
begin
  PermutationChoose1(InKey, OutData56);
  Key28l[0] := OutData56[0] shr 4;
  Key28l[1] := (OutData56[0] shl 4) or (OutData56[1] shr 4);
  Key28l[2] := (OutData56[1] shl 4) or (OutData56[2] shr 4);
  Key28l[3] := (OutData56[2] shl 4) or (OutData56[3] shr 4);
  Key28r[0] := OutData56[3] and $0F;
  Key28r[1] := OutData56[4];
  Key28r[2] := OutData56[5];
  Key28r[3] := OutData56[6];
  for I := 0 to 15 do
  begin
    CycleMove(Key28l, bitDisplace[I]);
    CycleMove(Key28r, bitDisplace[I]);
    Key56o[0] := (Key28l[0] shl 4) or (Key28l[1] shr 4);
    Key56o[1] := (Key28l[1] shl 4) or (Key28l[2] shr 4);
    Key56o[2] := (Key28l[2] shl 4) or (Key28l[3] shr 4);
    Key56o[3] := (Key28l[3] shl 4) or (Key28r[0]);
    Key56o[4] := Key28r[1];
    Key56o[5] := Key28r[2];
    Key56o[6] := Key28r[3];
    PermutationChoose2(Key56o, OutKey[I]);
  end;
end;

procedure Encry(const InData, ASubKey: array of Byte; var OutData: array of Byte);
var
  OutBuf: array[0..5] of Byte;
  Buf: array[0..7] of Byte;
  I: Integer;
begin
  Expand(InData, OutBuf);
  for I := 0 to 5 do OutBuf[I] := OutBuf[I] xor ASubKey[I];
  Buf[0] := OutBuf[0] shr 2;
  Buf[1] := ((OutBuf[0] and $03) shl 4) or (OutBuf[1] shr 4);
  Buf[2] := ((OutBuf[1] and $0F) shl 2) or (OutBuf[2] shr 6);
  Buf[3] := OutBuf[2] and $3F;
  Buf[4] := OutBuf[3] shr 2;
  Buf[5] := ((OutBuf[3] and $03) shl 4) or (OutBuf[4] shr 4);
  Buf[6] := ((OutBuf[4] and $0F) shl 2) or (OutBuf[5] shr 6);
  Buf[7] := OutBuf[5] and $3F;
  for I := 0 to 7 do Buf[I] := si(I, Buf[I]);
  for I := 0 to 3 do OutBuf[I] := (Buf[I * 2] shl 4) or Buf[I * 2 + 1];
  Permutation(OutBuf);
  for I := 0 to 3 do OutData[I] := OutBuf[I];
end;

// InData �� OutData Ҫ���� 8 �ֽ�����
procedure DesData(DesMode: TDesMode; SubKey: TSubKey; const InData: array of Byte;
  var OutData: array of Byte);
var
  I, J: Integer;
  Temp, Buf: array[0..3] of Byte;
begin
  for I := 0 to 7 do OutData[I] := InData[I];
  InitPermutation(OutData);
  if DesMode = dmEncry then
  begin
    for I := 0 to 15 do
    begin
      for J := 0 to 3 do Temp[J] := OutData[J];
      for J := 0 to 3 do OutData[J] := OutData[J + 4];
      Encry(OutData, SubKey[I], Buf);
      for J := 0 to 3 do OutData[J + 4] := Temp[J] xor Buf[J];
    end;
    for J := 0 to 3 do Temp[J] := OutData[J + 4];
    for J := 0 to 3 do OutData[J + 4] := OutData[J];
    for J := 0 to 3 do OutData[J] := Temp[J];
  end
  else if DesMode = dmDecry then
  begin
    for I := 15 downto 0 do
    begin
      for J := 0 to 3 do Temp[J] := OutData[J];
      for J := 0 to 3 do OutData[J] := OutData[J + 4];
      Encry(OutData, SubKey[I], Buf);
      for J := 0 to 3 do OutData[J + 4] := Temp[J] xor Buf[J];
    end;
    for J := 0 to 3 do Temp[J] := OutData[J + 4];
    for J := 0 to 3 do OutData[J + 4] := OutData[J];
    for J := 0 to 3 do OutData[J] := Temp[J];
  end;
  ConversePermutation(OutData);
end;

// �� Key �� #0 �ճ� 8 �ֽ�
procedure MakeKeyAlign(var Key: AnsiString);
begin
  if Length(Key) < CN_DES_KEYSIZE then
    while Length(Key) < CN_DES_KEYSIZE do
      Key := Key + Chr(0);
end;

// ���ַ����� #0 �ճ� 8 �ı�����ע��մ�����
procedure MakeInputAlign(var Str: AnsiString);
begin
  while Length(Str) mod CN_DES_KEYSIZE <> 0 do
    Str := Str + Chr(0);
end;

// ���ֽ����鲹 0 �ճ� 8 �ı�����ע������鲻��
procedure MakeInputBytesAlign(var Input: TBytes);
var
  I, Len, NL: Integer;
begin
  Len := Length(Input);
  if Len mod CN_DES_BLOCKSIZE <> 0 then
  begin
    NL := ((Len div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE;
    SetLength(Input, NL);
    for I := Len to NL - 1 do
      Input[I] := 0;
  end;
end;

function DESGetOutputLengthFromInputLength(InputByteLength: Integer): Integer;
begin
  Result := (((InputByteLength - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE;
end;

procedure DESEncryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  Str: AnsiString;
  I: Integer;
  SubKey: TSubKey;
begin
  MakeKeyAlign(Key);

  Str := Input;
  MakeInputAlign(Str);  // Str ����� 8 �ı���

  if Str = '' then      // �մ�ֱ�ӷ��ؿ�
  begin
    if Output <> nil then
      Output[0] := #0;
    Exit;
  end;

  Move(Key[1], KeyByte[0], SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);

  for I := 0 to Length(Str) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Str[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));
    DesData(dmEncry, SubKey, StrByte, OutByte);
    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;
end;

procedure DESDecryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  I: Integer;
  SubKey: TSubKey;
begin
  MakeKeyAlign(Key);
  Move(Key[1], KeyByte[0], SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);

  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));
    DesData(dmDecry, SubKey, StrByte, OutByte);
    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;

  // ĩβ���� 0 ���ⲿ�ж�ɾ��
end;

procedure DESEncryptCbcStr(Key: AnsiString; Iv: PAnsiChar;
  const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  Vector: TCnDESIv;
  Str: AnsiString;
  I: Integer;
  SubKey: TSubKey;
begin
  MakeKeyAlign(Key);

  Str := Input;
  MakeInputAlign(Str);

  if Str = '' then      // �մ�ֱ�ӷ��ؿ�
  begin
    if Output <> nil then
      Output[0] := #0;
    Exit;
  end;

  Move(Key[1], KeyByte[0], SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);
  Move(Iv^, Vector[0], SizeOf(TCnDESIv));

  for I := 0 to Length(Str) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Str[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));

    // CBC ���ݿ��ֵ�ȸ� Iv ���
    PCardinal(@StrByte[0])^ := PCardinal(@StrByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@StrByte[4])^ := PCardinal(@StrByte[4])^ xor PCardinal(@Vector[4])^;

    // �ټ���
    DesData(dmEncry, SubKey, StrByte, OutByte);
    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ܽ�����µ� Iv
    Move(OutByte[0], Vector[0], SizeOf(TCnDESIv));
  end;
end;

procedure DESDecryptCbcStr(Key: AnsiString; Iv: PAnsiChar;
  const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  Vector, TV: TCnDESIv;
  I: Integer;
  SubKey: TSubKey;
begin
  MakeKeyAlign(Key);
  Move(Key[1], KeyByte[0], SizeOf(TCnDESKey));

  MakeKey(KeyByte, SubKey);
  Move(Iv^, Vector[0], SizeOf(TCnDESIv));

  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));
    Move(StrByte[0], TV[0], SizeOf(TCnDESIv)); // �����ȴ�һ��

    // �Ƚ���
    DesData(dmDecry, SubKey, StrByte, OutByte);

    // CBC ���ݿ���ܺ��ֵ�ٸ� Iv ���
    PCardinal(@OutByte[0])^ := PCardinal(@OutByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@OutByte[4])^ := PCardinal(@OutByte[4])^ xor PCardinal(@Vector[4])^;

    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ĸ��µ� Iv
    Move(TV[0], Vector[0], SizeOf(TCnDESIv));
  end;

  // ĩβ���� 0 ���ⲿ�ж�ɾ��
end;

procedure SetResultLengthUsingInput(const Str: AnsiString; var Res: AnsiString);
var
  Len: Integer;
begin
  Len := Length(Str);
  if Len < CN_DES_BLOCKSIZE then
    Len := CN_DES_BLOCKSIZE
  else
    Len := (((Len - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE;
  SetLength(Res, Len);
end;

function DESEncryptEcbStrToHex(const Str, Key: AnsiString): AnsiString;
var
  TempResult: AnsiString;
begin
  Result := '';
  if Str = '' then
    Exit;

  SetResultLengthUsingInput(Str, TempResult);
  DESEncryptEcbStr(Key, Str, @TempResult[1]);
  Result := AnsiStrToHex(TempResult);
end;

function DESDecryptEcbStrFromHex(const HexStr, Key: AnsiString): AnsiString;
var
  Str: AnsiString;
begin
  Str := HexToAnsiStr(HexStr);
  SetResultLengthUsingInput(Str, Result);
  DESDecryptEcbStr(Key, Str, @(Result[1]));
end;

function DESEncryptCbcStrToHex(const Str, Key, Iv: AnsiString): AnsiString;
var
  TempResult: AnsiString;
begin
  Result := '';
  if Str = '' then
    Exit;

  SetResultLengthUsingInput(Str, TempResult);
  DESEncryptCbcStr(Key, PAnsiChar(Iv), Str, @TempResult[1]);
  Result := AnsiStrToHex(TempResult);
end;

function DESDecryptCbcStrFromHex(const HexStr, Key, Iv: AnsiString): AnsiString;
var
  Str: AnsiString;
begin
  Str := HexToAnsiStr(HexStr);
  SetResultLengthUsingInput(Str, Result);
  DESDecryptCbcStr(Key, PAnsiChar(Iv), Str, @(Result[1]));
end;

function DESEncryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  I: Integer;
  SubKey: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  MakeInputBytesAlign(Input);

  FillChar(KeyByte[0], SizeOf(TCnDESKey), 0);
  MoveMost(Key[0], KeyByte[0], Length(Key), SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));
    DesData(dmEncry, SubKey, StrByte, OutByte);
    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;
end;

function DESDecryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  I: Integer;
  SubKey: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  FillChar(KeyByte[0], SizeOf(TCnDESKey), 0);
  MoveMost(Key[0], KeyByte[0], Length(Key), SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));
    DesData(dmDecry, SubKey, StrByte, OutByte);
    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;
end;

function DESEncryptCbcBytes(Key, Iv: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  Vector: TCnDESIv;
  I: Integer;
  SubKey: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  MakeInputBytesAlign(Input);

  FillChar(KeyByte[0], SizeOf(TCnDESKey), 0);
  MoveMost(Key[0], KeyByte[0], Length(Key), SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);

  FillChar(Vector[0], SizeOf(TCnDESIv), 0);
  MoveMost(Iv[0], Vector[0], Length(Iv), SizeOf(TCnDESIv));

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));

    // CBC ���ݿ��ֵ�ȸ� Iv ���
    PCardinal(@StrByte[0])^ := PCardinal(@StrByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@StrByte[4])^ := PCardinal(@StrByte[4])^ xor PCardinal(@Vector[4])^;

    // �ټ���
    DesData(dmEncry, SubKey, StrByte, OutByte);
    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ܽ�����µ� Iv
    Move(OutByte[0], Vector[0], SizeOf(TCnDESIv));
  end;
end;

function DESDecryptCbcBytes(Key, Iv: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  KeyByte: TCnDESKey;
  Vector, TV: TCnDESIv;
  I: Integer;
  SubKey: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  FillChar(KeyByte[0], SizeOf(TCnDESKey), 0);
  MoveMost(Key[0], KeyByte[0], Length(Key), SizeOf(TCnDESKey));
  MakeKey(KeyByte, SubKey);

  FillChar(Vector[0], SizeOf(TCnDESIv), 0);
  MoveMost(Iv[0], Vector[0], Length(Iv), SizeOf(TCnDESIv));

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));
    Move(StrByte[0], TV[0], SizeOf(TCnDESIv)); // �����ȴ�һ��

    // �Ƚ���
    DesData(dmDecry, SubKey, StrByte, OutByte);

    // CBC ���ݿ���ܺ��ֵ�ٸ� Iv ���
    PCardinal(@OutByte[0])^ := PCardinal(@OutByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@OutByte[4])^ := PCardinal(@OutByte[4])^ xor PCardinal(@Vector[4])^;

    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ĸ��µ� Iv
    Move(TV[0], Vector[0], SizeOf(TCnDESIv));
  end;
end;

procedure DESEncryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; Dest: TStream); overload;
var
  TempIn, TempOut: TCnDESBuffer;
  Done: Cardinal;
  SubKey: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;

  MakeKey(Key, SubKey);
  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError.Create(SCnErrorDESReadError);

    DesData(dmEncry, SubKey, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);

    Dec(Count, SizeOf(TCnDESBuffer));
  end;

  if Count > 0 then // β���� 0
  begin
    Done := Source.Read(TempIn, Count);
    if Done < Count then
      raise EStreamError.Create(SCnErrorDESReadError);
    FillChar(TempIn[Count], SizeOf(TempIn) - Count, 0);

    DesData(dmEncry, SubKey, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);
  end;
end;

procedure DESDecryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; Dest: TStream); overload;
var
  TempIn, TempOut: TCnDESBuffer;
  Done: Cardinal;
  SubKey: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;
  if (Count mod SizeOf(TCnDESBuffer)) > 0 then
    raise ECnDESException.Create(SCnErrorDESInvalidInBufSize);

  MakeKey(Key, SubKey);
  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError.Create(SCnErrorDESReadError);

    DesData(dmDecry, SubKey, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);

    Dec(Count, SizeOf(TCnDESBuffer));
  end;
end;

procedure DESEncryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
var
  TempIn, TempOut: TCnDESBuffer;
  Vector: TCnDESIv;
  Done: Cardinal;
  SubKey: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;

  Vector := InitVector;
  MakeKey(Key, SubKey);

  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError.Create(SCnErrorDESReadError);

    PCardinal(@TempIn[0])^ := PCardinal(@TempIn[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@TempIn[4])^ := PCardinal(@TempIn[4])^ xor PCardinal(@Vector[4])^;

    DesData(dmEncry, SubKey, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);

    Move(TempOut[0], Vector[0], SizeOf(TCnDESIv));
    Dec(Count, SizeOf(TCnDESBuffer));
  end;

  if Count > 0 then
  begin
    Done := Source.Read(TempIn, Count);
    if Done < Count then
      raise EStreamError.Create(SCnErrorDESReadError);
    FillChar(TempIn[Count], SizeOf(TempIn) - Count, 0);

    PCardinal(@TempIn[0])^ := PCardinal(@TempIn[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@TempIn[4])^ := PCardinal(@TempIn[4])^ xor PCardinal(@Vector[4])^;

    DesData(dmEncry, SubKey, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);
  end;
end;

procedure DESDecryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCnDESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
var
  TempIn, TempOut: TCnDESBuffer;
  Vector1, Vector2: TCnDESIv;
  Done: Cardinal;
  SubKey: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;
  if (Count mod SizeOf(TCnDESBuffer)) > 0 then
    raise ECnDESException.Create(SCnErrorDESInvalidInBufSize);

  Vector1 := InitVector;
  MakeKey(Key, SubKey);

  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError(SCnErrorDESReadError);

    Move(TempIn[0], Vector2[0], SizeOf(TCnDESIv));
    DesData(dmDecry, SubKey, TempIn, TempOut);

    PCardinal(@TempOut[0])^ := PCardinal(@TempOut[0])^ xor PCardinal(@Vector1[0])^;
    PCardinal(@TempOut[4])^ := PCardinal(@TempOut[4])^ xor PCardinal(@Vector1[4])^;

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError(SCnErrorDESWriteError);

    Vector1 := Vector2;
    Dec(Count, SizeOf(TCnDESBuffer));
  end;
end;

procedure Make3DESKeys(Keys: AnsiString; var K1, K2, K3: TCnDESKey); overload;
var
  I: Integer;
begin
  if Length(Keys) < CN_TRIPLE_DES_KEYSIZE then
    while Length(Keys) < CN_TRIPLE_DES_KEYSIZE do
      Keys := Keys + Chr(0);

  for I := 0 to CN_DES_KEYSIZE - 1 do
  begin
    K1[I] := Ord(Keys[I + 1]);
    K2[I] := Ord(Keys[I + 1 + CN_DES_KEYSIZE]);
    K3[I] := Ord(Keys[I + 1 + CN_DES_KEYSIZE * 2]);
  end;
end;

procedure Make3DESKeys(Keys: TCn3DESKey; var K1, K2, K3: TCnDESKey); overload;
var
  I: Integer;
begin
  for I := 0 to CN_DES_KEYSIZE - 1 do
  begin
    K1[I] := Keys[I];
    K2[I] := Keys[I + CN_DES_KEYSIZE];
    K3[I] := Keys[I + CN_DES_KEYSIZE * 2];
  end;
end;

procedure Make3DESKeys(Keys: TBytes; var K1, K2, K3: TCnDESKey); overload;
var
  I, Len: Integer;
begin
  Len := Length(Keys);
  if Len < CN_TRIPLE_DES_KEYSIZE then
  begin
    SetLength(Keys, CN_TRIPLE_DES_KEYSIZE);
    for I := Len to CN_TRIPLE_DES_KEYSIZE - 1 do
      Keys[I] := 0;
  end;

  for I := 0 to CN_DES_KEYSIZE - 1 do
  begin
    K1[I] := Ord(Keys[I]);
    K2[I] := Ord(Keys[I + CN_DES_KEYSIZE]);
    K3[I] := Ord(Keys[I + CN_DES_KEYSIZE * 2]);
  end;
end;

function TripleDESGetOutputLengthFromInputLength(InputByteLength: Integer): Integer;
begin
  Result := (((InputByteLength - 1) div CN_TRIPLE_DES_BLOCKSIZE) + 1) * CN_TRIPLE_DES_BLOCKSIZE;
end;

procedure TripleDESEncryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  Str: AnsiString;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  Str := Input;
  MakeInputAlign(Str);

  if Str = '' then      // �մ�ֱ�ӷ��ؿ�
  begin
    if Output <> nil then
      Output[0] := #0;
    Exit;
  end;

  for I := 0 to Length(Str) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Str[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));

    DesData(dmEncry, SubKey1, StrByte, OutByte);
    DesData(dmDecry, SubKey2, OutByte, StrByte);
    DesData(dmEncry, SubKey3, StrByte, OutByte);

    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;
end;

procedure TripleDESDecryptEcbStr(Key: AnsiString; const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));

    DesData(dmDecry, SubKey3, StrByte, OutByte);
    DesData(dmEncry, SubKey2, OutByte, StrByte);
    DesData(dmDecry, SubKey1, StrByte, OutByte);

    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;

  // ĩβ���� 0 ���ⲿ�ж�ɾ��
end;

procedure TripleDESEncryptCbcStr(Key: AnsiString; Iv: PAnsiChar;
  const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  Vector: TCnDESIv;
  Str: AnsiString;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  Str := Input;
  MakeInputAlign(Str);

  if Str = '' then      // �մ�ֱ�ӷ��ؿ�
  begin
    if Output <> nil then
      Output[0] := #0;
    Exit;
  end;

  Move(Iv^, Vector[0], SizeOf(TCnDESIv));

  for I := 0 to Length(Str) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Str[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));

    // CBC ���ݿ��ֵ�ȸ� Iv ���
    PCardinal(@StrByte[0])^ := PCardinal(@StrByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@StrByte[4])^ := PCardinal(@StrByte[4])^ xor PCardinal(@Vector[4])^;

    // �ټ���
    DesData(dmEncry, SubKey1, StrByte, OutByte);
    DesData(dmDecry, SubKey2, OutByte, StrByte);
    DesData(dmEncry, SubKey3, StrByte, OutByte);

    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ܽ�����µ� Iv
    Move(OutByte[0], Vector[0], SizeOf(TCnDESIv));
  end;
end;

procedure TripleDESDecryptCbcStr(Key: AnsiString; Iv: PAnsiChar;
  const Input: AnsiString; Output: PAnsiChar);
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  Vector, TV: TCnDESIv;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  Move(Iv^, Vector[0], SizeOf(TCnDESIv));

  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE + 1], StrByte[0], SizeOf(TCnDESBuffer));
    Move(StrByte[0], TV[0], SizeOf(TCnDESIv)); // �����ȴ�һ��

    // �Ƚ���
    DesData(dmDecry, SubKey3, StrByte, OutByte);
    DesData(dmEncry, SubKey2, OutByte, StrByte);
    DesData(dmDecry, SubKey1, StrByte, OutByte);

    // CBC ���ݿ���ܺ��ֵ�ٸ� Iv ���
    PCardinal(@OutByte[0])^ := PCardinal(@OutByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@OutByte[4])^ := PCardinal(@OutByte[4])^ xor PCardinal(@Vector[4])^;

    Move(OutByte[0], Output[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ĸ��µ� Iv
    Move(TV[0], Vector[0], SizeOf(TCnDESIv));
  end;

  // ĩβ���� 0 ���ⲿ�ж�ɾ��
end;

function TripleDESEncryptEcbStrToHex(const Str, Key: AnsiString): AnsiString;
var
  TempResult, Temp: AnsiString;
  I: Integer;
begin
  SetResultLengthUsingInput(Str, TempResult);
  TripleDESEncryptEcbStr(Key, Str, @TempResult[1]);

  Result := '';
  for I := 0 to Length(TempResult) - 1 do
  begin
    Temp := AnsiString(Format('%x', [Ord(TempResult[I + 1])]));
    if Length(Temp) = 1 then
      Temp := '0' + Temp;
    Result := Result + Temp;
  end;
end;

function TripleDESDecryptEcbStrFromHex(const HexStr, Key: AnsiString): AnsiString;
var
  Str: AnsiString;
begin
  Str := HexToAnsiStr(HexStr);
  SetResultLengthUsingInput(Str, Result);
  TripleDESDecryptEcbStr(Key, Str, @(Result[1]));
end;

function TripleDESEncryptCbcStrToHex(const Str, Key, Iv: AnsiString): AnsiString;
var
  TempResult, Temp: AnsiString;
  I: Integer;
begin
  SetResultLengthUsingInput(Str, TempResult);
  TripleDESEncryptCbcStr(Key, PAnsiChar(Iv), Str, @TempResult[1]);

  Result := '';
  for I := 0 to Length(TempResult) - 1 do
  begin
    Temp := AnsiString(Format('%x', [Ord(TempResult[I + 1])]));
    if Length(Temp) = 1 then
      Temp := '0' + Temp;
    Result := Result + Temp;
  end;
end;

function TripleDESDecryptCbcStrFromHex(const HexStr, Key, Iv: AnsiString): AnsiString;
var
  Str: AnsiString;
begin
  Str := HexToAnsiStr(HexStr);
  SetResultLengthUsingInput(Str, Result);
  TripleDESDecryptCbcStr(Key, PAnsiChar(Iv), Str, @(Result[1]));
end;

function TripleDESEncryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  MakeInputBytesAlign(Input);

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));

    DesData(dmEncry, SubKey1, StrByte, OutByte);
    DesData(dmDecry, SubKey2, OutByte, StrByte);
    DesData(dmEncry, SubKey3, StrByte, OutByte);

    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;
end;

function TripleDESDecryptEcbBytes(Key: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));

    DesData(dmDecry, SubKey3, StrByte, OutByte);
    DesData(dmEncry, SubKey2, OutByte, StrByte);
    DesData(dmDecry, SubKey1, StrByte, OutByte);

    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));
  end;
end;

function TripleDESEncryptCbcBytes(Key, Iv: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  Vector: TCnDESIv;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  MakeInputBytesAlign(Input);
  FillChar(Vector[0], SizeOf(TCnDESIv), 0);
  MoveMost(Iv[0], Vector[0], Length(Iv), SizeOf(TCnDESIv));

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));

    // CBC ���ݿ��ֵ�ȸ� Iv ���
    PCardinal(@StrByte[0])^ := PCardinal(@StrByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@StrByte[4])^ := PCardinal(@StrByte[4])^ xor PCardinal(@Vector[4])^;

    // �ټ���
    DesData(dmEncry, SubKey1, StrByte, OutByte);
    DesData(dmDecry, SubKey2, OutByte, StrByte);
    DesData(dmEncry, SubKey3, StrByte, OutByte);

    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ܽ�����µ� Iv
    Move(OutByte[0], Vector[0], SizeOf(TCnDESIv));
  end;
end;

function TripleDESDecryptCbcBytes(Key, Iv: TBytes; Input: TBytes): TBytes;
var
  StrByte, OutByte: TCnDESBuffer;
  K1, K2, K3: TCnDESKey;
  Vector, TV: TCnDESIv;
  I: Integer;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Length(Input) <= 0 then
  begin
    Result := nil;
    Exit;
  end;

  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  FillChar(Vector[0], SizeOf(TCnDESIv), 0);
  MoveMost(Iv[0], Vector[0], Length(Iv), SizeOf(TCnDESIv));

  SetLength(Result, (((Length(Input) - 1) div CN_DES_BLOCKSIZE) + 1) * CN_DES_BLOCKSIZE);
  for I := 0 to Length(Input) div CN_DES_BLOCKSIZE - 1 do
  begin
    Move(Input[I * CN_DES_BLOCKSIZE], StrByte[0], SizeOf(TCnDESBuffer));
    Move(StrByte[0], TV[0], SizeOf(TCnDESIv)); // �����ȴ�һ��

    // �Ƚ���
    DesData(dmDecry, SubKey3, StrByte, OutByte);
    DesData(dmEncry, SubKey2, OutByte, StrByte);
    DesData(dmDecry, SubKey1, StrByte, OutByte);

    // CBC ���ݿ���ܺ��ֵ�ٸ� Iv ���
    PCardinal(@OutByte[0])^ := PCardinal(@OutByte[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@OutByte[4])^ := PCardinal(@OutByte[4])^ xor PCardinal(@Vector[4])^;

    Move(OutByte[0], Result[I * CN_DES_BLOCKSIZE], SizeOf(TCnDESBuffer));

    // ���ĸ��µ� Iv
    Move(TV[0], Vector[0], SizeOf(TCnDESIv));
  end;
end;

procedure TripleDESEncryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; Dest: TStream); overload;
var
  K1, K2, K3: TCnDESKey;
  TempIn, TempOut: TCnDESBuffer;
  Done: Cardinal;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;

  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError.Create(SCnErrorDESReadError);

    DesData(dmEncry, SubKey1, TempIn, TempOut);
    DesData(dmDecry, SubKey2, TempOut, TempIn);
    DesData(dmEncry, SubKey3, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);

    Dec(Count, SizeOf(TCnDESBuffer));
  end;

  if Count > 0 then // β���� 0
  begin
    Done := Source.Read(TempIn, Count);
    if Done < Count then
      raise EStreamError.Create(SCnErrorDESReadError);
    FillChar(TempIn[Count], SizeOf(TempIn) - Count, 0);

    DesData(dmEncry, SubKey1, TempIn, TempOut);
    DesData(dmDecry, SubKey2, TempOut, TempIn);
    DesData(dmEncry, SubKey3, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);
  end;
end;

procedure TripleDESDecryptStreamECB(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; Dest: TStream); overload;
var
  K1, K2, K3: TCnDESKey;
  TempIn, TempOut: TCnDESBuffer;
  Done: Cardinal;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;
  if (Count mod SizeOf(TCnDESBuffer)) > 0 then
    raise ECnDESException.Create(SCnErrorDESInvalidInBufSize);

  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError.Create(SCnErrorDESReadError);

    DesData(dmDecry, SubKey3, TempIn, TempOut);
    DesData(dmEncry, SubKey2, TempOut, TempIn);
    DesData(dmDecry, SubKey1, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);

    Dec(Count, SizeOf(TCnDESBuffer));
  end;
end;

procedure TripleDESEncryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
var
  K1, K2, K3: TCnDESKey;
  TempIn, TempOut: TCnDESBuffer;
  Vector: TCnDESIv;
  Done: Cardinal;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;

  Vector := InitVector;
  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError.Create(SCnErrorDESReadError);

    PCardinal(@TempIn[0])^ := PCardinal(@TempIn[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@TempIn[4])^ := PCardinal(@TempIn[4])^ xor PCardinal(@Vector[4])^;

    DesData(dmEncry, SubKey1, TempIn, TempOut);
    DesData(dmDecry, SubKey2, TempOut, TempIn);
    DesData(dmEncry, SubKey3, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);

    Move(TempOut[0], Vector[0], SizeOf(TCnDESIv));
    Dec(Count, SizeOf(TCnDESBuffer));
  end;

  if Count > 0 then
  begin
    Done := Source.Read(TempIn, Count);
    if Done < Count then
      raise EStreamError.Create(SCnErrorDESReadError);
    FillChar(TempIn[Count], SizeOf(TempIn) - Count, 0);

    PCardinal(@TempIn[0])^ := PCardinal(@TempIn[0])^ xor PCardinal(@Vector[0])^;
    PCardinal(@TempIn[4])^ := PCardinal(@TempIn[4])^ xor PCardinal(@Vector[4])^;

    DesData(dmEncry, SubKey1, TempIn, TempOut);
    DesData(dmDecry, SubKey2, TempOut, TempIn);
    DesData(dmEncry, SubKey3, TempIn, TempOut);

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError.Create(SCnErrorDESWriteError);
  end;
end;

procedure TripleDESDecryptStreamCBC(Source: TStream; Count: Cardinal;
  const Key: TCn3DESKey; const InitVector: TCnDESIv; Dest: TStream); overload;
var
  K1, K2, K3: TCnDESKey;
  TempIn, TempOut: TCnDESBuffer;
  Vector1, Vector2: TCnDESIv;
  Done: Cardinal;
  SubKey1, SubKey2, SubKey3: TSubKey;
begin
  if Count = 0 then
  begin
    Source.Position := 0;
    Count := Source.Size;
  end
  else
    Count := Min(Count, Source.Size - Source.Position);

  if Count = 0 then
    Exit;
  if (Count mod SizeOf(TCnDESBuffer)) > 0 then
    raise ECnDESException.Create(SCnErrorDESInvalidInBufSize);

  Vector1 := InitVector;
  Make3DESKeys(Key, K1, K2, K3);
  MakeKey(K1, SubKey1);
  MakeKey(K2, SubKey2);
  MakeKey(K3, SubKey3);

  while Count >= SizeOf(TCnDESBuffer) do
  begin
    Done := Source.Read(TempIn, SizeOf(TempIn));
    if Done < SizeOf(TempIn) then
      raise EStreamError(SCnErrorDESReadError);

    Move(TempIn[0], Vector2[0], SizeOf(TCnDESIv));

    DesData(dmDecry, SubKey3, TempIn, TempOut);
    DesData(dmEncry, SubKey2, TempOut, TempIn);
    DesData(dmDecry, SubKey1, TempIn, TempOut);

    PCardinal(@TempOut[0])^ := PCardinal(@TempOut[0])^ xor PCardinal(@Vector1[0])^;
    PCardinal(@TempOut[4])^ := PCardinal(@TempOut[4])^ xor PCardinal(@Vector1[4])^;

    Done := Dest.Write(TempOut, SizeOf(TempOut));
    if Done < SizeOf(TempOut) then
      raise EStreamError(SCnErrorDESWriteError);

    Vector1 := Vector2;
    Dec(Count, SizeOf(TCnDESBuffer));
  end;
end;

end.
