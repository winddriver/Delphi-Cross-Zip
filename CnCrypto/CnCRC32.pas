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

unit CnCRC32;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ�CRC ѭ������У�鵥Ԫ
* ��Ԫ���ߣ��ܾ��� (zjy@cnpack.org)
* ��    ע������Ԫʵ���� CRC8/CRC16/CRC32/CRC64 ѭ������У���㷨��
*           ע������ CRC �㷨�Ĺ淶������ʽ���ڶ������������Ԫ�е� CRC �㷨��ע����
*           ��淶���� CCITT������ʼֵ�����ֵ��ʹ�õĶ���ʽ��
*           ʹ��ʱ��������������������ļ����в�����������˶���Ӧ�����Ƿ�һ�¡�      
*
* ����ƽ̨��PWin2000Pro + Delphi 5.0
* ���ݲ��ԣ�PWin9X/2000/XP + Delphi 5/6
* �� �� �����õ�Ԫ�е��ַ��������ϱ��ػ�����ʽ
* �޸ļ�¼��2021.02.08 V1.7
*               ���� CRC8/CRC16 ��֧�ֲ�ע�����͡�����ʽ���ʼֵ��������ֵ
*           2019.12.12 V1.6
*               ֧�� TBytes
*           2019.04.15 V1.5
*               ֧�� Win32/Win64/MacOS
*           2015.06.12 V1.4
*               �ѻ���дΪ Pascal ����Ӧ 64 λ������
*           2009.08.21 V1.3
*               ���� CRC64 ��֧��
*           2009.07.31 V1.2
*               ����������ļ� CRC32 ����ȷ�����⣬���ӶԴ��� 4G �ļ���֧��
*           2009.04.16 V1.1
*               ����һ���������������
*           2002.08.11 V1.0
*               ������Ԫ
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, CnNative {$IFDEF MSWINDOWS}, Windows {$ENDIF};

//------------------------------------------------------------------------------
// CRC8 ϵ�к�����CCITT������ʼֵ $00��������ֵ $00������ʽΪ x8+x2+x+1
//------------------------------------------------------------------------------

function CalcCRC8Byte(OrgCRC8: Byte; B: Byte): Byte;
{* CRC8 ���㵥���ֽڣ�����������ʹ�á�

   ������
     OrgCRC8: Byte                        - ԭʼ�� CRC8 ֵ
     B: Byte                              - ���ֽ�ֵ

   ����ֵ��Byte                           - ���ؼ�����
}

function CRC8Calc(OrgCRC8: Byte; const Data; ByteLength: Cardinal): Byte;
{* �������ݿ�� CRC8 ֵ��

   ������
     OrgCRC8: Byte                        - ԭʼ�� CRC8 ֵ��Ĭ�Ͽɴ� 0
     const Data                           - ����������ݿ飬һ�㲻����ַ������������
     ByteLength: Cardinal                 - ����������ݿ��ֽڳ���

   ����ֵ��Byte                           - ���� CRC8 ������
}

function StrCRC8(OrgCRC8: Byte; const Text: string): Byte;
{* �����ַ����� CRC8 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC8: Byte                        - ԭʼ�� CRC8 ֵ
     const Text: string                   - ��������ַ���

   ����ֵ��Byte                           - ���� CRC8 ������
}

function StrCRC8A(OrgCRC8: Byte; const Text: AnsiString): Byte;
{* ���� AnsiString �������ݵ� CRC8 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC8: Byte                        - ԭʼ�� CRC8 ֵ
     const Text: AnsiString               - ��������ַ���

   ����ֵ��Byte                           - ���� CRC8 ������
}

function BytesCRC8(OrgCRC8: Byte; Data: TBytes): Byte;
{* �����ֽ������ CRC8 ֵ��

   ������
     OrgCRC8: Byte                        - ԭʼ�� CRC8 ֵ
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��Byte                           - ���� CRC8 ������
}

function FileCRC8(const Filename: string; var CRC: Byte; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
{* �����ļ��� CRC8 ֵ��֧�ֳ��� 4G �Ĵ��ļ���

   ������
     const Filename: string               - ��������ļ���
     var CRC: Byte                        - ԭʼ CRC8 ֵ��Ĭ�Ͽɴ� 0�����������
     StartPos: Int64                      - �ļ���ʼƫ������Ĭ��Ϊ 0�������ͷ��ʼ
     ByteLength: Int64                    - �ļ����ݼ��㳤�ȣ�Ĭ��Ϊ 0�����������ļ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

//------------------------------------------------------------------------------
// CRC16 ϵ�к�����CCITT������ʼֵ $FFFF��������ֵ $0000������ʽΪ x16+x12+x5+1
//------------------------------------------------------------------------------

function CalcCRC16Byte(OrgCRC16: Word; B: Byte): Word;
{* CRC16 ���㵥���ֽڣ�����������ʹ�á�

   ������
     OrgCRC16: Word                       - ԭʼ�� CRC16 ֵ
     B: Byte                              - ���ֽ�ֵ

   ����ֵ��Word                           - ���� CRC16 ������
}

function CRC16Calc(OrgCRC16: Word; const Data; ByteLength: Cardinal): Word;
{* �������ݿ�� CRC16 ֵ��

   ������
     OrgCRC16: Word                       - ԭʼ�� CRC16 ֵ��Ĭ��Ӧ�� 0���ڲ����󷴱�� FFFF �Է��� CCITT ��Ҫ��
     const Data                           - ����������ݿ飬һ�㲻����ַ������������
     ByteLength: Cardinal                 - ����������ݿ���ֽڳ���

   ����ֵ��Word                           - ���� CRC16 ������
}

function StrCRC16(OrgCRC16: Word; const Text: string): Word;
{* �����ַ����� CRC16 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC16: Word                       - ԭʼ�� CRC16 ֵ
     const Text: string                   - ��������ַ���

   ����ֵ��Word                           - ���� CRC16 ������
}

function StrCRC16A(OrgCRC16: Word; const Text: AnsiString): Word;
{* ���� AnsiString �������ݵ� CRC16 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC16: Word                       - ԭʼ�� CRC16 ֵ
     const Text: AnsiString               - ��������ַ���

   ����ֵ��Word                           - ���� CRC16 ������
}

function BytesCRC16(OrgCRC16: Word; Data: TBytes): Word;
{* �����ֽ������ CRC16 ֵ��

   ������
     OrgCRC16: Word                       - ԭʼ�� CRC16 ֵ
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��Word                           - ���� CRC16 ������
}

function FileCRC16(const FileName: string; var CRC: Word; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
{* �����ļ��� CRC16 ֵ��֧�ֳ��� 4G �Ĵ��ļ���

   ������
     const FileName: string               - ��������ļ���
     var CRC: Word                        - ԭʼ CRC16 ֵ��Ĭ�Ͽɴ� 0�����������
     StartPos: Int64                      - �ļ���ʼƫ������Ĭ��Ϊ 0�������ͷ��ʼ
     ByteLength: Int64                    - �ļ����ݼ��㳤�ȣ�Ĭ��Ϊ 0�����������ļ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

//------------------------------------------------------------------------------
// CRC32 ϵ�к�������ʼֵ $FFFFFFFF��������ֵ $FFFFFFFF
// ����ʽΪ x32+x26+x23+x22+x16+x12+x11+x10+x8+x7+x5+x4+x2+x+1
//------------------------------------------------------------------------------

function CalcCRC32Byte(OrgCRC32: Cardinal; B: Byte): Cardinal;
{* CRC32 ���㵥���ֽڣ�����������ʹ�á�

   ������
     OrgCRC32: Cardinal                   - ԭʼ�� CRC32 ֵ
     B: Byte                              - ���ֽ�ֵ

   ����ֵ��Cardinal                       - ���� CRC32 ������
}

function CRC32Calc(OrgCRC32: Cardinal; const Data; ByteLength: Cardinal): Cardinal;
{* �������ݿ�� CRC32 ֵ��

   ������
     OrgCRC32: Cardinal                   - ԭʼ�� CRC32 ֵ��Ĭ��Ӧ�� 0���ڲ����󷴱�� FFFFFFFF �Է��� CCITT ��Ҫ��
     const Data                           - ����������ݿ飬һ�㲻����ַ������������
     ByteLength: Cardinal                 - ����������ݿ��ֽڳ���

   ����ֵ��Cardinal                       - ���� CRC32 ������������ FFFFFFFF �������Է��� CCITT ��Ҫ��
}

function StrCRC32(OrgCRC32: Cardinal; const Text: string): Cardinal;
{* �����ַ����� CRC32 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC32: Cardinal                   - ԭʼ�� CRC32 ֵ
     const Text: string                   - ��������ַ���

   ����ֵ��Cardinal                       - ���� CRC32 ������
}

function StrCRC32A(OrgCRC32: Cardinal; const Text: AnsiString): Cardinal;
{* ���� AnsiString �������ݵ� CRC32 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC32: Cardinal                   - ԭʼ�� CRC32 ֵ
     const Text: AnsiString               - ��������ַ���

   ����ֵ��Cardinal                       - ���� CRC32 ������
}

function BytesCRC32(OrgCRC32: Cardinal; Data: TBytes): Cardinal;
{* �����ֽ������ CRC32 ֵ��

   ������
     OrgCRC32: Cardinal                   - ԭʼ�� CRC32 ֵ
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��Cardinal                       - ���� CRC32 ������
}

function FileCRC32(const FileName: string; var CRC: Cardinal; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
{* �����ļ��� CRC32 ֵ��֧�ֳ��� 4G �Ĵ��ļ���

   ������
     const FileName: string               - ��������ļ���
     var CRC: Cardinal                    - ԭʼ CRC32 ֵ��Ĭ�Ͽɴ� 0�����������
     StartPos: Int64                      - �ļ���ʼƫ������Ĭ��Ϊ 0�������ͷ��ʼ
     ByteLength: Int64                    - �ļ����ݼ��㳤�ȣ�Ĭ��Ϊ 0�����������ļ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

//------------------------------------------------------------------------------
// CRC64 ϵ�к�����ECMA������ʼֵ $FFFFFFFFFFFFFFFF��������ֵ $FFFFFFFFFFFFFFFF
// ����ʽΪ
// x64+x62+x57+x55+x54+x53+x52+x47+x46+x45+x40+x39+x38+x37+x35+x33+
// x32+x31+x29+x27+x24+x23+x22+x21+x19+x17+x13+x12+x10+x9+x7+x4+x+1
//------------------------------------------------------------------------------

function CRC64Calc(OrgCRC64: Int64; const Data; ByteLength: Cardinal): Int64;
{* �������ݿ�� CRC64 ֵ��

   ������
     OrgCRC64: Int64                      - ԭʼ�� CRC64 ֵ��Ĭ��Ӧ�� 0���ڲ����󷴱�� FFFFFFFFFFFFFFFF �Է��� CCITT ��Ҫ��
     const Data                           - ����������ݿ飬һ�㲻����ַ������������
     ByteLength: Cardinal                 - ����������ݿ��ֽڳ���

   ����ֵ��Int64                          - ���� CRC64 ������������ FFFFFFFFFFFFFFFF �������Է��� CCITT ��Ҫ��
}

function StrCRC64(OrgCRC64: Int64; const Text: string): Int64;
{* �����ַ����� CRC64 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC64: Int64                      - ԭʼ�� CRC64 ֵ
     const Text: string                   - ��������ַ���

   ����ֵ��Int64                          - ���� CRC64 ������
}

function StrCRC64A(OrgCRC64: Int64; const Text: AnsiString): Int64;
{* ���� AnsiString �������ݵ� CRC64 ֵ��ֱ�Ӽ������ڲ����ݣ�������ת����

   ������
     OrgCRC64: Int64                      - ԭʼ�� CRC64 ֵ
     const Text: AnsiString               - ��������ַ���

   ����ֵ��Int64                          - ���� CRC64 ������
}

function BytesCRC64(OrgCRC64: Int64; Data: TBytes): Int64;
{* �����ֽ������ CRC64 ֵ��

   ������
     OrgCRC64: Int64                      - ԭʼ�� CRC64 ֵ
     Data: TBytes                         - ��������ֽ�����

   ����ֵ��Int64                          - ���� CRC64 ������
}

function FileCRC64(const FileName: string; var CRC: Int64; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
{* �����ļ��� CRC64 ֵ��֧�ֳ��� 4G �Ĵ��ļ���

   ������
     const FileName: string               - ��������ļ���
     var CRC: Int64                       - ԭʼ CRC64 ֵ��Ĭ�Ͽɴ� 0�����������
     StartPos: Int64                      - �ļ���ʼƫ������Ĭ��Ϊ 0�������ͷ��ʼ
     ByteLength: Int64                    - �ļ����ݼ��㳤�ȣ�Ĭ��Ϊ 0�����������ļ�

   ����ֵ��Boolean                        - ���ؼ����Ƿ�ɹ�
}

function CRC32Hmac(Key: PAnsiChar; KeyLength: Integer; Input: PAnsiChar;
  ByteLength: Cardinal): Cardinal;
{* ���� CRC32 �� HMAC��Hash-based Message Authentication Code�����㣬
   ����ͨ���ݵļ����ϼ�����Կ�ĸ��Ҳ�м��Ρ�

   ������
     Key: PAnsiChar                       - ������ CRC32 �������Կ���ݿ��ַ
     KeyLength: Integer                   - ������ CRC32 �������Կ���ݿ��ֽڳ��ȣ��糬�� 4 �ֽڣ�����Ƚ���һ�� CRC32 ���㣬�� 4 �ֽڽ����Ϊ��Կ
     Input: PAnsiChar                     - ����������ݿ��ַ
     ByteLength: Cardinal                 - ����������ݿ��ֽڳ���

   ����ֵ��Cardinal                       - ���� CRC32 ������
}

function CRC64Hmac(Key: PAnsiChar; KeyLength: Integer; Input: PAnsiChar;
  ByteLength: Cardinal): Int64;
{* ���� CRC64 �� HMAC��Hash-based Message Authentication Code�����㣬
   ����ͨ���ݵļ����ϼ�����Կ�ĸ��Ҳ�м��Ρ�

   ������
     Key: PAnsiChar                       - ������ CRC64 �������Կ���ݿ��ַ
     KeyLength: Integer                   - ������ CRC64 �������Կ���ݿ��ֽڳ��ȣ��糬�� 4 �ֽڣ�����Ƚ���һ�� CRC64 ���㣬�� 8 �ֽڽ����ǰ 4 �ֽ���Ϊ��Կ
     Input: PAnsiChar                     - ����������ݿ��ַ
     ByteLength: Cardinal                 - ����������ݿ��ֽڳ���

   ����ֵ��Int64                          - ���� CRC64 ������
}

implementation

const
  BUFF_SIZE = 4096;
  CODE_CRC64 = $C96C5795D7870F42;

  HMAC_CRC32_BLOCK_SIZE_BYTE = 4;
  HMAC_CRC32_OUTPUT_LENGTH_BYTE = 4;

  HMAC_CRC64_BLOCK_SIZE_BYTE = 4;
  HMAC_CRC64_OUTPUT_LENGTH_BYTE = 4;

type
  // �ļ�������
  PBuff = ^TBuff;
  TBuff = array[0..BUFF_SIZE - 1] of Byte;

  // CRC8 ��
  TCRC8Table = array[0..255] of Byte;

  // CRC16 ��
  TCRC16Table = array[0..255] of Word;

  // CRC32 ��
  TCRC32Table = array[0..255] of Cardinal;

  // CRC64 ��
  TCRC64Table = array[0..255] of Int64;

var
  CRC8Table: TCRC8Table = (
    $00, $07, $0E, $09, $1C, $1B, $12, $15,
    $38, $3F, $36, $31, $24, $23, $2A, $2D,
    $70, $77, $7E, $79, $6C, $6B, $62, $65,
    $48, $4F, $46, $41, $54, $53, $5A, $5D,
    $E0, $E7, $EE, $E9, $FC, $FB, $F2, $F5,
    $D8, $DF, $D6, $D1, $C4, $C3, $CA, $CD,
    $90, $97, $9E, $99, $8C, $8B, $82, $85,
    $A8, $AF, $A6, $A1, $B4, $B3, $BA, $BD,
    $C7, $C0, $C9, $CE, $DB, $DC, $D5, $D2,
    $FF, $F8, $F1, $F6, $E3, $E4, $ED, $EA,
    $B7, $B0, $B9, $BE, $AB, $AC, $A5, $A2,
    $8F, $88, $81, $86, $93, $94, $9D, $9A,
    $27, $20, $29, $2E, $3B, $3C, $35, $32,
    $1F, $18, $11, $16, $03, $04, $0D, $0A,
    $57, $50, $59, $5E, $4B, $4C, $45, $42,
    $6F, $68, $61, $66, $73, $74, $7D, $7A,
    $89, $8E, $87, $80, $95, $92, $9B, $9C,
    $B1, $B6, $BF, $B8, $AD, $AA, $A3, $A4,
    $F9, $FE, $F7, $F0, $E5, $E2, $EB, $EC,
    $C1, $C6, $CF, $C8, $DD, $DA, $D3, $D4,
    $69, $6E, $67, $60, $75, $72, $7B, $7C,
    $51, $56, $5F, $58, $4D, $4A, $43, $44,
    $19, $1E, $17, $10, $05, $02, $0B, $0C,
    $21, $26, $2F, $28, $3D, $3A, $33, $34,
    $4E, $49, $40, $47, $52, $55, $5C, $5B,
    $76, $71, $78, $7F, $6A, $6D, $64, $63,
    $3E, $39, $30, $37, $22, $25, $2C, $2B,
    $06, $01, $08, $0F, $1A, $1D, $14, $13,
    $AE, $A9, $A0, $A7, $B2, $B5, $BC, $BB,
    $96, $91, $98, $9F, $8A, $8D, $84, $83,
    $DE, $D9, $D0, $D7, $C2, $C5, $CC, $CB,
    $E6, $E1, $E8, $EF, $FA, $FD, $F4, $F3);

  CRC16Table: TCRC16Table = (
    $0000, $1021, $2042, $3063, $4084, $50A5, $60C6, $70E7,
    $8108, $9129, $A14A, $B16B, $C18C, $D1AD, $E1CE, $F1EF,
    $1231, $0210, $3273, $2252, $52B5, $4294, $72F7, $62D6,
    $9339, $8318, $B37B, $A35A, $D3BD, $C39C, $F3FF, $E3DE,
    $2462, $3443, $0420, $1401, $64E6, $74C7, $44A4, $5485,
    $A56A, $B54B, $8528, $9509, $E5EE, $F5CF, $C5AC, $D58D,
    $3653, $2672, $1611, $0630, $76D7, $66F6, $5695, $46B4,
    $B75B, $A77A, $9719, $8738, $F7DF, $E7FE, $D79D, $C7BC,
    $48C4, $58E5, $6886, $78A7, $0840, $1861, $2802, $3823,
    $C9CC, $D9ED, $E98E, $F9AF, $8948, $9969, $A90A, $B92B,
    $5AF5, $4AD4, $7AB7, $6A96, $1A71, $0A50, $3A33, $2A12,
    $DBFD, $CBDC, $FBBF, $EB9E, $9B79, $8B58, $BB3B, $AB1A,
    $6CA6, $7C87, $4CE4, $5CC5, $2C22, $3C03, $0C60, $1C41,
    $EDAE, $FD8F, $CDEC, $DDCD, $AD2A, $BD0B, $8D68, $9D49,
    $7E97, $6EB6, $5ED5, $4EF4, $3E13, $2E32, $1E51, $0E70,
    $FF9F, $EFBE, $DFDD, $CFFC, $BF1B, $AF3A, $9F59, $8F78,
    $9188, $81A9, $B1CA, $A1EB, $D10C, $C12D, $F14E, $E16F,
    $1080, $00A1, $30C2, $20E3, $5004, $4025, $7046, $6067,
    $83B9, $9398, $A3FB, $B3DA, $C33D, $D31C, $E37F, $F35E,
    $02B1, $1290, $22F3, $32D2, $4235, $5214, $6277, $7256,
    $B5EA, $A5CB, $95A8, $8589, $F56E, $E54F, $D52C, $C50D,
    $34E2, $24C3, $14A0, $0481, $7466, $6447, $5424, $4405,
    $A7DB, $B7FA, $8799, $97B8, $E75F, $F77E, $C71D, $D73C,
    $26D3, $36F2, $0691, $16B0, $6657, $7676, $4615, $5634,
    $D94C, $C96D, $F90E, $E92F, $99C8, $89E9, $B98A, $A9AB,
    $5844, $4865, $7806, $6827, $18C0, $08E1, $3882, $28A3,
    $CB7D, $DB5C, $EB3F, $FB1E, $8BF9, $9BD8, $ABBB, $BB9A,
    $4A75, $5A54, $6A37, $7A16, $0AF1, $1AD0, $2AB3, $3A92,
    $FD2E, $ED0F, $DD6C, $CD4D, $BDAA, $AD8B, $9DE8, $8DC9,
    $7C26, $6C07, $5C64, $4C45, $3CA2, $2C83, $1CE0, $0CC1,
    $EF1F, $FF3E, $CF5D, $DF7C, $AF9B, $BFBA, $8FD9, $9FF8,
    $6E17, $7E36, $4E55, $5E74, $2E93, $3EB2, $0ED1, $1EF0);

  CRC32Table: TCRC32Table = (
    $00000000, $77073096, $EE0E612C, $990951BA,
    $076DC419, $706AF48F, $E963A535, $9E6495A3,
    $0EDB8832, $79DCB8A4, $E0D5E91E, $97D2D988,
    $09B64C2B, $7EB17CBD, $E7B82D07, $90BF1D91,
    $1DB71064, $6AB020F2, $F3B97148, $84BE41DE,
    $1ADAD47D, $6DDDE4EB, $F4D4B551, $83D385C7,
    $136C9856, $646BA8C0, $FD62F97A, $8A65C9EC,
    $14015C4F, $63066CD9, $FA0F3D63, $8D080DF5,
    $3B6E20C8, $4C69105E, $D56041E4, $A2677172,
    $3C03E4D1, $4B04D447, $D20D85FD, $A50AB56B,
    $35B5A8FA, $42B2986C, $DBBBC9D6, $ACBCF940,
    $32D86CE3, $45DF5C75, $DCD60DCF, $ABD13D59,
    $26D930AC, $51DE003A, $C8D75180, $BFD06116,
    $21B4F4B5, $56B3C423, $CFBA9599, $B8BDA50F,
    $2802B89E, $5F058808, $C60CD9B2, $B10BE924,
    $2F6F7C87, $58684C11, $C1611DAB, $B6662D3D,
    $76DC4190, $01DB7106, $98D220BC, $EFD5102A,
    $71B18589, $06B6B51F, $9FBFE4A5, $E8B8D433,
    $7807C9A2, $0F00F934, $9609A88E, $E10E9818,
    $7F6A0DBB, $086D3D2D, $91646C97, $E6635C01,
    $6B6B51F4, $1C6C6162, $856530D8, $F262004E,
    $6C0695ED, $1B01A57B, $8208F4C1, $F50FC457,
    $65B0D9C6, $12B7E950, $8BBEB8EA, $FCB9887C,
    $62DD1DDF, $15DA2D49, $8CD37CF3, $FBD44C65,
    $4DB26158, $3AB551CE, $A3BC0074, $D4BB30E2,
    $4ADFA541, $3DD895D7, $A4D1C46D, $D3D6F4FB,
    $4369E96A, $346ED9FC, $AD678846, $DA60B8D0,
    $44042D73, $33031DE5, $AA0A4C5F, $DD0D7CC9,
    $5005713C, $270241AA, $BE0B1010, $C90C2086,
    $5768B525, $206F85B3, $B966D409, $CE61E49F,
    $5EDEF90E, $29D9C998, $B0D09822, $C7D7A8B4,
    $59B33D17, $2EB40D81, $B7BD5C3B, $C0BA6CAD,
    $EDB88320, $9ABFB3B6, $03B6E20C, $74B1D29A,
    $EAD54739, $9DD277AF, $04DB2615, $73DC1683,
    $E3630B12, $94643B84, $0D6D6A3E, $7A6A5AA8,
    $E40ECF0B, $9309FF9D, $0A00AE27, $7D079EB1,
    $F00F9344, $8708A3D2, $1E01F268, $6906C2FE,
    $F762575D, $806567CB, $196C3671, $6E6B06E7,
    $FED41B76, $89D32BE0, $10DA7A5A, $67DD4ACC,
    $F9B9DF6F, $8EBEEFF9, $17B7BE43, $60B08ED5,
    $D6D6A3E8, $A1D1937E, $38D8C2C4, $4FDFF252,
    $D1BB67F1, $A6BC5767, $3FB506DD, $48B2364B,
    $D80D2BDA, $AF0A1B4C, $36034AF6, $41047A60,
    $DF60EFC3, $A867DF55, $316E8EEF, $4669BE79,
    $CB61B38C, $BC66831A, $256FD2A0, $5268E236,
    $CC0C7795, $BB0B4703, $220216B9, $5505262F,
    $C5BA3BBE, $B2BD0B28, $2BB45A92, $5CB36A04,
    $C2D7FFA7, $B5D0CF31, $2CD99E8B, $5BDEAE1D,
    $9B64C2B0, $EC63F226, $756AA39C, $026D930A,
    $9C0906A9, $EB0E363F, $72076785, $05005713,
    $95BF4A82, $E2B87A14, $7BB12BAE, $0CB61B38,
    $92D28E9B, $E5D5BE0D, $7CDCEFB7, $0BDBDF21,
    $86D3D2D4, $F1D4E242, $68DDB3F8, $1FDA836E,
    $81BE16CD, $F6B9265B, $6FB077E1, $18B74777,
    $88085AE6, $FF0F6A70, $66063BCA, $11010B5C,
    $8F659EFF, $F862AE69, $616BFFD3, $166CCF45,
    $A00AE278, $D70DD2EE, $4E048354, $3903B3C2,
    $A7672661, $D06016F7, $4969474D, $3E6E77DB,
    $AED16A4A, $D9D65ADC, $40DF0B66, $37D83BF0,
    $A9BCAE53, $DEBB9EC5, $47B2CF7F, $30B5FFE9,
    $BDBDF21C, $CABAC28A, $53B39330, $24B4A3A6,
    $BAD03605, $CDD70693, $54DE5729, $23D967BF,
    $B3667A2E, $C4614AB8, $5D681B02, $2A6F2B94,
    $B40BBE37, $C30C8EA1, $5A05DF1B, $2D02EF8D
  );

  CRC64Table: TCRC64Table;

//------------------------------------------------------------------------------
// CRC8 ϵ�к���
//------------------------------------------------------------------------------

function CalcCRC8Byte(OrgCRC8: Byte; B: Byte): Byte;
begin
  Result := CRC8Table[OrgCRC8 xor B];
end;

// ���� CRC8 ֵ
function DoCRC8Calc(const OrgCRC8: Byte; const Data; ByteLength: Cardinal): Byte;
var
  P: PByte;
begin
  Result := OrgCRC8;
  if (@Data = nil) or (ByteLength = 0) then
    Exit;

  P := PByte(@Data);
  while ByteLength > 0 do
  begin
    Result := CRC8Table[Result xor P^];

    Inc(P);
    Dec(ByteLength);
  end;
end;

// ���� CRC8 ֵ
function CRC8Calc(OrgCRC8: Byte; const Data; ByteLength: Cardinal): Byte;
begin
  Result := DoCRC8Calc(OrgCRC8, Data, ByteLength); // CRC8 ��ʼֵΪ 0��������
end;

// �����ַ����� CRC8 ֵ
function StrCRC8(OrgCRC8: Byte; const Text: string): Byte;
begin
  Result := CRC8Calc(OrgCRC8, PChar(Text)^, Length(Text) * SizeOf(Char));
end;

// ���� AnsiString �ַ����� CRC8 ֵ
function StrCRC8A(OrgCRC8: Byte; const Text: AnsiString): Byte;
begin
  Result := CRC8Calc(OrgCRC8, PAnsiChar(Text)^, Length(Text));
end;

// ���� TBytes �� CRC8 ֵ
function BytesCRC8(OrgCRC8: Byte; Data: TBytes): Byte;
begin
  Result := CRC8Calc(OrgCRC8, PAnsiChar(Data[0])^, Length(Data));
end;

{$IFNDEF MSWINDOWS}

function InternalCRC8Stream(Stream: TStream; const BufSize: Cardinal;
  var CRC: Byte): Boolean;
var
  Buf: PAnsiChar;
  BufLen: Cardinal;
  Size: Int64;
  ReadBytes: Cardinal;
  TotalBytes: Int64;
  SavePos: Int64;
begin
  Result := False;
  Size := Stream.Size;
  if Size = 0 then
    Exit;

  SavePos := Stream.Position;
  TotalBytes := 0;

  if Size < BufSize then
    BufLen := Size
  else
    BufLen := BufSize;

  GetMem(Buf, BufLen);
  try
    Stream.Position := 0;
    repeat
      ReadBytes := Stream.Read(Buf^, BufLen);
      if ReadBytes <> 0 then
      begin
        Inc(TotalBytes, ReadBytes);
        CRC := DoCrc8Calc(CRC, Buf^, ReadBytes);
      end;
    until (ReadBytes = 0) or (TotalBytes = Size);
    Result := True;
  finally
    FreeMem(Buf, BufLen);
    Stream.Position := SavePos;
  end;
end;

{$ENDIF}

// �����ļ� CRC8 ֵ�������ֱ�Ϊ���ļ�����CRC8 ֵ����ʼ��ַ�����㳤��
function FileCRC8(const FileName: string; var CRC: Byte; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
var
{$IFDEF MSWINDOWS}
  Handle: THandle;
  ReadCount: Integer;
  Size: Int64;
  Count: Int64;
  Buff: TBuff;
{$ELSE}
  Stream: TStream;
{$ENDIF}
begin
{$IFDEF MSWINDOWS}
  // �Թ������ʽ���ļ�
  Handle := CreateFile(PChar(FileName), GENERIC_READ,
    FILE_SHARE_READ, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0);
  Result := Handle <> INVALID_HANDLE_VALUE;
  if Result then
  try
    Int64Rec(Size).Lo := GetFileSize(Handle, @Int64Rec(Size).Hi);
    if Size < StartPos + ByteLength then
    begin
      Result := False;                  // �����ļ�����
      Exit;
    end;
    if ByteLength > 0 then
      Count := ByteLength
    else
      Count := Size - StartPos;         // ����Ϊ�㣬���㵽�ļ�β

    CRC := not CRC;
    SetFilePointer(Handle, Int64Rec(StartPos).Lo, @Int64Rec(StartPos).Hi, FILE_BEGIN);
    while Count > 0 do
    begin
      if Count > SizeOf(Buff) then
        ReadCount := SizeOf(Buff)
      else
        ReadCount := Count;
      ReadFile(Handle, Buff, ReadCount, Cardinal(ReadCount), nil);
      CRC := DoCrc8Calc(CRC, Buff, ReadCount);
      Dec(Count, ReadCount);
    end;
    CRC := not CRC;
  finally
    CloseHandle(Handle);
  end;
{$ELSE} // �� Windows ƽֱ̨�����ļ���
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := InternalCRC8Stream(Stream, 4096 * 1024, CRC);
  finally
    Stream.Free;
  end;
{$ENDIF}
end;

//------------------------------------------------------------------------------
// CRC16 ϵ�к���
//------------------------------------------------------------------------------

function CalcCRC16Byte(OrgCRC16: Word; B: Byte): Word;
begin
  Result := ((OrgCRC16 shl 8) or B) xor CRC16Table[OrgCRC16 shr 8];
end;

// ���� CRC16 ֵ
function DoCRC16Calc(const OrgCRC16: Word; const Data; Len: Cardinal): Word;
var
  P: PByte;
begin
  Result := OrgCRC16;
  if (@Data = nil) or (Len = 0) then
    Exit;

  P := PByte(@Data);
  while Len > 0 do
  begin                     // ������ or �Ƚ����
    Result := ((Result shl 8) or P^) xor CRC16Table[Result shr 8];
    Inc(P);
    Dec(Len);
  end;

  Result := (Result shl 8) xor CRC16Table[Result shr 8];
  Result := (Result shl 8) xor CRC16Table[Result shr 8];
end;

// ���� CRC16 ֵ
function CRC16Calc(OrgCRC16: Word; const Data; ByteLength: Cardinal): Word;
begin
  Result := not OrgCRC16;   // �� CRC16 ��ʼֵΪ FFFF
  Result := DoCRC16Calc(Result, Data, ByteLength);
end;

// �����ַ����� CRC16 ֵ
function StrCRC16(OrgCRC16: Word; const Text: string): Word;
begin
  Result := CRC16Calc(OrgCRC16, PChar(Text)^, Length(Text) * SizeOf(Char));
end;

// ���� AnsiString �ַ����� CRC16 ֵ
function StrCRC16A(OrgCRC16: Word; const Text: AnsiString): Word;
begin
  Result := CRC16Calc(OrgCRC16, PAnsiChar(Text)^, Length(Text));
end;

// ���� TBytes �� CRC16 ֵ
function BytesCRC16(OrgCRC16: Word; Data: TBytes): Word;
begin
  Result := CRC16Calc(OrgCRC16, PAnsiChar(Data[0])^, Length(Data));
end;

{$IFNDEF MSWINDOWS}

function InternalCRC16Stream(Stream: TStream; const BufSize: Cardinal;
  var CRC: Word): Boolean;
var
  Buf: PAnsiChar;
  BufLen: Cardinal;
  Size: Int64;
  ReadBytes: Cardinal;
  TotalBytes: Int64;
  SavePos: Int64;
begin
  Result := False;
  Size := Stream.Size;
  if Size = 0 then
    Exit;

  SavePos := Stream.Position;
  TotalBytes := 0;

  if Size < BufSize then
    BufLen := Size
  else
    BufLen := BufSize;

  GetMem(Buf, BufLen);
  try
    Stream.Position := 0;
    repeat
      ReadBytes := Stream.Read(Buf^, BufLen);
      if ReadBytes <> 0 then
      begin
        Inc(TotalBytes, ReadBytes);
        CRC := DoCrc16Calc(CRC, Buf^, ReadBytes);
      end;
    until (ReadBytes = 0) or (TotalBytes = Size);
    Result := True;
  finally
    FreeMem(Buf, BufLen);
    Stream.Position := SavePos;
  end;
end;

{$ENDIF}

// �����ļ� CRC16 ֵ�������ֱ�Ϊ���ļ�����CRC16 ֵ����ʼ��ַ�����㳤��
function FileCRC16(const FileName: string; var CRC: Word; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
var
{$IFDEF MSWINDOWS}
  Handle: THandle;
  ReadCount: Integer;
  Size: Int64;
  Count: Int64;
  Buff: TBuff;
{$ELSE}
  Stream: TStream;
{$ENDIF}
begin
{$IFDEF MSWINDOWS}
  // �Թ������ʽ���ļ�
  Handle := CreateFile(PChar(FileName), GENERIC_READ,
    FILE_SHARE_READ, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0);
  Result := Handle <> INVALID_HANDLE_VALUE;
  if Result then
  try
    Int64Rec(Size).Lo := GetFileSize(Handle, @Int64Rec(Size).Hi);
    if Size < StartPos + ByteLength then
    begin
      Result := False;                  // �����ļ�����
      Exit;
    end;
    if ByteLength > 0 then
      Count := ByteLength
    else
      Count := Size - StartPos;         // ����Ϊ�㣬���㵽�ļ�β

    CRC := not CRC;
    SetFilePointer(Handle, Int64Rec(StartPos).Lo, @Int64Rec(StartPos).Hi, FILE_BEGIN);
    while Count > 0 do
    begin
      if Count > SizeOf(Buff) then
        ReadCount := SizeOf(Buff)
      else
        ReadCount := Count;
      ReadFile(Handle, Buff, ReadCount, Cardinal(ReadCount), nil);
      CRC := DoCrc16Calc(CRC, Buff, ReadCount);
      Dec(Count, ReadCount);
    end;
    CRC := not CRC;
  finally
    CloseHandle(Handle);
  end;
{$ELSE} // �� Windows ƽֱ̨�����ļ���
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := InternalCRC16Stream(Stream, 4096 * 1024, CRC);
  finally
    Stream.Free;
  end;
{$ENDIF}
end;

//------------------------------------------------------------------------------
// CRC32 ϵ�к���
//------------------------------------------------------------------------------

function CalcCRC32Byte(OrgCRC32: Cardinal; B: Byte): Cardinal;
begin
  Result := ((OrgCRC32 shr 8) and $FFFFFF) xor CRC32Table[(OrgCRC32 and $FF) xor B];
end;

// ���� CRC32 ֵ
function DoCRC32Calc(OrgCRC32: Cardinal; const Data; Len: Cardinal): Cardinal;
var
  P: PByte;
begin
  Result := OrgCRC32;
  if (@Data = nil) or (Len = 0) then
    Exit;

  P := PByte(@Data);
  while Len > 0 do
  begin
    Result := ((Result shr 8) and $FFFFFF) xor CRC32Table[(Result and $FF) xor P^]; // CalcCRC32Byte(Result, P^);

    Inc(P);
    Dec(Len);
  end;
end;

// ���� CRC32 ֵ
function CRC32Calc(OrgCRC32: Cardinal; const Data; ByteLength: Cardinal): Cardinal;
begin
  Result := not OrgCRC32;   // �� CRC32 �㷨��ʼֵ FFFFFFFF
  Result := DoCRC32Calc(Result, Data, ByteLength);
  Result := not Result;     // �� CRC32 �㷨������ֵ FFFFFFFF
end;

// �����ַ����� CRC32 ֵ
function StrCRC32(OrgCRC32: Cardinal; const Text: string): Cardinal;
begin
  Result := CRC32Calc(OrgCRC32, PChar(Text)^, Length(Text) * SizeOf(Char));
end;

// ���� AnsiString �ַ����� CRC32 ֵ
function StrCRC32A(OrgCRC32: Cardinal; const Text: AnsiString): Cardinal;
begin
  Result := CRC32Calc(OrgCRC32, PAnsiChar(Text)^, Length(Text));
end;

// ���� TBytes �� CRC32 ֵ
function BytesCRC32(OrgCRC32: Cardinal; Data: TBytes): Cardinal;
begin
  Result := CRC32Calc(OrgCRC32, PAnsiChar(Data[0])^, Length(Data));
end;

{$IFNDEF MSWINDOWS}

function InternalCRC32Stream(Stream: TStream; const BufSize: Cardinal;
  var CRC: Cardinal): Boolean;
var
  Buf: PAnsiChar;
  BufLen: Cardinal;
  Size: Int64;
  ReadBytes: Cardinal;
  TotalBytes: Int64;
  SavePos: Int64;
begin
  Result := False;
  Size := Stream.Size;
  if Size = 0 then
    Exit;

  SavePos := Stream.Position;
  TotalBytes := 0;

  if Size < BufSize then
    BufLen := Size
  else
    BufLen := BufSize;

  GetMem(Buf, BufLen);
  try
    Stream.Position := 0;
    repeat
      ReadBytes := Stream.Read(Buf^, BufLen);
      if ReadBytes <> 0 then
      begin
        Inc(TotalBytes, ReadBytes);
        CRC := DoCrc32Calc(CRC, Buf^, ReadBytes);
      end;
    until (ReadBytes = 0) or (TotalBytes = Size);
    Result := True;
  finally
    FreeMem(Buf, BufLen);
    Stream.Position := SavePos;
  end;
end;

{$ENDIF}

// �����ļ� CRC32 ֵ�������ֱ�Ϊ���ļ�����CRC32 ֵ����ʼ��ַ�����㳤��
function FileCRC32(const FileName: string; var CRC: Cardinal; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
var
{$IFDEF MSWINDOWS}
  Handle: THandle;
  ReadCount: Integer;
  Size: Int64;
  Count: Int64;
  Buff: TBuff;
{$ELSE}
  Stream: TStream;
{$ENDIF}
begin
{$IFDEF MSWINDOWS}
  // �Թ������ʽ���ļ�
  Handle := CreateFile(PChar(FileName), GENERIC_READ,
    FILE_SHARE_READ, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0);
  Result := Handle <> INVALID_HANDLE_VALUE;
  if Result then
  try
    Int64Rec(Size).Lo := GetFileSize(Handle, @Int64Rec(Size).Hi);
    if Size < StartPos + ByteLength then
    begin
      Result := False;                  // �����ļ�����
      Exit;
    end;
    if ByteLength > 0 then
      Count := ByteLength
    else
      Count := Size - StartPos;         // ����Ϊ�㣬���㵽�ļ�β

    CRC := not CRC;
    SetFilePointer(Handle, Int64Rec(StartPos).Lo, @Int64Rec(StartPos).Hi, FILE_BEGIN);
    while Count > 0 do
    begin
      if Count > SizeOf(Buff) then
        ReadCount := SizeOf(Buff)
      else
        ReadCount := Count;
      ReadFile(Handle, Buff, ReadCount, Cardinal(ReadCount), nil);
      CRC := DoCrc32Calc(CRC, Buff, ReadCount);
      Dec(Count, ReadCount);
    end;
    CRC := not CRC;
  finally
    CloseHandle(Handle);
  end;
{$ELSE} // �� Windows ƽֱ̨�����ļ���
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := InternalCRC32Stream(Stream, 4096 * 1024, CRC);
  finally
    Stream.Free;
  end;
{$ENDIF}
end;

//------------------------------------------------------------------------------
// CRC64 ϵ�к���
//------------------------------------------------------------------------------

procedure Make_CRC64Table;
var
  I, J: Integer;
  Data: Int64;
begin
  for I := 0 to 255 do
  begin
    Data := I;
    for J := 0 to 7 do
    begin
      if (Data and 1) <> 0 then
        Data := Data shr 1 xor CODE_CRC64
      else
        Data := Data shr 1;

      CRC64Table[I] := Data;
    end;
  end;
end;

function DoCRC64Calc(const OrgCRC64: Int64; const Data; Len: Cardinal): Int64;
var
  I: Integer;
  P: PByte;
begin
  Result := OrgCRC64;
  if (@Data = nil) or (Len = 0) then
    Exit;

  P := @Data;
  for I := 0 to Len - 1 do
  begin
    Result := Result shr 8 xor
      CRC64Table[Cardinal(Result) and $FF xor P^];
    Inc(P);
  end;
end;

// ���� CRC64 ֵ
function CRC64Calc(OrgCRC64: Int64; const Data; ByteLength: Cardinal): Int64;
begin
  Result := not OrgCRC64;   // �� CRC64 �㷨��ʼֵ FFFFFFFFFFFFFFFF
  Result := DoCRC64Calc(Result, Data, ByteLength);
  Result := not Result;     // �� CRC64 �㷨������ֵ FFFFFFFFFFFFFFFF
end;

// �����ַ����� CRC64 ֵ
function StrCRC64(OrgCRC64: Int64; const Text: string): Int64;
begin
  Result := CRC64Calc(OrgCRC64, PChar(Text)^, Length(Text) * SizeOf(Char));
end;

// ���� AnsiString �ַ����� CRC64 ֵ
function StrCRC64A(OrgCRC64: Int64; const Text: AnsiString): Int64;
begin
  Result := CRC64Calc(OrgCRC64, PAnsiChar(Text)^, Length(Text));
end;

// ���� TBytes �� CRC64 ֵ
function BytesCRC64(OrgCRC64: Int64; Data: TBytes): Int64;
begin
  Result := CRC64Calc(OrgCRC64, PAnsiChar(Data[0])^, Length(Data));
end;

{$IFNDEF MSWINDOWS}

function InternalCRC64Stream(Stream: TStream; const BufSize: Cardinal;
  var CRC: Int64): Boolean;
var
  Buf: PAnsiChar;
  BufLen: Cardinal;
  Size: Int64;
  ReadBytes: Cardinal;
  TotalBytes: Int64;
  SavePos: Int64;
begin
  Result := False;
  Size := Stream.Size;
  if Size = 0 then
    Exit;

  SavePos := Stream.Position;
  TotalBytes := 0;

  if Size < BufSize then
    BufLen := Size
  else
    BufLen := BufSize;

  GetMem(Buf, BufLen);
  try
    Stream.Position := 0;
    repeat
      ReadBytes := Stream.Read(Buf^, BufLen);
      if ReadBytes <> 0 then
      begin
        Inc(TotalBytes, ReadBytes);
        CRC := DoCrc64Calc(CRC, Buf^, ReadBytes);
      end;
    until (ReadBytes = 0) or (TotalBytes = Size);
    Result := True;
  finally
    FreeMem(Buf, BufLen);
    Stream.Position := SavePos;
  end;
end;

{$ENDIF}

// �����ļ� CRC64 ֵ�������ֱ�Ϊ���ļ�����CRC64 ֵ����ʼ��ַ�����㳤��
function FileCRC64(const FileName: string; var CRC: Int64; StartPos: Int64 = 0;
  ByteLength: Int64 = 0): Boolean;
var
{$IFDEF MSWINDOWS}
  Handle: THandle;
  ReadCount: Integer;
  Size: Int64;
  Count: Int64;
  Buff: TBuff;
{$ELSE}
  Stream: TStream;
{$ENDIF}
begin
{$IFDEF MSWINDOWS}
  // �Թ������ʽ���ļ�
  Handle := CreateFile(PChar(FileName), GENERIC_READ,
    FILE_SHARE_READ, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0);
  Result := Handle <> INVALID_HANDLE_VALUE;
  if Result then
  try
    Int64Rec(Size).Lo := GetFileSize(Handle, @Int64Rec(Size).Hi);
    if Size < StartPos + ByteLength then
    begin
      Result := False;                  // �����ļ�����
      Exit;
    end;
    if ByteLength > 0 then
      Count := ByteLength
    else
      Count := Size - StartPos;         // ����Ϊ�㣬���㵽�ļ�β

    CRC := not CRC;
    SetFilePointer(Handle, Int64Rec(StartPos).Lo, @Int64Rec(StartPos).Hi, FILE_BEGIN);
    while Count > 0 do
    begin
      if Count > SizeOf(Buff) then
        ReadCount := SizeOf(Buff)
      else
        ReadCount := Count;
      ReadFile(Handle, Buff, ReadCount, Cardinal(ReadCount), nil);
      CRC := DoCrc64Calc(CRC, Buff, ReadCount);
      Dec(Count, ReadCount);
    end;
    CRC := not CRC;
  finally
    CloseHandle(Handle);
  end;
{$ELSE}
  // �� Windows ƽֱ̨�����ļ���
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    Result := InternalCRC64Stream(Stream, 4096 * 1024, CRC);
  finally
    Stream.Free;
  end;
{$ENDIF}
end;

function CRC32Hmac(Key: PAnsiChar; KeyLength: Integer; Input: PAnsiChar;
  ByteLength: Cardinal): Cardinal;
var
  I: Integer;
  Ipad, Opad: array[0..3] of Byte;
  Sum, Res: Cardinal;
begin
  if KeyLength > HMAC_CRC32_BLOCK_SIZE_BYTE then
  begin
    Sum := CRC32Calc(0, Key^, KeyLength);
    KeyLength := HMAC_CRC32_OUTPUT_LENGTH_BYTE;
    Key := @Sum;
  end;

  FillChar(Ipad, HMAC_CRC32_BLOCK_SIZE_BYTE, $36);
  FillChar(Opad, HMAC_CRC32_BLOCK_SIZE_BYTE, $5C);
  
  for I := 0 to KeyLength - 1 do
  begin
    Ipad[I] := Byte(Ipad[I] xor Byte(Key[I]));
    Opad[I] := Byte(Opad[I] xor Byte(Key[I]));
  end;

  Res := $FFFFFFFF;
  Res := DoCRC32Calc(Res, Ipad[0], HMAC_CRC32_BLOCK_SIZE_BYTE);
  Res := DoCRC32Calc(Res, Input^, ByteLength);
  Res := not Res;

  Result := $FFFFFFFF;
  Result := DoCRC32Calc(Result, Opad[0], HMAC_CRC32_BLOCK_SIZE_BYTE);
  Result := DoCRC32Calc(Result, Res, HMAC_CRC32_OUTPUT_LENGTH_BYTE);
  Result := not Result;
end;

function CRC64Hmac(Key: PAnsiChar; KeyLength: Integer; Input: PAnsiChar;
  ByteLength: Cardinal): Int64;
var
  I: Integer;
  Ipad, Opad: array[0..7] of Byte;
  Sum, Res: Int64;
begin
  if KeyLength > HMAC_CRC64_BLOCK_SIZE_BYTE then
  begin
    Sum := CRC64Calc(0, Key^, KeyLength);
    KeyLength := HMAC_CRC64_OUTPUT_LENGTH_BYTE;
    Key := @Sum;
  end;

  FillChar(Ipad, HMAC_CRC64_BLOCK_SIZE_BYTE, $36);
  FillChar(Opad, HMAC_CRC64_BLOCK_SIZE_BYTE, $5C);

  for I := 0 to KeyLength - 1 do
  begin
    Ipad[I] := Byte(Ipad[I] xor Byte(Key[I]));
    Opad[I] := Byte(Opad[I] xor Byte(Key[I]));
  end;

  Res := $FFFFFFFF;
  Res := DoCRC64Calc(Res, Ipad[0], HMAC_CRC64_BLOCK_SIZE_BYTE);
  Res := DoCRC64Calc(Res, Input^, ByteLength);
  Res := not Res;

  Result := $FFFFFFFF;
  Result := DoCRC64Calc(Result, Opad[0], HMAC_CRC64_BLOCK_SIZE_BYTE);
  Result := DoCRC64Calc(Result, Res, HMAC_CRC64_OUTPUT_LENGTH_BYTE);
  Result := not Result;
end;

initialization
//  Make_CRC32Table; // ��ʼ�� CRC32 ��
  
  Make_CRC64Table; // ��ʼ�� CRC64 ��

end.
