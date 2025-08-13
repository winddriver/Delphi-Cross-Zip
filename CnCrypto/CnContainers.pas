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

unit CnContainers;
{* |<PRE>
================================================================================
* ������ƣ�������������
* ��Ԫ���ƣ��������ʵ��
* ��Ԫ���ߣ�С��
* ��    ע���򵥵���������࣬��β Push����ͷ Pop�����������Ƕ��󣨱�ת����ָ�룩��
*           ����ʱ�ڲ����ڴ���ʱ���û�����ƣ��������ⲿͨ���ٽ������⡣�������ӣ�
*           ������
*           var
*             Q: TCnLinkedQueue;
*
*           ������
*             Q := TCnLinkedQueue.Create;
*            
*           ʹ�ã�
*
*           var
*             TmpObj: TObject;
*           begin
*             TmpObj := TObject.Create;
*             Q.Push(Data); // �������β
*           end;
*            
*           var
*             TmpObj: TObject;
*           begin
*             TmpObj := TObject(Q.Pop); // �Ӷ���ͷ��ȡ��
*             TmpObj.Free;
*           end;
*
*           �ͷţ�
*             Q.Free;
*
* ����ƽ̨��PWinXP + Delphi 7
* ���ݲ��ԣ�PWin2000/XP + Delphi 5/6/7
* �� �� �����õ�Ԫ�е��ַ��������ϱ��ػ�����ʽ
* �޸ļ�¼��2025.04.06 V1.5
*               �����б������������
*           2024.05.10 V1.4
*               �� CnClasses �е� UInt32/UInt64 �б��ƶ����˴���û����ֻ������
*           2024.04.28 V1.4
*               ���Ӷ�����У����������������
*           2023.08.21 V1.4
*               ������չ���ȸ������б�
*           2020.11.05 V1.3
*               �������ػ����ȡ���˴�
*           2017.01.17 V1.2
*               ���� TCnObjectRingBuffer ѭ��������ʵ��
*           2016.12.02 V1.1
*               ���� TCnObjectStack ʵ�֣����� Clear �ȷ���
*           2008.04.30 V1.0
*               С���ԭʼ������ֲ������
================================================================================
|</PRE>}

interface

{$I CnPack.inc}

uses
  SysUtils, Classes, Contnrs, SyncObjs, CnNative
  {$IFDEF FPC} , RTLConsts {$ELSE}
  {$IFDEF COMPILER6_UP}, RTLConsts {$ELSE}, Consts {$ENDIF} {$ENDIF}
  {$IFDEF POSIX}, System.Generics.Collections {$ENDIF};

{$DEFINE MULTI_THREAD} // ��ѧ�����֧�ֶ��̣߳����������½����粻��Ҫ��ע�ʹ��м���

type
  TCnLinkedQueue = class(TObject)
  {* ָ�����ʵ���࣬�ڲ���������ʵ�֡��������ڴ���ʱָ���Ƿ�֧�ֶ��̻߳���}
  private
    FMultiThread: Boolean;
    FHead: TObject;
    FTail: TObject;
    FSize: Integer;
    FLock: TCriticalSection;
    procedure FreeNode(Value: TObject);
    function GetSize: Integer;
  public
    constructor Create(MultiThread: Boolean = False); virtual;
    {* ���캯����

       ������
         MultiThread: Boolean             - �Ƿ���Ҫ���̻߳���

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure Push(Data: Pointer);
    {* ����β����һָ�롣

       ������
         Data: Pointer                    - �������ָ��

       ����ֵ��                           - ��
    }

    function Pop: Pointer;
    {* ����ͷ����һָ�룬����п��򷵻� nil��

       ������
         ���ޣ�

       ����ֵ��                           - ������ָ��
    }

    property Size: Integer read GetSize;
    {* �ڲ�ָ����}
  end;

  TCnObjectQueue = class(TObject)
  {* �������ʵ���࣬�������ڴ���ʱָ���Ƿ�֧�ֶ��̻߳��⡣
    �ڲ������б�ʵ�֣����������ã������ж���}
  private
    FMultiThread: Boolean;
    FLock: TCriticalSection;
    FList: TList;
  public
    constructor Create(MultiThread: Boolean = False); virtual;
    {* ���캯����

       ������
         MultiThread: Boolean             - �Ƿ���Ҫ���̻߳���

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    function Count: Integer;
    {* ������Ԫ��������

       ������
         ���ޣ�

       ����ֵ��                           - ���ض�����Ԫ������
    }

    function IsEmpty: Boolean;
    {* �����Ƿ�Ϊ�ա�

       ������
         ���ޣ�

       ����ֵ��                           - ���ض����Ƿ�Ϊ��
    }

    procedure Clear;
    {* �������������Ԫ��}

    procedure Push(AObject: TObject);
    {* ��һ��������С�

       ������
         AObject: TObject                 - ��������еĶ���

       ����ֵ��                           - ��
    }

    function Pop: TObject;
    {* �����ڳ�һ��������п������쳣��

       ������
         ���ޣ�

       ����ֵ��                           - �����Ķ���
    }
  end;

  TCnObjectStack = class(TObject)
  {* ����ջʵ���࣬�������ڴ���ʱָ���Ƿ�֧�ֶ��̻߳��⡣
     �ڲ������б�ʵ�֣����������ã������ж���}
  private
    FMultiThread: Boolean;
    FLock: TCriticalSection;
    FList: TList;
  public
    constructor Create(MultiThread: Boolean = False); virtual;
    {* ���캯����

       ������
         MultiThread: Boolean             - �Ƿ���Ҫ���̻߳���

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    function Count: Integer;
    {* ջ��Ԫ������}
    function IsEmpty: Boolean;
    {* ջ�Ƿ�Ϊ��}
    procedure Clear;
    {* ���ջ������Ԫ��}

    procedure Push(AObject: TObject);
    {* ��һ������ջ}
    function Pop: TObject;
    {* ��ջ��һ�������ջ�������쳣}
    function Peek: TObject;
    {* ȡջ���������ջ�������쳣}
  end;

  ECnRingBufferFullException = class(Exception);
  {* ѭ�����л�������ʱ�������쳣}

  ECnRingBufferEmptyException = class(Exception);
  {* ѭ�����л�������ʱ�������쳣}

  TCnObjectRingBuffer = class(TObject)
  {* �����ѭ�����л�����}
  private
    FFullOverwrite: Boolean;
    FMultiThread: Boolean;
    FSize: Integer;
    FList: TList;
    FLock: TCriticalSection;
    // Idx �������Ϊʼ��ָ������λ���м�ķ죬��Ŵӵ� 0 ���� Size - 1 ( �� Size Ҳ�����ڵ� 0 )
    // ��Ԫ�ص�����£�FrontIdx �ߺ�ʼ����Ԫ�أ�ǰ�����ǿգ����ƻ�����β��
    //                 BackIdx �ĵ�ǰʼ����Ԫ�أ�������ǿգ����ƻ�����ͷ
    // ��Ԫ�ص�����£�FrontIdx �� BackIdx ���
    FFrontIdx: Integer;
    FBackIdx: Integer;
    FCount: Integer;
    function GetCount: Integer;
  public
    constructor Create(ASize: Integer; AFullOverwrite: Boolean = False;
      AMultiThread: Boolean = False);
    {* ���캯����

       ������
         ASize: Integer                   - ѭ�����л�������Ԫ������
         AFullOverwrite: Boolean          - �Ƿ���������������д������ʱ������ǰ������
         AMultiThread: Boolean            - �Ƿ���Ҫ���̻߳���

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    procedure PushToFront(AObject: TObject);
    {* ��ѭ�����л�����ǰ������һ�� Object��ǰ����ָ�ڲ��洢�����͵�һ�ˣ������Ҳ������������쳣}
    function PopFromBack: TObject;
    {* ��ѭ�����л������󷽵���һ�� Object������ָ�ڲ��洢�����ߵ�һ�ˣ��޿ɵ������쳣}

    procedure PushToBack(AObject: TObject);
    {* ��ѭ�����л�����������һ�� Object������ָ�ڲ��洢�����ߵ�һ�ˣ������Ҳ������������쳣}
    function PopFromFront: TObject;
    {* ��ѭ�����л�����ǰ������һ�� Object��ǰ����ָ�ڲ��洢�����͵�һ�ˣ��޿ɵ������쳣}

    procedure Dump(List: TList; out FrontIdx: Integer; out BackIdx: Integer);
    {* ��ȫ�����ݵ�����һ TList���Լ�ָ��λ��}

    property FullOverwrite: Boolean read FFullOverwrite;
    {* ��ѭ�����л�������ʱ�Ƿ������Ǿ�����}
    property MultiThread: Boolean read FMultiThread;
    {* ��ѭ�����л������Ƿ���Ҫ֧�ֶ��̲߳������ʣ�Ϊ True ʱ�ڲ����ٽ�������}
    property Size: Integer read FSize;
    {* ��ѭ�����л������ĳߴ�}
    property Count: Integer read GetCount;
    {* ��ѭ�����л������ڵ���ЧԪ������}
  end;

  TCnMathObjectPool = class(TObjectList)
  {* ��ѧ�����ʵ���࣬����ʹ�õ���ѧ����صĵط����м̳в�������}
  private
{$IFDEF MULTI_THREAD}
    FCriticalSection: TCriticalSection;
{$ENDIF}
    procedure Enter; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
    procedure Leave; {$IFDEF SUPPORT_INLINE} inline; {$ENDIF}
  protected
    function CreateObject: TObject; virtual; abstract;
    {* ����������صĴ����������ķ���}
  public
    constructor Create; reintroduce;
    {* ���캯������ͨ�� TObjectList ���ж���}

    destructor Destroy; override;
    {* ������������ʽ�ͷ��ڲ�����}

    function Obtain: TObject;
    {* �Ӷ���ػ�ȡһ�����󣬲���ʱ����� Recycle �黹��

       ������
         ���ޣ�

       ����ֵ��TObject                    - ���صĶ���
    }

    procedure Recycle(Num: TObject);
    {* ��һ������黹������ء�

       ������
         Num: TObject                     - ���黹�Ķ���

       ����ֵ�����ޣ�
    }
  end;

//==============================================================================
// Int32 �б���
//==============================================================================

  TCnInt32CompareProc = function(I1, I2: Integer): Integer;

  TCnIntegerList = class(TList)
  {* �����б����� 32 λ Pointer �� 64 λ Pointer �ĵ� 32 λ�� Integer}
  private
    function Get(Index: Integer): Integer;
    procedure Put(Index: Integer; const Value: Integer);
  public
    function Add(Item: Integer): Integer; reintroduce;
    procedure AddList(List: TCnIntegerList);
    procedure Insert(Index: Integer; Item: Integer); reintroduce;
    procedure IntSort(CompareProc: TCnInt32CompareProc = nil);
    {* ����Ĭ�ϴ�С����}
    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}

    property Items[Index: Integer]: Integer read Get write Put; default;
  end;

//==============================================================================
// Int64 �б���
//==============================================================================

  PInt64List = ^TInt64List;
  TInt64List = array[0..MaxListSize - 1] of Int64;

  TCnInt64CompareProc = function(I1, I2: Int64): Integer;

  TCnInt64List = class(TObject)
  {* 64 λ�з��������б�}
  private
    FList: PInt64List;
    FCount: Integer;
    FCapacity: Integer;
  protected
    function Get(Index: Integer): Int64;
    procedure Grow; virtual;
    procedure Put(Index: Integer; Item: Int64);
    procedure SetCapacity(NewCapacity: Integer);
    procedure SetCount(NewCount: Integer);
  public
    destructor Destroy; override;
    function Add(Item: Int64): Integer;
    procedure AddList(List: TCnInt64List);
    procedure Clear; virtual;
    procedure Delete(Index: Integer);
    procedure DeleteLow(ACount: Integer);
    {* ����������ɾ�� ACount ����Ͷ�Ԫ�أ���� Count ������ɾ�� Count ��}
    class procedure Error(const Msg: string; Data: Integer); virtual;
    procedure Exchange(Index1: Integer; Index2: Integer);
    function Expand: TCnInt64List;
    function First: Int64;
    function IndexOf(Item: Int64): Integer;
    procedure Insert(Index: Integer; Item: Int64);
    procedure InsertBatch(Index: Integer; ACount: Integer);
    {* ������������ĳλ����������ȫ 0 ֵ ACount ��}
    function Last: Int64;
    procedure Move(CurIndex: Integer; NewIndex: Integer);
    function Remove(Item: Int64): Integer;
    procedure IntSort(CompareProc: TCnInt64CompareProc = nil);
    {* ����Ĭ�ϴ�С����}
    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}

    property Capacity: Integer read FCapacity write SetCapacity;
    property Count: Integer read FCount write SetCount;
    property Items[Index: Integer]: Int64 read Get write Put; default;
    property List: PInt64List read FList;
  end;

//==============================================================================
// UInt32 �б���
//==============================================================================

const
  CN_MAX_UINT32_SIZE = MaxInt div 16;

type
  PCnUInt32Array = ^TCnUInt32Array;
  TCnUInt32Array = array[0..CN_MAX_UINT32_SIZE - 1] of Cardinal;

  TCnUInt32CompareProc = function(U1, U2: Cardinal): Integer;

  TCnUInt32List = class(TObject)
  {* ���� UInt32 �� List}
  private
    FList: PCnUInt32Array;
    FCount: Integer;
    FCapacity: Integer;
    FIgnoreDuplicated: Boolean;
  protected
    function Get(Index: Integer): Cardinal;
    procedure Grow; virtual;
    procedure Put(Index: Integer; Item: Cardinal);
    procedure SetCapacity(NewCapacity: Integer);
    procedure SetCount(NewCount: Integer);
  public
    destructor Destroy; override;
    function Add(Item: Cardinal): Integer;
    procedure AddList(List: TCnUInt32List);
    procedure Clear; virtual;
    procedure Delete(Index: Integer);
    class procedure Error(const Msg: string; Data: Integer); overload; virtual;
    class procedure Error(Msg: PResStringRec; Data: Integer); overload;
    procedure Exchange(Index1: Integer; Index2: Integer);
    function Expand: TCnUInt32List;
    function Extract(Item: Cardinal): Cardinal;
    function First: Cardinal;
    function IndexOf(Item: Cardinal): Integer;
    procedure Insert(Index: Integer; Item: Cardinal);
    function Last: Cardinal;
    procedure Move(CurIndex: Integer; NewIndex: Integer);
    function Remove(Item: Cardinal): Integer;
    procedure IntSort(CompareProc: TCnUInt32CompareProc = nil);
    {* ����Ĭ�ϴ�С����}
    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}

    property Capacity: Integer read FCapacity write SetCapacity;
    property Count: Integer read FCount write SetCount;
    property Items[Index: Integer]: Cardinal read Get write Put; default;
    property List: PCnUInt32Array read FList;
    property IgnoreDuplicated: Boolean read FIgnoreDuplicated write FIgnoreDuplicated;
  end;

//==============================================================================
// UInt64 �б���
//==============================================================================

const
  CN_MAX_UINT64_SIZE = MaxInt div 16;
  CN_NOT_FOUND_INDEX: TUInt64 = TUInt64(-1);

type
  PCnUInt64Array = ^TCnUInt64Array;
  TCnUInt64Array = array[0..CN_MAX_UINT64_SIZE - 1] of TUInt64;

  TCnUInt64CompareProc = function(U1, U2: TUInt64): Integer;

  TCnUInt64List = class(TObject)
  {* ���� UInt64 �� List����֧�� UInt64 ��ƽ̨���� Int64 ����}
  private
    FList: PCnUInt64Array;
    FCount: TUInt64;
    FCapacity: TUInt64;
    FIgnoreDuplicated: Boolean;
  protected
    function Get(Index: TUInt64): TUInt64;
    procedure Grow; virtual;
    procedure Put(Index: TUInt64; Item: TUInt64);
    procedure SetCapacity(NewCapacity: TUInt64);
    procedure SetCount(NewCount: TUInt64);
  public
    destructor Destroy; override;
    function Add(Item: TUInt64): TUInt64;
    procedure AddList(List: TCnUInt64List);
    procedure Clear; virtual;
    procedure Delete(Index: TUInt64);
    class procedure Error(const Msg: string; Data: Integer); overload; virtual;
    class procedure Error(Msg: PResStringRec; Data: Integer); overload;
    procedure Exchange(Index1: TUInt64; Index2: TUInt64);
    function Expand: TCnUInt64List;
    function Extract(Item: TUInt64): TUInt64;
    function First: TUInt64;
    function IndexOf(Item: TUInt64): TUInt64;
    // �����±��� TUInt64��֮ǰ���� -1 �� UInt64 �����²����ô��� 0 ������
    // ���ж��Ƿ���� CN_NOT_FOUND_INDEX
    procedure Insert(Index: TUInt64; Item: TUInt64);
    function Last: TUInt64;
    procedure Move(CurIndex, NewIndex: TUInt64);
    function Remove(Item: TUInt64): TUInt64;
    procedure IntSort(CompareProc: TCnUInt64CompareProc = nil);
    {* ����Ĭ�ϴ�С����}
    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}

    property Capacity: TUInt64 read FCapacity write SetCapacity;
    property Count: TUInt64 read FCount write SetCount;
    property Items[Index: TUInt64]: TUInt64 read Get write Put; default;
    // �ڲ��±ꡢ�ߴ���� TUInt64 ��ʾ���������ڱ���������ʵ���ϴﲻ�� TUInt64
    property List: PCnUInt64Array read FList;
    property IgnoreDuplicated: Boolean read FIgnoreDuplicated write FIgnoreDuplicated;
  end;

  PExtendedList = ^TExtendedList;
  TExtendedList = array[0..MaxListSize - 1] of Extended;

  TCnExtendedCompareProc = function(E1, E2: Extended): Integer;

  TCnExtendedList = class(TObject)
  {* ��չ���ȸ������б�ע�ⲻͬƽ̨��Ԫ�س��ȿ��ܲ�һ��}
  private
    FList: PExtendedList;
    FCount: Integer;
    FCapacity: Integer;
  protected
    function Get(Index: Integer): Extended;
    procedure Grow; virtual;
    procedure Put(Index: Integer; Item: Extended);
    procedure SetCapacity(NewCapacity: Integer);
    procedure SetCount(NewCount: Integer);
  public
    destructor Destroy; override;
    function Add(Item: Extended): Integer;
    procedure AddList(List: TCnExtendedList);
    procedure Clear; virtual;
    procedure Delete(Index: Integer);
    procedure DeleteLow(ACount: Integer);
    {* ����������ɾ�� ACount ����Ͷ�Ԫ�أ���� Count ������ɾ�� Count ��}
    class procedure Error(const Msg: string; Data: Integer); virtual;
    procedure Exchange(Index1: Integer; Index2: Integer);
    function Expand: TCnExtendedList;
    function First: Extended;
    function IndexOf(Item: Extended): Integer;
    procedure Insert(Index: Integer; Item: Extended);
    procedure InsertBatch(Index: Integer; ACount: Integer);
    {* ������������ĳλ����������ȫ 0 ֵ ACount ��}
    function Last: Extended;
    procedure Move(CurIndex: Integer; NewIndex: Integer);
    function Remove(Item: Extended): Integer;
    procedure FloatSort(CompareProc: TCnExtendedCompareProc = nil);
    function ToString: string; {$IFDEF OBJECT_HAS_TOSTRING} override; {$ENDIF}

    property Capacity: Integer read FCapacity write SetCapacity;
    property Count: Integer read FCount write SetCount;
    property Items[Index: Integer]: Extended read Get write Put; default;
    property List: PExtendedList read FList;
  end;

  PRefObjectList = ^TRefObjectList;
  TRefObjectList = array[0..MaxListSize - 1] of TObject;

  TCnRefObjectList = class(TObject)
  {* ���������б������� TObjectList ���� Own ����}
  private
    FList: PRefObjectList;
    FCount: Integer;
    FCapacity: Integer;
  protected
    function Get(Index: Integer): TObject;
    procedure Grow; virtual;
    procedure Put(Index: Integer; Item: TObject);
    procedure SetCapacity(NewCapacity: Integer);
    procedure SetCount(NewCount: Integer);
  public
    destructor Destroy; override;
    {* ��������}
    function Add(Item: TObject): Integer;
    procedure Clear; virtual;
    procedure Delete(Index: Integer);
    procedure DeleteLow(ACount: Integer);
    {* ����������ɾ�� ACount ����Ͷ�Ԫ�أ���� Count ������ɾ�� Count ��}
    class procedure Error(const Msg: string; Data: Integer); virtual;
    procedure Exchange(Index1: Integer; Index2: Integer);
    function Expand: TCnRefObjectList;
    function First: TObject;
    function IndexOf(Item: TObject): Integer;
    procedure Insert(Index: Integer; Item: TObject);
    procedure InsertBatch(Index: Integer; ACount: Integer);
    {* ������������ĳλ����������ȫ 0 ֵ ACount ��}
    function Last: TObject;
    procedure Move(CurIndex: Integer; NewIndex: Integer);
    function Remove(Item: TObject): Integer;

    property Capacity: Integer read FCapacity write SetCapacity;
    property Count: Integer read FCount write SetCount;
    property Items[Index: Integer]: TObject read Get write Put; default;
    property List: PRefObjectList read FList;
  end;

{$IFDEF POSIX}

  TCnInternalList<T> = class(TList<T>)
  {* MACOS/LINUX ��ƽ̨�µ� TList û�� IgnoreDuplicated ���ܣ���Ҫ��дһ���ಢ�ֹ�ȥ��}
  public
    procedure RemoveDuplictedElements;
    {* ȥ���ظ���Ԫ��}
  end;

{$ENDIF}

  TCnBytesObject = class
  {* ��װ���ֽ�����Ķ����ڲ��������ݽ��й���}
  private
    FData: TBytes;
  public
    constructor Create(AMem: Pointer = nil; MemByteSize: Integer = 0); virtual;
    {* ���캯����

       ������
         AMem: Pointer                    - ���ݿ��ַ����Ϊ���ݸ��Ƶ��ڲ����ֽ�������
         MemByteSize: Integer             - ���ݿ��ֽڳ���

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    property Data: TBytes read FData write FData;
    {* �����ֽ�����}
  end;

  TCnBytesPair = class
  {* ��װ�����ֽ�����Ķ����ڲ��������ݽ��й���}
  private
    FKey: TBytes;
    FValue: TBytes;
  public
    constructor Create(AKeyMem: Pointer = nil; KeyMemByteSize: Integer = 0;
      AValueMem: Pointer = nil; ValueMemByteSize: Integer = 0); virtual;
    {* ���캯����

       ������
         AKeyMem: Pointer                 - Key �����ݿ��ַ����Ϊ���ݸ��Ƶ��ڲ����ֽ�������
         KeyMemByteSize: Integer          - Key �����ݿ��ֽڳ���
         AValueMem: Pointer               - Value �����ݿ��ַ����Ϊ���ݸ��Ƶ��ڲ����ֽ�������
         ValueMemByteSize: Integer        - Value �����ݿ��ֽڳ���

       ����ֵ��                           - ���ش����Ķ���ʵ��
    }

    destructor Destroy; override;
    {* ��������}

    property Key: TBytes read FKey write FKey;
    {* Key �ֽ�����}
    property Value: TBytes read FValue write FValue;
    {* Value �ֽ�����}
  end;

procedure CnIntegerListCopy(Dst: TCnIntegerList; Src: TCnIntegerList);
{* ���� TCnIntegerList��

   ������
     Dst: TCnIntegerList              - Ŀ���б�
     Src: TCnIntegerList              - Դ�б�

   ����ֵ��                           - ��
}

procedure CnInt64ListCopy(Dst: TCnInt64List; Src: TCnInt64List);
{* ���� TCnInt64List��

   ������
     Dst: TCnInt64List                - Ŀ���б�
     Src: TCnInt64List                - Դ�б�

   ����ֵ��                           - ��
}

procedure CnRefObjectListCopy(Dst: TCnRefObjectList; Src: TCnRefObjectList);
{* ���� TCnRefObjectList��

   ������
     Dst: TCnRefObjectList            - Ŀ���б�
     Src: TCnRefObjectList            - Դ�б�

   ����ֵ��                           - ��
}

implementation

resourcestring
  SCnInt64ListError = 'Int64 List Error. %d';
  SCnExtendedListError = 'Float List Error. %d';
  SCnRefObjectListError = 'Reference Object List Error. %d';
  SCnEmptyPopFromBackError = 'Ring Buffer Empty. Can NOT Pop From Back.';
  SCnEmptyPopFromFrontError = 'Ring Buffer Empty. Can NOT Pop From Front.';
  SCnFullPushToBackError = 'Ring Buffer Full. Can NOT Push To Back.';
  SCnFullPushToFrontError = 'Ring Buffer Full. Can NOT Push To Front.';

type
  TCnQueueNode = class
  private
    FNext: TCnQueueNode;
    FData: Pointer;
  public
    property Next: TCnQueueNode read FNext write FNext;
    property Data: Pointer read FData write FData;
  end;

threadvar
  FCompareProcExtended: TCnExtendedCompareProc;
  FCompareProcInt32: TCnInt32CompareProc;
  FCompareProcUInt32: TCnUInt32CompareProc;
  FCompareProcInt64: TCnInt64CompareProc;
  FCompareProcUInt64: TCnUInt64CompareProc;

function DefExtendedCompareProc(E1, E2: Extended): Integer;
begin
  if Abs(E1 - E2) < 0.000001 then
    Result := 0
  else if E1 > E2 then
    Result := 1
  else
    Result := -1;
end;

function DefInt32CompareProc(I1, I2: Integer): Integer;
begin
  if I1 = I2 then
    Result := 0
  else if I1 > I2 then
    Result := 1
  else
    Result := -1;
end;

function DefInt64CompareProc(I1, I2: Int64): Integer;
begin
  if I1 = I2 then
    Result := 0
  else if I1 > I2 then
    Result := 1
  else
    Result := -1;
end;

function DefUInt32CompareProc(U1, U2: Cardinal): Integer;
begin
  if U1 = U2 then
    Result := 0
  else if U1 > U2 then
    Result := 1
  else
    Result := -1;
end;

function DefUInt64CompareProc(U1, U2: TUInt64): Integer;
begin
  Result := UInt64Compare(U1, U2);
end;

function MyExtendedSortCompare(P1, P2: Pointer; ElementByteSize: Integer): Integer;
begin
  if Assigned(FCompareProcExtended) then
    Result := FCompareProcExtended(PExtended(P1)^, PExtended(P2)^)
  else
    Result := DefExtendedCompareProc(PExtended(P1)^, PExtended(P2)^);
end;

function MyInt32SortCompare(Item1, Item2: Pointer): Integer;
begin
  if Assigned(FCompareProcInt32) then
    Result := FCompareProcInt32(Integer(Item1), Integer(Item2))
  else
    Result := DefInt32CompareProc(Integer(Item1), Integer(Item2));
end;

function MyUInt32SortCompare(P1, P2: Pointer; ElementByteSize: Integer): Integer;
begin
  if Assigned(FCompareProcUInt32) then
    Result := FCompareProcUInt32(PCardinal(P1)^, PCardinal(P2)^)
  else
    Result := DefUInt32CompareProc(PCardinal(P1)^, PCardinal(P2)^);
end;

function MyInt64SortCompare(P1, P2: Pointer; ElementByteSize: Integer): Integer;
begin
  if Assigned(FCompareProcInt64) then
    Result := FCompareProcInt64(PInt64(P1)^, PInt64(P2)^)
  else
    Result := DefInt64CompareProc(PInt64(P1)^, PInt64(P2)^);
end;

function MyUInt64SortCompare(P1, P2: Pointer; ElementByteSize: Integer): Integer;
begin
  if Assigned(FCompareProcUInt64) then
    Result := FCompareProcUInt64(PUInt64(P1)^, PUInt64(P2)^)
  else
    Result := DefUInt64CompareProc(PUInt64(P1)^, PUInt64(P2)^);
end;

{ TCnQueue }

procedure TCnLinkedQueue.FreeNode(Value: TObject);
var
  Tmp: TCnQueueNode;
begin
  Tmp := TCnQueueNode(Value).Next;
  TCnQueueNode(Value).Free;
  if Tmp = nil then
    Exit;
  FreeNode(Tmp);
end;

constructor TCnLinkedQueue.Create(MultiThread: Boolean);
begin
  inherited Create;
  FMultiThread := MultiThread;
  FHead := nil;
  FTail := nil;
  FSize := 0;
  if FMultiThread then
    FLock := TCriticalSection.Create;
end;

destructor TCnLinkedQueue.Destroy;
begin
  if FHead <> nil then
    FreeNode(FHead);
  if FMultiThread then
    FLock.Free;
  inherited;
end;

function TCnLinkedQueue.Pop: Pointer;
var
  Tmp: TCnQueueNode;
begin
  if FMultiThread then
    FLock.Enter;

  try
    Result := nil;
    if FHead = nil then
      Exit;

    Result := TCnQueueNode(FHead).Data;
    Tmp := TCnQueueNode(FHead).Next;
    TCnQueueNode(FHead).Free;
    FHead := Tmp;
    
    if Tmp = nil then
      FTail := nil;
    FSize := FSize - 1;
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

procedure TCnLinkedQueue.Push(Data: Pointer);
var
  Tmp: TCnQueueNode;
begin
  if FMultiThread then
    FLock.Enter;

  try
    if Data = nil then Exit;
    Tmp := TCnQueueNode.Create;
    Tmp.Data := Data;
    Tmp.Next := nil;
    
    if FTail = nil then
    begin
      FTail := Tmp;
      FHead := Tmp;
    end
    else
    begin
      TCnQueueNode(FTail).Next := Tmp;
      FTail := Tmp;
    end;
    
    FSize := FSize + 1;
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

function TCnLinkedQueue.GetSize: Integer;
begin
  Result := FSize;
end;

{ TCnObjectQueue }

procedure TCnObjectQueue.Clear;
begin
  if FMultiThread then
    FLock.Enter;

  try
    FList.Clear;
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

function TCnObjectQueue.Count: Integer;
begin
  Result := FList.Count;
end;

constructor TCnObjectQueue.Create(MultiThread: Boolean);
begin
  inherited Create;
  FList := TList.Create;
  FMultiThread := MultiThread;
  if FMultiThread then
    FLock := TCriticalSection.Create;
end;

destructor TCnObjectQueue.Destroy;
begin
  if FMultiThread then
    FLock.Free;
  FList.Free;
  inherited;
end;

function TCnObjectQueue.IsEmpty: Boolean;
begin
  Result := FList.Count = 0;
end;

function TCnObjectQueue.Pop: TObject;
begin
  if FMultiThread then
    FLock.Enter;

  try
    Result := TObject(FList[0]);
    FList.Delete(0);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

procedure TCnObjectQueue.Push(AObject: TObject);
begin
  if FMultiThread then
    FLock.Enter;

  try
    FList.Add(AObject);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

{ TCnObjectStack }

procedure TCnObjectStack.Clear;
begin
  if FMultiThread then
    FLock.Enter;

  try
    FList.Clear;
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

function TCnObjectStack.Count: Integer;
begin
  Result := FList.Count;
end;

constructor TCnObjectStack.Create(MultiThread: Boolean);
begin
  inherited Create;
  FList := TList.Create;
  FMultiThread := MultiThread;
  if FMultiThread then
    FLock := TCriticalSection.Create;
end;

destructor TCnObjectStack.Destroy;
begin
  if FMultiThread then
    FLock.Free;
  FList.Free;
  inherited;
end;

function TCnObjectStack.IsEmpty: Boolean;
begin
  Result := FList.Count = 0;
end;

function TCnObjectStack.Peek: TObject;
begin
  Result := TObject(FList[FList.Count - 1]);
end;

function TCnObjectStack.Pop: TObject;
begin
  if FMultiThread then
    FLock.Enter;

  try
    Result := TObject(FList[FList.Count - 1]);
    FList.Delete(FList.Count - 1);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

procedure TCnObjectStack.Push(AObject: TObject);
begin
  if FMultiThread then
    FLock.Enter;

  try
    FList.Add(AObject);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

{ TCnRingBuffer }

constructor TCnObjectRingBuffer.Create(ASize: Integer; AFullOverwrite,
  AMultiThread: Boolean);
begin
  Assert(ASize > 0);

  FSize := ASize;
  FFullOverwrite := AFullOverwrite;
  FMultiThread := AMultiThread;

  FList := TList.Create;
  FList.Count := FSize;

  if FMultiThread then
    FLock := TCriticalSection.Create;
end;

destructor TCnObjectRingBuffer.Destroy;
begin
  if FMultiThread then
    FLock.Free;
  FList.Free;
  inherited;
end;

procedure TCnObjectRingBuffer.Dump(List: TList; out FrontIdx: Integer;
  out BackIdx: Integer);
var
  I: Integer;
begin
  FrontIdx := FFrontIdx;
  BackIdx := FBackIdx;
  if List <> nil then
  begin
    List.Clear;
    for I := 0 to FList.Count - 1 do
      List.Add(FList[I]);
  end;
end;

function TCnObjectRingBuffer.GetCount: Integer;
begin
  Result := FCount;
end;

{$HINTS OFF}

function TCnObjectRingBuffer.PopFromBack: TObject;
begin
  Result := nil;  // ������Ͱ汾 Delphi �о��棬����߰汾 Delphi �о���
  if FMultiThread then
    FLock.Enter;

  try
    if FCount <= 0 then
      raise ECnRingBufferEmptyException.Create(SCnEmptyPopFromBackError);

    Dec(FBackIdx);
    if FBackIdx < 0 then
      FBackIdx := FSize - 1;
    Result := TObject(FList[FBackIdx]);
    FList[FBackIdx] := nil;
    Dec(FCount);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

function TCnObjectRingBuffer.PopFromFront: TObject;
begin
  Result := nil; // ������Ͱ汾 Delphi �о��棬����߰汾 Delphi �о���
  if FMultiThread then
    FLock.Enter;

  try
    if FCount <= 0 then
      raise ECnRingBufferEmptyException.Create(SCnEmptyPopFromFrontError);

    Result := TObject(FList[FFrontIdx]);
    FList[FFrontIdx] := nil;

    Inc(FFrontIdx);
    if FFrontIdx >= FSize then
      FFrontIdx := 0;
    Dec(FCount);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

{$HINTS ON}

procedure TCnObjectRingBuffer.PushToBack(AObject: TObject);
begin
  if FMultiThread then
    FLock.Enter;

  try
    if not FFullOverwrite and (FCount >= FSize) then
      raise ECnRingBufferFullException.Create(SCnFullPushToBackError);

    FList[FBackIdx] := AObject;
    Inc(FBackIdx);
    if FBackIdx >= FSize then
      FBackIdx := 0;

    if FCount < FSize then
      Inc(FCount);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

procedure TCnObjectRingBuffer.PushToFront(AObject: TObject);
begin
  if FMultiThread then
    FLock.Enter;

  try
    if not FFullOverwrite and (FCount >= FSize) then
      raise ECnRingBufferFullException.Create(SCnFullPushToFrontError);

    Dec(FFrontIdx);
    if FFrontIdx < 0 then
      FFrontIdx := FSize - 1;
    FList[FFrontIdx] := AObject;

    if FCount < FSize then
      Inc(FCount);
  finally
    if FMultiThread then
      FLock.Leave;
  end;
end;

{ TCnMathObjectPool }

constructor TCnMathObjectPool.Create;
begin
  inherited Create(False);
{$IFDEF MULTI_THREAD}
  FCriticalSection := TCriticalSection.Create;
{$ENDIF}
end;

destructor TCnMathObjectPool.Destroy;
var
  I: Integer;
begin
  for I := 0 to Count - 1 do
    TObject(Items[I]).Free;

{$IFDEF MULTI_THREAD}
  FCriticalSection.Free;
{$ENDIF}
  inherited;
end;

procedure TCnMathObjectPool.Enter;
begin
{$IFDEF MULTI_THREAD}
  FCriticalSection.Enter;
{$ENDIF}
end;

procedure TCnMathObjectPool.Leave;
begin
{$IFDEF MULTI_THREAD}
  FCriticalSection.Leave;
{$ENDIF}
end;

function TCnMathObjectPool.Obtain: TObject;
begin
  Enter;
  try
    if Count = 0 then
      Result := CreateObject
    else
    begin
      Result := TObject(Items[Count - 1]);
      Delete(Count - 1);
    end;
  finally
    Leave;
  end;
end;

procedure TCnMathObjectPool.Recycle(Num: TObject);
begin
  if Num <> nil then
  begin
    Enter;
    try
      Add(Num);
    finally
      Leave;
    end;
  end;
end;

{ TCnIntegerList }

function TCnIntegerList.Add(Item: Integer): Integer;
begin
  Result := inherited Add(IntegerToPointer(Item));
end;

procedure TCnIntegerList.AddList(List: TCnIntegerList);
var
  I: Integer;
begin
  if (List <> nil) and (List.Count > 0) then
  begin
    for I := 0 to List.Count - 1 do
      Add(List[I]);
  end;
end;

function TCnIntegerList.Get(Index: Integer): Integer;
begin
  Result := PointerToInteger(inherited Get(Index));
end;

procedure TCnIntegerList.Insert(Index, Item: Integer);
begin
  inherited Insert(Index, IntegerToPointer(Item));
end;

procedure TCnIntegerList.IntSort(CompareProc: TCnInt32CompareProc);
begin
  FCompareProcInt32 := CompareProc;
  Sort(MyInt32SortCompare);
end;

function TCnIntegerList.ToString: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
  begin
    if I = 0 then
      Result := IntToStr(Items[I])
    else
      Result := Result + ',' + IntToStr(Items[I]);
  end;
end;

procedure TCnIntegerList.Put(Index: Integer; const Value: Integer);
begin
  inherited Put(Index, IntegerToPointer(Value));
end;

{ TCnInt64List }

destructor TCnInt64List.Destroy;
begin
  Clear;
end;

function TCnInt64List.Add(Item: Int64): Integer;
begin
  Result := FCount;
  if Result = FCapacity then
    Grow;
  FList^[Result] := Item;
  Inc(FCount);
end;

procedure TCnInt64List.AddList(List: TCnInt64List);
var
  I: Integer;
begin
  if (List <> nil) and (List.Count > 0) then
  begin
    for I := 0 to List.Count - 1 do
      Add(List[I]);
  end;
end;

procedure TCnInt64List.Clear;
begin
  SetCount(0);
  SetCapacity(0);
end;

procedure TCnInt64List.Delete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnInt64ListError, Index);

  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(Int64));
end;

procedure TCnInt64List.DeleteLow(ACount: Integer);
begin
  if ACount > 0 then
  begin
    if ACount >= FCount then
      Clear
    else
    begin
      Dec(FCount, ACount);

      // �� 0 ɾ���� ACount - 1��Ҳ���ǰ� ACount �� Count - 1 ���� Move �� 0
      System.Move(FList^[ACount], FList^[0],
        FCount * SizeOf(Int64));
    end;
  end;
end;

class procedure TCnInt64List.Error(const Msg: string; Data: Integer);
begin
  raise EListError.CreateFmt(Msg, [Data]);
end;

procedure TCnInt64List.Exchange(Index1: Integer; Index2: Integer);
var
  Item: Int64;
begin
  if (Index1 < 0) or (Index1 >= FCount) then
    Error(SCnInt64ListError, Index1);
  if (Index2 < 0) or (Index2 >= FCount) then
    Error(SCnInt64ListError, Index2);
  Item := FList^[Index1];
  FList^[Index1] := FList^[Index2];
  FList^[Index2] := Item;
end;

function TCnInt64List.Expand: TCnInt64List;
begin
  if FCount = FCapacity then
    Grow;
  Result := Self;
end;

function TCnInt64List.First: Int64;
begin
  Result := Get(0);
end;

function TCnInt64List.Get(Index: Integer): Int64;
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnInt64ListError, Index);
  Result := FList^[Index];
end;

procedure TCnInt64List.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8 then
      Delta := 16
    else
      Delta := 4;
  SetCapacity(FCapacity + Delta);
end;

function TCnInt64List.IndexOf(Item: Int64): Integer;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do
    Inc(Result);
  if Result = FCount then
    Result := -1;
end;

procedure TCnInt64List.Insert(Index: Integer; Item: Int64);
begin
  if (Index < 0) or (Index > FCount) then
    Error(SCnInt64ListError, Index);
  if FCount = FCapacity then
    Grow;
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(Int64));
  FList^[Index] := Item;
  Inc(FCount);
end;

procedure TCnInt64List.InsertBatch(Index, ACount: Integer);
begin
  if ACount <= 0 then
    Exit;

  if (Index < 0) or (Index > FCount) then
    Error(SCnInt64ListError, Index);
  SetCapacity(FCount + ACount); // �������������� FCount + ACount��FCount û��

  System.Move(FList^[Index], FList^[Index + ACount],
    (FCount - Index) * SizeOf(Int64));
  System.FillChar(FList^[Index], ACount * SizeOf(Int64), 0);
  FCount := FCount + ACount;
end;

function TCnInt64List.Last: Int64;
begin
  Result := Get(FCount - 1);
end;

procedure TCnInt64List.Move(CurIndex, NewIndex: Integer);
var
  Item: Int64;
begin
  if CurIndex <> NewIndex then
  begin
    if (NewIndex < 0) or (NewIndex >= FCount) then
      Error(SCnInt64ListError, NewIndex);
    Item := Get(CurIndex);
    FList^[CurIndex] := 0;
    Delete(CurIndex);
    Insert(NewIndex, 0);
    FList^[NewIndex] := Item;
  end;
end;

procedure TCnInt64List.Put(Index: Integer; Item: Int64);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnInt64ListError, Index);

  FList^[Index] := Item;
end;

function TCnInt64List.Remove(Item: Int64): Integer;
begin
  Result := IndexOf(Item);
  if Result >= 0 then
    Delete(Result);
end;

procedure TCnInt64List.IntSort(CompareProc: TCnInt64CompareProc);
begin
  FCompareProcInt64 := CompareProc;
  if FCount >= 1 then
    MemoryQuickSort(FList, SizeOf(Int64), FCount, MyInt64SortCompare);
end;

function TCnInt64List.ToString: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
  begin
    if I = 0 then
      Result := IntToStr(Items[I])
    else
      Result := Result + ',' + IntToStr(Items[I]);
  end;
end;

procedure TCnInt64List.SetCapacity(NewCapacity: Integer);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxListSize) then
    Error(SCnInt64ListError, NewCapacity);
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(Int64));
    FCapacity := NewCapacity;
  end;
end;

procedure TCnInt64List.SetCount(NewCount: Integer);
var
  I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Error(SCnInt64ListError, NewCount);
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(Int64), 0)
  else
    for I := FCount - 1 downto NewCount do
      Delete(I);
  FCount := NewCount;
end;

{ TCnUInt32List }

function TCnUInt32List.Add(Item: Cardinal): Integer;
begin
  if FIgnoreDuplicated and (IndexOf(Item) >= 0) then
  begin
    Result := -1;
    Exit;
  end;

  Result := FCount;
  if Result = FCapacity then
    Grow;
  FList^[Result] := Item;
  Inc(FCount);
end;

procedure TCnUInt32List.AddList(List: TCnUInt32List);
var
  I: Integer;
begin
  if (List <> nil) and (List.Count > 0) then
  begin
    for I := 0 to List.Count - 1 do
      Add(List[I]);
  end;
end;

procedure TCnUInt32List.Clear;
begin
  SetCount(0);
  SetCapacity(0);
end;

procedure TCnUInt32List.Delete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(@SListIndexError, Index);

  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(Cardinal));
end;

destructor TCnUInt32List.Destroy;
begin
  Clear;
  inherited;
end;

class procedure TCnUInt32List.Error(Msg: PResStringRec; Data: Integer);
begin
  TCnUInt32List.Error(LoadResString(Msg), Data);
end;

class procedure TCnUInt32List.Error(const Msg: string; Data: Integer);
begin
  raise EListError.CreateFmt(Msg, [Data])
end;

procedure TCnUInt32List.Exchange(Index1: Integer; Index2: Integer);
var
  Item: Cardinal;
begin
  if (Index1 < 0) or (Index1 >= FCount) then
    Error(@SListIndexError, Index1);
  if (Index2 < 0) or (Index2 >= FCount) then
    Error(@SListIndexError, Index2);
  Item := FList^[Index1];
  FList^[Index1] := FList^[Index2];
  FList^[Index2] := Item;
end;

function TCnUInt32List.Expand: TCnUInt32List;
begin
  if FCount = FCapacity then
    Grow;
  Result := Self;
end;

function TCnUInt32List.Extract(Item: Cardinal): Cardinal;
var
  I: Integer;
begin
  Result := 0;
  I := IndexOf(Item);
  if I >= 0 then
  begin
    Result := Item;
    FList^[I] := 0;
    Delete(I);
  end;
end;

function TCnUInt32List.First: Cardinal;
begin
  Result := Get(0);
end;

function TCnUInt32List.Get(Index: Integer): Cardinal;
begin
  if (Index < 0) or (Index >= FCount) then
    Error(@SListIndexError, Index);
  Result := FList^[Index];
end;

procedure TCnUInt32List.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8 then
      Delta := 16
    else
      Delta := 4;
  SetCapacity(FCapacity + Delta);
end;

function TCnUInt32List.IndexOf(Item: Cardinal): Integer;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do
    Inc(Result);
  if Result = FCount then
    Result := -1;
end;

procedure TCnUInt32List.Insert(Index: Integer; Item: Cardinal);
begin
  if (Index < 0) or (Index > FCount) then
    Error(@SListIndexError, Index);
  if FCount = FCapacity then
    Grow;
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(Cardinal));
  FList^[Index] := Item;
  Inc(FCount);
end;

function TCnUInt32List.Last: Cardinal;
begin
  Result := Get(FCount - 1);
end;

procedure TCnUInt32List.Move(CurIndex, NewIndex: Integer);
var
  Item: Cardinal;
begin
  if CurIndex <> NewIndex then
  begin
    if (NewIndex < 0) or (NewIndex >= FCount) then
      Error(@SListIndexError, NewIndex);
    Item := Get(CurIndex);
    FList^[CurIndex] := 0;
    Delete(CurIndex);
    Insert(NewIndex, 0);
    FList^[NewIndex] := Item;
  end;
end;

procedure TCnUInt32List.Put(Index: Integer; Item: Cardinal);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(@SListIndexError, Index);
  if FIgnoreDuplicated and (IndexOf(Item) >= 0) then
    Exit;

  FList^[Index] := Item;
end;

function TCnUInt32List.Remove(Item: Cardinal): Integer;
begin
  Result := IndexOf(Item);
  if Result >= 0 then
    Delete(Result);
end;

procedure TCnUInt32List.IntSort(CompareProc: TCnUInt32CompareProc);
begin
  FCompareProcUInt32 := CompareProc;
  if FCount >= 1 then
    MemoryQuickSort(FList, SizeOf(Cardinal), FCount, MyUInt32SortCompare);
end;

function TCnUInt32List.ToString: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
  begin
    if I = 0 then
      Result := UInt32ToStr(Items[I])
    else
      Result := Result + ',' + UInt32ToStr(Items[I]);
  end;
end;

procedure TCnUInt32List.SetCapacity(NewCapacity: Integer);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxListSize) then
    Error(@SListCapacityError, NewCapacity);
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(Cardinal));
    FCapacity := NewCapacity;
  end;
end;

procedure TCnUInt32List.SetCount(NewCount: Integer);
var
  I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Error(@SListCountError, NewCount);
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(Cardinal), 0)
  else
    for I := FCount - 1 downto NewCount do
      Delete(I);
  FCount := NewCount;
end;

{ TCnUInt64List }

function TCnUInt64List.Add(Item: TUInt64): TUInt64;
begin
  if FIgnoreDuplicated and (IndexOf(Item) <> CN_NOT_FOUND_INDEX) then
  begin
    Result := CN_NOT_FOUND_INDEX;
    Exit;
  end;

  Result := FCount;
  if Result = FCapacity then
    Grow;
  FList^[Result] := Item;
  Inc(FCount);
end;

procedure TCnUInt64List.AddList(List: TCnUInt64List);
var
  I: Integer;
begin
  if (List <> nil) and (List.Count > 0) then
  begin
    for I := 0 to List.Count - 1 do
      Add(List[I]);
  end;
end;

procedure TCnUInt64List.Clear;
begin
  SetCount(0);
  SetCapacity(0);
end;

procedure TCnUInt64List.Delete(Index: TUInt64);
begin
  if (UInt64Compare(Index, 0) < 0) or (UInt64Compare(Index, FCount) >= 0) then
    Error(@SListIndexError, Index);

  Dec(FCount);
  if UInt64Compare(Index, FCount) < 0 then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(TUInt64));
end;

destructor TCnUInt64List.Destroy;
begin
  Clear;
  inherited;
end;

class procedure TCnUInt64List.Error(Msg: PResStringRec; Data: Integer);
begin
  TCnUInt64List.Error(LoadResString(Msg), Data);
end;

class procedure TCnUInt64List.Error(const Msg: string; Data: Integer);
begin
  raise EListError.CreateFmt(Msg, [Data])
end;

procedure TCnUInt64List.Exchange(Index1: TUInt64; Index2: TUInt64);
var
  Item: TUInt64;
begin
  if (Index1 < 0) or (Index1 >= FCount) then
    Error(@SListIndexError, Index1);
  if (Index2 < 0) or (Index2 >= FCount) then
    Error(@SListIndexError, Index2);
  Item := FList^[Index1];
  FList^[Index1] := FList^[Index2];
  FList^[Index2] := Item;
end;

function TCnUInt64List.Expand: TCnUInt64List;
begin
  if FCount = FCapacity then
    Grow;
  Result := Self;
end;

function TCnUInt64List.Extract(Item: TUInt64): TUInt64;
var
  I: Integer;
begin
  Result := 0;
  I := IndexOf(Item);
  if I <> CN_NOT_FOUND_INDEX then
  begin
    Result := Item;
    FList^[I] := 0;
    Delete(I);
  end;
end;

function TCnUInt64List.First: TUInt64;
begin
  Result := Get(0);
end;

function TCnUInt64List.Get(Index: TUInt64): TUInt64;
begin
  if (UInt64Compare(Index, 0) < 0) or (UInt64Compare(Index, FCount) >= 0) then
    Error(@SListIndexError, Index);
  Result := FList^[Index];
end;

procedure TCnUInt64List.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8 then
      Delta := 16
    else
      Delta := 4;
  SetCapacity(FCapacity + TUInt64(Delta));
end;

function TCnUInt64List.IndexOf(Item: TUInt64): TUInt64;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do
    Inc(Result);
  if Result = FCount then
    Result := CN_NOT_FOUND_INDEX;
end;

procedure TCnUInt64List.Insert(Index: TUInt64; Item: TUInt64);
begin
  if (UInt64Compare(Index, 0) < 0) or (UInt64Compare(Index, FCount) >= 0) then
    Error(@SListIndexError, Index);
  if FCount = FCapacity then
    Grow;
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(TUInt64));
  FList^[Index] := Item;
  Inc(FCount);
end;

function TCnUInt64List.Last: TUInt64;
begin
  Result := Get(FCount - 1);
end;

procedure TCnUInt64List.Move(CurIndex, NewIndex: TUInt64);
var
  Item: TUInt64;
begin
  if CurIndex <> NewIndex then
  begin
    if (UInt64Compare(NewIndex, 0) < 0) or (UInt64Compare(NewIndex, FCount) >= 0) then
      Error(@SListIndexError, NewIndex);
    Item := Get(CurIndex);
    FList^[CurIndex] := 0;
    Delete(CurIndex);
    Insert(NewIndex, 0);
    FList^[NewIndex] := Item;
  end;
end;

procedure TCnUInt64List.Put(Index: TUInt64; Item: TUInt64);
begin
  if (UInt64Compare(Index, 0) < 0) or (UInt64Compare(Index, FCount) >= 0) then
    Error(@SListIndexError, Index);
  if FIgnoreDuplicated and (IndexOf(Item) <> CN_NOT_FOUND_INDEX) then
    Exit;

  FList^[Index] := Item;
end;

function TCnUInt64List.Remove(Item: TUInt64): TUInt64;
begin
  Result := IndexOf(Item);
  if Result <> CN_NOT_FOUND_INDEX then
    Delete(Result);
end;

procedure TCnUInt64List.IntSort(CompareProc: TCnUInt64CompareProc);
begin
  FCompareProcUInt64 := CompareProc;
  if FCount >= 1 then
    MemoryQuickSort(FList, SizeOf(TUInt64), FCount, MyUInt64SortCompare);
end;

function TCnUInt64List.ToString: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
  begin
    if I = 0 then
      Result := UInt64ToStr(Items[I])
    else
      Result := Result + ',' + UInt64ToStr(Items[I]);
  end;
end;

procedure TCnUInt64List.SetCapacity(NewCapacity: TUInt64);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxListSize) then
    Error(@SListCapacityError, NewCapacity);
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(TUInt64));
    FCapacity := NewCapacity;
  end;
end;

procedure TCnUInt64List.SetCount(NewCount: TUInt64);
var
  I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Error(@SListCountError, NewCount);
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(TUInt64), 0)
  else
  begin
    for I := FCount - 1 downto NewCount do
      Delete(I);
  end;
  FCount := NewCount;
end;

{ TCnExtendedList }

destructor TCnExtendedList.Destroy;
begin
  Clear;
end;

function TCnExtendedList.Add(Item: Extended): Integer;
begin
  Result := FCount;
  if Result = FCapacity then
    Grow;
  FList^[Result] := Item;
  Inc(FCount);
end;

procedure TCnExtendedList.AddList(List: TCnExtendedList);
var
  I: Integer;
begin
  if (List <> nil) and (List.Count > 0) then
  begin
    for I := 0 to List.Count - 1 do
      Add(List[I]);
  end;
end;

procedure TCnExtendedList.Clear;
begin
  SetCount(0);
  SetCapacity(0);
end;

procedure TCnExtendedList.Delete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnExtendedListError, Index);

  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(Extended));
end;

procedure TCnExtendedList.DeleteLow(ACount: Integer);
begin
  if ACount > 0 then
  begin
    if ACount >= FCount then
      Clear
    else
    begin
      Dec(FCount, ACount);

      // �� 0 ɾ���� ACount - 1��Ҳ���ǰ� ACount �� Count - 1 ���� Move �� 0
      System.Move(FList^[ACount], FList^[0],
        FCount * SizeOf(Extended));
    end;
  end;
end;

class procedure TCnExtendedList.Error(const Msg: string; Data: Integer);
begin
  raise EListError.CreateFmt(Msg, [Data]);
end;

procedure TCnExtendedList.Exchange(Index1: Integer; Index2: Integer);
var
  Item: Extended;
begin
  if (Index1 < 0) or (Index1 >= FCount) then
    Error(SCnExtendedListError, Index1);
  if (Index2 < 0) or (Index2 >= FCount) then
    Error(SCnExtendedListError, Index2);
  Item := FList^[Index1];
  FList^[Index1] := FList^[Index2];
  FList^[Index2] := Item;
end;

function TCnExtendedList.Expand: TCnExtendedList;
begin
  if FCount = FCapacity then
    Grow;
  Result := Self;
end;

function TCnExtendedList.First: Extended;
begin
  Result := Get(0);
end;

function TCnExtendedList.Get(Index: Integer): Extended;
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnExtendedListError, Index);
  Result := FList^[Index];
end;

procedure TCnExtendedList.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8 then
      Delta := 16
    else
      Delta := 4;
  SetCapacity(FCapacity + Delta);
end;

function TCnExtendedList.IndexOf(Item: Extended): Integer;
begin
  Result := 0;
  while (Result < FCount) and (Abs(FList^[Result] - Item) < 0.00001) do
    Inc(Result);
  if Result = FCount then
    Result := -1;
end;

procedure TCnExtendedList.Insert(Index: Integer; Item: Extended);
begin
  if (Index < 0) or (Index > FCount) then
    Error(SCnExtendedListError, Index);
  if FCount = FCapacity then
    Grow;
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(Extended));
  FList^[Index] := Item;
  Inc(FCount);
end;

procedure TCnExtendedList.InsertBatch(Index, ACount: Integer);
begin
  if ACount <= 0 then
    Exit;

  if (Index < 0) or (Index > FCount) then
    Error(SCnExtendedListError, Index);
  SetCapacity(FCount + ACount); // �������������� FCount + ACount��FCount û��

  System.Move(FList^[Index], FList^[Index + ACount],
    (FCount - Index) * SizeOf(Extended));
  System.FillChar(FList^[Index], ACount * SizeOf(Extended), 0);
  FCount := FCount + ACount;
end;

function TCnExtendedList.Last: Extended;
begin
  Result := Get(FCount - 1);
end;

procedure TCnExtendedList.Move(CurIndex: Integer; NewIndex: Integer);
var
  Item: Extended;
begin
  if CurIndex <> NewIndex then
  begin
    if (NewIndex < 0) or (NewIndex >= FCount) then
      Error(SCnExtendedListError, NewIndex);
    Item := Get(CurIndex);
    FList^[CurIndex] := 0;
    Delete(CurIndex);
    Insert(NewIndex, 0);
    FList^[NewIndex] := Item;
  end;
end;

procedure TCnExtendedList.Put(Index: Integer; Item: Extended);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnExtendedListError, Index);

  FList^[Index] := Item;
end;

function TCnExtendedList.Remove(Item: Extended): Integer;
begin
  Result := IndexOf(Item);
  if Result >= 0 then
    Delete(Result);
end;

procedure TCnExtendedList.FloatSort(CompareProc: TCnExtendedCompareProc);
begin
  FCompareProcExtended := CompareProc;
  if FCount >= 1 then
    MemoryQuickSort(FList, SizeOf(Extended), FCount, MyExtendedSortCompare);
end;

function TCnExtendedList.ToString: string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Count - 1 do
  begin
    if I = 0 then
      Result := FloatToStr(Items[I])
    else
      Result := Result + ',' + FloatToStr(Items[I]);
  end;
end;

procedure TCnExtendedList.SetCapacity(NewCapacity: Integer);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxListSize) then
    Error(SCnExtendedListError, NewCapacity);
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(Extended));
    FCapacity := NewCapacity;
  end;
end;

procedure TCnExtendedList.SetCount(NewCount: Integer);
var
  I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Error(SCnExtendedListError, NewCount);
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(Extended), 0)
  else
    for I := FCount - 1 downto NewCount do
      Delete(I);
  FCount := NewCount;
end;

{ TCnRefObjectList }

destructor TCnRefObjectList.Destroy;
begin
  Clear;
end;

function TCnRefObjectList.Add(Item: TObject): Integer;
begin
  Result := FCount;
  if Result = FCapacity then
    Grow;
  FList^[Result] := Item;
  Inc(FCount);
end;

procedure TCnRefObjectList.Clear;
begin
  SetCount(0);
  SetCapacity(0);
end;

procedure TCnRefObjectList.Delete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnRefObjectListError, Index);

  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(TObject));
end;

procedure TCnRefObjectList.DeleteLow(ACount: Integer);
begin
  if ACount > 0 then
  begin
    if ACount >= FCount then
      Clear
    else
    begin
      Dec(FCount, ACount);

      // �� 0 ɾ���� ACount - 1��Ҳ���ǰ� ACount �� Count - 1 ���� Move �� 0
      System.Move(FList^[ACount], FList^[0],
        FCount * SizeOf(TObject));
    end;
  end;
end;

class procedure TCnRefObjectList.Error(const Msg: string; Data: Integer);
begin
  raise EListError.CreateFmt(Msg, [Data]);
end;

procedure TCnRefObjectList.Exchange(Index1: Integer; Index2: Integer);
var
  Item: TObject;
begin
  if (Index1 < 0) or (Index1 >= FCount) then
    Error(SCnRefObjectListError, Index1);
  if (Index2 < 0) or (Index2 >= FCount) then
    Error(SCnRefObjectListError, Index2);
  Item := FList^[Index1];
  FList^[Index1] := FList^[Index2];
  FList^[Index2] := Item;
end;

function TCnRefObjectList.Expand: TCnRefObjectList;
begin
  if FCount = FCapacity then
    Grow;
  Result := Self;
end;

function TCnRefObjectList.First: TObject;
begin
  Result := Get(0);
end;

function TCnRefObjectList.Get(Index: Integer): TObject;
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnRefObjectListError, Index);
  Result := FList^[Index];
end;

procedure TCnRefObjectList.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8 then
      Delta := 16
    else
      Delta := 4;
  SetCapacity(FCapacity + Delta);
end;

function TCnRefObjectList.IndexOf(Item: TObject): Integer;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do
    Inc(Result);
  if Result = FCount then
    Result := -1;
end;

procedure TCnRefObjectList.Insert(Index: Integer; Item: TObject);
begin
  if (Index < 0) or (Index > FCount) then
    Error(SCnRefObjectListError, Index);
  if FCount = FCapacity then
    Grow;
  if Index < FCount then
    System.Move(FList^[Index], FList^[Index + 1],
      (FCount - Index) * SizeOf(TObject));
  FList^[Index] := Item;
  Inc(FCount);
end;

procedure TCnRefObjectList.InsertBatch(Index, ACount: Integer);
begin
  if ACount <= 0 then
    Exit;

  if (Index < 0) or (Index > FCount) then
    Error(SCnRefObjectListError, Index);
  SetCapacity(FCount + ACount); // �������������� FCount + ACount��FCount û��

  System.Move(FList^[Index], FList^[Index + ACount],
    (FCount - Index) * SizeOf(TObject));
  System.FillChar(FList^[Index], ACount * SizeOf(TObject), 0);
  FCount := FCount + ACount;
end;

function TCnRefObjectList.Last: TObject;
begin
  Result := Get(FCount - 1);
end;

procedure TCnRefObjectList.Move(CurIndex, NewIndex: Integer);
var
  Item: TObject;
begin
  if CurIndex <> NewIndex then
  begin
    if (NewIndex < 0) or (NewIndex >= FCount) then
      Error(SCnRefObjectListError, NewIndex);
    Item := Get(CurIndex);
    FList^[CurIndex] := nil;
    Delete(CurIndex);
    Insert(NewIndex, nil);
    FList^[NewIndex] := Item;
  end;
end;

procedure TCnRefObjectList.Put(Index: Integer; Item: TObject);
begin
  if (Index < 0) or (Index >= FCount) then
    Error(SCnRefObjectListError, Index);

  FList^[Index] := Item;
end;

function TCnRefObjectList.Remove(Item: TObject): Integer;
begin
  Result := IndexOf(Item);
  if Result >= 0 then
    Delete(Result);
end;

procedure TCnRefObjectList.SetCapacity(NewCapacity: Integer);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxListSize) then
    Error(SCnRefObjectListError, NewCapacity);
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(TObject));
    FCapacity := NewCapacity;
  end;
end;

procedure TCnRefObjectList.SetCount(NewCount: Integer);
var
  I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Error(SCnRefObjectListError, NewCount);
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(TObject), 0)
  else
    for I := FCount - 1 downto NewCount do
      Delete(I);
  FCount := NewCount;
end;

procedure CnIntegerListCopy(Dst: TCnIntegerList; Src: TCnIntegerList);
begin
  if (Src <> nil) and (Dst <> nil) and (Src <> Dst) then
  begin
    Dst.Count := Src.Count;
    if Src.Count > 0 then
    begin
{$IFDEF LIST_NEW_POINTER}
      Move(Src.List[0], Dst.List[0], Src.Count * SizeOf(Integer));
{$ELSE}
      Move(Src.List^, Dst.List^, Src.Count * SizeOf(Integer));
{$ENDIF}
    end;
  end;
end;

procedure CnInt64ListCopy(Dst: TCnInt64List; Src: TCnInt64List);
begin
  if (Src <> nil) and (Dst <> nil) and (Src <> Dst) then
  begin
    Dst.Count := Src.Count;
    if Src.Count > 0 then
      Move(Src.List^, Dst.List^, Src.Count * SizeOf(Int64));
  end;
end;

procedure CnRefObjectListCopy(Dst: TCnRefObjectList; Src: TCnRefObjectList);
begin
  if (Src <> nil) and (Dst <> nil) and (Src <> Dst) then
  begin
    Dst.Count := Src.Count;
    if Src.Count > 0 then
      Move(Src.List^, Dst.List^, Src.Count * SizeOf(TObject));
  end;
end;

{$IFDEF POSIX}

{ TCnInternalList<T> }

procedure TCnInternalList<T>.RemoveDuplictedElements;
var
  I, J: Integer;
  V: NativeInt;
  Dup: Boolean;
begin
  for I := Count - 1 downto 0 do
  begin
    V := ItemValue(Items[I]);
    Dup := False;
    for J := 0 to I - 1 do
    begin
      if V = ItemValue(Items[J]) then
      begin
        Dup := True;
        Break;
      end;
    end;

    if Dup then
      Delete(I);
  end;
end;

{$ENDIF}

{ TCnBytesObject }

constructor TCnBytesObject.Create(AMem: Pointer; MemByteSize: Integer);
begin
  inherited Create;
  if (AMem <> nil) and (MemByteSize > 0) then
  begin
    SetLength(FData, MemByteSize);
    Move(AMem^, FData[0], MemByteSize);
  end;
end;

destructor TCnBytesObject.Destroy;
begin
  SetLength(FData, 0);
  inherited;
end;

{ TCnBytesPair }

constructor TCnBytesPair.Create(AKeyMem: Pointer; KeyMemByteSize: Integer;
  AValueMem: Pointer; ValueMemByteSize: Integer);
begin
  inherited Create;

  if (AKeyMem <> nil) and (KeyMemByteSize > 0) then
  begin
    SetLength(FKey, KeyMemByteSize);
    Move(AKeyMem^, FKey[0], KeyMemByteSize);
  end;

  if (AValueMem <> nil) and (ValueMemByteSize > 0) then
  begin
    SetLength(FValue, ValueMemByteSize);
    Move(AValueMem^, FValue[0], ValueMemByteSize);
  end;
end;

destructor TCnBytesPair.Destroy;
begin
  SetLength(FKey, 0);
  SetLength(FValue, 0);
  inherited;
end;

end.
