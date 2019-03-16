(*********************************************)
(*	Name:    ViC Library                     *)
(*	Type:    Delphi Library Exportation      *)
(*	Author:  vic4key/mrVic aka Shim Ji Young *)
(*	Mail:    vic4key@gmail.com               *)
(*	Website: cin1team.biz | reaonline.net    *)
(*********************************************)

unit mrVic;

interface

uses Windows, Imagehlp, SysUtils, TlHelp32, ActiveX, ShlObj;

type
  {$IF CompilerVersion < 22.00} // Below Delphi XE
    T_SIZE = DWORD;

    tagMODULEENTRY32A = record
      dwSize: DWORD;
      th32ModuleID: DWORD;  // This module
      th32ProcessID: DWORD; // owning process
      GlblcntUsage: DWORD;  // Global usage count on the module
      ProccntUsage: DWORD;  // Module usage count in th32ProcessID's context
      modBaseAddr: PBYTE;   // Base address of module in th32ProcessID's context
      modBaseSize: DWORD;   // Size in bytes of module starting at modBaseAddr
      hModule: HMODULE;     // The hModule of this module in th32ProcessID's context
      szModule: array[0..MAX_MODULE_NAME32] of AnsiChar;
      szExePath: array[0..MAX_PATH - 1] of AnsiChar;
    end;
    MODULEENTRY32A = tagMODULEENTRY32A;
    PMODULEENTRY32A = ^tagMODULEENTRY32A;
    LPMODULEENTRY32A = ^tagMODULEENTRY32A;
    TModuleEntry32A = tagMODULEENTRY32A;

    tagMODULEENTRY32W = record
      dwSize: DWORD;
      th32ModuleID: DWORD;  // This module
      th32ProcessID: DWORD; // owning process
      GlblcntUsage: DWORD;  // Global usage count on the module
      ProccntUsage: DWORD;  // Module usage count in th32ProcessID's context
      modBaseAddr: PBYTE;   // Base address of module in th32ProcessID's context
      modBaseSize: DWORD;   // Size in bytes of module starting at modBaseAddr
      hModule: HMODULE;     // The hModule of this module in th32ProcessID's context
      szModule: array[0..MAX_MODULE_NAME32] of WChar;
      szExePath: array[0..MAX_PATH - 1] of WChar;
    end;
    MODULEENTRY32W = tagMODULEENTRY32W;
    PMODULEENTRY32W = ^tagMODULEENTRY32W;
    LPMODULEENTRY32W = ^tagMODULEENTRY32W;
    TModuleEntry32W = tagMODULEENTRY32W;

    TModule32FirstA = Function(hSnapshot: THandle; var lpme: TModuleEntry32A): BOOL stdcall;
    TModule32NextA  = Function(hSnapshot: THandle; var lpme: TModuleEntry32A): BOOL stdcall;
    TModule32FirstW = Function(hSnapshot: THandle; var lpme: TModuleEntry32W): BOOL stdcall;
    TModule32NextW  = Function(hSnapshot: THandle; var lpme: TModuleEntry32W): BOOL stdcall;
  {$ELSE} // Above or Equal Delphi XE, like XE, XE2, XE3, XE4...
    T_SIZE = SIZE_T;
  {$IFEND}

  TSizeReg = 1..4;

  TSysCharSet = set of AnsiChar;

  IMAGE_IMPORT_DESCRIPTOR = record
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD;
    FirstThunk: DWORD;
  case Byte of
    0: (Characteristics: DWORD);
    1: (OriginalFirstThunk: DWORD);
  end;
  TImageImportDescriptor = IMAGE_IMPORT_DESCRIPTOR;
  PImageImportDescriptor = ^IMAGE_IMPORT_DESCRIPTOR;

  PNtAnsiString = ^TNtAnsiString;
  TNtAnsiString = packed record
    Length: Word;
    MaximumLength: Word;
    Buffer: PAnsiChar;
  end;

  PNtUnicodeString = ^TNtUnicodeString;
  TNtUnicodeString = packed record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;

  PCurDir = ^TCurDir;
  TCurDir = packed record
    DosPath: TNtUnicodeString;
    Handle : THandle;
  end;     

  PRtlDriveLetterCurDir = ^TRtlDriveLetterCurDir;
  TRtlDriveLetterCurDir = packed record
    Flags    : Word;
    Length   : Word;
    TimeStamp: Cardinal;
    DosPath  : TNtAnsiString;
  end;

  PRtlUserProcessParameters = ^TRtlUserProcessParameters;
  TRtlUserProcessParameters = record
    MaximumLength    : Cardinal;
    Length           : Cardinal;
    Flags            : Cardinal;
    DebugFlags       : Cardinal;
    ConsoleHandle    : THandle;
    ConsoleFlags     : Cardinal;
    StandardInput    : THandle;
    StandardOutput   : THandle;
    StandardError    : THandle;
    CurrentDirectory : TCurDir;
    DllPath          : TNtUnicodeString;
    ImagePathName    : TNtUnicodeString;
    CommandLine      : TNtUnicodeString;
    Environment      : Pointer;
    StartingX        : Cardinal;
    StartingY        : Cardinal;
    CountX           : Cardinal;
    CountY           : Cardinal;
    CountCharsX      : Cardinal;
    CountCharsY      : Cardinal;
    FillAttribute    : Cardinal;
    WindowFlags      : Cardinal;
    ShowWindowFlags  : Cardinal;
    WindowTitle      : TNtUnicodeString;
    DesktopInfo      : TNtUnicodeString;
    ShellInfo        : TNtUnicodeString;
    RuntimeData      : TNtUnicodeString;
    CurrentDirectores: array [0..31] of TRtlDriveLetterCurDir;
  end;

  PPebLdrData = ^TPebLdrData;
  TPebLdrData = packed record
    Length                         : Cardinal;        // 0h
    Initialized                    : LongBool;        // 4h
    SsHandle                       : THandle;         // 8h
    InLoadOrderModuleList          : TListEntry;      // 0Ch
    InMemoryOrderModuleList        : TListEntry;      // 14h
    InInitializationOrderModuleList: TListEntry;      // 1Ch
  end;

  PPebFreeBlock = ^TPebFreeBlock;
  TPebFreeBlock = record
    Next: PPebFreeBlock;
    Size: Cardinal;
  end;  
  
  PPEB = ^TPEB;
  TPEB = packed record
    InheritedAddressSpace         : Boolean;
    ReadImageFileExecOptions      : Boolean;
    BeingDebugged                 : Boolean;
    SpareBool                     : Boolean;
    Mutant                        : Pointer;
    ImageBaseAddress              : Pointer;
    Ldr                           : PPebLdrData;
    ProcessParameters             : PRtlUserProcessParameters;
    SubSystemData                 : Pointer;
    ProcessHeap                   : Pointer;
    FastPebLock                   : Pointer;
    FastPebLockRoutine            : Pointer;
    FastPebUnlockRoutine          : Pointer;
    EnvironmentUpdateCount        : Cardinal;
    KernelCallbackTable           : Pointer;
    case Integer of
      4: (
        EventLogSection           : Pointer;
        EventLog                  : Pointer);
      5:(
        SystemReserved            : array [0..1] of Cardinal;
        FreeList                      : PPebFreeBlock;
        TlsExpansionCounter           : Cardinal;
        TlsBitmap                     : Pointer;
        TlsBitmapBits                 : array [0..1] of Cardinal;
        ReadOnlySharedMemoryBase      : Pointer;
        ReadOnlySharedMemoryHeap      : Pointer;
        ReadOnlyStaticServerData      : ^Pointer;
        AnsiCodePageData              : Pointer;
        OemCodePageData               : Pointer;
        UnicodeCaseTableData          : Pointer;
        NumberOfProcessors            : Cardinal;
        NtGlobalFlag                  : Cardinal;
        Unknown                       : Cardinal;
        CriticalSectionTimeout        : TLargeInteger;
        HeapSegmentReserve            : Cardinal;
        HeapSegmentCommit             : Cardinal;
        HeapDeCommitTotalFreeThreshold: Cardinal;
        HeapDeCommitFreeBlockThreshold: Cardinal;
        NumberOfHeaps                 : Cardinal;
        MaximumNumberOfHeaps          : Cardinal;
        ProcessHeaps                  : ^Pointer;
        GdiSharedHandleTable          : Pointer;
        ProcessStarterHelper          : Pointer;
        GdiDCAttributeList            : Cardinal;
        LoaderLock                    : Pointer;
        OSMajorVersion                : Cardinal;
        OSMinorVersion                : Cardinal;
        OSBuildNumber                 : Word;
        OSCSDVersion                  : Word;
        OSPlatformId                  : Cardinal;
        ImageSubsystem                : Cardinal;
        ImageSubsystemMajorVersion    : Cardinal;
        ImageSubsystemMinorVersion    : Cardinal;
        ImageProcessAffinityMask      : Cardinal;
        GdiHandleBuffer               : Array [0..33] of Cardinal;
        PostProcessInitRoutine        : ^Pointer;
        TlsExpansionBitmap            : Pointer;
        TlsExpansionBitmapBits        : Array [0..31] of Cardinal;
        SessionId                     : Cardinal;
        AppCompatInfo                 : Pointer;
        CSDVersion                    : TNtUnicodeString
        );
    end;

  TVIC = class
  private
    { Private declarations }
  public
    Function  FindPattern(hProcess: THandle; dwStartAddress: DWORD; dwMemorySize: T_SIZE; const arSignature: array of Byte): DWORD; stdcall;

    (* The API Hooking *)
    Function  API_HookIAT(lpszModuleName, lpszFunctionName: PAnsiChar; pCallbackFunc: Pointer; var pOriApi: Pointer): Boolean; stdcall;
    Function  API_UnHookIAT(lpszModuleName, lpszFunctionName: PAnsiChar; pCallback: Pointer): Boolean; stdcall;
    Function  API_HookInline(lpszModuleName, lpszFunctionName: PAnsiChar; pCallback: Pointer; var pOriApi: Pointer): Boolean; stdcall;
    Function  API_UnHookInline(lpszModuleName, lpszFunctionName: PAnsiChar; pResCode: Pointer): Boolean; stdcall;

    Function  DLL_Inject(dwPID: DWORD; psLibraryName: String): Boolean; stdcall;
    Function  DLL_UnInject(dwPID: DWORD; psLibraryName: String): Boolean; stdcall;
    Function  HideModule(dwPID: DWORD; psModuleName: String): Boolean; stdcall;

    (* Read and Write to the memory of the process *)
    Procedure AsmWrite(const dwAddress: DWORD; dwBuffer: DWORD; nSize: TSizeReg); stdcall;
    Function  AsmRead(const dwAddress: DWORD; nSize: TSizeReg): DWORD; stdcall;
    Function  ReadNotSafe(const dwAddress: DWORD; nSize: TSizeReg): DWORD; stdcall;
    Procedure WriteNotSafe(const dwAddress: DWORD; dwBuffer: DWORD; nSize: TSizeReg); stdcall;
    Function  SafeReadMemory(const dwAddress: DWORD; nSize: TSizeReg): DWORD; stdcall;
    Procedure SafeWriteMemory(const dwAddress: DWORD; dwBuffer: DWORD; nSize: TSizeReg); stdcall;
    Function  RpmEx(const dwAddress: DWORD; const arOffset: array of const; nNumberOfByteToRead: TSizeReg): DWORD; stdcall;

    Function  LengthOfOpcode(const dwAddress: DWORD): DWORD; stdcall;
    Function  LengthToJump(const dwSrcAddress, dwDestAddress: DWORD): DWORD; stdcall;
    Function  SizeOfProc(pProc: Pointer): DWORD; stdcall;

    Function  PidToName(dwPID: DWORD): String; stdcall;
    Function  NameToPid(szProcessName: String): DWORD; stdcall;

    Function  UserName: String; stdcall;
    Function  PrevFolder(Path: String): String; stdcall;
    Function  GetTempDirectory: String; stdcall;
    Function  GetSizeOfFile(psPathFile: String): DWORD; stdcall;
    Function  ZeroEntryPoint(psFilePath: String): Boolean; stdcall;
    Function  GetTheParentPID: DWORD; stdcall;

    Procedure MapFileA(psFilePath: String; var FileHandle: THandle; var ObjectHandle: THandle; var MappedObject: Pointer); stdcall;
    Procedure UnMapFileA(FileHandle, ObjectHandle: THandle; MappedObject: Pointer); stdcall;

    (* The PIPE transfer *)
    Procedure PIPE_Initialize(psNamePipe: String; dwSizeInBuffer, dwSizeOutBuffer: DWORD; var HandlePipe: THandle); stdcall; // SV
    Function  PIPE_IsConnected(HandlePipe: THandle): Boolean; stdcall; // SV
    Procedure PIPE_OpenPipe(psNamePipe: String; var HandlePipe: THandle); stdcall; // CL
    Procedure PIPE_WritePipe(HandlePipe: THandle; const pInBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
    Procedure PIPE_ReadPipe(HandlePipe: THandle; var pOutBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
    Procedure PIPE_ClosePipe(HandlePipe: THandle); stdcall; // CL
    Function  PIPE_EndPipe(HandlePipe: THandle): Boolean; stdcall; // SV

    (* Mailslot transfer *)
    Procedure MSL_Initialize(psMainslotName: String; var hMailslot: THandle); stdcall; // SV
    Function  MSL_IsConnected(hMailslot: THandle): Boolean; stdcall; // SV
    Procedure MSL_OpenMailslot(psMainslotName: String; var hMailslot: THandle); stdcall; // CL
    Procedure MSL_WriteMailslot(hMailslot: THandle; const pInBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
    Procedure MSL_ReadMailslot(hMailslot: THandle; var pOutBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
    Procedure MSL_CloseMailslot(hMailslot: THandle); stdcall; // SV

    (* File Mapping transfer *)
    Procedure FILEMAP_Initialize(psMapName: String; var pBuffer: Pointer; var hFileMap: THandle); stdcall; // SV
    Procedure FILEMAP_GetMapFile(psMapName: String; var hFileMap: THandle; var pBuffer: Pointer); stdcall; // SV
    Procedure FILEMAP_SendMsg(pBuffer: Pointer; psData: String); stdcall; // S/C
    Function  FILEMAP_ReceiveMsg(hBuffer: Pointer): String; stdcall; // S/C
    Procedure FILEMAP_CloseMap(hMapFile: THandle; hBuffer: Pointer); stdcall; // SV

    Function  Detour(pOldFunction: Pointer; pNewFunction: Pointer; var pResCode: Pointer): Boolean; stdcall;
    Function  JDetour(pOldFunction: Pointer; pNewFunction: Pointer; var pResCode: Pointer): Boolean; stdcall;

    Function  ASMHGetProcAddress(HandleModule: HModule; paProcName: PAnsiChar): Pointer; stdcall;
    Function  ASMNGetProcAddress(lpszModuleName, paProcName: PAnsiChar): Pointer; stdcall;
end;

const
  MSVCRT = 'msvcrt.dll';
  CR = #13;
  LF = #10;
  CRLF = CR + LF;
  DCRLF = CRLF + CRLF;

var
  VIC: TVIC;
  LoadOpCodes: array[0..23] of Byte =
  ($68,$00,$00,$00,$00,$E8,$00,$00,$00,$00,$B8,$FF,
  $FF,$FF,$FF,$50,$E8,$00,$00,$00,$00,$EB,$F3,$C3);
  FreeOpCodes: array[0..32] of Byte =
  ($68,$00,$00,$00,$00,$E8,$00,$00,$00,$00,$B9,$FF,
  $FF,$00,$00,$50,$51,$50,$E8,$00,$00,$00,$00,$59,
  $83,$F8,$00,$58,$74,$02,$E2,$EF,$C3);

//{$L EliRT_OMF_B.obj}

  {$IF CompilerVersion < 22.00} // Below Delphi XE
    // Variables
    _Module32FirstA: TModule32FirstA;
    _Module32NextA: TModule32NextA;
    _Module32FirstW: TModule32FirstW;
    _Module32NextW: TModule32NextW;
    // Functions
    Function Module32FirstA(hSnapshot: THandle; var lpme: TModuleEntry32A): BOOL; stdcall;
    Function Module32NextA(hSnapshot: THandle; var lpme: TModuleEntry32A): BOOL; stdcall;
    Function Module32FirstW(hSnapshot: THandle; var lpme: TModuleEntry32W): BOOL; stdcall;
    Function Module32NextW(hSnapshot: THandle; var lpme: TModuleEntry32W): BOOL; stdcall;
  {$IFEND}

Procedure Pause; stdcall;
Function  TError: String; stdcall;
Procedure VICBox(psText: String); stdcall; overload;
Procedure VICBox(psTitle, psText: String); stdcall; overload;
Procedure VICBox(psFormat: string; const arArgs: array of const); stdcall; overload;
Procedure VICBox(Handle: THandle; psText: String); stdcall; overload;
Procedure VICBox(Handle: THandle; psTitle, psText: String); stdcall; overload;
Procedure VICBox(Handle: THandle; psFormat: string; const arArgs: array of const); stdcall; overload;
Procedure VICMsg(psText: String); stdcall; overload;
Procedure VICMsg(psFormat: string; const arArgs: array of const); stdcall; overload;
Procedure VICBox(psTitle, psFormat: String; const arArgs: array of const); stdcall; overload;
Procedure VICBox(Handle: THandle; psTitle: String; psFormat: string; const arArgs: array of const); stdcall; overload;
Function  fm(psFormat: String; arArgs: array of const): String; stdcall;
Procedure Printf(psText: String); stdcall; overload;
Procedure Printf(arArgs: array of const); stdcall; overload;
Procedure Printf(psFormat: string; const arArgs: array of const); stdcall; overload;
Procedure PrintfLn; stdcall; overload;
Procedure PrintfLn(psText: String); stdcall; overload;
Procedure PrintfLn(arArgs: array of const); stdcall; overload;
Procedure PrintfLn(psFormat: string; const arArgs: array of const);  stdcall; overload;

{Some C++ functions in msvcrt.dll}
Function  Sprintf(Buffer, Format: PAnsiChar): Integer; cdecl; varargs;
Function  Swprintf(Buffer, Format: PWideChar): Integer; cdecl; varargs;
Function  Wprintf(Format: PWideChar): Integer; cdecl; varargs;

Function  HexToInt(const psHexan: String): LongInt; stdcall;
Function  PacToStr(lpszText: PAnsiChar): String; stdcall;
Function  StrToPac(psString: String): PAnsiChar; stdcall;
Function  ChrInSet(C: Char; const CharSet: TSysCharSet): Boolean; stdcall;
Procedure DumpExceptionInfomation; stdcall;
Procedure memcpy(pDes, pSrc: Pointer; dwSize: T_SIZE); stdcall;
Function  RPM(const dwAddress: DWORD; dwSize: T_SIZE): DWORD; stdcall; overload;
Function  WPM(const dwAddress: DWORD; const Buffer: DWORD; dwSize: T_SIZE): Boolean; stdcall; overload;
Function  RPM(const dwAddress: DWORD; pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
Function  WPM(const dwAddress: DWORD; const pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
Function  RPM(hProcess: THandle; const dwAddress: DWORD; pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
Function  WPM(hProcess: THandle; const dwAddress: DWORD; const pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;

implementation

Function RPM(const dwAddress: DWORD; pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
var
  dwOldProtect: DWORD;
  dwRead: T_SIZE;
begin
  VirtualProtect(Ptr(dwAddress),dwSize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
  ReadProcessMemory(GetCurrentProcess,Ptr(dwAddress),pBuffer,dwSize,dwRead);
  VirtualProtect(Ptr(dwAddress),dwSize,dwOldProtect,@dwOldProtect);
  Result:= dwRead = dwSize;
end;

Function WPM(hProcess: THandle; const dwAddress: DWORD; const pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
var
  dwOldProtect: DWORD;
  dwWritten: T_SIZE;
begin
  VirtualProtect(Ptr(dwAddress),dwSize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
  WriteProcessMemory(hProcess,Ptr(dwAddress),pBuffer,dwSize,dwWritten);
  VirtualProtect(Ptr(dwAddress),dwSize,dwOldProtect,@dwOldProtect);
  Result:= dwWritten = dwSize;
end;

Function RPM(hProcess: THandle; const dwAddress: DWORD; pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
var
  dwOldProtect: DWORD;
  dwRead: T_SIZE;
begin
  VirtualProtect(Ptr(dwAddress),dwSize,PAGE_READWRITE,@dwOldProtect);
  ReadProcessMemory(hProcess,Ptr(dwAddress),pBuffer,dwSize,dwRead);
  VirtualProtect(Ptr(dwAddress),dwSize,dwOldProtect,@dwOldProtect);
  Result:= dwRead = dwSize;
end;

Function WPM(const dwAddress: DWORD; const pBuffer: Pointer; dwSize: T_SIZE): Boolean; stdcall; overload;
var
  dwOldProtect: DWORD;
  dwWritten: T_SIZE;
begin
  VirtualProtect(Ptr(dwAddress),dwSize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
  WriteProcessMemory(GetCurrentProcess,Ptr(dwAddress),pBuffer,dwSize,dwWritten);
  VirtualProtect(Ptr(dwAddress),dwSize,dwOldProtect,@dwOldProtect);
  Result:= dwWritten = dwSize;
end;

Function RPM(const dwAddress: DWORD; dwSize: T_SIZE): DWORD; stdcall; overload;
var
  dwOldProtect: DWORD;
  dwRead: T_SIZE;
begin
  Result:= 0;
  VirtualProtect(Ptr(dwAddress),dwSize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
  ReadProcessMemory(GetCurrentProcess,Ptr(dwAddress),@Result,dwSize,dwRead);
  VirtualProtect(Ptr(dwAddress),dwSize,dwOldProtect,@dwOldProtect);
end;

Function WPM(const dwAddress: DWORD; const Buffer: DWORD; dwSize: T_SIZE): Boolean; stdcall; overload;
var
  dwOldProtect: DWORD;
  dwWritten: T_SIZE;
begin
  VirtualProtect(Ptr(dwAddress),dwSize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
  WriteProcessMemory(GetCurrentProcess,Ptr(dwAddress),@Buffer,dwSize,dwWritten);
  VirtualProtect(Ptr(dwAddress),dwSize,dwOldProtect,@dwOldProtect);
  Result:= dwWritten = dwSize;
end;

Procedure memcpy(pDes, pSrc: Pointer; dwSize: T_SIZE); stdcall;
var dwOldProtect: DWORD;
begin
  VirtualProtect(pSrc,dwSize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
  CopyMemory(pDes,pSrc,dwSize);
  VirtualProtect(pSrc,dwSize,dwOldProtect,@dwOldProtect);
end;

Function IsWin9x: Boolean; stdcall;
asm
  mov eax,dword ptr fs:[30h]
  test eax,eax
  sets al
end;

Function PacToStr(lpszText: PAnsiChar): String; stdcall;
begin
  Result:= String(lpszText);
end;

Function HexToInt(const psHexan: String): LongInt; stdcall;
var
  iNdx: Integer;
  cTmp: Char;
begin
  Result:= 0;
  if (psHexan = '') then Exit;
  for iNdx:= 1 to Length(psHexan) do
  begin
    cTmp:= psHexan[iNdx];
    case cTmp of
      '0'..'9': Result:= 16 * Result + (Ord(cTmp) - $30);
      'A'..'F': Result:= 16 * Result + (Ord(cTmp) - $37);
      'a'..'f': Result:= 16 * Result + (Ord(cTmp) - $57);
    else Exit;
    end;
  end;
end;

Function StrToPac(psString: String): PAnsiChar; stdcall;
begin
  Result:= PAnsiChar(AnsiString(psString));
end;

Procedure Pause; stdcall;
begin
  ReadLn;
end;

Function ChrInSet(C: Char; const CharSet: TSysCharSet): Boolean; stdcall;
begin
  {$IF CompilerVersion >= 22.0}
    Result:= CharInSet(C,CharSet);
  {$ELSE}
    Result:= C in CharSet;
  {$IFEND}
end;

Function fm(psFormat: String; arArgs: array of const): String; stdcall;
begin
  try
    Result:= Format(psFormat,arArgs);
  except
    on E: Exception do
      MessageBoxA(GetActiveWindow,StrToPac(E.Message),PAnsiChar('Error'),MB_ICONERROR);
  end;
end;

Procedure VICBox(psText: String); stdcall; overload;
begin
  MessageBoxA(GetActiveWindow,StrToPac(psText),StrToPac('VIC'),MB_OK);
end;

Procedure VICBox(psTitle, psText: String); stdcall; overload;
begin
  MessageBoxA(GetActiveWindow,StrToPac(psText),StrToPac(psTitle),MB_OK);
end;

Procedure VICBox(Handle: THandle; psText: String); stdcall; overload;
begin
  MessageBoxA(Handle,StrToPac(psText),StrToPac('VIC'),MB_OK);
end;

Procedure VICBox(Handle: THandle; psTitle, psText: String); stdcall; overload;
begin
  MessageBoxA(Handle,StrToPac(psText),StrToPac(psTitle),MB_OK);
end;

Procedure VICBox(psFormat: String; const arArgs: array of const); stdcall; overload;
begin
  MessageBoxA(GetActiveWindow,StrToPac(fm(psFormat,arArgs)),StrToPac('VIC'),MB_OK);
end;

Procedure VICBox(psTitle, psFormat: String; const arArgs: array of const); stdcall; overload;
begin
  MessageBoxA(GetActiveWindow,StrToPac(fm(psFormat,arArgs)),StrToPac(psTitle),MB_OK);
end;

Procedure VICBox(Handle: THandle; psFormat: string; const arArgs: array of const); stdcall; overload;
begin
  MessageBoxA(Handle,StrToPac(fm(psFormat,arArgs)),StrToPac('VIC'),MB_OK);
end;

Procedure VICBox(Handle: THandle; psTitle: String; psFormat: string; const arArgs: array of const); stdcall; overload;
begin
  MessageBoxA(Handle,StrToPac(fm(psFormat,arArgs)),StrToPac(psTitle),MB_OK);
end;

Procedure VICMsg(psText: String); stdcall; overload;
begin
  OutputDebugStringA(StrToPac('VIC: ' + psText));
end;

Procedure VICMsg(psFormat: String; const arArgs: array of const); stdcall; overload;
begin
  OutputDebugStringA(StrToPac(fm('VIC: ' + psFormat,arArgs)));
end;

Function TError: String; stdcall;
var
  uiErrorCode: UINT;
  cBuffer: array[0..MAXBYTE] of Char;
begin
  uiErrorCode:= GetLastError;
  ZeroMemory(@cBuffer, sizeof(cBuffer));
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM,NIL,uiErrorCode,LANG_USER_DEFAULT,@cBuffer,MAXBYTE,NIL);
  Result:= fm('%s',[PacToStr(PAnsiChar(@cBuffer))]);
end;

{Some C++ functions in msvcrt.dll}
Function  Sprintf(Buffer, Format: PAnsiChar): Integer; cdecl; varargs; external MSVCRT name 'sprintf';
Function  Swprintf(Buffer, Format: PWideChar): Integer; cdecl; varargs; external MSVCRT name 'swprintf';
Function  Wprintf(Format: PWideChar): Integer; cdecl; varargs; external MSVCRT name 'wprintf';

Procedure Printf(psFormat: string; const arArgs: array of const); stdcall; overload;
begin
  Write(fm(psFormat,arArgs));
end;

Procedure Printf(arArgs: array of const); stdcall; overload;
var i: Integer;
begin
  if (High(arArgs) < 1) then Exit;
  for i:= 0 to High(arArgs) do
  begin
    case arArgs[i].vType of
      vtInteger:    Write(arArgs[i].vInteger);
      vtBoolean:    Write(arArgs[i].vBoolean);
      vtChar:       Write(arArgs[i].vChar);
      vtExtended:   Write(arArgs[i].vExtended^);
      vtString:     Write(arArgs[i].vString^);
      vtPointer:    Write(LongInt(arArgs[i].vPointer));
      vtPChar:      Write(arArgs[i].vPChar);
      vtObject:     Write(arArgs[i].vObject.ClassName);
      vtClass:      Write(arArgs[i].vClass.ClassName);
      vtAnsiString: Write(AnsiString(arArgs[I].vAnsiString));
      vtWideChar:   Write(arArgs[I].VWideChar);
      vtPWideChar:  Write(arArgs[I].VPWideChar);
      vtWideString: Write(WideString(arArgs[I].VWideChar));
      vtInt64:      Write(arArgs[I].VInt64^);
      vtCurrency:   Write(CurrToStr(arArgs[I].VCurrency^));
      else Write(arArgs[i].vType);
    end;
  end;
end;

Procedure Printf(psText: String); stdcall; overload;
begin
  Write(psText);
end;

Procedure PrintfLn; stdcall; overload;
begin
  WriteLn;
end;

Procedure PrintfLn(psFormat: String; const arArgs: array of const); stdcall; overload;
begin
  WriteLn(fm(psFormat,arArgs));
end;

Procedure PrintfLn(arArgs: array of const); stdcall; overload;
begin
  Printf(arArgs);
  WriteLn;
end;

Procedure PrintfLn(psText: String); stdcall; overload;
begin
  WriteLn(psText);
end;

Function GetExceptionCodeMessage(dwExceptionCode: DWORD): String; stdcall;
begin
	case dwExceptionCode of
		$C0000005: Result:= 'Access violation';
		$C0000006: Result:= 'In page error';
		$C0000017: Result:= 'No memory';
		$C000001D: Result:= 'Illegal instruction';
		$C0000025: Result:= 'Non-continuable exception';
		$C0000026: Result:= 'Invalid disposition';
		$C000008C: Result:= 'Array bounds exceeded';
		$C000008D: Result:= 'Fload denormal operation';
		$C000008E: Result:= 'Float device by zero';
		$C000008F: Result:= 'Float inexact result';
		$C0000090: Result:= 'Float invalid operation';
		$C0000091: Result:= 'Float overflow';
		$C0000092: Result:= 'Float stack Check';
		$C0000093: Result:= 'Float underflow';
		$C0000094: Result:= 'Integer divide by zero';
		$C0000095: Result:= 'Integer overflow';
		$C0000096: Result:= 'Privileged instruction';
		$C00000FD: Result:= 'Stack overflow';
		$C000013A: Result:= 'Control C exit';
		$80000001: Result:= 'Violation of a guard page in memory';
		$80000003: Result:= 'Breakpoint occurred';
		$80000004: Result:= 'Single step during debugging';
	else Result:= 'Unknown exception';
	end;
end;

Function GetExceptionFlagMessage(dwExceptionFlag: DWORD): String; stdcall;
begin
  case dwExceptionFlag of
    0: Result:= 'A continuable exception - can be repaired';
    1: Result:= 'A non-continuable exception - cannot be repaired';
    2: Result:= 'The stack is unwinding - do not try to repair';
    else Result:= 'Unknown flag';
  end;
end;

Function GetModuleCrash(dwPID, dwCrashAddress: DWORD; var ImageBase: DWORD): String; stdcall;
var
  hSnap: THandle;
  me: TModuleEntry32A;
begin
  ImageBase:= 0;
  Result:= ExtractFileName(GetModuleName(GetModuleHandleA(NIL)));
  hSnap:= CreateToolHelp32Snapshot(TH32CS_SNAPMODULE,dwPID);
  if (hSnap <> 0) then
  begin
    me.dwSize:= sizeof(TModuleEntry32);
    if (Module32FirstA(hSnap,me) = True) then
    begin
      while Module32NextA(hSnap,me) = True do
      begin
        if (DWORD(me.modBaseAddr) <= dwCrashAddress)
        and (DWORD(me.modBaseAddr) + me.modBaseSize >= dwCrashAddress) then
        begin
          ImageBase:= DWORD(me.modBaseAddr);
          Result:= PacToStr(PAnsiChar(@me.szModule));
          Break;
        end;
      end;
    end;
    CloseHandle(hSnap);
  end;
end;

Procedure DumpExceptionInfomation; stdcall;
var
    tf:  TextFile;
    per: PExceptionRecord;
    pct: PContext;
    peb: PPEB;
    ImageBase: DWORD;
const CRASH_LOG = 'CRASHDUMP.log';
begin
    asm
        pushfd
        pushad
        mov eax,dword ptr ss:[ebp+30h]  // Pointer to exception record
        mov per,eax
        mov eax,dword ptr ss:[ebp+38h]  // Pointer to context of registers
        mov pct,eax
        mov eax,dword ptr fs:[30h]      // Pointer to Process Environment Block
        mov peb,eax
        popad
        popfd
    end;

    AssignFile(tf,CRASH_LOG);
    if FileExists(CRASH_LOG) then Append(tf)
    else ReWrite(tf);

    WriteLn(tf,'EXCEPTION INFOMATION DUMP FILE');
    WriteLn(tf,'');

    WriteLn(tf,fm('Operating system  : %d.%d.%d, platform %d',[peb.OSMajorVersion,peb.OSMinorVersion,peb.OSBuildNumber,peb.OSPlatformId]));
    WriteLn(tf,fm('Crash Time        : %s',[DateTimeToStr(Now)]));
    WriteLn(tf,'');

    WriteLn(tf,fm('Executable module : %s',[GetModuleCrash(GetCurrentProcessId,DWORD(per.ExceptionAddress),ImageBase)]));
    WriteLn(tf,fm('Exception Code    : %.8X (%s)',[per.ExceptionCode,GetExceptionCodeMessage(per.ExceptionCode)]));
    WriteLn(tf,fm('Exception Flags   : %.8X (%s)',[per.ExceptionFlags,GetExceptionFlagMessage(per.ExceptionFlags)]));
    WriteLn(tf,fm('Exception Address : %.P',[per.ExceptionAddress]));
    WriteLn(tf,fm('Exception RVA     : %.8X',[DWORD(per.ExceptionAddress) - ImageBase]));
    WriteLn(tf,fm('Parameters        : %.8X',[per.NumberParameters]));
    WriteLn(tf,'');

    WriteLn(tf,fm('EAX = %.8X ECX = %.8X EDX = %.8X EBX = %.8X',[pct.Eax,pct.Ecx,pct.Edx,pct.Ebx]));
    WriteLn(tf,fm('ESP = %.8X EBP = %.8X ESI = %.8X EDI = %.8X',[pct.Esp,pct.Ebp,pct.Esi,pct.Edi]));
    WriteLn(tf,fm('EIP = %.8X EFL = %.8X',[pct.Eip,pct.EFlags]));
    WriteLn(tf,'');

    WriteLn(tf,fm('Dr0 = %.8X Dr1 = %.8X Dr2 = %.8X',[pct.Dr0,pct.Dr1,pct.Dr2]));
    WriteLn(tf,fm('Dr3 = %.8X Dr6 = %.8X Dr7 = %.8X',[pct.Dr3,pct.Dr6,pct.Dr7]));
    WriteLn(tf,'');
  
    WriteLn(tf,fm('CS = %.8X DS = %.8X ES = %.8X',[pct.SegCs,pct.SegDs,pct.SegEs]));
    WriteLn(tf,fm('FS = %.8X GS = %.8X SS = %.8X',[pct.SegFs,pct.SegGs,pct.SegSs]));
    WriteLn(tf,'------------------------------------------------------------------');

    CloseFile(tf);
end;

{$Region 'Mapping Sample'}
(*
var
  hMap: THandle;
  hBuff: Pointer;
  psData: String;
const psName = 'VICMAP';
*)
{$EndRegion}

Procedure TVIC.MapFileA(psFilePath: String; var FileHandle: THandle; var ObjectHandle: THandle; var MappedObject: Pointer); stdcall;
begin
  FileHandle:= 0;
  ObjectHandle:= 0;
  MappedObject:= NIL;
  FileHandle:= FileOpen(psFilePath,fmOpenReadWrite or fmShareDenyNone);
  if (FileHandle = INVALID_HANDLE_VALUE) then
  begin
    VICMsg('MappFileA::FileOpen::Failure' + TError);
    Exit;
  end;
  ObjectHandle:= CreateFileMappingA(FileHandle,NIL,PAGE_READWRITE,0,0,'');
  if (ObjectHandle = 0) then
  begin
    CloseHandle(FileHandle);
    VICMsg('MappFileA::CreateFileMappingA::Failure' + TError);
    Exit;
  end;
  MappedObject:= MapViewOfFile(ObjectHandle,FILE_MAP_ALL_ACCESS,0,0,0);
  if (MappedObject = NIL) then
  begin
    CloseHandle(ObjectHandle);
    CloseHandle(FileHandle);
    VICMsg('MappFileA::MapViewOfFile::Failure' + TError);
    Exit;
  end;
end;

Procedure TVIC.UnMapFileA(FileHandle, ObjectHandle: THandle; MappedObject: Pointer); stdcall;
begin
  if not (UnmapViewOfFile(MappedObject)
  or CloseHandle(ObjectHandle)
  or CloseHandle(FileHandle)) then
  begin
    VICMsg('UnMapFileA::Failure' + TError);
    Exit;
  end;
end;

Procedure TVIC.FILEMAP_Initialize(psMapName: String; var pBuffer: Pointer; var hFileMap: THandle); stdcall; // SV
const BUF_SIZE = MAXBYTE;
begin
  hFileMap:= CreateFileMappingA(
    INVALID_HANDLE_VALUE,
    NIL,
    PAGE_READWRITE,
    0,
    BUF_SIZE,
    StrToPac(psMapName));
  if (hFileMap = 0) or (GetLastError = ERROR_ALREADY_EXISTS) then
  begin
    hFileMap:= 0;
    VICMsg('FM::CreateFileMappingA::Failure' + TError);
    Exit;
  end;
  pBuffer:= MapViewOfFile(hFileMap,FILE_MAP_ALL_ACCESS,0,0,BUF_SIZE);
  if (pBuffer = NIL) then
  begin
    CloseHandle(hFileMap);
    hFileMap:= 0;
    VICMsg('FM::MapViewOfFile::Failure' + TError);
    Exit;
  end;
end;

Procedure TVIC.FILEMAP_GetMapFile(psMapName: String; var hFileMap: THandle; var pBuffer: Pointer); stdcall; // CL
const BUF_SIZE = MAXBYTE;
begin
  hFileMap:= OpenFileMappingA(FILE_MAP_ALL_ACCESS,False,StrToPac(psMapName));
  if (hFileMap = 0) then
  begin
    VICMsg('FM::OpenFileMapping::Failure' + TError);
    Exit;
  end;
  pBuffer:= MapViewOfFile(hFileMap,FILE_MAP_ALL_ACCESS,0,0,BUF_SIZE);
  if (pBuffer = NIL) then
  begin
    hFileMap:= 0;
    VICMsg('FM::MapViewOfFile::Failure' + TError);
    CloseHandle(hFileMap);
    Exit;
  end;
end;

Procedure TVIC.FILEMAP_SendMsg(pBuffer: Pointer; psData: String); stdcall; // S/C
const BUF_SIZE = MAXBYTE;
begin
  CopyMemory(pBuffer,StrToPac(psData),BUF_SIZE);
end;

Function TVIC.FILEMAP_ReceiveMsg(hBuffer: Pointer): String; stdcall; // S/C
begin
  Result:= String(PAnsiChar(hBuffer));
end;

Procedure TVIC.FILEMAP_CloseMap(hMapFile: THandle; hBuffer: Pointer); stdcall; // SV
begin
  if (UnmapViewOfFile(hBuffer) = True) then
  begin
    if (CloseHandle(hMapFile) = False) then VICMsg('FM::CloseHandle::Failure' + TError);
  end else VICMsg('FM::UnmapViewOfFile::Failure' + TError);
end;

{$Region 'PIPE Sample'}
(*
Variables & Const of Pipe;
const
  lpNamePipe = 'VICPIPE';
  sizeBuff   = 1024;

type TArrayChar = Array[0..sizeBuff] of Char;

var
  hPipe:  THandle = 0;
  ioBuff: TArrayChar;
  data:   String = '';

Note:
  Server: R -> S;
  Client: S - R;
  strcopy(ioBuff,PAnsiChar(data));
*)
{$EndRegion}

Procedure TVIC.PIPE_Initialize(psNamePipe: String; dwSizeInBuffer, dwSizeOutBuffer: DWORD; var HandlePipe: THandle); stdcall; // SV
const TIME_OUT = 1000;
var sa: TSecurityAttributes;
begin
  with sa do
  begin
    nLength:= SizeOf(TSecurityAttributes);
    lpSecurityDescriptor:= NIL;
    bInheritHandle:= True;
  end;
  ZeroMemory(@sa,SizeOf(sa));
  HandlePipe:= CreateNamedPipeA(
    StrToPac('\\.\pipe\' + psNamePipe),
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE + PIPE_READMODE_MESSAGE + PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    dwSizeInBuffer,
    dwSizeOutBuffer,
    TIME_OUT,
    @sa);
  if (HandlePipe = INVALID_HANDLE_VALUE) then
  begin
    HandlePipe:= 0;
    VICMsg('PIPE::CreateNamedPipeA::Failure' + TError);
    Exit;
  end else VICMsg('PIPE::CreateNamedPipeA::Success');
end;

Function TVIC.PIPE_IsConnected(HandlePipe: THandle): Boolean; stdcall; // SV
var
  hEvent: THandle;
  ovlap: OVERLAPPED;
begin
  Result:= True;
  try
    hEvent:= CreateEventA(NIL,True,False,NIL);
    if (hEvent = 0) then
    begin
      CloseHandle(HandlePipe);
      Result:= False;
      VICMsg('PIPE::CreateEventA::Failure' + TError);
      Exit;
    end else VICMsg('PIPE::CreateEventA::Success');
    ZeroMemory(@ovlap,SizeOf(OVERLAPPED));
    ovlap.hEvent:= hEvent;
    if not ConnectNamedPipe(HandlePipe,@ovlap) then
    begin
      CloseHandle(HandlePipe);
      CloseHandle(hEvent);
      Result:= False;
      VICMsg('PIPE::ConnectNamedPipe::Failure' + TError);
      Exit;
    end else VICMsg('PIPE::ConnectNamedPipe::Success');
    if (WaitForSingleObject(hEvent,INFINITE) = WAIT_FAILED) then
    begin
      CloseHandle(HandlePipe);
      CloseHandle(hEvent);
      Result:= False;
      VICMsg('PIPE::WaitForSingleObject::Failure' + TError);
      Exit;
    end else VICMsg('PIPE::WaitForSingleObject::Success');
    CloseHandle(hEvent);
  except
    DisConnectNamedPipe(HandlePipe);
    CloseHandle(HandlePipe);
    Result:= False;
  end;
end;

Function TVIC.PIPE_EndPipe(HandlePipe: THandle): Boolean; stdcall; // SV
begin
  Result:= True;
  if (CloseHandle(HandlePipe) = False) then
  begin
    VICMsg('PIPE::CloseHandle::Failure' + TError);
    Result:= False;
  end;
  if (DisConnectNamedPipe(HandlePipe) = False) then
  begin
    VICMsg('PIPE::DisConnectNamedPipe::Failure' + TError);
    Result:= False;
  end;
  VICMsg('PIPE::Done');
end;

Procedure TVIC.PIPE_OpenPipe(psNamePipe: String; var HandlePipe: THandle); stdcall; // CL
begin
  HandlePipe:= CreateFileA(
    StrToPac('\\.\pipe\' + psNamePipe),
    GENERIC_READ + GENERIC_WRITE,
    FILE_SHARE_READ + FILE_SHARE_WRITE,
    NIL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    0);
  if (HandlePipe = INVALID_HANDLE_VALUE) then VICMsg('PIPE::CreateFileA::Failure' + TError)
  else VICMsg('PIPE::CreateFileA::Success');
end;

Procedure TVIC.PIPE_ClosePipe(HandlePipe: THandle); stdcall; // CL
begin
  if CloseHandle(HandlePipe) then VICMsg('PIPE::CloseHandle::Success')
  else VICMsg('PIPE::CloseHandle::Failure' + TError);
end;

Procedure TVIC.PIPE_WritePipe(HandlePipe: THandle; const pInBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
var dwByteWritten: DWORD;
begin
  WriteFile(HandlePipe,pInBuffer,dwSizeBuffer,dwByteWritten,NIL);
end;

Procedure TVIC.PIPE_ReadPipe(HandlePipe: THandle; var pOutBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
var dwByteRead: DWORD;
begin
  ReadFile(HandlePipe,pOutBuffer,dwSizeBuffer,dwByteRead,NIL);
end;

{$Region 'Mailslot Sample'}
(*
type TArrayChar = Array[0..100] Of Char;

const
  mslName = 'vicmsl';
  sizebuff = 500;

var
  hSlot: THandle;
  buff: TArrayChar;
  data: String;
*)
{$EndRegion}

Procedure TVIC.MSL_Initialize(psMainslotName: String; var hMailslot: THandle); stdcall; // SV
begin
  hMailslot:= 0;
  hMailslot:= CreateMailslotA(
    StrToPac('\\.\mailslot\' + psMainslotName),
    0, // Max size of message;
    MAILSLOT_WAIT_FOREVER,
    NIL);
  if (hMailslot = INVALID_HANDLE_VALUE) then
  begin
    VICMsg('MSL::CreateMailslot::Failure' + TError);
    hMailslot:= 0;
    Exit;
  end else VICMsg('MSL::CreateMailslotA::Success');
end;

Function TVIC.MSL_IsConnected(hMailslot: THandle): Boolean; stdcall; // SV
var
  dwMsgCount, dwNextSize: DWORD;
  IsInfo: Boolean;
  hEvent: THandle;
  sa: TSecurityAttributes;
begin
  Result:= True;
  dwNextSize:= 0;
  dwMsgCount:= 0;
  ZeroMemory(@sa,SizeOf(sa));
  with sa do
  begin
    nLength:= SizeOf(TSecurityAttributes);
    lpSecurityDescriptor:= NIL;
    bInheritHandle:= True;
  end;
  hEvent:= CreateEventA(@sa,True,False,'EventSlot');
  if (hEvent = 0) then
  begin
    Result:= False;
    VICMsg('MSL::CreateEventA::Failure' + TError);
    Exit;
  end else VICMsg('MSL::CreateEventA::Success');
  IsInfo:= GetMailslotInfo(hMailslot,NIL,dwNextSize,@dwMsgCount,NIL); // Returns immediately if no message is present;
  if (IsInfo = False) then
  begin
    Result:= False;
    VICMsg('MSL::GetMailslotInfo::Failure' + TError);
    Exit;
  end else VICMsg('GetMailslotInfo::Success');
  if (dwNextSize = MAILSLOT_NO_MESSAGE) then
  begin
    Result:= False;
    VICMsg('Waiting for a message...');
    Exit;
  end;

  {$Region 'Junk'}
  (*
  while (lpMsgCount <> 0) do
  begin
    ZeroMemory(@buff,SizeOf(buff));
    IsRead:= ReadFile(
        hMailslot,
        buff,
        lpNextSize,
        dwRead,
        NIL);
    if (IsRead = False) then
    begin
      VICMsg('ReadFile::Failure' + TError);
      Exit;
    end else VICMsg('ReadFile::Success');
    WriteLn('The message has been received: ',buff);
    IsInfo:= GetMailslotInfo(
      hMailslot, 	   // mailslot handle
      NIL,           // no maximum message size
      lpNextSize,    // size of next message
      @lpMsgCount,   // number of messages
      NIL);          // no read time-out
    if (IsInfo = False) then
    begin
      VICMsg('GetMailslotInfo::Failure' + TError);
      Exit;
    end else VICMsg('GetMailslotInfo::Success');
  end;
  *)
  {$EndRegion}
end;

Procedure TVIC.MSL_OpenMailslot(psMainslotName: String; var hMailslot: THandle); stdcall; // CL
begin
  hMailslot:= CreateFileA(
    StrToPac('\\.\mailslot\' + psMainslotName),
    GENERIC_READ + GENERIC_WRITE,
    FILE_SHARE_READ + FILE_SHARE_WRITE,
    NIL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    0);
  if (hMailslot = INVALID_HANDLE_VALUE) then
  VICMsg('MSL::CreateFileA::Failure' + TError)
  else VICMsg('MSL::CreateFileA::Success');
end;

Procedure TVIC.MSL_CloseMailslot(hMailslot: THandle); stdcall; // SV
begin
  if CloseHandle(hMailslot) then VICMsg('MSL::CloseHandle::Success')
  else VICMsg('MSL::CloseHandle::Failure' + TError);
end;

Procedure TVIC.MSL_ReadMailslot(hMailslot: THandle; var pOutBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
var dwByteRead: DWORD;
begin
  ReadFile(hMailslot,pOutBuffer,dwSizeBuffer,dwByteRead,NIL);
end;

Procedure TVIC.MSL_WriteMailslot(hMailslot: THandle; const pInBuffer; dwSizeBuffer: DWORD); stdcall; // S/C
var dwByteWritten: DWORD;
begin
  WriteFile(hMailslot,pInBuffer,dwSizeBuffer,dwByteWritten,NIL);
end;

Function TVIC.SizeOfProc(pProc: Pointer): DWORD; stdcall;
var Len: DWORD;
begin
  Result:= 0;
  repeat
    Len:= LengthOfOpcode(DWORD(pProc));
    Inc(Result,Len);
    if ((Len = 1) and (Byte(pProc^) = $C3)) then Break;
    pProc:= Pointer(DWORD(pProc) + Len);
  until (Len = 0);
end;

Function TVIC.GetTheParentPID: DWORD; stdcall;
const BufferSize = $1000;
var
  HandleSnapShot  : THandle;
  EntryParentProc : TProcessEntry32;
  ParentProcessId : THandle;
  CurrentProcessId: THandle;
begin
  ParentProcessId:= 0;
  HandleSnapShot:= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); // Enumerate the process
  if (HandleSnapShot <> INVALID_HANDLE_VALUE) then
  begin
    EntryParentProc.dwSize:= SizeOf(EntryParentProc);
    if Process32First(HandleSnapShot,EntryParentProc) then // Find the first process
    begin
      CurrentProcessId:= GetCurrentProcessId; // Get the id of the current process
      repeat
        if (EntryParentProc.th32ProcessID = CurrentProcessId) then
        begin
          ParentProcessId:= EntryParentProc.th32ParentProcessID; // Get the id of the parent process
          Break;
        end;
      until not Process32Next(HandleSnapShot,EntryParentProc);
    end;
    CloseHandle(HandleSnapShot);
  end;
  Result:= ParentProcessId;
end;

Function TVIC.ZeroEntryPoint(psFilePath: String): Boolean; stdcall;
var
  hFile, lpWritten, JmpAddr: DWORD;
  IDH: TImageDosHeader;
  INH: TImageNtHeaders;
const
  push_edx: Byte = $52;
  inc_ebp:  Byte = $45;
  jmp_x:    Byte = $E9;
begin
  Result:= FALSE;
  hFile:= FileOpen(psFilePath,fmOpenRead or fmShareDenyNone);
  if (hFile <> INVALID_HANDLE_VALUE) then
  begin
    SetFilePointer(hFile,0,NIL,FILE_BEGIN);
    ReadFile(hFile,IDH,SizeOf(IDH),lpWritten,NIL);
    if (IDH.e_magic = IMAGE_DOS_SIGNATURE) then
    begin
      SetFilePointer(hFile,IDH._lfanew,NIL,FILE_BEGIN);
      ReadFile(hFile,INH,SizeOf(INH),lpWritten,NIL);
      if (INH.Signature = IMAGE_NT_SIGNATURE) then
      begin
        if (INH.OptionalHeader.AddressOfEntryPoint > 0) then
        begin
          JmpAddr:= INH.OptionalHeader.AddressOfEntryPoint - 9;
          SetFilePointer(hFile,2,NIL,FILE_BEGIN);
          WriteFile(hFile,push_edx,1,lpWritten,NIL);
          SetFilePointer(hFile,3,NIL,FILE_BEGIN);
          WriteFile(hFile,inc_ebp,1,lpWritten,NIL);
          SetFilePointer(hFile,4,NIL,FILE_BEGIN);
          WriteFile(hFile,jmp_x,1,lpWritten,NIL);
          SetFilePointer(hFile,5,NIL,FILE_BEGIN);
          WriteFile(hFile,JmpAddr,4,lpWritten,NIL);
          INH.OptionalHeader.AddressOfEntryPoint:= 0;
          SetFilePointer(hFile,IDH._lfanew,NIL,FILE_BEGIN);
          WriteFile(hFile,INH,248,lpWritten,NIL);
          Result:= True;
        end;
      end;
    end;
    CloseHandle(hFile);
  end;
end;

Function TVIC.UserName: String; stdcall;
var
  nSize: DWORD;
  lpszUserName: PAnsiChar;
begin     
  nSize:= MAXBYTE;
  lpszUserName:= AllocMem(nSize);
  GetUserNameA(lpszUserName,nSize);
  Result:= PacToStr(lpszUserName);
end;

Function TVIC.PrevFolder(Path: String): String; stdcall;
var i: Integer;
begin
  for i:= (Length(Path) - 1) downto 1 do
    if ((Path[i] = '/') or (Path[i]='\')) then Break;
  if (i = 1) then Exit;
  Result:= Copy(Path,1,i);
end;

Function TVIC.GetTempDirectory: String; stdcall;
var paTempFolder: PAnsiChar;
begin
  paTempFolder:= AllocMem(MAX_PATH);
  GetTempPathA(MAX_PATH,paTempFolder);
  Result:= PacToStr(paTempFolder);
end;

Function TVIC.GetSizeOfFile(psPathFile: String): DWORD; stdcall;
var hFile: DWORD;
begin
  hFile:= CreateFileA(
    StrToPac(psPathFile),
    GENERIC_READ + GENERIC_WRITE,
    0,NIL,OPEN_EXISTING,0,0);
  if (hFile = INVALID_HANDLE_VALUE) then Result:= 0
  else Result:= GetFileSize(hFile,NIL);
  CloseHandle(hFile);
end;

Function TVIC.FindPattern(hProcess: THandle; dwStartAddress: DWORD; dwMemorySize: T_SIZE; const arSignature: array of Byte): DWORD; stdcall;
var
  dwNextRea: DWORD;
  pBufferFile: Pointer;
  nNextByte, nSizeOfSignature: Byte;
  dwNumberOfByteToReads: T_SIZE;
  dwOldProtect: DWORD;
begin
  Result:= 0;
  pBufferFile:= NIL;
  try
    nSizeOfSignature:= Length(arSignature);
    pBufferFile:= VirtualAlloc(NIL,dwMemorySize,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    VirtualProtectEx(hProcess,Ptr(dwStartAddress),dwMemorySize,PAGE_EXECUTE_READWRITE,@dwOldProtect);
    if (IsBadReadPtr(Ptr(dwStartAddress),dwMemorySize) = True) then
    begin
      ReadProcessMemory(hProcess,Ptr(dwStartAddress),pBufferFile,dwMemorySize,dwNumberOfByteToReads);
      VirtualProtectEx(hProcess,Ptr(dwStartAddress),dwMemorySize,dwOldProtect,dwOldProtect);
      for dwNextRea:= 0 to (dwMemorySize - 1) do
      begin
        for nNextByte:= 0 to (nSizeOfSignature - 1) do
        if (arSignature[nNextByte] <> $00) then
          if (Byte(Pointer(DWORD(pBufferFile) + dwNextRea + nNextByte)^) <> arSignature[nNextByte]) then Break;
        if (nNextByte = nSizeOfSignature) then
        begin
          Result:= dwStartAddress + dwNextRea;
          Break;
        end;
      end;
    end else VICMsg('FPT -> Cannot read the memory');
  except
    VICMsg('FPT -> Catch an exception');
  end;
  VirtualFree(pBufferFile,dwMemorySize,MEM_RELEASE);
end;

Function TVIC.API_HookIAT(lpszModuleName, lpszFunctionName: PAnsiChar; pCallbackFunc: Pointer; var pOriApi: Pointer): Boolean; stdcall;
var
  dwLoaded, dwPeOffset, dwOld, dwModuleBase: DWORD;
  pImportDesc: PImageImportDescriptor;
  pNtHdr:      PImageNtHeaders;
  pDosHdr:     PImageDosHeader;
  ppCode:      ^Pointer;
  pProtoFill:  Pointer;
  bYesNo:      Boolean;
begin
  dwLoaded:= LoadLibraryA(lpszModuleName);
  pProtoFill:= VIC.ASMHGetProcAddress(dwLoaded,lpszFunctionName);  {Get Pointer point to Function.}
  pOriApi:= pProtoFill;
  dwModuleBase:= GetModuleHandleA(NIL);              {Get ImageBase.}
  pDosHdr:= PImageDosHeader(dwModuleBase);
  dwPeOffset:= pDosHdr^._lfanew;                     {Get Offset of PE Header.}
  pNtHdr:= Pointer(DWORD(pDosHdr) + dwPeOffset);     {Pointer point to NT Header.}
  pImportDesc:= Pointer(DWORD(pDosHdr) +             {Get pointer point to IData.}
  pNtHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  bYesNo:= False;
  while (pImportDesc^.Name <> 0) do
  begin
    ppCode:= Pointer(DWORD(pDosHdr) + pImportDesc^.FirstThunk);
    while (ppCode^ <> NIL) do
    begin
      if (ppCode^ = pProtoFill) then
      begin
        VirtualProtect(ppCode,4,PAGE_EXECUTE_READWRITE,@dwOld);
        bYesNo:= True;
        ppCode^:= pCallbackFunc;
      end;
      ppCode:= Pointer(DWORD(ppCode) + 4);
    end;
    pImportDesc:= Pointer(DWORD(pImportDesc) + 20);
  end;
  Result:= bYesNo;
end;

Function TVIC.API_UnHookIAT(lpszModuleName, lpszFunctionName: PAnsiChar; pCallback: Pointer): Boolean; stdcall;
var
  pProtoFill:  Pointer;
  ppCode:      ^Pointer;
  bYesNo:      Boolean;
  pDosHdr:     PImageDosHeader;
  pNtHdr:      PImageNtHeaders;
  pImportDesc: PImageImportDescriptor;
  dwLoaded, dwModuleBase, dwPeOffset: DWORD;
begin
  dwLoaded:= LoadLibraryA(lpszModuleName);
  pProtoFill:= VIC.ASMHGetProcAddress(dwLoaded,lpszFunctionName);
  dwModuleBase:= GetModuleHandleA(NIL);
  pDosHdr:= PImageDosHeader(dwModuleBase);
  dwPeOffset:= pDosHdr^._lfanew;
  pNtHdr:= Pointer(DWORD(pDosHdr) + dwPeOffset);
  pImportDesc:= Pointer(DWORD(pDosHdr) +
  pNtHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  bYesNo:= False;
  while (pImportDesc^.Name <> 0) do
  begin
    ppCode:= Pointer(DWORD(pDosHdr) + pImportDesc^.FirstThunk);
    while (ppCode^ <> NIL) do
    begin
      if (ppCode^ = pCallback) then
      begin
        ppCode^:= pProtoFill;
        bYesNo:= True;
      end;
      ppCode:= Pointer(DWORD(ppCode) + 4);
    end;
    pImportDesc:= Pointer(DWORD(pImportDesc) + 20);
  end;
  if (bYesNo = True) then Result:= True else Result:= False;
end;

Function TVIC.LengthOfOpcode(const dwAddress: DWORD): DWORD; stdcall; assembler;
const
  O_UNIQUE   = 0;
  O_PREFIX   = 1;
  O_IMM8     = 2;
  O_IMM16    = 3;
  O_IMM24    = 4;
  O_IMM32    = 5;
  O_IMM48    = 6;
  O_MODRM    = 7;
  O_MODRM8   = 8;
  O_MODRM32  = 9;
  O_EXTENDED = 10;
  O_WEIRD    = 11;
  O_ERROR    = 12;
asm
  {$Region 'Hidden'}
	pushad
	cld
	xor	edx,edx
	mov esi,dwAddress
 	mov	ebp,esp
	push 1097F71Ch
	push 0F71C6780h
	push 17389718h
	push 101CB718h
	push 17302C17h
	push 18173017h
	push 0F715F547h
	push 4C103748h
	push 272CE7F7h
	push 0F7AC6087h
	push 1C121C52h
	push 7C10871Ch
	push 201C701Ch
	push 4767602Bh
	push 20211011h
	push 40121625h
	push 82872022h
	push 47201220h
	push 13101419h
	push 18271013h
	push 28858260h
	push 15124045h
	push 5016A0C7h
	push 28191812h
	push 0F2401812h
	push 19154127h
	push 50F0F011h
	mov	ecx,15124710h
	push ecx
	push 11151247h
	push 10111512h
	push 47101115h
	mov	eax,12472015h
	push eax
	push eax
	push 12471A10h
	add	cl,10h
	push ecx
	sub	cl, 20h
	push ecx
	xor	ecx, ecx
	dec	ecx
@@ps:
	inc ecx
	mov edi,esp
@@go:
	lodsb
	mov bh,al
@@ft:
	mov ah,[edi]
	inc edi
	shr ah,4
	sub al,ah
	jnc @@ft
	mov al,[edi-1]
	and	al,0Fh
	cmp al,O_ERROR
	jnz @@i7
	pop	edx
	not	edx
@@i7:
	inc	edx
	cmp	al,O_UNIQUE
	jz @@t_exit
	cmp	al,O_PREFIX
	jz @@ps
	add edi,51h
	cmp al,O_EXTENDED
	jz @@go
	mov	edi,[ebp+((1+8)*4)+4]
@@i6:
    inc edx
    cmp al,O_IMM8
    jz @@t_exit
    cmp al,O_MODRM
    jz @@t_modrm
    cmp al,O_WEIRD
    jz @@t_weird
@@i5:
    inc edx
    cmp al,O_IMM16
    jz @@t_exit
    cmp al, O_MODRM8
    jz @@t_modrm
@@i4:
    inc edx
    cmp al, O_IMM24
    jz @@t_exit
@@i3:
    inc edx
@@i2:
    inc edx
    pushad
    mov al,66h
    repnz scasb
    popad
    jnz @@c32
@@d2:
    dec edx
    dec edx
@@c32:
    cmp al, O_MODRM32
    jz @@t_modrm
    sub al, O_IMM32
    jz @@t_imm32
@@i1:
    inc edx
@@t_exit:
    jmp @@ASMEnded
@@t_modrm:
	lodsb
	mov ah,al
	shr al,7
	jb @@prmk
	jz @@prm
	add dl, 4
	pushad
	mov al,67h
	repnz scasb
	popad
	jnz @@prm
@@d3:  
	sub dl,3
	dec al
@@prmk:
	jnz @@t_exit
	inc edx
	inc eax
@@prm:
	and ah,00000111b
	pushad
	mov al,67h
	repnz scasb
	popad
	jz @@prm67chk
	cmp ah,04h
	jz @@prmsib
	cmp ah, 05h
	jnz  @@t_exit
@@prm5chk:
	dec al
	jz @@t_exit
@@i42: 
	add dl,4
	jmp  @@t_exit
@@prm67chk:
	cmp ax,0600h
	jnz @@t_exit
	inc edx
	jmp @@i1
@@prmsib:
	cmp al,00h
	jnz @@i1
	lodsb
	and al,00000111b
	sub al,05h
	jnz @@i1
	inc edx
	jmp @@i42
@@t_weird:
	test byte ptr [esi], 00111000b
	jnz @@t_modrm
	mov al, O_MODRM8
	shr bh, 1
	adc al, 0
	jmp @@i5
@@t_imm32:
	sub bh,0A0h
	cmp bh,04h
	jae @@d2
	pushad
	mov al,67h
	repnz scasb
	popad
	jnz @@chk66t
@@d4:  
	dec edx
	dec edx
@@chk66t:
	pushad
	mov al,66h
	repnz scasb
	popad
	jz @@i1
	jnz @@d2
@@ASMEnded:
    mov esp, ebp
    mov [result+(9*4)], edx
    popad
  {$EndRegion}
end;

Function TVIC.PidToName(dwPID: DWORD): String; stdcall;
var
  PE32: TProcessEntry32;
  snap: THandle;
  szRes:  String;
begin
  PE32.dwSize:= SizeOf(PE32);
  snap:= CreateToolHelp32SnapShot(TH32CS_SNAPALL,0);
  Process32First(snap,PE32);
  repeat
    if (PE32.th32ProcessID = dwPID) then szRes:= PE32.szExeFile;
  until (Process32Next(snap,PE32) = False);
  Result:= szRes;
end;

Function TVIC.NameToPid(szProcessName: String): DWORD; stdcall;
var
  hSnap: THandle;
  p32: TProcessEntry32;
begin
  hSnap:= CreateToolHelp32SnapShot(TH32CS_SNAPPROCESS, 0);
  p32.dwSize:= Sizeof(TProcessEntry32);
  Process32First(hSnap, p32);
  repeat
    if (SameText(UpperCase(szProcessName),UpperCase(ExtractFileName(p32.szExeFile)))) then
    begin
      Result:= p32.th32ProcessID;
      Break;
    end else Result:= 0;
  until not Process32Next(hSnap,p32);
  CloseHandle(hSnap);
end;

Function TVIC.ReadNotSafe(const dwAddress: DWORD; nSize: TSizeReg): DWORD; stdcall;
begin
  Result:= 0;
  case nSize of
    1: Result:= PByte(dwAddress)^;
    2: Result:= PWord(dwAddress)^;
    4: Result:= PDWORD(dwAddress)^;
  end;
end;

Procedure TVIC.WriteNotSafe(const dwAddress: DWORD; dwBuffer: DWORD; nSize: TSizeReg); stdcall;
begin
  case nSize of
    1: PByte(dwAddress)^:= dwBuffer;
    2: PWord(dwAddress)^:= dwBuffer;
    4: PDWORD(dwAddress)^:= dwBuffer;
  end;
end;

Function TVIC.SafeReadMemory(const dwAddress: DWORD; nSize: TSizeReg): DWORD; stdcall;
var
  dwOldPtr: DWORD;
  pAddr: Pointer;
begin
  try
    Result:= 0;
    pAddr:= Ptr(dwAddress);
    if not IsBadReadPtr(pAddr,nSize) then
    begin
      VirtualProtect(pAddr,nSize,PAGE_EXECUTE_READWRITE,@dwOldPtr);
      CopyMemory(@Result,pAddr,4);
      VirtualProtect(pAddr,nSize,dwOldPtr,@dwOldPtr);
    end;
    case nSize of
      1: Result:= Result and $FF;
      2: Result:= Result and $FFFF;
      4: Result:= Result and $FFFFFFFF;
      else Result:= Result;
    end;
  except
    Result:= 0;
  end;
end;

Procedure TVIC.SafeWriteMemory(const dwAddress: DWORD; dwBuffer: DWORD; nSize: TSizeReg); stdcall;
var
  dwOldPtr: DWORD;
  pAddr: Pointer;
begin
  try
    pAddr:= Ptr(dwAddress);
    if not IsBadReadPtr(pAddr,nSize) then
    begin
      VirtualProtect(pAddr,nSize,PAGE_EXECUTE_READWRITE,dwOldPtr);
      CopyMemory(pAddr,@dwBuffer,4);
      VirtualProtect(pAddr,nSize,dwOldPtr,dwOldPtr);
    end;
  except
    Exit;
  end;
end;

Procedure TVIC.AsmWrite(const dwAddress: DWORD; dwBuffer: DWORD; nSize: TSizeReg); stdcall;
begin
  WriteNotSafe(dwAddress, dwBuffer, nSize);
end;

Function TVIC.AsmRead(const dwAddress: DWORD; nSize: TSizeReg): DWORD; stdcall;
begin
  Result:= ReadNotSafe(dwAddress, nSize);
end;

Function TVIC.RpmEx(const dwAddress: DWORD; const arOffset: array of const; nNumberOfByteToRead: TSizeReg): DWORD; stdcall;
var
  i, nLen: Byte;
  ret: DWORD;
begin
  try
    nLen:= Length(arOffset);
    RPM(dwAddress,@ret,4);
    Result:= ret;
    if (Result = 0) then
    begin
      Result:= 0;
      VICMsg('ReadEx: Can not read (1)' + TError);
      Exit;
    end;
    if (nLen < 1) then Exit;
    for i:= 1 to nLen do
    begin
      RPM(Result + DWORD(arOffset[i].VInteger),@ret,4);
      Result:= ret;
    end;
    case nNumberOfByteToRead of
      1: Result:= Result and $FF;
      2: Result:= Result and $FFFF;
      3: Result:= Result and $FFFFFF;
      else Result:= Result and $FFFFFFFF;
    end;
  except
    Result:= 0;
    VICMsg('ReadEx: Can not read (2)' + TError);
    Exit;
  end;
end;

Function _LengthToJump(const dwSrcAddress, dwDestAddress: DWORD): DWORD; stdcall;
begin
  Result:= dwDestAddress - (dwSrcAddress + 5);
end;

Function TVIC.LengthToJump(const dwSrcAddress, dwDestAddress: DWORD): DWORD; stdcall;
begin
  if (dwDestAddress < dwSrcAddress) then
  begin
    Result:= dwSrcAddress - dwDestAddress;
    Result:= $FFFFFFFF - Result;
    Result:= Result - 4;
  end
  else
  begin
    Result:= dwDestAddress - dwSrcAddress;
    Result:= Result - 5;
  end;
end;

Function TVIC.API_HookInline(lpszModuleName, lpszFunctionName: PAnsiChar; pCallback: Pointer; var pOriApi: Pointer): Boolean; stdcall;
var
  hMod:  HMODULE;
  pFunc: Pointer;
begin
  Result:= False;
  if IsWin9x then Exit;
  hMod:= GetModuleHandleA(lpszModuleName);
  if (hMod = 0) then hMod:= LoadLibraryA(lpszModuleName);
  pFunc:= VIC.ASMHGetProcAddress(hMod,lpszFunctionName);
  if (pFunc = NIL) or (pCallback = NIL) then Exit;
  Result:= VIC.JDetour(pFunc,pCallback,pOriApi);
end;

Function TVIC.API_UnHookInline(lpszModuleName, lpszFunctionName: PAnsiChar; pResCode: Pointer): Boolean; stdcall;
var
  hMod: HModule;
  pFunc: Pointer;
  dwOldPtr: DWORD;
  nSize, nLen, nAdd: Byte;
begin
  Result:= False;
  hMod:= GetModuleHandleA(lpszModuleName);
  if (hMod = 0) then hMod:= LoadLibraryA(lpszModuleName);
  pFunc:= VIC.ASMHGetProcAddress(hMod,lpszFunctionName);
  if (pFunc = NIL) or (pResCode = NIL) then Exit;
  nLen:= 0;
  nAdd:= 0;
  repeat
    nSize:= VIC.LengthOfOpcode(DWORD(pResCode) + nAdd);
    nLen:= nLen + nSize;
    nAdd:= nAdd + nSize;
  until (nLen >= 5); // 5 -> JDetour / 6 -> Detource
  VirtualProtect(pFunc,nLen,PAGE_EXECUTE_READWRITE,@dwOldPtr);
  CopyMemory(pFunc,Pointer(DWORD(pResCode)),nLen);
  VirtualProtect(pFunc,nLen,dwOldPtr,@dwOldPtr);
  Result:= True;
end;

Function TVIC.DLL_Inject(dwPID: DWORD; psLibraryName: String): Boolean; stdcall;
const
  MAX_LIBRARYNAME  =  MAX_PATH;
  MAX_FUNCTIONNAME =  255;
  MIN_INSTRSIZE    =  5;
  
type
  PLibRemote = ^TLibRemote;
  TLibRemote = packed record
    ProcessID:     DWORD;
    LibraryName:   array [0..MAX_LIBRARYNAME] of Char;
    LibraryHandle: HMODULE;
  end;
  
var
  hKernel:     HMODULE;
  hProcess:    THandle;
  hThread:     THandle;
  dwNull:      DWORD;
  nuiWritten:  T_SIZE;
  pRemote:     PLibRemote;
  paLibRemote: PAnsiChar;
begin
  Result:= False;
  if (Length(psLibraryName) > 0) and ((GetVersion and $80000000) = 0)then
  begin
    hProcess:= OpenProcess(PROCESS_ALL_ACCESS,False,dwPID);
    if (hProcess <> 0) then
    begin
      try
        hKernel:= GetModuleHandleA('kernel32');
        if (hKernel <> 0) then
        begin
          paLibRemote:= VirtualAllocEx(hProcess,NIL,Succ(Length(psLibraryName)),MEM_COMMIT,PAGE_READWRITE);
          if Assigned(paLibRemote) then
          begin
            try
              WriteProcessMemory(
                hProcess,
                paLibRemote,
                StrToPac(psLibraryName),
                Length(psLibraryName),
                nuiWritten);
              hThread:= CreateRemoteThread(
                hProcess,
                NIL,
                0,
                VIC.ASMHGetProcAddress(hKernel,'LoadLibraryA'),
                paLibRemote,
                0,
                dwNull);
              if (hThread <> 0) then
              begin
                try
                  pRemote:= AllocMem(SizeOf(TLibRemote));
                  pRemote^.ProcessID:= dwPID;
                  memcpy(@pRemote^.LibraryName,StrToPac(psLibraryName),MAXBYTE); // <-
                  WaitForSingleObject(hThread,INFINITE);
                  GetExitCodeThread(hThread,DWORD(pRemote^.LibraryHandle));
                  Result:= True;
                finally
                  CloseHandle(hThread);
                end;
              end;
            finally
              VirtualFree(paLibRemote,0,MEM_RELEASE);
            end;
          end;
        end;
      finally
        CloseHandle(hProcess);
      end;
    end;
  end;
end;

Function TVIC.DLL_UnInject(dwPID: DWORD; psLibraryName: String): Boolean; stdcall;
var
  Process, Thread, ThreadId: DWORD;
  Bytes: T_SIZE;
  Params: Pointer;
  FreeLib, GetMod, St: DWORD;
begin
  Result:= False;
  if (IsWin9x) or (psLibraryName = '') then Exit;
  FreeLib:= DWORD(VIC.ASMHGetProcAddress(GetModuleHandleA('kernel32'),'FreeLibrary'));
  GetMod:= DWORD(VIC.ASMHGetProcAddress(GetModuleHandleA('kernel32'),'GetModuleHandleA'));
  if (@FreeLib = NIL) or (@GetMod = NIL) then Exit;
  Process:= OpenProcess(PROCESS_ALL_ACCESS,False,dwPID);
  if (Process = 0) then Process:= dwPID;
  Params:= VirtualAllocEx(Process,NIL,$1000,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
  if (Params = NIL) then Exit;
  WriteProcessMemory(Process,Params,StrToPac(psLibraryName),Length(psLibraryName),Bytes);
  St:= Integer(Params) + Length(psLibraryName) + 1;
  DWORD(Pointer(DWORD(@FreeOpCodes) + 1)^):= DWORD(Params);
  DWORD(Pointer(DWORD(@FreeOpCodes) + 6)^):= LengthToJump(St + 5,GetMod);
  DWORD(Pointer(DWORD(@FreeOpCodes) + 19)^):= LengthToJump(St + 18,FreeLib);
  WriteProcessMemory(Process,Pointer(St),@FreeOpCodes,SizeOf(FreeOpCodes),Bytes);
  Thread:= CreateRemoteThread(Process,NIL,0,Pointer(St),NIL,0,ThreadId);
  if (Thread <> 0) then CloseHandle(Thread);
  CloseHandle(Process);
  Result:= True;
end;

Function TVIC.Detour(pOldFunction: Pointer; pNewFunction: Pointer; var pResCode: Pointer): Boolean; stdcall;
type
  TRedirect = packed record
    push: Byte; address: DWORD;
    ret: Byte;
  end;
var
  i, nSize, nAdd, nLen: Byte;
  C2O, O2N: TRedirect;
  dwOldPrt: DWORD;
const sizePushRet = 6;
begin
  Result:= False;
  // Find the real length;
  nLen:= 0;
  nAdd:= 0;
  repeat
    nSize:= VIC.LengthOfOpcode(DWORD(pOldFunction) + nAdd);
    nLen:= nLen + nSize;
    nAdd:= nAdd + nSize;
  until (nLen >= 6);
  GetMem(pResCode,nLen + sizePushRet);
  if (pResCode = NIL) then Exit;
  memcpy(pResCode,pOldFunction,nLen);
  // Nop some byte;
  VirtualProtect(pOldFunction,nLen,PAGE_EXECUTE_READWRITE,@dwOldPrt);
  for i:= 0 to (nLen - 1) do Byte(Pointer(DWORD(pOldFunction) + i)^):= $90;
  // Jump from old to new;
  with O2N do
  begin
    push:= $68; address:= DWORD(pNewFunction); // push xxxxxxxx
    ret:= $C3;                                 // ret
  end;
  CopyMemory(pOldFunction,@O2N,sizePushRet);
  VirtualProtect(pOldFunction,nLen,dwOldPrt,@dwOldPrt);
  // Jump from callback to old;
  with C2O do
  begin
    push:= $68; address:= DWORD(pOldFunction) + nLen; // push xxxxxxxx
    ret:= $C3;                                        // ret
  end;
  CopyMemory(Pointer(DWORD(pResCode) + nLen),@C2O,sizePushRet);
  Result:= True;
end;

Function TVIC.JDetour(pOldFunction: Pointer; pNewFunction: Pointer; var pResCode: Pointer): Boolean; stdcall;
type
  TRedirect = packed record
    jmp: Byte;
    address: DWORD;
  end;
var
  i, nSize, nAdd, nLen: Byte;
  C2O, O2N: TRedirect;
  dwOldPrt: DWORD;
  arTNop: array of Byte;
const sizejmpret = 5;
begin
  Result:= False;
  // Find the real length;
  nLen:= 0;
  nAdd:= 0;
  repeat
    nSize:= VIC.LengthOfOpcode(DWORD(pOldFunction) + nAdd);
    nLen:= nLen + nSize;
    nAdd:= nAdd + nSize;
  until (nLen >= 5);
  // Backup old byte;
  pResCode:= VirtualAlloc(NIL,nLen + sizejmpret,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
  if (pResCode = NIL) then Exit;
  memcpy(pResCode,pOldFunction,nLen);
  // Nop Len Byte;
  SetLength(arTNop,nLen);
  for i:= 0 to (nLen - 1) do arTNop[i]:= $90;
  VirtualProtect(pOldFunction,nLen,PAGE_EXECUTE_READWRITE,@dwOldPrt);
  Move(arTNop,pOldFunction^,Length(arTNop));
  // Jump from old to new;
  O2N.jmp:= $E9;
  O2N.address:= VIC.LengthToJump(DWORD(pOldFunction),DWORD(pNewFunction));//DWORD(pNewFundFunction) - 5;
  CopyMemory(pOldFunction,@O2N,nLen);
  VirtualProtect(pOldFunction,nLen,dwOldPrt,@dwOldPrt);
  // Jump to callback to old;
  C2O.jmp:= $E9;
  C2O.address:= VIC.LengthToJump(DWORD(pResCode),DWORD(pOldFunction)); //(DWORD(pOldFunction) + Len) - DWORD(resCode) - (Len + 5);
  CopyMemory(Pointer(DWORD(pResCode) + nLen),@C2O,nLen + sizejmpret);
  Result:= True;
end;

Function TVIC.HideModule(dwPID: DWORD; psModuleName: String): Boolean; stdcall;
const ProcessBasicInformation = 0;

type
  PPROCESS_BASIC_INFORMATION = ^PROCESS_BASIC_INFORMATION;
  PROCESS_BASIC_INFORMATION = packed record
    ExitStatus: DWORD;
    PebBaseAddress: Pointer;
    AffinityMask: DWORD;
    BasePriority: DWORD;
    UniqueProcessId: DWORD;
    InheritedUniquePID: DWORD;
  end;

  _UNICODE_STRING = record
    Length: WORD;
    MaximumLength: WORD;
    Buffer: PWideChar;
  end;
  UNICODE_STRING = _UNICODE_STRING;
  PUNICODE_STRING = ^_UNICODE_STRING;

  _PEB_LDR_DATA = record
    Length: ULONG;
    Initialized: BOOLEAN;
    SsHandle: Pointer;
    InLoadOrderModuleList: LIST_ENTRY;
    InMemoryOrderModuleList: LIST_ENTRY;
    InInitializationOrderModuleList: LIST_ENTRY;
  end;
  PEB_LDR_DATA = _PEB_LDR_DATA;
  PPEB_LDR_DATA = ^_PEB_LDR_DATA;

  _LDR_MODULE = record
    InLoadOrderModuleList: LIST_ENTRY;
    InMemoryOrderModuleList: LIST_ENTRY;
    InInitializationOrderModuleList: LIST_ENTRY;
    BaseAddress: Pointer;
    EntryPoint: Pointer;
    SizeOfImage: ULONG;
    FullDllName: UNICODE_STRING;
    BaseDllName: UNICODE_STRING;
    Flags: ULONG;
    LoadCount: SMALLINT;
    TlsIndex: SMALLINT;
    HashTableEntry: LIST_ENTRY;
    TimeDateStamp: ULONG;
  end;
  LDR_MODULE = _LDR_MODULE;
  PLDR_MODULE = ^_LDR_MODULE;

var
  hProcess: THandle;
  retLen: Integer;
  ldraddr: DWORD;
  btsIO: T_SIZE;
  ProcessBasic: PROCESS_BASIC_INFORMATION;
  LdrData: _PEB_LDR_DATA;
  fDllName: WideString;
  modules, back, fwd: _LDR_MODULE;
  modulename: PWideChar;
  NtQueryInformationProcess: Function(
    hProcess: THandle;
    ProcessInformationClass: Integer;
    var ProcessInformation;
    ProcessInformationLength: Integer;
    var ReturnLength: Integer): Integer; stdcall;
begin
  Result:= False;
  @NtQueryInformationProcess:= VIC.ASMHGetProcAddress(GetModuleHandleA('ntdll'),'NtQueryInformationProcess');
  if (@NtQueryInformationProcess = NIL) then Exit;
  hProcess:= OpenProcess(PROCESS_ALL_ACCESS,False,dwPID);
  if (hProcess <> INVALID_HANDLE_VALUE) then
  begin
    NtQueryInformationProcess(
      hProcess,
      ProcessBasicInformation,
      ProcessBasic,
      Sizeof(ProcessBasic),
      retLen);
    ReadProcessMemory(
      hProcess,
      Ptr(DWORD(ProcessBasic.PebBaseAddress) + $0C),
      @ldraddr,
      SizeOf(ldraddr),
      btsIO);
    ReadProcessMemory(
      hProcess,
      Ptr(ldraddr),
      @LdrData,
      Sizeof(LdrData),
      btsIO);
    ReadProcessMemory(
      hProcess,
      LdrData.InLoadOrderModuleList.Flink,
      @modules,
      Sizeof(modules),
      btsIO);
    while (modules.BaseAddress <> NIL) do
    begin
      GetMem(modulename,modules.BaseDllName.MaximumLength);
      ZeroMemory(modulename,modules.BaseDllName.MaximumLength);
      ReadProcessMemory(
        hProcess,
        modules.BaseDllName.Buffer,
        modulename,
        modules.BaseDllName.Length,
        btsIO);
      fDllName:= WideString(modulename);
      if UpperCase(fDllName) = UpperCase(psModuleName) then
      begin
        ReadProcessMemory(
          hProcess,
          modules.InLoadOrderModuleList.Blink,
          @back,
          Sizeof(back),
          btsIO);
        ReadProcessMemory(
          hProcess,
          modules.InLoadOrderModuleList.Flink,
          @fwd,
          Sizeof(fwd), btsIO);
        back.InLoadOrderModuleList.Flink:= modules.InLoadOrderModuleList.Flink;
        fwd.InLoadOrderModuleList.Blink:= modules.InLoadOrderModuleList.Blink;
        WriteProcessMemory(
          hProcess,
          modules.InLoadOrderModuleList.Blink,
          @back,
          Sizeof(back),
          btsIO);
        WriteProcessMemory(
          hProcess,
          modules.InLoadOrderModuleList.Flink,
          @fwd,
          Sizeof(fwd),
          btsIO);
        Result:= True;
        Exit;
      end;
      FreeMem(modulename);
      ReadProcessMemory(
        hProcess,
        modules.InLoadOrderModuleList.Flink,
        @modules,
        Sizeof(modules),
        btsIO);
    end;
    CloseHandle(hProcess);
  end;
end;

Function TVIC.ASMHGetProcAddress(HandleModule: HModule; paProcName: PAnsiChar): Pointer; stdcall;
type
  PSEH = ^TSEH;
  TSEH = record
    _esp: DWORD;
    _ebp: DWORD;
    safeeip: DWORD;
  end;

var SEH: TSEH;

const MAX_API_STRING_LENGTH = 150;

Function SEHDefault(a, b, c, d: Pointer): DWORD; stdcall;
begin
  with PContext(c)^ do
  begin
    esp:= SEH._esp;
    ebp:= SEH._ebp;
    eip:= SEH.safeeip;
  end;
  Result:= 0;  // Continue Execution
end;

begin
  asm
    {Backup the Registers to use}
    push esi
    push edi
    push ecx
    push ebx
    push edx
    xor edx,edx
    {Install SE Handler}
    push offset SEHDefault
    push dword ptr fs:[0]
    mov SEH._esp,esp
    mov SEH._ebp,ebp
    mov SEH.safeeip,offset @notfound
    mov dword ptr fs:[0],esp
    {String length the api function}
    mov edi,paProcName
    mov ecx,MAX_API_STRING_LENGTH
    xor al,al
    repne scas byte ptr es:[edi]
    mov ecx,edi
    sub ecx,paProcName
    {Get and check PE file header }
    mov edx,HandleModule
    cmp [edx].TImageDosHeader.e_magic,IMAGE_DOS_SIGNATURE
    jnz @notFound
    add edx,[EDX].TImageDosHeader._lfanew
    cmp [edx].TImageNtHeaders.Signature,IMAGE_NT_SIGNATURE
    jnz @notFound
    {Get and check export directory }
    mov edx,[edx].TImageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].TImageDataDirectory.VirtualAddress
    or edx,edx
    jz @notfound
    add edx,HandleModule
    {Find the address of API function}
    mov ebx,[edx].TImageExportDirectory.AddressOfNames
    add ebx,HandleModule
    xor eax,eax
  @Loop:
    mov edi,dword ptr ds:[ebx]
    add edi,HandleModule
    mov esi,paProcName
    push ecx
    repe cmps byte ptr ds:[esi],byte ptr es:[edi]
    pop ecx
    je @Found
    add ebx,4
    inc eax
    cmp eax,[edx].TImageExportDirectory.NumberOfNames
    jb @Loop
    jmp @notFound
  @Found:
    {Convert Name -> Ordinal }
    shl eax,1
    add eax, [EDX].TImageExportDirectory.AddressOfNameOrdinals
    add eax,HandleModule
    mov ax,word ptr ds:[eax]
    and eax,0FFFFh
    {Convert Ordinal -> Address of API Function }
    shl eax,2
    add eax,[edx].TImageExportDirectory.AddressOfFunctions
    add eax,HandleModule
    mov eax,dword ptr ds:[eax]
    add eax,HandleModule
    mov Result,eax
    jmp @Exit
  @notFound:
    xor eax,eax
  @Exit:
    {Clean up Struct Exception Handler frame}
    xor edx,edx
    pop dword ptr fs:[0]
    add esp,4
    {Restore used Registers}
    pop edx
    pop ebx
    pop ecx
    pop edi
    pop esi
  end;
end;

Function TVIC.ASMNGetProcAddress(lpszModuleName, paProcName: PAnsiChar): Pointer; stdcall;
var hMdl: HModule;
begin
  Result:= NIL;
  hMdl:= GetModuleHandleA(lpszModuleName);
  if (hMdl = 0) then hMdl:= LoadLibraryA(lpszModuleName);
  if (hMdl = 0) then Exit;
  Result:= VIC.ASMHGetProcAddress(hMdl,paProcName);
end;

{$IF CompilerVersion < 22.00}
Function InitToolHelp: Boolean;
var hKernel32: HMODULE;
begin
  Result:= False;
  hKernel32:= LoadLibraryA(kernel32);
  if (hKernel32 <> 0) then
  begin
    @_Module32FirstA:= GetProcAddress(hKernel32,'Module32First');
    @_Module32NextA:= GetProcAddress(hKernel32,'Module32Next');
    @_Module32FirstW:= GetProcAddress(hKernel32,'Module32FirstW');
    @_Module32NextW:= GetProcAddress(hKernel32,'Module32NextW');
    Result:= True;
  end;
  FreeLibrary(hKernel32);
end;

Function Module32FirstA(hSnapshot: THandle; var lpme: TModuleEntry32A): BOOL; stdcall;
begin
  if InitToolHelp then
    Result:= _Module32FirstA(hSnapshot,lpme)
  else
    Result:= False;
end;

Function Module32NextA(hSnapshot: THandle; var lpme: TModuleEntry32A): BOOL; stdcall;
begin
  if InitToolHelp then
    Result:= _Module32NextA(hSnapshot,lpme)
  else
    Result:= False;
end;

Function Module32FirstW(hSnapshot: THandle; var lpme: TModuleEntry32W): BOOL; stdcall;
begin
  if InitToolHelp then
    Result:= _Module32FirstW(hSnapshot,lpme)
  else
    Result:= False;
end;

Function Module32NextW(hSnapshot: THandle; var lpme: TModuleEntry32W): BOOL; stdcall;
begin
  if InitToolHelp then
    Result:= _Module32NextW(hSnapshot, lpme)
  else
    Result:= False;
end;
{$IFEND}

Function GetShortcutTarget(ShortcutFilename: String): String; stdcall;
var
  Psl: IShellLink;
  Ppf: IPersistFile;
  WideName: array[0..MAX_PATH] of WideChar;
  pResult: array[0..MAX_PATH - 1] of Char;
  Data: TWin32FindData;
const IID_IPersistFile: TGUID = (D1: $0000010B; D2: $0000; D3: $0000; D4: ($C0,$00,$00,$00,$00,$00,$00,$46));
begin
  CoCreateInstance(CLSID_ShellLink,NIL,CLSCTX_INPROC_SERVER,IID_IShellLinkA,Psl);
  Psl.QueryInterface(IID_IPersistFile,Ppf);
  MultiByteToWideChar(CP_ACP,0,StrToPac(ShortcutFilename),-1,WideName,MAX_PATH);
  Ppf.Load(WideName,STGM_READ);
  Psl.Resolve(0,SLR_ANY_MATCH);
  Psl.GetPath(@pResult,MAX_PATH,Data,SLGP_UNCPRIORITY);
  Result:= PacToStr(PAnsiChar(@pResult));
end;

end.
