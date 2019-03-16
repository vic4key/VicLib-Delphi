program VicLib;

{$APPTYPE CONSOLE}

uses
  Windows,
  SysUtils,
  TlHelp32,
  MD5 in 'lib\MD5.pas',
  mrVic in 'lib\mrVic.pas',
  TiTan in 'lib\TiTan.pas',
  WinCrt in 'lib\WinCrt.pas';

begin
  PrintfLn(' + CompilerVersion = %n',[CompilerVersion]);
  PrintfLn(' + Build -> Done');
  Pause;
end.

