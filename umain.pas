unit uMain;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls, Regexpr;

type

  { TfrmMain }

  TfrmMain = class(TForm)
    btnProcess: TButton;
    btnImportFile: TButton;
    tbResult: TEdit;
    mtbInput: TMemo;
    procedure btnProcessClick(Sender: TObject);
    function detectEncoding(inputData: string): string;
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.lfm}

{ TfrmMain }

function TfrmMain.detectEncoding(inputData: string): string;
const
  arrID: array [0 .. 28] of string =
    ('ByteRun Protector for PHP | www.byterun.com',
    'ByteRun Protector for PHP | www.byterun.com',
    'ByteRun Protector for PHP | www.byterun.com',
    'SourceCop PHP Protector | www.sourcecop.com',
    'SourceCop PHP Protector | www.sourcecop.com',
    'SourceCop PHP Protector | www.sourcecop.com',
    'SourceCop PHP Protector | www.sourcecop.com ',
    'CodeLock 2.x | www.codelock.co.nz', 'CodeLock 2.x | www.codelock.co.nz',
    'PHPCipher | www.phpcipher.com', 'PHPCipher | www.phpcipher.com',
    'phpSHIELD | www.phpshield.com', 'phpSHIELD | www.phpshield.com',
    'phpSHIELD | www.phpshield.com', 'eAccelerator | eaccelerator.net',
    'eAccelerator | eaccelerator.net', 'CNCrypto | www.cn-software.com',
    'ionCube PHP Encoder | www.ioncube.com', 'PHP LockIt! | www.phplockit.com',
    'PHP LockIt! | www.phplockit.com', 'PHP LockIt! | www.phplockit.com',
    'PHP Defender | www.phpdefender.com', 'Obfusc | www.obfusc.com',
    'Zorex PHP CryptZ | www.zorex.info', 'Zorex PHP CryptZ | www.zorex.info',
    'Zorex PHP CryptZ | www.zorex.info',
    'Free Online PHP Obfuscator | fopo.com.ar',
    'BCompiler | pecl.php.net/package/bcompiler',
    'ZenCrypt | www.zencrypt.com');
  arrSignatures: array [0 .. 28] of string = ('\$_F=__FILE__;\$_X=',
    '=strrev\(''edoced_46esab''\);eval\(\$_', 'return byterun_exec\(''',
    '\$REXISTHECAT4FBI=', '\$REXISTHEDOG4FBI=',
    'ini_set\(''include_path'',''\.''\);',
    '\(strstr\(\$s,'',27h,''sprintf'',27h,''\)==false\)\?false:exit\(\):exit\(\):exit\(\)',
    '\$codelock_lock=\"', '\$codelock_filed=dirname\(__FILE__\)',
    '\$_REQUEST\[''phpCipher''\]', '\"0x\"\.\$phpCipher',
    'return phpshield_load\(''', '@phpSHIELD;', '@\"phpSHIELD\"',
    '!is_callable\("eaccelerator_load"\)', 'eaccelerator_load\(',
    '\"\)\);/\*CNS', '!extension_loaded\(''ionCube Loader''\)', '=__FILE__;\$',
    ';eval\(\(base64_decode\(', ';eval\(gzuncompress\(base64_decode\(',
    'by PHPDefender', '\+1]\)-ord\(''A''\)\)\*16\+\(ord\(\$',
    'eval\(base64_decode\("ZXZhbChiYXNlNjRfZGVjb2Rl',
    'include\(\"\$cryptz_dpath/', '\$cryptz_zlib = 0;',
    '="\\x62\\141\\x73\\145\\x36\\64\\x5f\\144\\x65\\143\\x6f\\144\\x65";@eval\(\$',
    'bcompiler v0.', '\(ireegf\(rqbprq_46rfno\(rgnysavmt\(ynir');
var
  x, y: integer;
  regex: TRegExpr;
begin
  regex := TRegExpr.Create;
  try
    for x := 0 to Length(arrSignatures) do
    begin
      regex.Expression := arrSignatures[x];
      if regex.Exec(inputData) then
      begin
        Result := arrID[x];
        Break;
      end;
    end;
  except
    on E: Exception do
      Result := 'Unknown or invalid input. Open an issue on GitHub to have the issue investigated!';
  end;
end;

procedure TfrmMain.btnProcessClick(Sender: TObject);
begin
  tbResult.Text := detectEncoding(mtbInput.Text);
end;

end.
