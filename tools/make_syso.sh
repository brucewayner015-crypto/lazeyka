#!/usr/bin/env bash
# Builds rsrc_windows_amd64.syso: exe icon, application manifest
# (asInvoker, per-monitor DPI, common controls 6) and version info.
# Needs llvm-rc and llvm-cvtres (LLVM 15+). Run from the repository root.
set -euo pipefail
cd "$(dirname "$0")/.."

ver=$(sed -n 's/^\(const\|var\) Version = "\(.*\)"$/\2/p' internal/app/app.go)
[ -n "$ver" ] || ver=$(sed -n 's/^\tVersion *= *"\(.*\)"$/\1/p' internal/app/app.go)
[ -n "$ver" ] || { echo "version not found" >&2; exit 1; }
IFS=. read -r v1 v2 v3 <<<"$ver"
v4=0

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp assets/icons/lazeyka.ico "$work/lazeyka.ico"

cat >"$work/lazeyka.manifest" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Lazeyka" version="$v1.$v2.$v3.$v4" processorArchitecture="amd64"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
EOF

cat >"$work/lazeyka.rc" <<EOF
#pragma code_page(65001)
1 ICON "lazeyka.ico"
1 24 "lazeyka.manifest"
1 VERSIONINFO
FILEVERSION $v1,$v2,$v3,$v4
PRODUCTVERSION $v1,$v2,$v3,$v4
FILEFLAGSMASK 0x3F
FILEFLAGS 0x0
FILEOS 0x40004
FILETYPE 0x1
FILESUBTYPE 0x0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "041904B0"
    BEGIN
      VALUE "CompanyName", "Лазейка"
      VALUE "FileDescription", "Лазейка"
      VALUE "FileVersion", "$ver"
      VALUE "InternalName", "Lazeyka"
      VALUE "LegalCopyright", "Личная сборка. mihomo (MetaCubeX) и zapret (bol-van, Flowseal) скачиваются отдельно."
      VALUE "OriginalFilename", "Lazeyka.exe"
      VALUE "ProductName", "Лазейка"
      VALUE "ProductVersion", "$ver"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0419, 1200
  END
END
EOF

(cd "$work" && llvm-rc /C 65001 /FO lazeyka.res lazeyka.rc)
llvm-cvtres /MACHINE:X64 /OUT:rsrc_windows_amd64.syso "$work/lazeyka.res" >/dev/null
echo "rsrc_windows_amd64.syso for $ver"
