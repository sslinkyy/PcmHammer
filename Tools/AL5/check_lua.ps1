param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$LuaDll = 'C:\Program Files (x86)\EFILive\V8\lua54.dll'
)
# Syntax-only validation in the installed standard Lua runtime. It never runs
# the chunk, opens EFILive, or registers any EFILive APIs. Use 32-bit PowerShell
# with the installed x86 DLL. No proprietary controller object is loaded.
$ErrorActionPreference = 'Stop'
if ([IntPtr]::Size -ne 4) { throw 'Use SysWOW64 WindowsPowerShell for this x86 Lua DLL.' }
$dllLiteral = $LuaDll.Replace('"','""')
$source = @"
using System;
using System.Runtime.InteropServices;
public static class AL5LuaSyntax {
    [DllImport(@"$dllLiteral", CallingConvention=CallingConvention.Cdecl)]
    public static extern IntPtr luaL_newstate();
    [DllImport(@"$dllLiteral", CallingConvention=CallingConvention.Cdecl)]
    public static extern int luaL_loadfilex(IntPtr state, string filename, string mode);
    [DllImport(@"$dllLiteral", CallingConvention=CallingConvention.Cdecl)]
    public static extern IntPtr lua_tolstring(IntPtr state, int index, IntPtr length);
    [DllImport(@"$dllLiteral", CallingConvention=CallingConvention.Cdecl)]
    public static extern void lua_close(IntPtr state);
}
"@
Add-Type -TypeDefinition $source
$resolved = (Resolve-Path -LiteralPath $Path).Path
$state = [AL5LuaSyntax]::luaL_newstate()
if ($state -eq [IntPtr]::Zero) { throw 'Lua allocation failed' }
try {
    $rc = [AL5LuaSyntax]::luaL_loadfilex($state,$resolved,'t')
    if ($rc -ne 0) {
        $message = [Runtime.InteropServices.Marshal]::PtrToStringAnsi(
            [AL5LuaSyntax]::lua_tolstring($state,-1,[IntPtr]::Zero))
        throw $message
    }
    Write-Output "Lua syntax PASS: $resolved (chunk not executed)"
} finally {
    [AL5LuaSyntax]::lua_close($state)
}
