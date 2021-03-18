﻿<#
    .SYNOPSIS
       Convert windows registry key storage to Json
    .DESCRIPTION
       Convert windows registry key storage to Json
       It is windows-only compatibility cmdlet
#>
function Convert-SSHRegistryToJSonKnownHost {
    $JsonStore = Get-SSHJsonKnowHost
    $p = Get-ItemProperty HKCU:\SOFTWARE\PoshSSH
    $p | Get-Member -MemberType NoteProperty |
    Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
    ForEach-Object {
        $name = $_.Name
        Write-Host "Save ssh-rsa key for $name"
        [void]$JsonStore.SetKey($name, 'ssh-rsa', $p.$name)
    }
}
