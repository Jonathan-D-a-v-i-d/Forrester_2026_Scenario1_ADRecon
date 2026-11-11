<#
.SYNOPSIS
    AD Recon "Scattered" - same recon burst as Invoke-ADReconBurst.ps1, but each command is
    REPARENTED so it does NOT form one giant process tree. Companion/contrast file for XDR demos.

.DESCRIPTION
    Invoke-ADReconBurst.ps1 runs every tool as a direct child of one powershell.exe -> a single
    dense process tree (clean lineage, easy correlation).

    This file instead launches each command through an intermediary so Windows reparents it:
      -Method WMI       -> each tool becomes a child of WmiPrvSE.exe   (ATT&CK T1047)
      -Method Schtasks  -> each tool is run by the Task Scheduler/svchost (ATT&CK T1053.005)

    Every action carries its MITRE ATT&CK technique ID in the log. Result in Cortex: the same
    discovery events as the Burst file, but NO common ancestor linking them to the operator shell.
    See README.md for the side-by-side.

    NATIVE TOOLING ONLY. Read-only discovery (no changes). RSAT-dependent tools skip if absent.

    *** LAB / AUTHORIZED DEMO USE ONLY. *** Intentionally loud.

.PARAMETER Method
    WMI (default) or Schtasks. The reparenting mechanism.

.PARAMETER LogPath
    Timestamped activity log. Defaults to .\ADReconScattered_<timestamp>.log

.PARAMETER JitterMs
    Sleep between launches. Default 0 = everything at once.

.PARAMETER WaitSec
    Max seconds to wait for each WMI-launched process to exit before moving on. Default 30.

.PARAMETER DryRun
    Show what would launch without executing.

.EXAMPLE
    .\Invoke-ADReconScattered.ps1
.EXAMPLE
    .\Invoke-ADReconScattered.ps1 -Method Schtasks
.EXAMPLE
    .\Invoke-ADReconScattered.ps1 -DryRun
#>

function Invoke-ADReconScattered {
    [CmdletBinding()]
    param(
        [ValidateSet('WMI','Schtasks')]
        [string]$Method   = 'WMI',
        [string]$LogPath  = ".\ADReconScattered_$(Get-Date -Format yyyyMMdd_HHmmss).log",
        [int]$JitterMs    = 0,
        [int]$WaitSec     = 30,
        [switch]$DryRun
    )

    # --- resolve domain --------------------------------------------------------------------
    $Domain = $env:USERDNSDOMAIN
    if (-not $Domain) { try { $Domain = (Get-WmiObject Win32_ComputerSystem).Domain } catch {} }
    if (-not $Domain) { $Domain = "." }

    $WorkDir = Join-Path $env:TEMP ("reconscatter_" + (Get-Date -Format yyyyMMddHHmmss))

    # --- command set: @{ Cat; Line; Ttp } --------------------------------------------------
    # Full command lines (quotes handled natively by Win32_Process.Create). 1:1 with Burst file.
    $pwsh = 'powershell.exe -NoProfile -Command'
    $Commands = @(
        @{ Cat='Identity'; Ttp='T1033'; Line='whoami.exe /all' }
        @{ Cat='Identity'; Ttp='T1033'; Line='whoami.exe /groups' }
        @{ Cat='Identity'; Ttp='T1033'; Line='whoami.exe /priv' }
        @{ Cat='Identity'; Ttp='T1033'; Line='klist.exe' }

        @{ Cat='Host';     Ttp='T1082'; Line='hostname.exe' }
        @{ Cat='Host';     Ttp='T1082'; Line='systeminfo.exe' }
        @{ Cat='Host';     Ttp='T1016'; Line='ipconfig.exe /all' }
        @{ Cat='Host';     Ttp='T1016'; Line='arp.exe -a' }
        @{ Cat='Host';     Ttp='T1016'; Line='route.exe print' }
        @{ Cat='Host';     Ttp='T1049'; Line='netstat.exe -ano' }
        @{ Cat='Host';     Ttp='T1057'; Line='tasklist.exe /v' }
        @{ Cat='Host';     Ttp='T1033'; Line='qwinsta.exe' }
        @{ Cat='Host';     Ttp='T1033'; Line='quser.exe' }

        @{ Cat='Domain';   Ttp='T1018'; Line="nltest.exe /dclist:$Domain" }
        @{ Cat='Domain';   Ttp='T1482'; Line='nltest.exe /domain_trusts /all_trusts' }
        @{ Cat='Domain';   Ttp='T1482'; Line='nltest.exe /trusted_domains' }
        @{ Cat='Domain';   Ttp='T1018'; Line="nltest.exe /dsgetdc:$Domain" }

        @{ Cat='NetEnum';  Ttp='T1087.002'; Line='net.exe user /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Domain Admins" /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Enterprise Admins" /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Domain Controllers" /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Schema Admins" /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Server Operators" /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Account Operators" /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.002'; Line='net.exe group "Backup Operators" /domain' }
        @{ Cat='NetEnum';  Ttp='T1201';     Line='net.exe accounts /domain' }
        @{ Cat='NetEnum';  Ttp='T1069.001'; Line='net.exe localgroup administrators' }
        @{ Cat='NetEnum';  Ttp='T1069.001'; Line='net.exe localgroup "Remote Desktop Users"' }
        @{ Cat='NetEnum';  Ttp='T1135';     Line='net.exe view /domain' }
        @{ Cat='NetEnum';  Ttp='T1135';     Line='net.exe share' }
        @{ Cat='NetEnum';  Ttp='T1049';     Line='net.exe session' }
        @{ Cat='NetEnum';  Ttp='T1016';     Line='net.exe config workstation' }
        @{ Cat='NetEnum';  Ttp='T1124';     Line='net.exe time /domain' }

        @{ Cat='WMIC';     Ttp='T1082'; Line='wmic.exe computersystem get domain' }
        @{ Cat='WMIC';     Ttp='T1482'; Line='wmic.exe ntdomain list /format:list' }
        @{ Cat='WMIC';     Ttp='T1087'; Line='wmic.exe useraccount get name,sid' }
        @{ Cat='WMIC';     Ttp='T1069'; Line='wmic.exe group get name,sid' }

        @{ Cat='LDAP';     Ttp='T1087.002'; Line='dsquery.exe user -limit 0' }
        @{ Cat='LDAP';     Ttp='T1018';     Line='dsquery.exe computer -limit 0' }
        @{ Cat='LDAP';     Ttp='T1069.002'; Line='dsquery.exe group -limit 0' }
        @{ Cat='LDAP';     Ttp='T1016';     Line='dsquery.exe subnet -limit 0' }
        @{ Cat='SPN';      Ttp='T1087.002'; Line='setspn.exe -q */*' }

        @{ Cat='DCAdmin';  Ttp='T1018'; Line='repadmin.exe /showrepl' }
        @{ Cat='DCAdmin';  Ttp='T1018'; Line='repadmin.exe /replsummary' }
        @{ Cat='DCAdmin';  Ttp='T1018'; Line='dcdiag.exe' }
        @{ Cat='DCAdmin';  Ttp='T1018'; Line='netdom.exe query dc' }
        @{ Cat='DCAdmin';  Ttp='T1018'; Line='netdom.exe query fsmo' }
        @{ Cat='DCAdmin';  Ttp='T1482'; Line='netdom.exe query trust' }
        @{ Cat='DCAdmin';  Ttp='T1018'; Line='netdom.exe query workstation' }

        @{ Cat='DNS';      Ttp='T1018'; Line="nslookup.exe -type=SRV _ldap._tcp.dc._msdcs.$Domain" }
        @{ Cat='Time';     Ttp='T1124'; Line='w32tm.exe /query /status' }

        @{ Cat='Policy';   Ttp='T1615'; Line='gpresult.exe /z' }

        # ActiveDirectory module cmdlets, reparented as powershell.exe child processes
        @{ Cat='ADModule'; Ttp='T1482';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADDomain | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1482';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADForest | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1482';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADTrust -Filter * | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1018';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADDomainController -Filter * | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1201';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADDefaultDomainPasswordPolicy | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1087.002'; Line="$pwsh ""Import-Module ActiveDirectory; Get-ADUser -Filter * -ResultSetSize `$null | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1018';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADComputer -Filter * -ResultSetSize `$null | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1069.002'; Line="$pwsh ""Import-Module ActiveDirectory; Get-ADGroup -Filter * | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1069.002'; Line="$pwsh ""Import-Module ActiveDirectory; Get-ADGroupMember 'Domain Admins' | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1087';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADOrganizationalUnit -Filter * | Out-Null""" }
        @{ Cat='ADModule'; Ttp='T1482';     Line="$pwsh ""Import-Module ActiveDirectory; Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' | Out-Null""" }
    )

    # --- logging ---------------------------------------------------------------------------
    function Write-Log {
        param([string]$Message,[string]$Level='INFO')
        $line = "{0} [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Level, $Message
        Write-Host $line
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }

    function Test-ToolPresent {
        param([string]$Line)
        $tool = ($Line -split '\s+')[0]
        return [bool](Get-Command $tool -ErrorAction SilentlyContinue)
    }

    function Wait-ForPid {
        param([int]$TargetPid,[int]$Seconds)
        if ($TargetPid -le 0) { return }
        $deadline = (Get-Date).AddSeconds($Seconds)
        while ((Get-Date) -lt $deadline) {
            if (-not (Get-Process -Id $TargetPid -ErrorAction SilentlyContinue)) { return }
            Start-Sleep -Milliseconds 100
        }
    }

    # --- launchers -------------------------------------------------------------------------
    function Invoke-ViaWMI {
        param([string]$Line)
        $res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = $Line; CurrentDirectory = $env:SystemRoot }
        return [pscustomobject]@{ ReturnValue = $res.ReturnValue; ProcessId = [int]$res.ProcessId }
    }

    function Invoke-ViaSchtasks {
        param([string]$Line,[int]$Index)
        if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
        $stub = Join-Path $WorkDir ("task_{0:D2}.cmd" -f $Index)
        Set-Content -Path $stub -Value "@echo off`r`n$Line" -Encoding ASCII
        $taskName = "ReconScatter_{0:D2}_{1}" -f $Index, (Get-Random -Maximum 99999)
        & schtasks.exe /create /tn $taskName /tr "cmd.exe /c `"$stub`"" /sc once /st 00:00 /f | Out-Null
        & schtasks.exe /run /tn $taskName | Out-Null
        Start-Sleep -Milliseconds 400
        & schtasks.exe /delete /tn $taskName /f | Out-Null
        return [pscustomobject]@{ ReturnValue = $LASTEXITCODE; ProcessId = -1; TaskName = $taskName }
    }

    # --- run -------------------------------------------------------------------------------
    Write-Log "=== AD Recon SCATTERED START (Method=$Method) ===" 'INFO'
    Write-Log "Host=$env:COMPUTERNAME User=$env:USERNAME Domain=$Domain PID=$PID JitterMs=$JitterMs DryRun=$($DryRun.IsPresent)" 'INFO'
    Write-Log "Reparent anchor: $(if($Method -eq 'WMI'){'WmiPrvSE.exe (T1047)'}else{'Task Scheduler / svchost.exe (T1053.005)'})" 'INFO'
    Write-Log "Commands queued: $($Commands.Count)" 'INFO'

    $i = 0
    foreach ($c in $Commands) {
        $i++
        $tag = "[$($c.Cat)|$($c.Ttp)]"
        if (-not (Test-ToolPresent $c.Line)) {
            Write-Log "$tag SKIP (not present): $($c.Line)" 'SKIP'
            continue
        }
        if ($DryRun) {
            Write-Log "$tag WOULD LAUNCH via $Method : $($c.Line)" 'DRY'
            continue
        }
        try {
            if ($Method -eq 'WMI') {
                $r = Invoke-ViaWMI -Line $c.Line
                Write-Log "$tag WMI rv=$($r.ReturnValue) newPID=$($r.ProcessId) parent=WmiPrvSE :: $($c.Line)" 'EXEC'
                Wait-ForPid -TargetPid $r.ProcessId -Seconds $WaitSec
            }
            else {
                $r = Invoke-ViaSchtasks -Line $c.Line -Index $i
                Write-Log "$tag Schtasks task=$($r.TaskName) rv=$($r.ReturnValue) parent=svchost :: $($c.Line)" 'EXEC'
            }
        }
        catch {
            Write-Log "$tag ERROR: $($c.Line) :: $($_.Exception.Message)" 'ERR'
        }
        if ($JitterMs -gt 0) { Start-Sleep -Milliseconds $JitterMs }
    }

    if ($Method -eq 'Schtasks' -and (Test-Path $WorkDir)) {
        try { Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }

    Write-Log "=== AD Recon SCATTERED END ===" 'INFO'
    Write-Host ""
    Write-Host "Note: reparented/detached processes -> tool OUTPUT is not captured here; the point is the"
    Write-Host "PROCESS telemetry in Cortex. This log records lineage facts (PID/parent/task) + ATT&CK IDs."
    Write-Host "Transcript written to: $LogPath"
}