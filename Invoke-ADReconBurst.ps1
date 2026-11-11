<#
.SYNOPSIS
    AD Recon "Shotgun" - maximum-noise native LOLBin telemetry generator for XDR/Cortex demos.

.DESCRIPTION
    Fires a burst of legitimate, built-in Windows administration / LOTL commands used in the
    discovery + AD-recon phases of an intrusion. Everything runs as a child of THIS PowerShell
    process, so you get a single dense process tree that is ideal for showing causality /
    correlation in Cortex XDR / XSIAM.

    Every action is tagged with its MITRE ATT&CK technique ID in the log so your alerts map
    straight to the matrix. Companion file: Invoke-ADReconScattered.ps1 (same commands, but
    reparented so they do NOT form one tree) - see README.md for the side-by-side.

    NATIVE TOOLING ONLY. No external binaries are downloaded. RSAT-dependent tools (dsquery,
    setspn, repadmin, dcdiag, netdom, the ActiveDirectory module) are logged as skipped if absent
    and the burst continues.

    *** LAB / AUTHORIZED DEMO USE ONLY. ***
    This is intentionally LOUD. It performs read-only discovery (no changes), but it will
    generate high-severity alerts. Run it only in an environment you own or are authorized to test.

.PARAMETER LogPath
    File to write the timestamped transcript to. Defaults to .\ADReconBurst_<timestamp>.log

.PARAMETER JitterMs
    Milliseconds to sleep between commands. Default 0 = true shotgun (everything at once).

.PARAMETER DryRun
    Print what WOULD run without executing anything.

.EXAMPLE
    .\Invoke-ADReconBurst.ps1
.EXAMPLE
    .\Invoke-ADReconBurst.ps1 -JitterMs 300 -LogPath C:\demo\recon.log
.EXAMPLE
    .\Invoke-ADReconBurst.ps1 -DryRun
#>
function Invoke-ADReconBurst {
    [CmdletBinding()]
    param(
        [string]$LogPath = ".\ADReconBurst_$(Get-Date -Format yyyyMMdd_HHmmss).log",
        [int]$JitterMs = 0,
        [switch]$DryRun
    )

    # --- resolve current domain for targeted commands (best-effort) -------------------------
    $Domain = $env:USERDNSDOMAIN
    if (-not $Domain) { try { $Domain = (Get-WmiObject Win32_ComputerSystem).Domain } catch {} }
    if (-not $Domain) { $Domain = "." }

    # --- command set: @{ Cat; Tool; Args; Ttp } --------------------------------------------
    # Ttp = MITRE ATT&CK technique for the activity. Grouped by recon phase. Edit freely.
    $Commands = @(
        # 1. Identity / local context
        @{ Cat='Identity'; Tool='whoami.exe';    Args=@('/all');                     Ttp='T1033' }
        @{ Cat='Identity'; Tool='whoami.exe';    Args=@('/groups');                  Ttp='T1033' }
        @{ Cat='Identity'; Tool='whoami.exe';    Args=@('/priv');                    Ttp='T1033' }
        @{ Cat='Identity'; Tool='klist.exe';     Args=@();                           Ttp='T1033' }

        # 2. Host / network discovery
        @{ Cat='Host';     Tool='hostname.exe';  Args=@();                           Ttp='T1082' }
        @{ Cat='Host';     Tool='systeminfo.exe';Args=@();                           Ttp='T1082' }
        @{ Cat='Host';     Tool='ipconfig.exe';  Args=@('/all');                     Ttp='T1016' }
        @{ Cat='Host';     Tool='arp.exe';       Args=@('-a');                       Ttp='T1016' }
        @{ Cat='Host';     Tool='route.exe';     Args=@('print');                    Ttp='T1016' }
        @{ Cat='Host';     Tool='netstat.exe';   Args=@('-ano');                     Ttp='T1049' }
        @{ Cat='Host';     Tool='tasklist.exe';  Args=@('/v');                       Ttp='T1057' }
        @{ Cat='Host';     Tool='qwinsta.exe';   Args=@();                           Ttp='T1033' }
        @{ Cat='Host';     Tool='quser.exe';     Args=@();                           Ttp='T1033' }

        # 3. Domain / DC / trust discovery  (nltest = near-pure recon, very high signal)
        @{ Cat='Domain';   Tool='nltest.exe';    Args=@("/dclist:$Domain");          Ttp='T1018' }
        @{ Cat='Domain';   Tool='nltest.exe';    Args=@('/domain_trusts','/all_trusts'); Ttp='T1482' }
        @{ Cat='Domain';   Tool='nltest.exe';    Args=@('/trusted_domains');         Ttp='T1482' }
        @{ Cat='Domain';   Tool='nltest.exe';    Args=@("/dsgetdc:$Domain");         Ttp='T1018' }

        # 4. net.exe family  (spawns net1.exe -> classic detection anchor)
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('user','/domain');           Ttp='T1087.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Domain Admins','/domain');     Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Enterprise Admins','/domain');  Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Domain Controllers','/domain'); Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Schema Admins','/domain');       Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Server Operators','/domain');    Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Account Operators','/domain');   Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('group','Backup Operators','/domain');    Ttp='T1069.002' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('accounts','/domain');       Ttp='T1201' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('localgroup','administrators');           Ttp='T1069.001' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('localgroup','Remote Desktop Users');     Ttp='T1069.001' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('view','/domain');           Ttp='T1135' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('share');                    Ttp='T1135' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('session');                  Ttp='T1049' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('config','workstation');     Ttp='T1016' }
        @{ Cat='NetEnum';  Tool='net.exe';       Args=@('time','/domain');           Ttp='T1124' }

        # 5. WMIC  (deprecated binary -> strong detection trigger on its own; exec via WMI = T1047)
        @{ Cat='WMIC';     Tool='wmic.exe';      Args=@('computersystem','get','domain');       Ttp='T1082' }
        @{ Cat='WMIC';     Tool='wmic.exe';      Args=@('ntdomain','list','/format:list');       Ttp='T1482' }
        @{ Cat='WMIC';     Tool='wmic.exe';      Args=@('useraccount','get','name,sid');         Ttp='T1087' }
        @{ Cat='WMIC';     Tool='wmic.exe';      Args=@('group','get','name,sid');               Ttp='T1069' }

        # 6. RSAT command-line LDAP tooling  (may be absent -> skipped)
        @{ Cat='LDAP';     Tool='dsquery.exe';   Args=@('user','-limit','0');        Ttp='T1087.002' }
        @{ Cat='LDAP';     Tool='dsquery.exe';   Args=@('computer','-limit','0');    Ttp='T1018' }
        @{ Cat='LDAP';     Tool='dsquery.exe';   Args=@('group','-limit','0');       Ttp='T1069.002' }
        @{ Cat='LDAP';     Tool='dsquery.exe';   Args=@('subnet','-limit','0');      Ttp='T1016' }
        @{ Cat='SPN';      Tool='setspn.exe';    Args=@('-q','*/*');                 Ttp='T1087.002' }

        # 7. RSAT DC / replication / trust admin tools
        @{ Cat='DCAdmin';  Tool='repadmin.exe';  Args=@('/showrepl');                Ttp='T1018' }
        @{ Cat='DCAdmin';  Tool='repadmin.exe';  Args=@('/replsummary');             Ttp='T1018' }
        @{ Cat='DCAdmin';  Tool='dcdiag.exe';    Args=@();                           Ttp='T1018' }
        @{ Cat='DCAdmin';  Tool='netdom.exe';    Args=@('query','dc');               Ttp='T1018' }
        @{ Cat='DCAdmin';  Tool='netdom.exe';    Args=@('query','fsmo');             Ttp='T1018' }
        @{ Cat='DCAdmin';  Tool='netdom.exe';    Args=@('query','trust');            Ttp='T1482' }
        @{ Cat='DCAdmin';  Tool='netdom.exe';    Args=@('query','workstation');      Ttp='T1018' }

        # 8. DNS-based DC discovery + time
        @{ Cat='DNS';      Tool='nslookup.exe';  Args=@('-type=SRV',"_ldap._tcp.dc._msdcs.$Domain"); Ttp='T1018' }
        @{ Cat='Time';     Tool='w32tm.exe';     Args=@('/query','/status');         Ttp='T1124' }

        # 9. Policy
        @{ Cat='Policy';   Tool='gpresult.exe';  Args=@('/z');                       Ttp='T1615' }
    )

    # --- ActiveDirectory module cmdlet burst: @{ Label; Ttp; Script } -----------------------
    # Runs only if the RSAT ActiveDirectory module is installed. Pure enumeration cmdlets.
    $AdCmdlets = @(
        @{ Label='Get-ADDomain';                     Ttp='T1482'; Script={ Get-ADDomain } }
        @{ Label='Get-ADForest';                     Ttp='T1482'; Script={ Get-ADForest } }
        @{ Label='Get-ADTrust -Filter *';            Ttp='T1482'; Script={ Get-ADTrust -Filter * } }
        @{ Label='Get-ADDomainController -Filter *'; Ttp='T1018'; Script={ Get-ADDomainController -Filter * } }
        @{ Label='Get-ADDefaultDomainPasswordPolicy';Ttp='T1201'; Script={ Get-ADDefaultDomainPasswordPolicy } }
        @{ Label='Get-ADFineGrainedPasswordPolicy';  Ttp='T1201'; Script={ Get-ADFineGrainedPasswordPolicy -Filter * } }
        @{ Label='Get-ADReplicationSite -Filter *';  Ttp='T1016'; Script={ Get-ADReplicationSite -Filter * } }
        @{ Label='Get-ADReplicationSubnet -Filter *';Ttp='T1016'; Script={ Get-ADReplicationSubnet -Filter * } }
        @{ Label='Get-ADUser -Filter *';             Ttp='T1087.002'; Script={ Get-ADUser -Filter * -ResultSetSize $null } }
        @{ Label='Get-ADComputer -Filter *';         Ttp='T1018'; Script={ Get-ADComputer -Filter * -ResultSetSize $null } }
        @{ Label='Get-ADGroup -Filter *';            Ttp='T1069.002'; Script={ Get-ADGroup -Filter * } }
        @{ Label='Get-ADGroupMember Domain Admins';  Ttp='T1069.002'; Script={ Get-ADGroupMember 'Domain Admins' } }
        @{ Label='Get-ADOrganizationalUnit -Filter *';Ttp='T1087';    Script={ Get-ADOrganizationalUnit -Filter * } }
        @{ Label='Get-ADServiceAccount -Filter *';   Ttp='T1087';     Script={ Get-ADServiceAccount -Filter * } }
        @{ Label='Get-ADObject trustedDomain';       Ttp='T1482'; Script={ Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' } }
    )

    # --- helpers ----------------------------------------------------------------------------
    function Write-Log {
        param([string]$Message,[string]$Level='INFO')
        $line = "{0} [{1,-5}] {2}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Level, $Message
        Write-Host $line
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }

    function Invoke-Recon {
        param($Entry)
        $toolName = $Entry.Tool
        $display  = ("$toolName " + ($Entry.Args -join ' ')).Trim()
        $tag      = "[$($Entry.Cat)|$($Entry.Ttp)]"

        if (-not (Get-Command $toolName -ErrorAction SilentlyContinue)) {
            Write-Log "$tag SKIP (not present): $display" 'SKIP'
            return
        }
        if ($DryRun) {
            Write-Log "$tag WOULD RUN: $display" 'DRY'
            return
        }

        Write-Log "$tag >>> $display" 'EXEC'
        try {
            # Direct invocation -> each tool is a child of this powershell.exe (fat process tree)
            $out = & $toolName @($Entry.Args) 2>&1
            if ($out) { Add-Content -Path $LogPath -Value ($out | Out-String).TrimEnd() -Encoding UTF8 }
            Write-Log "$tag <<< done (exit=$LASTEXITCODE)" 'DONE'
        }
        catch {
            Write-Log "$tag ERROR: $($_.Exception.Message)" 'ERR'
        }
        if ($JitterMs -gt 0) { Start-Sleep -Milliseconds $JitterMs }
    }

    # --- run --------------------------------------------------------------------------------
    Write-Log "=== AD Recon Burst START (single process tree) ===" 'INFO'
    Write-Log "Host=$env:COMPUTERNAME User=$env:USERNAME Domain=$Domain PID=$PID JitterMs=$JitterMs DryRun=$($DryRun.IsPresent)" 'INFO'
    Write-Log "Native/RSAT commands queued: $($Commands.Count)  | AD cmdlets queued: $($AdCmdlets.Count)" 'INFO'

    foreach ($c in $Commands) { Invoke-Recon -Entry $c }

    # --- ActiveDirectory module burst (only if present) -------------------------------------
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Log "[ADModule|-] ActiveDirectory module present -> firing cmdlet burst" 'INFO'
        try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Log "[ADModule|-] import failed: $($_.Exception.Message)" 'ERR' }
        foreach ($cmd in $AdCmdlets) {
            $tag = "[ADModule|$($cmd.Ttp)]"
            if ($DryRun) { Write-Log "$tag WOULD RUN: $($cmd.Label)" 'DRY'; continue }
            Write-Log "$tag >>> $($cmd.Label)" 'EXEC'
            try {
                $null = & $cmd.Script 2>&1
                Write-Log "$tag <<< done" 'DONE'
            } catch {
                Write-Log "$tag ERROR: $($_.Exception.Message)" 'ERR'
            }
            if ($JitterMs -gt 0) { Start-Sleep -Milliseconds $JitterMs }
        }
    } else {
        Write-Log "[ADModule|-] SKIP (ActiveDirectory module not installed)" 'SKIP'
    }

    Write-Log "=== AD Recon Burst END ===" 'INFO'
    Write-Host ""
    Write-Host "Transcript written to: $LogPath"
}