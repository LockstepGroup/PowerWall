function Get-PwAsaAnalysis {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Performs config analysis on ASA from config file or backup.
	#>

    Param (
        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'config')]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigPath,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'backup')]
        [string]$BackupPath
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwAsaAnalysis:"

    if ($BackupPath) {
        if (Test-Path $BackupPath) {
            $BackupDirectory = Get-ChildItem -Path $BackupPath | Split-Path -Parent
            $BackupName = (Get-ChildItem -Path $BackupPath).BaseName
            $DestinationDirectory = Join-Path -Path $BackupDirectory -ChildPath $BackupName

            $CurrentFiles = Get-ChildItem -Path $BackupDirectory

            # Expand archives
            Expand-Archive -Path $BackupPath -DestinationPath $BackupDirectory

            $NewFiles = Get-ChildItem -Path $BackupDirectory
            $NewFolder = $NewFiles | Where-Object { $CurrentFiles.Name -notcontains $_.Name }
            Rename-Item -Path $NewFolder -NewName $BackupName
            Write-Verbose "$VerbosePrefix $($NewFolder.FullName)"

            $ExcelPath = Join-Path -Path $DestinationDirectory -ChildPath "$BackupName`.xlsx"
            $ConfigPath = Join-Path -Path $DestinationDirectory -ChildPath "running-config.cfg"
        } else {
            Throw "BackupPath not found: $BackupPath"
        }
    } elseif ($ConfigPath) {
        if (Test-Path $ConfigPath) {
            #$BackupDirectory = Get-ChildItem -Path $ConfigPath | Split-Path -Parent
            $BackupName = (Get-ChildItem -Path $ConfigPath).BaseName
            $DestinationDirectory = Get-ChildItem -Path $ConfigPath | Split-Path -Parent
            #$NewDirectory = New-Item -Path $DestinationDirectory -ItemType Directory

            $ExcelPath = Join-Path -Path $DestinationDirectory -ChildPath "$BackupName`.xlsx"
            #$CopyConfigPath = Join-Path -Path $NewDirectory -ChildPath 'running-config.txt'
            #$CopyItem = Copy-Item -Path $ConfigPath -Destination $CopyConfigPath
        } else {
            Throw "ConfigPath not found: $ConfigPath"
        }
    }

    Write-Verbose "$VerbosePrefix OutputPath is $ExcelPath"

    #region asa
    #####################################################

    Write-Verbose "$VerbosePrefix Getting Access Policies"
    $AccessPolicies = Get-PwAsaSecurityPolicy -ConfigPath $ConfigPath -Verbose:$false
    $Global:AccessPolicies = $AccessPolicies
    Write-Verbose "$VerbosePrefix Found $($AccessPolicies.Count) Access Policies"

    Write-Verbose "$VerbosePrefix Getting Objects"
    $Objects = Get-PwAsaObject -ConfigPath $ConfigPath -Verbose:$false
    $NetworkObjects = $Objects | Where-Object { $_.GetType().Name -eq 'NetworkObject' }
    $ServiceObjects = $Objects | Where-Object { $_.GetType().Name -eq 'ServiceObject' }
    if ($ServiceObjects.Count -eq 0) {
        $ServiceObjects = @()
        $ServiceObjects += New-PwServiceObject -name 'dummy-fake-service'
    }
    $Global:NetworkObjects = $NetworkObjects
    $Global:ServiceObjects = $ServiceObjects
    Write-Verbose "$VerbosePrefix Found $($NetworkObjects.Count) Network Objects"
    Write-Verbose "$VerbosePrefix Found $($ServiceObjects.Count) Service Objects"

    Write-Verbose "$VerbosePrefix Resolving Access Policies"
    $ResolvedAccessPolicies = $AccessPolicies | Resolve-PwSecurityPolicy -NetworkObjects $NetworkObjects -ServiceObjects $ServiceObjects -FirewallType 'asa' -Verbose:$false

    Write-Verbose "Getting Nat Policies"
    $NatPolicies = Get-PwAsaNatPolicy -ConfigPath $ConfigPath -Verbose:$false
    $Global:NatPolicies = $NatPolicies
    Write-Verbose "Resolving Nat Policies"
    $ResolvedNatPolicies = $NatPolicies | Resolve-PwNatPolicy -NetworkObjects $NetworkObjects -ServiceObjects $ServiceObjects -FirewallType 'asa' -Verbose:$false

    # remove natexempts
    $InterestingNats = $ResolvedNatPolicies | Where-Object { !($_.NatExempt) }
    $global:InterestingNats = $InterestingNats

    # look for 32 bit only Nats
    $IpRx = [regex] '^(\d+)\.(\d+)\.(\d+)\.(\d+)$'
    $InterestingNats = $InterestingNats | Where-Object { ($_.ResolvedOriginalSource -match '/32') -or ($_.ResolvedOriginalSource -eq '') -or ($IpRx.Match($_.ResolvedOriginalSource).Success) }
    $InterestingNats = $InterestingNats | Where-Object { ($_.ResolvedOriginalDestination -match '/32') -or ($_.ResolvedOriginalDestination -eq '') -or ($IpRx.Match($_.ResolvedOriginalDestination).Success) }
    $InterestingNats = $InterestingNats | Where-Object { ($_.ResolvedTranslatedSource -match '/32') -or ($_.ResolvedTranslatedSource -eq '') -or ($IpRx.Match($_.ResolvedTranslatedSource).Success) }
    $InterestingNats = $InterestingNats | Where-Object { ($_.ResolvedTranslatedDestination -match '/32') -or ($_.ResolvedTranslatedDestination -eq '') -or ($IpRx.Match($_.ResolvedTranslatedDestination).Success) }

    # filter for public IPs
    $PublicNatsOnly = @()
    foreach ($nat in $InterestingNats) {
        $PublicNat = $false
        if ($nat.ResolvedOriginalSource -ne "") {
            if (!(Test-IpInRange -ContainingNetwork 192.168.0.0/16 -ContainedNetwork $nat.ResolvedOriginalSource) -and
                !(Test-IpInRange -ContainingNetwork 172.16.0.0/12 -ContainedNetwork $nat.ResolvedOriginalSource) -and
                !(Test-IpInRange -ContainingNetwork 10.0.0.0/8 -ContainedNetwork $nat.ResolvedOriginalSource)) {
                $PublicNat = $true
            }
        }

        if ($nat.ResolvedOriginalDestination -ne "") {
            if (!(Test-IpInRange -ContainingNetwork 192.168.0.0/16 -ContainedNetwork $nat.ResolvedOriginalDestination) -and
                !(Test-IpInRange -ContainingNetwork 172.16.0.0/12 -ContainedNetwork $nat.ResolvedOriginalDestination) -and
                !(Test-IpInRange -ContainingNetwork 10.0.0.0/8 -ContainedNetwork $nat.ResolvedOriginalDestination)) {
                $PublicNat = $true
            }
        }

        if ($nat.ResolvedTranslatedSource -ne "") {
            if (!(Test-IpInRange -ContainingNetwork 192.168.0.0/16 -ContainedNetwork $nat.ResolvedTranslatedSource) -and
                !(Test-IpInRange -ContainingNetwork 172.16.0.0/12 -ContainedNetwork $nat.ResolvedTranslatedSource) -and
                !(Test-IpInRange -ContainingNetwork 10.0.0.0/8 -ContainedNetwork $nat.ResolvedTranslatedSource)) {
                $PublicNat = $true
            }
        }

        if ($nat.ResolvedTranslatedDestination -ne "") {
            if (!(Test-IpInRange -ContainingNetwork 192.168.0.0/16 -ContainedNetwork $nat.ResolvedTranslatedDestination) -and
                !(Test-IpInRange -ContainingNetwork 172.16.0.0/12 -ContainedNetwork $nat.ResolvedTranslatedDestination) -and
                !(Test-IpInRange -ContainingNetwork 10.0.0.0/8 -ContainedNetwork $nat.ResolvedTranslatedDestination)) {
                $PublicNat = $true
            }
        }

        if ($PublicNat) {
            $PublicNatsOnly += $nat
        }
    }

    # Generate Nat Report
    $NatSummary = @()
    foreach ($nat in $PublicNatsOnly) {

        if (!(Test-IpInRange -ContainingNetwork 192.168.0.0/16 -ContainedNetwork $nat.ResolvedOriginalSource) -and
            !(Test-IpInRange -ContainingNetwork 172.16.0.0/12 -ContainedNetwork $nat.ResolvedOriginalSource) -and
            !(Test-IpInRange -ContainingNetwork 10.0.0.0/8 -ContainedNetwork $nat.ResolvedOriginalSource)) {
            $NatInternalAddress = $nat.ResolvedTranslatedSource -replace '/32', ''
            $NatExternalAddress = $nat.ResolvedOriginalSource -replace '/32', ''
        } else {
            $NatInternalAddress = $nat.ResolvedOriginalSource -replace '/32', ''
            $NatExternalAddress = $nat.ResolvedTranslatedSource -replace '/32', ''
        }

        # Nat Name
        $ObjectLookup = $NetworkObjects | Where-Object { $_.Member -contains "$NatInternalAddress/32" }
        if ($nat.Name) {
            $NatObjectName = $nat.Name
        } elseif ($nat.OriginalSource -match '[a-z][A-Z]') {
            $NatObjectName = $nat.OriginalSource
        } elseif ($nat.TranslatedSource -match '[a-z][A-Z]') {
            $NatObjectName = $nat.TranslatedSource
        } elseif ($ObjectLookup) {
            $NatObjectName = $ObjectLookup.Name
        } else {
            $NatObjectName = $NatInternalAddress
        }

        $AccessLookup = $ResolvedAccessPolicies | Where-Object { ($_.ResolvedDestination -eq "$NatInternalAddress/32") -or ($_.ResolvedDestination -eq "$NatExternalAddress/32") } | Select-Object Source, ResolvedSource, Service, ResolvedService -Unique
        $Sources = ($AccessLookup.Source | Select-Object -Unique)
        foreach ($source in $Sources) {
            $NatSourceName = $source
            $ResolvedSource = $AccessLookup | Where-Object { $_.Source -eq $source } | Select-Object ResolvedSource -Unique

            foreach ($rs in $ResolvedSource) {
                $UniqueServices = $AccessLookup | Where-Object { $_.Source -eq $NatSourceName } | Select-Object Service -Unique
                $NatServiceName = $UniqueServices

                foreach ($uservice in $NatServiceName) {
                    #$NatServiceName = $uservice.Service
                    $ResolvedService = $AccessLookup | Where-Object { ($_.Source -eq $NatSourceName) -and ($_.Service -eq $uservice.Service) } | Select-Object ResolvedService -Unique

                    foreach ($rservice in $ResolvedService) {
                        $new = "" | Select-Object ObjectName, InternalAddress, ExternalAddress, SourceName, SourceAddress, ServiceName, Service
                        $NatSummary += $new
                        $new.ObjectName = $NatObjectName
                        $new.InternalAddress = $NatInternalAddress
                        $new.ExternalAddress = $NatExternalAddress
                        $new.SourceName = $NatSourceName
                        $new.SourceAddress = $rs.ResolvedSource
                        $new.ServiceName = $uservice.Service[0]
                        $new.Service = $rservice.ResolvedService
                    }
                }
            }
        }
    }

    $Interfaces = Get-PwAsaInterface -ConfigPath $ConfigPath
    $SourceInterfaceMap = @{ }
    $DestinationInterfaceMap = @{ }
    foreach ($interface in $Interfaces) {
        if ($interface.AccessList) {
            $AclName = $interface.AccessList
            if ($interface.AccessListDirection -eq 'in') {
                $SourceInterfaceMap.$AclName = $interface.NameIf
            } elseif ($interface.AccessListDirection -eq 'out') {
                $DestinationInterfaceMap.$AclName = $interface.NameIf
            }
        }
    }

    #$BaseName = (Get-ChildItem -Path $ConfigPath).BaseName
    #$ExcelPath = Join-Path -Path (Split-Path -Path $ConfigPath) -ChildPath "$BaseName`.xlsx"
    $NatSummary | Export-Excel -Path $ExcelPath -WorksheetName 'Overview' -Verbose:$false

    $ResolvedNatPolicies | Select-Object Number, Comment, Enabled, SourceInterface, DestinationInterface, `
        OriginalSource, ResolvedOriginalSource,
    OriginalDestination, ResolvedOriginalDestination,
    OriginalService, ResolvedOriginalService,
    TranslatedSource, ResolvedTranslatedSource,
    TranslatedDestination, ResolvedTranslatedDestination,
    TranslatedService, ResolvedTranslatedService,
    SourceTranslationType,
    DestinationTranslationType,
    ProxyArp,
    RouteLookup,
    NatExempt | Export-Excel -Path $ExcelPath -WorksheetName 'NAT' -Verbose:$false

    $ResolvedAccessPolicies | Select-Object AccessList, AclType, Number, Action, `
        #SourceInterface, DestinationInterface,
    @{ Name = 'SourceInterface'; Expression = { $SourceInterfaceMap."$($_.AccessList)" } },
    @{ Name = 'DestinationInterface'; Expression = { $DestinationInterfaceMap."$($_.AccessList)" } },
    @{ Name = 'Source'; Expression = { $_.Source -join ',' } }, ResolvedSource,
    @{ Name = 'Destination'; Expression = { $_.Destination -join ',' } }, ResolvedDestination,
    Protocol,
    SourcePort, ResolvedSourcePort,
    DestinationPort, ResolvedDestinationPort,
    @{ Name = 'SourceService'; Expression = { $_.SourceService -join ',' } },
    ResolvedSourceService,
    @{ Name = 'Service'; Expression = { $_.Service -join ',' } },
    ResolvedService,
    Comment,
    Enabled,
    NewRule,
    Status,
    Notes | Export-Excel -Path $ExcelPath -WorksheetName 'AccessPolicies' -FreezeTopRow -Verbose:$false
    #####################################################
    #endregion asa

}