function Get-PwFgAnalysis {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Performs config analysis on ASA from config file or backup.
	#>

    Param (
        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'config')]
        [string]$ConfigPath
    )

    #region setup
    #####################################################
    $VerbosePrefix = "Get-PwFgAnalysis:"

    if (Test-Path -Path $ConfigPath -PathType Leaf) {
        # Check that file exists
        $ConfigPath = Resolve-Path $ConfigPath
        $ConfigArray = Get-Content $ConfigPath

        # Setup ExcelPath
        $BaseName = (Get-ChildItem -Path $ConfigPath).BaseName
        $ExcelPath = Join-Path -Path (Split-Path -Path $ConfigPath) -ChildPath "$BaseName`.xlsx"
    } else {
        Throw "$VerbosePrefix ConfigPath does not exist: $ConfigPath"
    }

    # check for ImportExcel module
    try {
        Import-Module ImportExcel
    } catch {
        Throw "VerbosePrefix This cmdlet requires ImportExcel module. https://github.com/dfinke/ImportExcel"
    }

    #####################################################
    #endregion setup

    #region interfaces
    #####################################################
    Write-Verbose "$VerbosePrefix Getting Interfaces"
    $WorksheetName = 'Interfaces'
    $Interfaces = Get-PwFgInterface -ConfigArray $ConfigArray -Verbose:$false

    $Excel = $Interfaces | Select-Object Name, Comment, Vdom, Category, IpAddress, VlanId, IsDhcpClient, InterfaceType, ParentInterface,
    @{Name = "AggregateMember"; Expression = { $_.AggregateMember -join [Environment]::NewLine } },
    @{Name = "AllowedMgmtMethods"; Expression = { $_.AllowedMgmtMethods -join [Environment]::NewLine } },
    IsManagement, IsPPPoE `
    | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Verbose:$false -Calculate -FreezeTopRow -AutoSize -PassThru

    # add word wrap
    $WrapColumns = @()
    $WrapColumns += 'J'
    $WrapColumns += 'K'
    foreach ($col in $WrapColumns) {
        $Range = $Excel.Workbook.Worksheets[$WorksheetName].Dimension.Address -replace 'A1', "$col`2" -replace ':[A-Z]+', ":$col"
        Set-Format -WorkSheet $Excel.Workbook.Worksheets[$WorksheetName] -Range $Range -WrapText
    }
    Close-ExcelPackage $Excel
    #####################################################
    #endregion interfaces

    #region staticroutes
    #####################################################
    Write-Verbose "$VerbosePrefix Getting Static Routes"
    $WorksheetName = 'StaticRoutes'
    $StaticRoutes = Get-PwFgStaticRoute -ConfigArray $ConfigArray -Verbose:$false

    $Excel = $StaticRoutes | Select-Object Vdom, Destination, Interface, Nexthop, Metric, Comment `
    | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Verbose:$false -Calculate -FreezeTopRow -AutoSize -PassThru

    # add word wrap
    $WrapColumns = @()
    foreach ($col in $WrapColumns) {
        $Range = $Excel.Workbook.Worksheets[$WorksheetName].Dimension.Address -replace 'A1', "$col`2" -replace ':[A-Z]+', ":$col"
        Set-Format -WorkSheet $Excel.Workbook.Worksheets[$WorksheetName] -Range $Range -WrapText
    }
    Close-ExcelPackage $Excel
    #####################################################
    #endregion staticroutes

    #region networkobjects
    #####################################################
    Write-Verbose "$VerbosePrefix Getting Network Objects"
    $WorksheetName = 'NetworkObjects'
    $NetworkObjects = Get-PwFgNetworkObject -ConfigArray $ConfigArray -Verbose:$false

    $Excel = $NetworkObjects | Select-Object Name, Comment, Vdom,
    @{Name = "Member"; Expression = { $_.Member -join [Environment]::NewLine } } `
    | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Verbose:$false -Calculate -FreezeTopRow -AutoSize -PassThru

    # add word wrap
    $WrapColumns = @()
    $WrapColumns += 'D'
    foreach ($col in $WrapColumns) {
        $Range = $Excel.Workbook.Worksheets[$WorksheetName].Dimension.Address -replace 'A1', "$col`2" -replace ':[A-Z]+', ":$col"
        Set-Format -WorkSheet $Excel.Workbook.Worksheets[$WorksheetName] -Range $Range -WrapText
    }
    Close-ExcelPackage $Excel
    #####################################################
    #endregion networkobjects

    #region serviceobjects
    #####################################################
    Write-Verbose "$VerbosePrefix Getting Service Objects"
    $WorksheetName = 'ServiceObjects'
    $ServiceObjects = Get-PwFgServiceObject -ConfigArray $ConfigArray -Verbose:$false

    $Excel = $ServiceObjects | Select-Object Name, Comment, Vdom, Category, Protocol,
    @{Name = "DestinationPort"; Expression = { $_.DestinationPort -join [Environment]::NewLine } },
    @{Name = "Member"; Expression = { $_.Member -join [Environment]::NewLine } } `
    | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Verbose:$false -Calculate -FreezeTopRow -AutoSize -PassThru

    # add word wrap
    $WrapColumns = @()
    $WrapColumns += 'F'
    $WrapColumns += 'G'
    foreach ($col in $WrapColumns) {
        $Range = $Excel.Workbook.Worksheets[$WorksheetName].Dimension.Address -replace 'A1', "$col`2" -replace ':[A-Z]+', ":$col"
        Set-Format -WorkSheet $Excel.Workbook.Worksheets[$WorksheetName] -Range $Range -WrapText
    }
    Close-ExcelPackage $Excel
    #####################################################
    #endregion serviceobjects

    #region securitypolicies
    #####################################################
    Write-Verbose "$VerbosePrefix Getting Security Policies"
    $WorksheetName = 'SecurityPolicy'
    $SecurityPolicies = Get-PwFgSecurityPolicy -ConfigArray $ConfigArray -Verbose:$false

    $Excel = $SecurityPolicies | Select-Object Number, Action, Vdom, Enabled,
    @{Name = "SourceInterface"; Expression = { $_.SourceInterface -join [Environment]::NewLine } },
    @{Name = "DestinationInterface"; Expression = { $_.DestinationInterface -join [Environment]::NewLine } },
    @{Name = "Source"; Expression = { $_.Source -join [Environment]::NewLine } },
    @{Name = "SourceUser"; Expression = { $_.SourceUser -join [Environment]::NewLine } },
    @{Name = "Destination"; Expression = { $_.Destination -join [Environment]::NewLine } },
    @{Name = "Service"; Expression = { $_.Service -join [Environment]::NewLine } },
    @{Name = "Application"; Expression = { $_.Application -join [Environment]::NewLine } },
    Comment | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Verbose:$false -Calculate -FreezeTopRow -AutoSize -PassThru

    # add word wrap
    $WrapColumns = @()
    $WrapColumns += 'E'
    $WrapColumns += 'F'
    $WrapColumns += 'G'
    $WrapColumns += 'H'
    $WrapColumns += 'I'
    $WrapColumns += 'J'
    $WrapColumns += 'K'
    foreach ($col in $WrapColumns) {
        $Range = $Excel.Workbook.Worksheets[$WorksheetName].Dimension.Address -replace 'A1', "$col`2" -replace ':[A-Z]+', ":$col"
        Set-Format -WorkSheet $Excel.Workbook.Worksheets[$WorksheetName] -Range $Range -WrapText
    }
    Close-ExcelPackage $Excel
    #####################################################
    #endregion securitypolicies

    #region resolvedsecuritypolicies
    #####################################################
    Write-Verbose "$VerbosePrefix Resolving Security Policies"
    $WorksheetName = 'ResolvedSecurityPolicy'
    $ResolvedSecurityPolicies = $SecurityPolicies | Resolve-PwSecurityPolicy -NetworkObjects $NetworkObjects -ServiceObjects $ServiceObjects -FirewallType 'Fortigate' -Verbose:$false
    $global:rpol = $ResolvedSecurityPolicies
    $global:expath = $ExcelPath

    $Excel = $ResolvedSecurityPolicies | Select-Object Number, Action, Vdom, Enabled,
    @{Name = "SourceInterface"; Expression = { $_.SourceInterface -join [Environment]::NewLine } },
    @{Name = "DestinationInterface"; Expression = { $_.DestinationInterface -join [Environment]::NewLine } },
    @{Name = "Source"; Expression = { $_.Source -join [Environment]::NewLine } },
    @{Name = "ResolvedSource"; Expression = { $_.ResolvedSource -join [Environment]::NewLine } },
    @{Name = "SourceUser"; Expression = { $_.SourceUser -join [Environment]::NewLine } },
    @{Name = "Service"; Expression = { $_.Service -join [Environment]::NewLine } },
    @{Name = "ResolvedService"; Expression = { $_.ResolvedService -join [Environment]::NewLine } },
    @{Name = "DestinationPort"; Expression = { $_.DestinationPort -join [Environment]::NewLine } },
    @{Name = "ResolvedDestinationPort"; Expression = { $_.ResolvedDestinationPort -join [Environment]::NewLine } },
    @{Name = "Application"; Expression = { $_.Application -join [Environment]::NewLine } },
    Comment | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Calculate -FreezeTopRow -AutoSize -PassThru

    # add word wrap
    $WrapColumns = @()
    $WrapColumns += 'E'
    $WrapColumns += 'F'
    $WrapColumns += 'G'
    $WrapColumns += 'H'
    $WrapColumns += 'I'
    $WrapColumns += 'J'
    $WrapColumns += 'K'
    $WrapColumns += 'L'
    $WrapColumns += 'M'
    $WrapColumns += 'N'
    foreach ($col in $WrapColumns) {
        $Range = $Excel.Workbook.Worksheets[$WorksheetName].Dimension.Address -replace 'A1', "$col`2" -replace ':[A-Z]+', ":$col"
        Set-Format -WorkSheet $Excel.Workbook.Worksheets[$WorksheetName] -Range $Range -WrapText
    }
    Close-ExcelPackage $Excel
    #####################################################
    #endregion resolvedsecuritypolicies


    <#
    Write-Verbose "Getting Objects"
    $Objects = Get-PwAsaObject -ConfigPath $ConfigPath -Verbose:$false
    $NetworkObjects = $Objects | Where-Object { $_.GetType().Name -eq 'NetworkObject' }
    $ServiceObjects = $Objects | Where-Object { $_.GetType().Name -eq 'ServiceObject' }

    Write-Verbose "Resolving Access Policies"
    $ResolvedAccessPolicies = $AccessPolicies | Resolve-PwSecurityPolicy -NetworkObjects $NetworkObjects -ServiceObjects $ServiceObjects -FirewallType 'asa' -Verbose:$false

    Write-Verbose "Getting Nat Policies"
    $NatPolicies = Get-PwAsaNatPolicy -ConfigPath $ConfigPath -Verbose:$false
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
    @{ Name = 'Service'; Expression = { $_.Service -join ',' } },
    ResolvedService,
    Comment,
    Enabled,
    NewRule,
    Status,
    Notes | Export-Excel -Path $ExcelPath -WorksheetName 'AccessPolicies' -FreezeTopRow -Verbose:$false
    #####################################################
    #endregion asa #>
    #$global:Excel = $Excel
    #Close-ExcelPackage $Excel
}