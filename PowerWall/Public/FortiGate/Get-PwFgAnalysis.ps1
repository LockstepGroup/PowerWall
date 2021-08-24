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
        Throw "$VerbosePrefix This cmdlet requires ImportExcel module. https://github.com/dfinke/ImportExcel"
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

    $Excel = $ResolvedSecurityPolicies | Select-Object Number, Name, Action, Vdom, Enabled,
    @{Name = "SourceInterface"; Expression = { $_.SourceInterface -join [Environment]::NewLine } },
    @{Name = "DestinationInterface"; Expression = { $_.DestinationInterface -join [Environment]::NewLine } },
    @{Name = "Source"; Expression = { $_.Source -join [Environment]::NewLine } },
    @{Name = "ResolvedSource"; Expression = { $_.ResolvedSource -join [Environment]::NewLine } },
    @{Name = "SourceUser"; Expression = { $_.SourceUser -join [Environment]::NewLine } },
    @{Name = "Service"; Expression = { $_.Service -join [Environment]::NewLine } },
    @{Name = "ResolvedService"; Expression = { $_.ResolvedService -join [Environment]::NewLine } },
    @{Name = "Destination"; Expression = { $_.Destination -join [Environment]::NewLine } },
    @{Name = "ResolvedDestination"; Expression = { $_.ResolvedDestination -join [Environment]::NewLine } },
    Comment | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Calculate -FreezeTopRow -AutoSize -PassThru -ClearSheet

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

    #region vips
    #####################################################
    Write-Verbose "$VerbosePrefix Analyzing Vips"
    $WorksheetName = 'Vips'
    $Vips = Get-PwFgVip -ConfigArray $ConfigArray -Verbose:$false

    $Excel = $Vips | Select-Object Name, Vdom, NatSourceVip, OriginalDestination, SourceInterface, TranslatedDestination, Comment `
    | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Calculate -FreezeTopRow -AutoSize -PassThru -ClearSheet
    Close-ExcelPackage $Excel
    #####################################################
    #endregion vips

    #region vipusage
    #####################################################
    Write-Verbose "$VerbosePrefix Analyzing Vips usage"
    $WorksheetName = 'VipUsage'

    $VipUsage = @()

    foreach ($vip in $Vips) {
        $PolicyHits = $ResolvedSecurityPolicies | Where-Object { $_.ResolvedDestination -contains "$($vip[0].OriginalDestination)/32" }
        $PolicyHits += $ResolvedSecurityPolicies | Where-Object { $_.ResolvedDestination -contains "$($vip[0].TranslatedDestination)/32" }

        if ($PolicyHits.Count -gt 0) {
            $UniqueSources = $PolicyHits | Select-Object Source -Unique
            foreach ($source in $UniqueSources) {
                $NewVip = Copy-PsObjectWithNewProperty -PsObject $vip -NewProperty Source,Service,PolicyHits
                $NewVip.Source = $source.Source

                $Service = ($PolicyHits | Where-Object { $_.Source -eq $source.Source }).ResolvedService
                $NewVip.Service = $Service
                $NewVip.PolicyHits = ($PolicyHits | Select-Object Index -Unique).Index
                $VipUsage += $NewVip
            }
        } else {
            $NewVip = Copy-PsObjectWithNewProperty -PsObject $vip -NewProperty Source,Service,PolicyHits
            $NewVip.PolicyHits = @()
            $VipUsage += $NewVip
        }
    }

    $Excel = $VipUsage | Select-Object Name, Vdom, NatSourceVip, OriginalDestination, SourceInterface, TranslatedDestination,
    @{Name = "PolicyHits"; Expression = { $_.PolicyHits -join [Environment]::NewLine } },
    @{Name = "Source"; Expression = { $_.Source -join [Environment]::NewLine } },
    @{Name = "Service"; Expression = { $_.Service -join [Environment]::NewLine } },
    Comment | Export-Excel -Path $ExcelPath -WorksheetName $WorksheetName -Calculate -FreezeTopRow -AutoSize -PassThru -ClearSheet
    Close-ExcelPackage $Excel
    #####################################################
    #endregion vipusage
}