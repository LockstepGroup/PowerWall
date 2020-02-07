function Get-PwFgInterface {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Gets named addresses from saved ASA config file.
	#>

    Param (
        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'path')]
        [string]$ConfigPath,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'array')]
        [array]$ConfigArray
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwFgInterface:"

    # Check for path and import
    if ($ConfigPath) {
        if (Test-Path $ConfigPath) {
            $LoopArray = Get-Content $ConfigPath
        }
    } else {
        $LoopArray = $ConfigArray
    }

    # Setup return Array
    $ReturnArray = @()

    $IpRx = [regex] "(\d+)\.(\d+)\.(\d+)\.(\d+)"

    $TotalLines = $LoopArray.Count
    $i = 0
    $StopWatch = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down

    :fileloop foreach ($entry in $LoopArray) {
        $i++

        # Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever

        if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
            $PercentComplete = [math]::truncate($i / $TotalLines * 100)
            Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
            $StopWatch.Reset()
            $StopWatch.Start()
        }

        if ($entry -eq "") { continue }

        ###########################################################################################
        # Check for the Section

        $EvalParams = @{ }
        $EvalParams.StringToEval = $entry

        $EvalParams.Regex = [regex] "^config\ system\ interface"
        $Eval = Get-RegexMatch @EvalParams
        if ($Eval) {
            Write-Verbose "$VerbosePrefix $i Section Start"
            $InSection = $true
            continue
        }

        if ($InSection) {
            #region ignoredregex
            ################################################
            $IgnoredRegex = @()
            $IgnoredRegex += '^\s*next$'
            $IgnoredRegex += '^\s*set\ snmp-index\ \d+'
            $IgnoredRegex += '^\s*set\ alias\ "?.+"?$'

            foreach ($regex in $IgnoredRegex) {
                $EvalParams.Regex = [regex] $regex
                $Eval = Get-RegexMatch @EvalParams
                if ($Eval) {
                    continue fileloop
                }
            }
            ################################################
            #endregion ignoredregex


            # Section Ends
            $EvalParams.Regex = [regex] '^end$'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$VerbosePrefix $i Section End"
                $InSection = $false
                break
            }

            # start interface entry
            $EvalParams.Regex = [regex] '^\ *edit\ "?(.+)"?'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject = [Interface]::new()
                $ReturnArray += $NewObject

                $NewObject.Name = $Eval
                continue
            }

            # set mode dhcp
            $EvalParams.Regex = [regex] '^\ *set\ mode\ dhcp'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.IsDhcpClient = $true
                continue
            }

            # set mode pppoe
            $EvalParams.Regex = [regex] '^\ *set\ mode\ pppoe'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.IsPPPoE = $true
                continue
            }

            # set dedicated-to management
            $EvalParams.Regex = [regex] '^\ *set\ dedicated-to\ management'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.IsManagement = $true
                continue
            }

            # set allowaccess ping https http fgfm capwap
            $EvalParams.Regex = [regex] '^\ *set\ allowaccess\ (.+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject.AllowedMgmtMethods = $Eval.Split()
                continue
            }

            # set member "port3" "port4"
            $EvalParams.Regex = [regex] '^\ *set\ member\ (.+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                foreach ($m in $Eval.Split('" "')) {
                    $NewObject.AggregateMember += $m.Trim('"')
                }
                continue
            }

            # set ip 192.0.2.1 255.255.255.0
            $EvalParams.Regex = [regex] '^\ *set\ ip\ (?<address>[^\ ]+)\ (?<mask>[^\ ]+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Address = $Eval.Groups['address'].Value
                $MaskLength = ConvertTo-MaskLength $Eval.Groups['mask'].Value
                $NewObject.IpAddress = $Address + '/' + $MaskLength
                continue
            }

            #region simpleprops
            ################################################
            $EvalParams.VariableToUpdate = ([REF]$NewObject)
            $EvalParams.ReturnGroupNum = 1
            $EvalParams.LoopName = 'fileloop'
            $EvalParams.Verbose = $false

            # set vdom "root"
            $EvalParams.ObjectProperty = "Vdom"
            $EvalParams.Regex = [regex] '^\s*set\ vdom\ "?(.+)"?'
            $Eval = Get-RegexMatch @EvalParams

            # set type physical
            $EvalParams.ObjectProperty = "InterfaceType"
            $EvalParams.Regex = [regex] '^\s*set\ type\ (.+)'
            $Eval = Get-RegexMatch @EvalParams

            # set vlanid 70
            $EvalParams.ObjectProperty = "VlanId"
            $EvalParams.Regex = [regex] '^\s*set\ vlanid\ (\d+)'
            $Eval = Get-RegexMatch @EvalParams

            # set interface "Parent Interface"
            $EvalParams.ObjectProperty = "ParentInterface"
            $EvalParams.Regex = [regex] '^\s*set\ interface\ "?(.+)"?'
            $Eval = Get-RegexMatch @EvalParams

            # set description "Description"
            $EvalParams.ObjectProperty = "Comment"
            $EvalParams.Regex = [regex] '^\s*set\ description\ "(.+)"'
            $Eval = Get-RegexMatch @EvalParams

            ################################################
            #endregion simpleprops

            Write-Warning "VerbosePrefix $i UNHANDLED: $entry"
        }
    }
    return $ReturnArray
}