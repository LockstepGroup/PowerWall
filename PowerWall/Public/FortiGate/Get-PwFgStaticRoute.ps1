function Get-PwFgStaticRoute {
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
    $VerbosePrefix = "Get-PwFgStaticRoute:"

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

        #region getvdom
        ################################################
        $EvalParams.Regex = [regex] '^config vdom$'
        $Eval = Get-RegexMatch @EvalParams
        if ($Eval) {
            Write-Verbose "$VerbosePrefix $i Lookup for vdom"
            $LookingForVdom = $true
            continue fileloop
        }

        if ($LookingForVdom) {
            $EvalParams.Regex = [regex] '^edit\ (.+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                Write-Verbose "$VerbosePrefix $i vdom found: $Eval"
                $LookingForVdom = $false
                $ActiveVdom = $Eval
                continue fileloop
            }
        }
        ################################################
        #region getvdom

        $EvalParams.Regex = [regex] "^config\ router\ static"
        $Eval = Get-RegexMatch @EvalParams
        if ($Eval) {
            Write-Verbose "$VerbosePrefix $i Section Start"
            $InSection = $true
            continue
        }

        if ($InSection) {
            #region ignoredregex
            ################################################
            $EvalParams.Regex = [regex] '^\s?next$'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                continue
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

            # edit 1
            $EvalParams.Regex = [regex] '^\ *edit\ \d+'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject = [Route]::new()
                $ReturnArray += $NewObject
                $NewObject.Vdom = $ActiveVdom
                continue
            }

            # set dst 192.0.2.1 255.255.255.0
            $EvalParams.Regex = [regex] '^\ *set\ dst\ (?<address>[^\ ]+)\ (?<mask>[^\ ]+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Address = $Eval.Groups['address'].Value
                $MaskLength = ConvertTo-MaskLength $Eval.Groups['mask'].Value
                $NewObject.Destination = $Address + '/' + $MaskLength
                continue
            }

            #region simpleprops
            ################################################
            if ($NewObject) {
                $EvalParams.VariableToUpdate = ([REF]$NewObject)
                $EvalParams.ReturnGroupNum = 1
                $EvalParams.LoopName = 'fileloop'
                $EvalParams.Verbose = $false

                # set gateway 192.0.2.1
                $EvalParams.ObjectProperty = "NextHop"
                $EvalParams.Regex = [regex] '^\s*set\ gateway\ (.+)'
                $Eval = Get-RegexMatch @EvalParams

                # set interface "Parent Interface"
                $EvalParams.ObjectProperty = "Interface"
                $EvalParams.Regex = [regex] '^\s*set\ device\ "?(.+)"?'
                $Eval = Get-RegexMatch @EvalParams

                # set description "Description"
                $EvalParams.ObjectProperty = "Comment"
                $EvalParams.Regex = [regex] '^\s*set\ comment\ "?(.+)"?'
                $Eval = Get-RegexMatch @EvalParams

                # set distance 250
                $EvalParams.ObjectProperty = "Metric"
                $EvalParams.Regex = [regex] '^\s*set\ distance\ (\d+)'
                $Eval = Get-RegexMatch @EvalParams

                # set priority 250
                $EvalParams.ObjectProperty = "Priority"
                $EvalParams.Regex = [regex] '^\s*set\ priority\ (\d+)'
                $Eval = Get-RegexMatch @EvalParams
            }
            ################################################
            #endregion simpleprops

            Write-Warning "$VerbosePrefix $i UNHANDLED: $entry"
        }
    }
    return $ReturnArray
}