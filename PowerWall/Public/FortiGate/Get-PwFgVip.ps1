function Get-PwFgVip {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Get VIPs from Fortigate config file
	#>

    Param (
        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'path')]
        [string]$ConfigPath,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'array')]
        [array]$ConfigArray
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwFgVip:"

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
    $SectionRegex = @()
    $SectionRegex += '^config\ firewall\ vip$'

    $IgnoredRegex = @()
    $IgnoredRegex += '^\s+next$'

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

        #region sectionstart
        ################################################
        foreach ($regex in $SectionRegex) {
            $EvalParams.Regex = [regex] $regex
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$VerbosePrefix $i Section Start"
                $InSection = $true
                continue fileloop
            }
        }
        ################################################
        #region sectionstart

        if ($InSection) {
            #region ignoredregex
            ################################################
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
                continue
            }

            # edit 1
            $EvalParams.Regex = [regex] '^\ +edit\ "(.+?)"'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                Write-Verbose "$VerbosePrefix new object: $Eval"
                $NewObject = [NatPolicy]::new()
                $ReturnArray += $NewObject

                $NewObject.Name = $Eval
                $NewObject.Vdom = $ActiveVdom
                continue
            }

          <#   [string]$SourceInterface
            [string]$DestinationInterface

            [string]$OriginalSource
            [string]$OriginalDestination
            [string]$OriginalService

            [string]$TranslatedSource
            [string]$TranslatedDestination
            [string]$TranslatedService
 #>

            #region simpleprops
            ################################################
            if ($NewObject) {
                $EvalParams.VariableToUpdate = ([REF]$NewObject)
                $EvalParams.ReturnGroupNum = 1
                $EvalParams.LoopName = 'fileloop'
                $EvalParams.Verbose = $false

                # set extip 192.0.2.1
                $EvalParams.ObjectProperty = "OriginalDestination"
                $EvalParams.Regex = [regex] '^\s*set\ extip\ (.+)'
                $Eval = Get-RegexMatch @EvalParams

                # set extintf "interface"
                $EvalParams.ObjectProperty = "SourceInterface"
                $EvalParams.Regex = [regex] '^\s*set\ extintf\ "(.+?)"'
                $Eval = Get-RegexMatch @EvalParams

                # set mappedip "192.0.2.1"
                $EvalParams.ObjectProperty = "TranslatedDestination"
                $EvalParams.Regex = [regex] '^\s*set\ mappedip\ "(.+?)"'
                $Eval = Get-RegexMatch @EvalParams
            }
            ################################################
            #endregion simpleprops

            Write-Warning "$VerbosePrefix $i UNHANDLED: $entry"
        }
    }
    return $ReturnArray
}