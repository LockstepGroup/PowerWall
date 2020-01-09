function Get-PwFgNetworkObject {
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
    $VerbosePrefix = "Get-PwFgNetworkObject:"

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
    $SectionRegex += '^config\ firewall\ address$'
    $SectionRegex += '^config\ firewall\ addrgrp$'

    $IgnoredRegex = @()
    $IgnoredRegex += '^\s+next$'
    $IgnoredRegex += '^\s+set\ visibility\ disable$'
    $IgnoredRegex += '^\s+set\ uuid\ .+'
    $IgnoredRegex += '^\s+set\ color\ \d+'
    $IgnoredRegex += '^\s+set\ type\ iprange'
    $IgnoredRegex += '^\s+set\ associated-interface\ ".+"'

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
                $NewObject = [NetworkObject]::new()
                $ReturnArray += $NewObject

                $NewObject.Name = $Eval
                $NewObject.Vdom = $ActiveVdom
                continue
            }

            # set ip 192.0.2.1 255.255.255.0
            $EvalParams.Regex = [regex] '^\ +set\ subnet\ (?<address>[^\ ]+)\ (?<mask>[^\ ]+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Address = $Eval.Groups['address'].Value
                $MaskLength = ConvertTo-MaskLength $Eval.Groups['mask'].Value
                $NewObject.Member += $Address + '/' + $MaskLength
                continue
            }

            # set member "DNS" "IMAP"
            $EvalParams.Regex = [regex] '^\s+set\ member\ (.+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject.Member = ($Eval -replace '"', '').Split()
                continue
            }

            # set start-ip 192.0.2.1
            $EvalParams.Regex = [regex] '^\s+set\ start-ip\ (.+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $StartIp = $Eval
                continue
            }

            if ($StartIp) {
                # set end-ip 192.0.2.255
                $EvalParams.Regex = [regex] '^\s+set\ end-ip\ (.+)'
                $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
                if ($Eval) {
                    $NewObject.Member += $StartIp + '-' + $Eval
                    $StartIp = $null
                    continue
                }
            }

            #region simpleprops
            ################################################
            if ($NewObject) {
                $EvalParams.VariableToUpdate = ([REF]$NewObject)
                $EvalParams.ReturnGroupNum = 1
                $EvalParams.LoopName = 'fileloop'
                $EvalParams.Verbose = $false

            }
            ################################################
            #endregion simpleprops

            Write-Warning "VerbosePrefix $i UNHANDLED: $entry"
        }
    }
    return $ReturnArray
}