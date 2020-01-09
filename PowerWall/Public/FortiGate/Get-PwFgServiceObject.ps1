function Get-PwFgServiceObject {
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
    $VerbosePrefix = "Get-PwFgServiceObject:"

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

        # config firewall service custom
        $EvalParams.Regex = [regex] "^config\ firewall\ service\ custom"
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
            $IgnoredRegex += '^\s+next$'
            $IgnoredRegex += '^\s+set\ visibility\ disable$'
            $IgnoredRegex += '^\s+unset\ icmpcode$'
            $IgnoredRegex += '^\s+set\ proxy\ enable$'

            foreach ($regex in $IgnoredRegex) {
                $EvalParams.Regex = [regex] $regex
                $Eval = Get-RegexMatch @EvalParams
                if ($Eval) {
                    continue fileloop
                }
            }
            ################################################
            #endregion ignoredregex

            # config firewall service group
            $EvalParams.Regex = [regex] "^config\ firewall\ service\ group"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$VerbosePrefix $i Second Section Start"
                $InSecondSection = $true
                continue
            }

            # Section Ends
            $EvalParams.Regex = [regex] '^end$'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$VerbosePrefix $i Section End"
                if ($InSecondSection) {
                    break
                }
                continue
            }

            # edit 1
            $EvalParams.Regex = [regex] '^\ +edit\ "(.+?)"'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject = [ServiceObject]::new()
                $ReturnArray += $NewObject

                $NewObject.Name = $Eval
                continue
            }

            # set tcp-portrange 5190-5194
            # set udp-portrange 67-68
            # set udp-portrange 53
            $EvalParams.Regex = [regex] '^\ +set\ (?<protocol>tcp|udp)-portrange\ (?<range>\d+(-\d+)?)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Protocol = $Eval.Groups['protocol'].Value
                $Range = $Eval.Groups['range'].Value
                $NewObject.DestinationPort = $Protocol + '/' + $Range
                continue
            }

            # set protocol-number 47
            $EvalParams.Regex = [regex] '^\s+set\ protocol-number\ (\d+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject.DestinationPort = $NewObject.Protocol.ToLower() + '/' + $Eval
                continue
            }

            # unset icmptype
            $EvalParams.Regex = [regex] '^\s+unset\ icmptype'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                if ($NewObject.Protocol -match '^ICMP6?$') {
                    $NewObject.DestinationPort = 'icmp/all'
                }
                continue
            }

            # set icmptype 8
            $EvalParams.Regex = [regex] '^\s+set\ icmptype\ (\d+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                if ($NewObject.Protocol -match '^ICMP6?$') {
                    $NewObject.DestinationPort = 'icmp/' + $Eval
                }
                continue
            }

            # set member "DNS" "IMAP"
            $EvalParams.Regex = [regex] '^\s+set\ member\ (.+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject.Member = ($Eval -replace '"', '').Split()
                continue
            }

            #region simpleprops
            ################################################
            if ($NewObject) {
                $EvalParams.VariableToUpdate = ([REF]$NewObject)
                $EvalParams.ReturnGroupNum = 1
                $EvalParams.LoopName = 'fileloop'
                $EvalParams.Verbose = $false

                # set protocol IP
                $EvalParams.ObjectProperty = "Protocol"
                $EvalParams.Regex = [regex] '^\s+set\ protocol\ (.+)'
                $Eval = Get-RegexMatch @EvalParams

                # set category "General"
                $EvalParams.ObjectProperty = "Category"
                $EvalParams.Regex = [regex] '^\s+set\ category\ "(.+?)"'
                $Eval = Get-RegexMatch @EvalParams
            }
            ################################################
            #endregion simpleprops

            Write-Warning "VerbosePrefix $i UNHANDLED: $entry"
        }
    }
    return $ReturnArray
}