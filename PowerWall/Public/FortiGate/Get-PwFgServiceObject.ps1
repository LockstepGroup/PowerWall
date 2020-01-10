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
    $SectionRegex = @()
    $SectionRegex += '^config\ firewall\ service\ custom'
    $SectionRegex += '^config\ firewall\ service\ group'

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
        # Setup
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
                $NewObject = [ServiceObject]::new()
                $ReturnArray += $NewObject

                $NewObject.Name = $Eval
                $NewObject.Vdom = $ActiveVdom
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
                $NewObject.DestinationPort = $Range
                $NewObject.Protocol = $Protocol
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
                foreach ($m in $Eval.Split('" "')) {
                    $NewObject.Member += $m.Trim('"')
                }
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