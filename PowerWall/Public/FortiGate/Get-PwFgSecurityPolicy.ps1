function Get-PwFgSecurityPolicy {
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
    $VerbosePrefix = "Get-PwFgSecurityPolicy:"

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
    $SectionRegex += '^config\ firewall\ policy$'

    $IgnoredRegex = @()
    $IgnoredRegex += '^\s+next$'
    $IgnoredRegex += '^\s+set\ uuid\ .+'
    $IgnoredRegex += '^\s+set\ logtraffic\ .+'
    $IgnoredRegex += '^\s+set\ schedule\ ".+"'
    $IgnoredRegex += '^\s+set\ av-profile\ ".+"'
    $IgnoredRegex += '^\s+set\ ips-sensor\ ".+"'
    $IgnoredRegex += '^\s+set\ ssl-ssh-profile\ ".+"'
    $IgnoredRegex += '^\s+set\ utm-status\ .+'
    $IgnoredRegex += '^\s+set\ fsso\ disable'
    $IgnoredRegex += '^\s+set\ global-label\ ".+"'
    $IgnoredRegex += '^\s+set\ scan-botnet-connections\ block'

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
            $EvalParams.Regex = [regex] '^\ +edit\ (\d+)'
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNumber 1
            if ($Eval) {
                $NewObject = [SecurityPolicy]::new()
                $ReturnArray += $NewObject

                $NewObject.Name = $Eval
                $NewObject.Vdom = $ActiveVdom
                $NewObject.Number = $ReturnArray.Count
                continue
            }

            # set srcintf "port0" "port1"
            # set dstintf "port0" "port0"
            $EvalParams.Regex = [regex] '^\s+set\ (?<direction>src|dst)intf\ (?<member>.+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                foreach ($m in ($Eval.Groups['member'].Value).Split('" "')) {
                    switch ($Eval.Groups['direction'].Value) {
                        'src' {
                            $NewObject.SourceInterface += $m.Trim('"')
                        }
                        'dst' {
                            $NewObject.DestinationInterface += $m.Trim('"')
                        }
                    }
                }
                continue
            }

            # set srcaddr "add1" "add2"
            # set dstaddr "add1" "add2"
            $EvalParams.Regex = [regex] '^\s+set\ (?<direction>src|dst)addr\ (?<member>.+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                foreach ($m in ($Eval.Groups['member'].Value).Split('" "')) {
                    switch ($Eval.Groups['direction'].Value) {
                        'src' {
                            $NewObject.Source += $m.Trim('"')
                        }
                        'dst' {
                            $NewObject.Destination += $m.Trim('"')
                        }
                    }
                }
                continue
            }

            # set service "service1" "service2"
            $EvalParams.Regex = [regex] '^\s+set\ service\ (?<member>.+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                foreach ($m in ($Eval.Groups['member'].Value).Split('" "')) {
                    $NewObject.Service += $m.Trim('"')
                }
                continue
            }

            # set groups "group1" "group2"
            $EvalParams.Regex = [regex] '^\s+set\ groups\ (?<member>.+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                foreach ($m in ($Eval.Groups['member'].Value).Split('" "')) {
                    $NewObject.SourceUser += $m.Trim('"')
                }
                continue
            }

            # set application-list "default"
            $EvalParams.Regex = [regex] '^\s+set\ application-list\ (?<member>.+)'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                foreach ($m in ($Eval.Groups['member'].Value).Split('" "')) {
                    $NewObject.Application += $m.Trim('"')
                }
                continue
            }

            # set status disable
            $EvalParams.Regex = [regex] '^\s+set\ status\ disable'
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Enabled = $false
                continue
            }

            #region simpleprops
            ################################################
            if ($NewObject) {
                $EvalParams.VariableToUpdate = ([REF]$NewObject)
                $EvalParams.ReturnGroupNum = 1
                $EvalParams.LoopName = 'fileloop'
                $EvalParams.Verbose = $false
            }

            # set action accept
            $EvalParams.ObjectProperty = "Action"
            $EvalParams.Regex = [regex] '^\s+set\ action\ (.+)'
            $Eval = Get-RegexMatch @EvalParams

            # set action accept
            $EvalParams.ObjectProperty = "Comment"
            $EvalParams.Regex = [regex] '^\s+set\ comments\ "(.+?)"'
            $Eval = Get-RegexMatch @EvalParams
            ################################################
            #endregion simpleprops

            Write-Warning "VerbosePrefix $i UNHANDLED: $entry"
        }
    }
    return $ReturnArray
}