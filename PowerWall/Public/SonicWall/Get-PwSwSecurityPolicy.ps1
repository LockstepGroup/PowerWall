function Get-PwSwSecurityPolicy {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Gets named addresses from saved ASA config file.
	#>

    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [array]$ConfigPath
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwSwSecurityPolicy:"

    # Check for path and import
    if (Test-Path $ConfigPath) {
        $LoopArray = Get-Content $ConfigPath
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

        $Regex = [regex] "^Rules$"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $true
            Write-Verbose "$VerbosePrefix Section Starts on line: $i"
            continue
        }

        $Regex = [regex] "^#Firewall\s:\sAccess\sRules_START"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $true
            Write-Verbose "$VerbosePrefix Section Starts on line: $i"
            continue
        }

        $Regex = [regex] "^#Firewall\s:\sAccess\sRules_END"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $false
            Write-Verbose "$VerbosePrefix Section Ends on line: $i"
            break
        }

        $Regex = [regex] "^#Firewall\s:\sSecurity\sPolicy\sTable_END"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $false
            Write-Verbose "$VerbosePrefix Section Ends on line: $i"
            break
        }

        if ($KeepGoing) {
            #######################################
            # Special Properties
            $EvalParams = @{ }
            $EvalParams.StringToEval = $entry

            # Zones
            $EvalParams.Regex = [regex] "^From\ (?<sourcezone>.+?)\ To\ (?<destzone>.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $SourceZone = $Eval.Groups['sourcezone'].Value
                $DestinationZone = $Eval.Groups['destzone'].Value
                Write-Verbose "$i`: $SourceZone -> $DestinationZone"
                $Number = 1
                continue
            }

            # MemberOf
            $EvalParams.Regex = [regex] "^Rule\ (?<number>\d+)\ \((?<status>.+?)\)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject = [SecurityPolicy]::new("")
                $NewObject.SourceInterface = $SourceZone
                $NewObject.DestinationInterface = $DestinationZone
                $NewObject.Number = $Number

                if ($Eval.Groups['status'].Value -eq 'Enabled') {
                    $NewObject.Enabled = $true
                } else {
                    $NewObject.Enabled = $false
                }

                $ReturnArray += $NewObject

                $Number++

                Write-Verbose "$i`: Create New Rule"
                continue
            }

            # Action and Service
            $EvalParams.Regex = [regex] "^action:\ +(?<action>.+?),\ service:\ (?<service>.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Action = $Eval.Groups['action'].Value
                $NewObject.Service = $Eval.Groups['service'].Value
                continue
            }

            # Rule line 1
            # example: Rule 3 @ 0xd7421468 Deny Service Any -> Any (Enabled)
            $EvalParams.Regex = [regex] "^Rule\ (?<number>\d+)\ @\ 0x[0-9a-f]+\ (?<action>.+?)\ Service (?<sourceservice>.+?)\ ->\ (?<destservice>.+?)\ \((?<status>.+?)\)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject = [SecurityPolicy]::new("")
                $NewObject.SourceInterface = $SourceZone
                $NewObject.DestinationInterface = $DestinationZone
                $NewObject.Number = $Eval.Groups['number'].Value
                $NewObject.SourcePort = $Eval.Groups['sourceservice'].Value
                $NewObject.DestinationPort = $Eval.Groups['destservice'].Value
                $NewObject.Action = $Eval.Groups['action'].Value

                if ($Eval.Groups['status'].Value -eq 'Enabled') {
                    $NewObject.Enabled = $true
                } else {
                    $NewObject.Enabled = $false
                }

                $ReturnArray += $NewObject

                $Number++

                Write-Verbose "$i`: Create New Rule"
                continue
            }

            # Rule line 2
            # example:        IP: Any -> All X0 Management IP  Iface: Any (ffffffff) -> Any (ffffffff)
            $EvalParams.Regex = [regex] "^\s+IP:\ (?<source>.+?)\ ->\ (?<destination>.+)(\ {2}Iface)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Source = $Eval.Groups['source'].Value
                $NewObject.Destination = $Eval.Groups['destination'].Value

                Write-Verbose "$i`: adding source: $($NewObject.Source) to destination: $($NewObject.Destination)"
                continue
            }

            # Rule line 1
            # example: Rule 1 LAN -> LAN Allow Service Any -> SNMP (Enabled)
            $EvalParams.Regex = [regex] "^Rule\ (?<number>\d+)\ (?<sourcezone>.+?)\ ->\ (?<destzone>.+?)\ (?<action>.+?)\ Service (?<sourceservice>.+?)\ ->\ (?<destservice>.+?)\ \((?<status>.+?)\)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject = [SecurityPolicy]::new("")
                $NewObject.SourceInterface = $Eval.Groups['sourcezone'].Value
                $NewObject.DestinationInterface = $Eval.Groups['destzone'].Value
                $NewObject.Number = $Eval.Groups['number'].Value
                $NewObject.SourcePort = $Eval.Groups['sourceservice'].Value
                $NewObject.DestinationPort = $Eval.Groups['destservice'].Value
                $NewObject.Action = $Eval.Groups['action'].Value

                if ($Eval.Groups['status'].Value -eq 'Enabled') {
                    $NewObject.Enabled = $true
                } else {
                    $NewObject.Enabled = $false
                }

                $ReturnArray += $NewObject

                $Number++

                Write-Verbose "$i`: Create New Rule"
                continue
            }

            #######################################
            # Special Properties
            $EvalParams.ReturnGroupNum = 1

            # Source
            $EvalParams.Regex = [regex] "^source:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Source = $Eval
                continue
            }

            # Destination
            $EvalParams.Regex = [regex] "^destination:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Destination = $Eval
                continue
            }

            # Comment
            $EvalParams.Regex = [regex] "^[Cc]omment:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Comment = $Eval
                continue
            }

            # RxBytes
            $EvalParams.Regex = [regex] "^Rx\ bytes:\ +(\d+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.RxBytes = $Eval
                continue
            }

            # TxBytes
            $EvalParams.Regex = [regex] "^Tx\ bytes:\ +(\d+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.TxBytes = $Eval
                continue
            }

            # Name
            $EvalParams.Regex = [regex] "^Policy\ Name:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Name = $Eval
                continue
            }

            #Write-Verbose "$i $entry"
        }
    }

    return $ReturnArray
}