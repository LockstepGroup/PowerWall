function Get-PwSwNatPolicy {
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
    $VerbosePrefix = "Get-PwSwNatPolicy:"

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

        $Regex = [regex] "^Nat Policy Table$"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $true
            Write-Verbose "$VerbosePrefix Section Starts on line: $i"
            continue
        }

        $Regex = [regex] "^#Network\ :\ NAT\ Policies_START"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $true
            Write-Verbose "$VerbosePrefix Section Starts on line: $i"
            continue
        }

        $Regex = [regex] "^#Network\ :\ NAT\ Policies_END"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $false
            Write-Verbose "$VerbosePrefix Section ends on line: $i"
            break
        }

        if ($KeepGoing) {
            #######################################
            # Special Properties
            $EvalParams = @{ }
            $EvalParams.StringToEval = $entry

            # Start Nat Policy
            $EvalParams.Regex = [regex] "^Index\ +:\ (\d+)"
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNum 1
            if ($Eval) {
                $NewObject = [NatPolicy]::new("")
                $NewObject.Number = $Eval

                $ReturnArray += $NewObject
                Write-Verbose "$i`: Create New Rule"
                continue
            }

            # Enabled
            $EvalParams.Regex = [regex] "^Enabled(\ NAT\ Policy)?\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNum 1
            if ($Eval) {
                if ($Eval -eq 0) {
                    $NewObject.Enabled = $false
                } else {
                    $NewObject.Enabled = $true
                }
                continue
            }

            #######################################
            # Simple Properties
            $EvalParams.ReturnGroupNum = 2

            # OriginalSource
            $EvalParams.Regex = [regex] "^Original\ (Src\ Address\ Object|Source)\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.OriginalSource = $Eval
                continue
            }

            # OriginalDestination
            $EvalParams.Regex = [regex] "^Original\ (Dst\ Address\ Object|Destination)\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.OriginalDestination = $Eval
                continue
            }

            # OriginalService
            $EvalParams.Regex = [regex] "^Original\ Service(\ Object)?\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.OriginalService = $Eval
                continue
            }

            # TranslatedSource
            $EvalParams.Regex = [regex] "^Translated\ (Src\ Address\ Object|Source)\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.TranslatedSource = $Eval
                continue
            }

            # TranslatedDestination
            $EvalParams.Regex = [regex] "^Translated\ (Dst\ Address\ Object|Destination)\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.TranslatedDestination = $Eval
                continue
            }

            # TranslatedService
            $EvalParams.Regex = [regex] "^Translated\ Service(\ Object)?\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.TranslatedService = $Eval
                continue
            }

            # SourceInterface
            $EvalParams.Regex = [regex] "^(Src|Inbound)\ Interface\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.SourceInterface = $Eval
                continue
            }

            # DestinationInterface
            $EvalParams.Regex = [regex] "^(Dst|Outbound)\ Interface\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.DestinationInterface = $Eval
                continue
            }

            # Comment
            $EvalParams.Regex = [regex] "^Comment\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Comment = $Eval
                continue
            }

            # RxBytes
            $EvalParams.Regex = [regex] "^RX\ Bytes\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.RxBytes = $Eval
                continue
            }

            # TxBytes
            $EvalParams.Regex = [regex] "^TX\ Bytes\ +:\ +(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.TxBytes = $Eval
                continue
            }

            # Name
            $EvalParams.Regex = [regex] "^Name\ +:(\ )?(.+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Name = $Eval
                continue
            }

            Write-Verbose "$i $entry"
        }
    }

    return $ReturnArray
}