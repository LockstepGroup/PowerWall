function Get-PwSwAddressObject {
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
    $VerbosePrefix = "Get-PwSwAddressObject:"

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

        $Regex = [regex] "^(Address\ Object\ Table:|#Network\ :\ Address\ Objects_START)"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $true
            Write-Verbose "$VerbosePrefix Section Starts on line: $i"
            continue
        }

        $Regex = [regex] "^(End\ Address\ Object\ Table|#Network\ :\ Address\ Objects_END)"
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

            # Skip Node Callback Lines
            $EvalParams.Regex = [regex] "^Node\ Callback:"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                Write-Verbose "$i`: Skipping Node Callback"
                continue
            }

            # MemberOf
            $EvalParams.Regex = [regex] "^\s*Group\ \(Member\ of\):\s+([^\,]+)"
            $Eval = Get-RegexMatch @EvalParams -ReturnGroupNum 1
            if ($Eval) {
                $NewObject.MemberOf += $Eval
                Write-Verbose "$i`: MemberOf: $Eval"
                continue
            }

            # Member
            $EvalParams.Regex = [regex] "^\ +member:(\ Ptr:0x0x[a-f0-9]+)?\ Name:(?<name>.+?)\ Handle:\d+"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $NewObject.Member += $Eval.Groups['name'].Value
                Write-Verbose "$i`: Member: $Eval"
                continue
            }

            # New Object
            $EvalParams.Regex = [regex] "(?x)
                ^(---+)?
                (?<name>.+?)
                (\((?<comment>.+?)\))?
                (---+|:)
                .+?
                (
                    GROUP|
                    HOST:\ (?<address>$IpRx)|
                    NETWORK:\ (?<address>$IpRx)\ -\ (?<mask>$IpRx)|
                    RANGE:\ (?<address>$IpRx)\ -\ (?<endaddress>$IpRx)
                )"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Lookup = $ReturnArray | Where-Object { $_.Name -ceq $Eval.Groups['name'].Value }
                if ($Lookup) {
                    Write-Verbose "dupe object $($Eval.Groups['name'].Value)"
                    continue
                }
                $NewObject = [NetworkObject]::new()
                $NewObject.Name = $Eval.Groups['name'].Value
                $NewObject.Comment = $Eval.Groups['comment'].Value
                $ReturnArray += $NewObject
                Write-Verbose "$i`: NewObject: $($NewObject.Name) ($($NewObject.Comment))"

                if ($Eval.Groups['address'].Success) {
                    $Member = $Eval.Groups['address'].Value
                    if ($Eval.Groups['mask'].Success) {
                        $Member += '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
                    }
                    if ($Eval.Groups['endaddress'].Success) {
                        $Member += '-' + $Eval.Groups['endaddress'].Value
                    }
                    $NewObject.Member += $Member
                }

                continue
            }

            # New New Object
            $EvalParams.Regex = [regex] "(?x)
                ^(---+)?
                (?<name>.+?)
                (\((?<comment>.+?)\))?
                (---+)"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                $Lookup = $ReturnArray | Where-Object { $_.Name -ceq $Eval.Groups['name'].Value }
                if ($Lookup) {
                    Write-Verbose "dupe object $($Eval.Groups['name'].Value)"
                    continue
                }
                $NewObject = New-PwNetworkObject -Name $Eval.Groups['name'].Value
                $NewObject.Comment = $Eval.Groups['comment'].Value
                $ReturnArray += $NewObject
                Write-Verbose "$i`: NewObject: $($NewObject.Name) ($($NewObject.Comment))"
                <#
                if ($Eval.Groups['address'].Success) {
                    $Member = $Eval.Groups['address'].Value
                    if ($Eval.Groups['mask'].Success) {
                        $Member += '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
                    }
                    if ($Eval.Groups['endaddress'].Success) {
                        $Member += '-' + $Eval.Groups['endaddress'].Value
                    }
                    $NewObject.Member += $Member
                }


 #>
                continue
            }

            # NETWORK|HOST|GROUP|RANGE
            $EvalParams.Regex = [regex] "(?x)
            (
                GROUP|
                HOST:\ (?<address>$IpRx)|
                NETWORK:\ (?<address>$IpRx)\ -\ (?<mask>$IpRx)|
                RANGE:\ (?<address>$IpRx)\ -\ (?<endaddress>$IpRx)
            )"
            $Eval = Get-RegexMatch @EvalParams
            if ($Eval) {
                if ($Eval.Groups['address'].Success) {
                    $Member = $Eval.Groups['address'].Value
                    if ($Eval.Groups['mask'].Success) {
                        $Member += '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
                    }
                    if ($Eval.Groups['endaddress'].Success) {
                        $Member += '-' + $Eval.Groups['endaddress'].Value
                    }
                    $NewObject.Member += $Member
                }
                continue
            }

            #Write-Verbose "$i $entry"
        }
    }

    $global:testarray = $ReturnArray
    foreach ($object in $ReturnArray) {

        $global:testobject = $object
        if ($object.MemberOf) {
            foreach ($m in $object.MemberOf) {
                $Lookup = $ReturnArray | Where-Object { $_.Name -ceq $m }
                if ($Lookup) {
                    $MemberLookup = $Lookup.Member | Where-Object { $_ -eq $object.Name }
                    if (!($MemberLookup)) {
                        $Lookup.Member += $object.Name
                    }
                } else {
                    Throw "Group not found $m"
                }
            }
        }
    }

    return $ReturnArray
}