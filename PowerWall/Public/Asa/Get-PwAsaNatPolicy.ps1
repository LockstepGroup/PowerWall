function Get-PwAsaNatPolicy {
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
    $VerbosePrefix = "Get-PwAsaNatPolicy:"

    # Check for path and import
    if ($ConfigPath) {
        if (Test-Path $ConfigPath) {
            $LoopArray = Get-Content $ConfigPath
        }
    } else {
        $LoopArray = $ConfigArray
    }

    # Get Network Objects to resolve network nat
    $Objects = Get-PwAsaObject -ConfigPath $ConfigPath -Verbose:$false
    $NetworkObjects = $Objects | Where-Object { $_.GetType().Name -eq 'NetworkObject' }
    $NetworkObjectsWithNat = $NetworkObjects | Where-Object { $_.NatSourceInterface }
    $NetworkObjectsWithNatNeeded = $true

    # Get interfaces to resolve pat statements
    $Interfaces = Get-PwAsaInterface -ConfigPath $ConfigPath -Verbose:$false

    Write-Verbose "$VerbosePrefix NetworkObjectsWithNat: $($NetworkObjectsWithNat.Count)"

    # Setup return Array
    $ReturnArray = @()

    $IpRx = [regex] "(\d+)\.(\d+)\.(\d+)\.(\d+)"
    $JustIpRx = [regex] '^(\d+)\.(\d+)\.(\d+)\.(\d+)$'

    $TotalLines = $LoopArray.Count
    $i = 0
    $n = 0
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

        #More prompts and blank lines
        $Regex = [regex] '^<'
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            continue
        }
        $Regex = [regex] '^\s+$'
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            continue
        }

        # Inject Network Nat
        $Regex = [regex] '^!$'
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            Write-Verbose "$VerbosePrefix matched !"
            if ($ReturnArray.Count -gt 0) {
                Write-Verbose "$VerbosePrefix ReturnArray -gt 0"
                if ($NetworkObjectsWithNat.Count -gt 0) {
                    Write-Verbose "$VerbosePrefix NetworkObjectsWithNat -gt 0"
                    if ($NetworkObjectsWithNatNeeded) {
                        Write-Verbose "$VerbosePrefix NetworkObjectsWithNatNeeded -eq $true"
                        foreach ($object in $NetworkObjectsWithNat) {
                            $n++
                            Write-Verbose "$VerbosePrefix adding object NAT"
                            $NewObject = [NatPolicy]::new("Asa")
                            $ReturnArray += $NewObject
                            Write-Verbose "$VerbosePrefix $entry"

                            $NewObject.Number = $n
                            $NewObject.Name = $object.Name
                            $NewObject.SourceInterface = $object.NatSourceInterface
                            $NewObject.DestinationInterface = $object.NatDestinationInterface
                            $NewObject.OriginalSource = $object.Member
                            if ($JustIpRx.Match($object.NatSourceAddress).Success) {
                                $NewObject.TranslatedSource = $object.NatSourceAddress + '/32'
                            } else {
                                $NewObject.TranslatedSource = $object.NatSourceAddress
                            }
                            $NewObject.SourceTranslationType = 'ObjectNat'
                            $NetworkObjectsWithNatNeeded = $false
                        }
                    }
                }
            }
        }

        # End object
        $Regex = [regex] "^[^\ ]"
        $Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            $KeepGoing = $false
            $Protocol = $null
        }

        $EvalParams = @{ }
        $EvalParams.StringToEval = $entry

        # Single Line Nat
        #nat (inside,outside) after-auto source dynamic any pat-pool Outside_Pool inactive

        $EvalParams.Regex = [regex] "(?x)
                                     ^nat\ \((?<srcint>.+?),(?<dstint>.+?)\)
                                     (\ after-auto)?
                                     \ source\ (?<srctrantype>.+?)\ (?<src>.+?)(\ pat-pool)?\ (?<transrc>[^\ ]+)
                                     (\ destination\ (?<dsttrantype>.+?)\ (?<dst>.+?)\ (?<trandst>[^\ ]+))?
                                     (?<noproxyarp>\ no-proxy-arp)?
                                     (?<routelookup>\ route-lookup)?
                                     (?<inactive>\ inactive)?"

        $Eval = Get-RegexMatch @EvalParams
        if ($Eval) {
            $n++
            $NewObject = [NatPolicy]::new("Asa")
            $ReturnArray += $NewObject
            Write-Verbose "$VerbosePrefix $entry"

            $NewObject.Number = $n
            $NewObject.SourceInterface = $Eval.Groups['srcint'].Value
            $NewObject.DestinationInterface = $Eval.Groups['dstint'].Value
            $NewObject.OriginalSource = $Eval.Groups['src'].Value
            $NewObject.OriginalDestination = $Eval.Groups['dst'].Value
            $NewObject.TranslatedSource = $Eval.Groups['transrc'].Value
            $NewObject.TranslatedDestination = $Eval.Groups['trandst'].Value
            $NewObject.SourceTranslationType = $Eval.Groups['srctrantype'].Value
            $NewObject.DestinationTranslationType = $Eval.Groups['dsttrantype'].Value

            if ($Eval.Groups['noproxyarp'].Value) {
                $NewObject.ProxyArp = $false
            }

            if ($Eval.Groups['routelookup'].Value) {
                $NewObject.RouteLookup = $true
            }

            if ($Eval.Groups['inactive'].Value) {
                $NewObject.Enabled = $false
            }
        }

        # static pat pre-8.3
        # static (inside,outside) tcp interface 3303 192.0.2.1 ssh netmask 255.255.255.255
        $EvalParams.Regex = [regex] "(?x)
                                     ^static\ \((?<srcint>.+?),(?<dstint>.+?)\)
                                     \ (?<protocol>tcp|udp)
                                     \ (?<transrc>.+?)
                                     \ (?<tranport>.+?)
                                     \ (?<src>.+?)
                                     \ (?<port>.+?)
                                     \ netmask
                                     \ (?<mask>[^\ ]+)
                                     (?<inactive>\ inactive)?"

        $Eval = Get-RegexMatch @EvalParams
        if ($Eval) {
            $n++
            $NewObject = [NatPolicy]::new("Asa")
            $ReturnArray += $NewObject
            Write-Verbose "$VerbosePrefix static nat: $entry"

            $NewObject.Number = $n
            $NewObject.SourceInterface = $Eval.Groups['srcint'].Value
            $NewObject.DestinationInterface = $Eval.Groups['dstint'].Value
            $NewObject.OriginalSource = $Eval.Groups['src'].Value + '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
            if ($Eval.Groups['transrc'].Value -eq 'interface') {
                $InterfaceLookup = $Interfaces | Where-Object { $_.Nameif -eq $NewObject.DestinationInterface }
                $InterfaceLookup = $InterfaceLookup.Ipaddress -replace '\/\d+', "/$(ConvertTo-MaskLength $Eval.Groups['mask'].Value)"
                $NewObject.TranslatedSource = $InterfaceLookup
            } else {
                if ($IpRx.Match($Eval.Groups['transrc'].Value).Success) {
                    $NewObject.TranslatedSource = $Eval.Groups['transrc'].Value + '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
                } else {
                    $NewObject.TranslatedSource = $Eval.Groups['transrc'].Value
                }
            }

            $Port = $Eval.Groups['port'].Value
            if ($Port -match '[a-z]') {
                $NewObject.OriginalService = $Port
            } else {
                $NewObject.OriginalService = $Eval.Groups['protocol'].Value + '/' + $Port
            }

            $TranslatedPort = $Eval.Groups['tranport'].Value
            if ($TranslatedPort -match '[a-z]') {
                $NewObject.TranslatedService = $TranslatedPort
            } else {
                $NewObject.TranslatedService = $Eval.Groups['protocol'].Value + '/' + $TranslatedPort
            }
            continue fileloop
        }

        # static single line nat from pre-8.3
        # static (dmz,outside) 198.51.100.1 192.0.2.1 netmask 255.255.255.255

        $EvalParams.Regex = [regex] "(?x)
                                     ^static\ \((?<srcint>.+?),(?<dstint>.+?)\)
                                     \ (?<src>.+?)
                                     \ (?<transrc>.+?)
                                     \ netmask
                                     \ (?<mask>[^\ ]+)
                                     (?<inactive>\ inactive)?"

        $Eval = Get-RegexMatch @EvalParams
        if ($Eval) {
            $n++
            $NewObject = [NatPolicy]::new("Asa")
            $ReturnArray += $NewObject
            Write-Verbose "$VerbosePrefix $entry"

            $NewObject.Number = $n
            $NewObject.SourceInterface = $Eval.Groups['srcint'].Value
            $NewObject.DestinationInterface = $Eval.Groups['dstint'].Value
            $NewObject.OriginalSource = $Eval.Groups['src'].Value + '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)

            if ($IpRx.Match($Eval.Groups['transrc'].Value).Success) {
                $NewObject.TranslatedSource = $Eval.Groups['transrc'].Value + '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
            } else {
                $NewObject.TranslatedSource = $Eval.Groups['transrc'].Value
            }
        }
    }

    foreach ($nat in $ReturnArray) {
        # Nat Exempt Check
        if ($nat.OriginalSource -eq $nat.TranslatedSource) {
            if ($nat.OriginalDestination -eq $nat.TranslatedDestination) {
                if ($nat.OriginalService -eq $nat.TranslatedService) {
                    $global:NewObject = $nat
                    $nat.NatExempt = $true
                }
            }
        }
    }

    return $ReturnArray
}