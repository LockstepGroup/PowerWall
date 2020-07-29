function Get-PwAsaSecurityPolicy {
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
    $VerbosePrefix = "Get-PwAsaSecurityPolicy:"

    Write-Verbose "$VerbosePrefix Getting rules from $ConfigPath"

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
    $n = 1

    $TotalLines = $LoopArray.Count
    $i = 0
    $StopWatch = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down

    $ReturnObject = @()

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
        $entry = $entry.Trim()

        ###########################################################################################
        # Check for the Section

        $RegexIpOnly = [regex] "(?x)
            ^access-list\s
            (?<aclname>[^\ ]+?)\s

            (
                (?<type>extended)\s
                (?<action>[^\ ]+?)

                # protocol
                \ ((?<prottype>object-group|object)\ )?(?<protocol>[^\ ]+?)

                # source
                (
                    \s((?<srctype>host|object-group|object)\s)(?<source>[^\ ]+)|
                    \s((?<srcnetwork>[^\ ]+)\s(?<srcmask>$IpRx))|
                    \s(?<source>any)
                )

                # destination
                (
                    \s((?<dsttype>host|object-group|object|interface)\s)(?<destination>[^\ ]+)|
                    \s((?<dstnetwork>[^\ ]+)\s(?<dstmask>$IpRx))|
                    \s(?<destination>any)
                )

                # flags
                (?<log>\ log(\ (?<loglevel>\d+|warnings))?)?
                (?<inactive>\ inactive)?
            |
                (?<type>standard)\s
                (?<action>[^\ ]+?)\s
                (
                    ((?<srcnetwork>$IpRx)\ (?<srcmask>$IpRx))|
                    ((?<srctype>host|object-group|object)\ )?(?<source>[^\ ]+)
                )
            )`$
        "

        $RegexDestinationService = [regex] "(?x)
            ^access-list\s
            (?<aclname>[^\ ]+?)\s

            (
                (?<type>extended)\s
                (?<action>[^\ ]+?)

                # protocol
                \ ((?<prottype>object-group|object)\ )?(?<protocol>[^\ ]+?)

                # source
                (
                    \s((?<srctype>host|object-group|object)\s)(?<source>[^\ ]+)|
                    \s((?<srcnetwork>[^\ ]+)\s(?<srcmask>$IpRx))|
                    \s(?<source>any)
                )

                # destination
                (
                    \s((?<dsttype>host|object-group|object|interface)\s)(?<destination>[^\ ]+)|
                    \s((?<dstnetwork>[^\ ]+)\s(?<dstmask>$IpRx))|
                    \s(?<destination>any)
                )

                # service
                (
                    \ (?<svctype>object-group|eq)\ (?<service>[^\ ]+)|
                    \ (?<svctype>range)\ (?<service>\w+\ \w+)|
                    \ (?<service>echo)
                )?

                # flags
                (?<log>\ log(\ (?<loglevel>\d+))?)?
                (?<inactive>\ inactive)?
            |
                (?<type>standard)\s
                (?<action>[^\ ]+?)\s
                (
                    ((?<srcnetwork>$IpRx)\ (?<srcmask>$IpRx))|
                    ((?<srctype>host|object-group|object)\ )?(?<source>[^\ ]+)
                )
            )`$
        "

        $RegexSourceDestinationService = [regex] "(?x)
            ^access-list\s
            (?<aclname>[^\ ]+?)\s

            (
                (?<type>extended)\s
                (?<action>[^\ ]+?)

                # protocol
                \ ((?<prottype>object-group|object)\ )?(?<protocol>[^\ ]+?)

                # source
                (
                    \s((?<srctype>host|object-group|object)\s)(?<source>[^\ ]+)|
                    \s((?<srcnetwork>[^\ ]+)\s(?<srcmask>$IpRx))|
                    \s(?<source>any)
                )

                # sourceservice
                (
                    \s(?<srcsvctype>object-group|eq)\s(?<srcservice>[^\ ]+)|
                    \s(?<srcsvctype>range)\s(?<srcservice>\w+\s\w+)|
                    \s(?<srcservice>echo)
                )?

                # destination
                (
                    \s((?<dsttype>host|object-group|object|interface)\s)(?<destination>[^\ ]+)|
                    \s((?<dstnetwork>[^\ ]+)\s(?<dstmask>$IpRx))|
                    \s(?<destination>any)
                )

                # service
                (
                    \ (?<svctype>object-group|eq)\ (?<service>[^\ ]+)|
                    \ (?<svctype>range)\ (?<service>\w+\ \w+)|
                    \ (?<service>echo)
                )?

                # flags
                (?<log>\ log(\ (?<loglevel>\d+))?)?
                (?<inactive>\ inactive)?
            |
                (?<type>standard)\s
                (?<action>[^\ ]+?)\s
                (
                    ((?<srcnetwork>$IpRx)\ (?<srcmask>$IpRx))|
                    ((?<srctype>host|object-group|object)\ )?(?<source>[^\ ]+)
                )
            )`$
        "

        $RegexRemark = [regex] "(?x)
        access-list\s
        (?<aclname>[^\ ]+?)\s
            remark\s
            (?<remark>.+)
        "

        $MatchRemark = Get-RegexMatch $RegexRemark $entry
        $MatchIpOnly = Get-RegexMatch $RegexIpOnly $entry
        $MatchDestinationService = Get-RegexMatch $RegexDestinationService $entry
        $MatchSourceDestinationService = Get-RegexMatch $RegexSourceDestinationService $entry

        if ($MatchRemark) {
            Write-Verbose "$VerbosePrefix MatchRemark: $i`: $entry"
            $Match = $MatchRemark
        } elseif ($MatchIpOnly) {
            Write-Verbose "$VerbosePrefix RegexIpOnly: $i`: $entry"
            $Match = $MatchIpOnly
        } elseif ($MatchDestinationService) {
            Write-Verbose "$VerbosePrefix RegexDestinationService: $i`: $entry"
            $Match = $MatchDestinationService
        } elseif ($MatchSourceDestinationService) {
            Write-Verbose "$VerbosePrefix RegexSourceDestinationService: $i`: $entry"
            $Match = $MatchSourceDestinationService
        } else {
            $Match = $null
        }


        # access-list outside-in extended permit tcp any object-group DESTINATIONOBJECT eq www


        #$Match = Get-RegexMatch $Regex $entry
        if ($Match) {
            #Write-Verbose "$VerbosePrefix match: $i`: $entry"

            <#             if ($Match.Groups['srcservice'].Success) {
                Write-Verbose "$VerbosePrefix SourceService found"
                if (-not $Match.Groups['dstnetwork'].Success) {
                    Write-Verbose "$VerbosePrefix dstnetwork not found"
                    if (-not $Match.Groups['destination'].success) {
                        Write-Verbose "$VerbosePrefix destination not found, updating match"
                        $Regex = [regex] "(?x)
                            access-list\s
                            (?<aclname>[^\ ]+?)\s
                            (
                                remark\s
                                (?<remark>.+)
                            |
                                (
                                    (?<type>extended)\s
                                    (?<action>[^\ ]+?)

                                    # protocol
                                    \ ((?<prottype>object-group|object)\ )?(?<protocol>[^\ ]+?)

                                    # source
                                    (
                                        \ ((?<srcnetwork>$IpRx)\ (?<srcmask>$IpRx))|
                                        \ ((?<srctype>host|object-group|object)\ )?(?<source>[^\ ]+)
                                    )

                                    # destination
                                    (
                                        \ ((?<dstnetwork>$IpRx)\ (?<dstmask>$IpRx))|
                                        \ ((?<dsttype>host|object-group|object|interface)\ )?(?<destination>[^\ ]+)
                                    )
                                    # service
                                    (
                                        \ (?<svctype>object-group|eq)\ (?<service>[^\ ]+)|
                                        \ (?<svctype>range)\ (?<service>\w+\ \w+)|
                                        \ (?<service>echo)
                                    )?

                                    # flags
                                    (?<log>\ log(\ (?<loglevel>\d+))?)?
                                    (?<inactive>\ inactive)?
                                |
                                    (?<type>standard)\s
                                    (?<action>[^\ ]+?)\s
                                    (
                                        ((?<srcnetwork>$IpRx)\ (?<srcmask>$IpRx))|
                                        ((?<srctype>host|object-group|object)\ )?(?<source>[^\ ]+)
                                    )
                                )
                            )
                        "
                        $Match = Get-RegexMatch $Regex $entry
                    } else {
                        Write-Verbose "$VerbosePrefix dstnetwork found, keeping current match"
                    }
                } else {
                    Write-Verbose "$VerbosePrefix destination found, keeping current match"
                }
            } else {
                Write-Verbose "$VerbosePrefix no SourceService found, keeping current match"
            } #>

            if ($Match.Groups['remark'].Success) {
                $Remark = $Match.Groups['remark'].Value
                #$NewObject.Comment = $Remark
                Write-Verbose "$VerbosePrefix Adding remark: $Remark"
                continue
            } else {
                # create new ace
                $NewObject = [SecurityPolicy]::new("")

                $NewObject.AccessList = $Match.Groups['aclname'].Value
                $NewObject.AclType = $Match.Groups['type'].Value

                # See if we need to increment the sequence number
                $CheckForAcl = $ReturnArray | Where-Object { $_.AccessList -eq $NewObject.AccessList }
                if ($CheckForAcl) {
                    $n++
                } else {
                    $n = 1
                    # had to add this to account for remarks that are leftover at the end of ACLs
                    $Remark = $null
                }

                # add remark
                if ($Remark) {
                    $NewObject.Comment = $Remark
                    $Remark = $null
                }

                $ReturnArray += $NewObject
                $NewObject.Number = $n

                Write-Verbose "$VerbosePrefix Creating new SecurityPolicy: $($NewObject.AccessList):$($NewObject.AclType):$n"
            }

            $NewObject.Action = $Match.Groups['action'].Value
            $NewObject.Protocol = $Match.Groups['protocol'].Value

            # Source
            if ($Match.Groups['srcnetwork'].Success) {
                $Source = $Match.Groups['srcnetwork'].Value
                if ($Match.Groups['srcmask'].Success) {
                    $Source += '/'
                    $Source += ConvertTo-MaskLength $Match.Groups['srcmask'].Value
                }
                $NewObject.Source = $Source
            } else {
                #$NewObject.SourceType = $Match.Groups['srctype'].Value
                $NewObject.Source = $Match.Groups['source'].Value
            }

            # Destination
            if ($Match.Groups['dstnetwork'].Success) {
                $Destination = $Match.Groups['dstnetwork'].Value
                if ($Match.Groups['dstmask'].Success) {
                    $Destination += '/'
                    $Destination += ConvertTo-MaskLength $Match.Groups['dstmask'].Value
                }
                $NewObject.Destination = $Destination
            } else {
                #$NewObject.DestinationType = $Match.Groups['dsttype'].Value
                $NewObject.Destination = $Match.Groups['destination'].Value
            }

            if ($Match.Groups['inactive'].Value) {
                $NewObject.Enabled = $false
            }

            #Service
            $NewObject.Protocol = $Match.Groups['protocol'].Value
            $NewObject.Service = $Match.Groups['service'].Value
            <# if ($ProtocolType -match 'object') {
                $NewObject.Service = $NewObject.Protocol
            } else { #>
            if ($NewObject.Service -match ".+\ .+") {
                $NewObject.Service = $NewObject.Protocol + '/' + ($NewObject.Service -replace ' ', '-')
            } elseif ($NewObject.Service -match '^\d+$') {
                $NewObject.Service = $NewObject.Protocol + '/' + $NewObject.Service
            }
            <# } #>

            #SourceService
            $NewObject.SourceService = $Match.Groups['srcservice'].Value
            if ($NewObject.SourceService -match ".+\ .+") {
                $NewObject.SourceService = $NewObject.Protocol + '/' + ($NewObject.SourceService -replace ' ', '-')
            } elseif ($NewObject.SourceService -match '^\d+$') {
                $NewObject.SourceService = $NewObject.Protocol + '/' + $NewObject.SourceService
            }

            continue
        }
    }
    return $ReturnArray
}