function Get-PwAsaSecurityPolicy {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Gets named addresses from saved ASA config file.
	#>

    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string]$ConfigPath
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Get-PwAsaSecurityPolicy:"

    Write-Verbose "$VerbosePrefix Getting rules from $ConfigPath"

    # Check for path and import
    if (Test-Path $ConfigPath) {
        $LoopArray = Get-Content $ConfigPath
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

        ###########################################################################################
        # Check for the Section


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
                    (?<log>\ log\ (?<loglevel>\w+))?
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
        if ($Match) {
            Write-Verbose "$VerbosePrefix Match Found"
            if ($Match.Groups['remark'].Success) {
                $Remark = $Match.Groups['remark'].Value
                #$NewObject.Comment = $Remark
                Write-Verbose "$VerbosePrefix Adding remark: $Remark"
                continue
            } else {
                $NewObject = [SecurityPolicy]::new("")
                if ($Remark) {
                    $NewObject.Comment = $Remark
                    $Remark = $null
                }

                $NewObject.AccessList = $Match.Groups['aclname'].Value
                $NewObject.AclType = $Match.Groups['type'].Value

                # See if we need to increment the sequence number
                $CheckForAcl = $ReturnArray | Where-Object { $_.AccessList -eq $NewObject.AccessList }
                if ($CheckForAcl) {
                    $n++
                } else {
                    $n = 1
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
            $ProtocolType = $Match.Groups['prottype'].Value
            $NewObject.Service = $Match.Groups['service'].Value
            if ($ProtocolType -match 'object') {
                $NewObject.Service = $NewObject.Protocol
            } else {
                if ($NewObject.Service -match "\d+\ \d+") {
                    $NewObject.Service = $NewObject.Protocol + '/' + ($NewObject.Service -replace ' ', '-')
                }
            }

            continue
        }
    }
    return $ReturnArray
}