function Resolve-PwObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string[]]$ObjectToResolve,

        [Parameter(Mandatory = $True, Position = 1)]
        [array]$ObjectList,

        [Parameter(Mandatory = $False)]
        [String]$FirewallType
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwObject:"

    $ReturnArray = @()

    foreach ($object in $ObjectToResolve) {
        Write-Verbose "$VerbosePrefix Looking up $object"
        $Lookup = $ObjectList | Where-Object { $_.Name -ceq $object }
        if ($Lookup) {
            Write-Verbose "$VerbosePrefix Object Found with type: $($Lookup.GetType().Name)"
            switch ($Lookup.GetType().Name) {
                'ServiceObject' {
                    if ($Lookup.Member) {
                        Write-Verbose "$VerbosePrefix Looking up $($Lookup.Member.Count) members"
                        $ReturnArray += Resolve-PwObject -ObjectToResolve $Lookup.Member -ObjectList $ObjectList
                    } else {
                        $New = "" | Select-Object Protocol, SourcePort, DestinationPort

                        if ($Lookup.SourcePort) {
                            $New.SourcePort = $Lookup.SourcePort
                        }

                        if ($Lookup.DestinationPort) {
                            $New.DestinationPort = $Lookup.DestinationPort
                        }

                        if ($Lookup.Protocol) {
                            $New.Protocol = ($Lookup.Protocol).ToLower()
                        }

                        $ReturnArray += $New
                    }
                }
                'NetworkObject' {
                    Write-Verbose "$VerbosePrefix Object is NetworkObject with $($Lookup.Member.Count) members"
                    foreach ($value in $Lookup.Member) {
                        if ($value -ceq $object) {
                            $ReturnArray += $value
                        } else {
                            $ReturnArray += Resolve-PwObject -ObjectToResolve $value -ObjectList $ObjectList
                        }
                    }

                }
                'SsExpression' {
                    $ReturnArray += $Lookup
                }
                default {
                    Throw "Type not handled: $($Lookup.GetType().Name)"
                }
            }

        } else {
            Write-Verbose "$VerbosePrefix Object not found"
            if ([HelperRegex]::isFqdnOrIpv4($object, $true)) {
                $ReturnArray += $object
            } elseif ($object -ne 'any') {
                $ServiceRx = [regex] '^(?<protocol>\w+(-\w+)?)\/(?<port>\d+(-\d+)?)$'
                $ServiceMatch = $ServiceRx.Match($object)
                if (!($ServiceMatch.Success)) {
                    if ($FirewallType) {
                        Write-Verbose "$VerbosePrefix FirewallType Specified: $FirewallType"
                        switch ($FirewallType) {
                            'asa' {
                                $object = Resolve-BuiltinService -Service $object -FirewallType $FirewallType
                                Write-Verbose "$VerbosePrefix Resolved BuiltinService: $object"
                                #$object = "builtin/" + $object
                            }
                            $null {}
                            'default' {
                                Throw "$VerbosePrefix FirewallType not handled: $FirewallType"
                            }
                        }
                    }
                }
                $ServiceMatch = $ServiceRx.Match($object)
                if ($ServiceMatch.Success) {
                    $New = "" | Select-Object Protocol, SourcePort, DestinationPort
                    $New.Protocol = $ServiceMatch.Groups['protocol'].Value
                    $New.DestinationPort = $ServiceMatch.Groups['port'].Value
                    $ReturnArray += $New
                } else {
                    $ReturnArray += $object
                }
            } else {
                $ReturnArray += $object
            }
        }
    }

    $ReturnArray
}