function Resolve-PwObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [string[]]$ObjectToResolve,

        [Parameter(Mandatory = $True, Position = 1)]
        [array]$ObjectList,

        [Parameter(Mandatory = $False)]
        [String]$FirewallType,

        [Parameter(Mandatory = $False)]
        [String]$Vdom
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwObject:"

    $AsaServices = [HelperBuiltinService]::getAsaServices()

    $ReturnArray = @()

    foreach ($object in $ObjectToResolve) {
        Write-Verbose "$VerbosePrefix Looking up $object"
        $Lookup = $ObjectList | Where-Object { $_.Name -ceq $object }
        if ($Lookup) {
            Write-Verbose "$VerbosePrefix Object $($Lookup.Name) Found with type: $($Lookup.GetType().Name)"
            Write-Verbose "$VerbosePrefix Vdom: $Vdom"
            if ($Vdom) {
                $Lookup = $Lookup | Where-Object { $_.Vdom -eq $Vdom }
            }
            switch ($Lookup.GetType().Name) {
                'ServiceObject' {
                    if ($Lookup.Member) {
                        Write-Verbose "$VerbosePrefix Looking up $($Lookup.Member.Count) members"
                        $Params = @{ }
                        $Params.ObjectToResolve = $Lookup.Member
                        $Params.ObjectList = $ObjectList
                        if ($Vdom) {
                            $Params.Vdom = $Vdom
                        }
                        $ReturnArray += Resolve-PwObject @Params
                        $global:lmember = $Lookup.Member
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
            Write-Verbose "$VerbosePrefix Object not found: $object"
            if ([HelperRegex]::isFqdnOrIpv4($object, $true) -or ($object -eq 'interface')) {
                Write-Verbose "$VerbosePrefix Object is IP or FQDN"
                $ReturnArray += $object
            } elseif (($object -ne 'any') -and ($object -ne 'any4') -and ($object -ne 'all')) {
                Write-Verbose "$VerbosePrefix object is not 'any'"
                $ServiceRx = [regex] '^(?<protocol>\w+(-\w+)?)\/(?<port>\d+(-\d+)?)$'
                $ServiceMatch = $ServiceRx.Match($object)
                if (!($ServiceMatch.Success)) {
                    Write-Verbose "$VerbosePrefix not a service string (ie: tcp/445)"
                    if ($FirewallType) {
                        Write-Verbose "$VerbosePrefix FirewallType Specified: $FirewallType"
                        switch ($FirewallType) {
                            'asa' {
                                Write-Verbose "$VerbosePrefix Checking builtin asa services"
                                $Lookup = $AsaServices | Where-Object { $_.Name -ceq $object }
                                $Global:Glookup = $Lookup
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
                            $null { }
                            'default' {
                                Throw "$VerbosePrefix FirewallType not handled: $FirewallType"
                            }
                        }
                    }
                } elseif ($ServiceMatch.Success) {
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