function Resolve-Property {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        $Policy,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateSet("Source", "Destination", "Service")]
        [string]$Property,

        [Parameter(Mandatory = $True, Position = 2)]
        [array]$Objects
    )

    $ReturnArray = @()
    $CopyProps = ($Policy | Get-Member -MemberType property).name

    foreach ($value in $Policy.$Property) {
        if ($Property -eq "Service") {
            $ResolvedObjects = Resolve-PwObject -ObjectToResolve $value -ObjectList $Objects -FirewallType:$FirewallType
        } else {
            $ResolvedObjects = Resolve-PwObject -ObjectToResolve $value -ObjectList $Objects
        }
        foreach ($r in $ResolvedObjects) {
            $NewObject = [ResolvedSecurityPolicy]::new()

            # should convert this to a method on the ResolvedSecurityPolicy class
            foreach ($prop in $CopyProps) {
                $NewObject.$prop = $entry.$prop
            }

            switch ($Property) {
                'Service' {
                    $NewObject.Service = $value
                    if ($r.Protocol) {
                        $NewObject.Protocol = $r.Protocol
                    } else {
                        # pull protocol from original acl entry if there isn't one on the resovled service
                        $NewObject.Protocol = $entry.Protocol
                    }
                    $NewObject.SourcePort = $r.SourcePort
                    if ($r.DestinationPort) {
                        $NewObject.DestinationPort = $r.DestinationPort
                    } else {
                        $NewObject.DestinationPort = $r
                    }
                    $ReturnArray += $NewObject
                }
                { ($_ -eq 'Source') -or `
                    ($_ -eq 'Destination') } {

                    if ($ResolvedObjects.GetType().Name -eq 'SsExpression') {
                        $ResolvedExpression = Resolve-PwObject -ObjectToResolve $r.Value -ObjectList $Objects
                        foreach ($v in $ResolvedExpression) {
                            $NewObject = [ResolvedSecurityPolicy]::new()

                            # should convert this to a method on the ResolvedSecurityPolicy class
                            foreach ($prop in $CopyProps) {
                                $NewObject.$prop = $entry.$prop
                            }

                            switch ($ResolvedObjects.Operator) {
                                'exclusion' {
                                    $NewObject."$Property`Negate" = $true
                                }
                                default {
                                    Throw "VerbosePrefix Expression Operator not handled: $($ResolvedObjects.Operator)"
                                }
                            }

                            $NewObject.$Property = $value
                            $NewObject."Resolved$Property" = $v
                            $ReturnArray += $NewObject
                        }
                    } else {
                        $NewObject.$Property = $value
                        $NewObject."Resolved$Property" = $r
                        $ReturnArray += $NewObject
                    }


                }
                default {
                    Throw "$VerbosePrefix Property not handled: $Property"
                }
            }

        }
    }

    $ReturnArray
}