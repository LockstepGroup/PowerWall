function Resolve-PwSecurityPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [SecurityRule[]]$Policy,

        [Parameter(Mandatory=$True,Position=1)]
        [array]$NetworkObjects,

        [Parameter(Mandatory=$True,Position=2)]
        [array]$ServiceObjects
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwSecurityPolicy:"

    $ReturnArray = @()
    
    foreach ($entry in $Policy) {
        Write-Verbose "$VerbosePrefix Looking up $object"
        $Lookup = $ObjectList | Where-Object { $_.Name -ceq $object }
        if ($Lookup) {
            switch ($Lookup.GetType().Name) {
                'ServiceObject' {
                    if ($Lookup.Members) {
                        $ReturnArray += Resolve-PwObject -ObjectToResolve $Lookup.Members -ObjectList $ObjectList
                    } else {
                        $New = "" | Select SourcePort,DestinationPort

                        if ($Lookup.SourcePort) {
                            $New.SourcePort = $Lookup.Protocol + '/' + $Lookup.SourcePort
                        }

                        if ($Lookup.DestinationPort) {
                            $New.DestinationPort = $Lookup.Protocol + '/' + $Lookup.DestinationPort
                        }

                        $ReturnArray += $New
                    }
                }
                'NetworkObject' {
                    $ReturnArray += Resolve-PwObject -ObjectToResolve $Lookup.Value -ObjectList $ObjectList
                }
                default {
                    Throw "Type not handled: $($Lookup.GetType().Name)"
                }
            }
            
        } else {
            $ReturnArray += $object
        }
    }

    $ReturnArray
}