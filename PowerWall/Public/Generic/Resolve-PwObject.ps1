function Resolve-PwObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [string[]]$ObjectToResolve,

        [Parameter(Mandatory=$True,Position=1)]
        [array]$ObjectList
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwObject:"

    $ReturnArray = @()
    
    foreach ($object in $ObjectToResolve) {
        Write-Verbose "$VerbosePrefix Looking up $object"
        $Lookup = $ObjectList | Where-Object { $_.Name -ceq $object }
        if ($Lookup) {
            Write-Verbose "$VerbosePrefix Object Found"
            switch ($Lookup.GetType().Name) {
                'ServiceObject' {
                    if ($Lookup.Member) {
                        $ReturnArray += Resolve-PwObject -ObjectToResolve $Lookup.Member -ObjectList $ObjectList
                    } else {
                        $New = "" | Select-Object Protocol,SourcePort,DestinationPort

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
            $ReturnArray += $object
        }
    }

    $ReturnArray
}