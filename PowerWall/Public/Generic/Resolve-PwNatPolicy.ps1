function Resolve-PwNatPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, Position = 0)]
        [NatPolicy]$Policy,

        [Parameter(Mandatory = $True, Position = 1)]
        [NetworkObject[]]$NetworkObjects,

        [Parameter(Mandatory = $false, Position = 2)]
        [ServiceObject[]]$ServiceObjects,

        [Parameter(Mandatory = $False)]
        [String]$FirewallType
    )

    Begin {
        # It's nice to be able to see what cmdlet is throwing output isn't it?
        $VerbosePrefix = "Resolve-PwNatPolicy:"
        $ReturnArray = @()
    }

    Process {
        Write-Verbose "$VerbosePrefix Resolving OriginalSource, CurrentPolicy Count: $($Policy.Count)"
        $ResolvedPolicy = $Policy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'OriginalSource' -FirewallType asa

        Write-Verbose "$VerbosePrefix Resolving TranslatedSource, CurrentPolicy Count: $($ResolvedPolicy.Count)"
        $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'TranslatedSource' -FirewallType asa

        Write-Verbose "$VerbosePrefix Resolving OriginalDestination, CurrentPolicy Count: $($ResolvedPolicy.Count)"
        $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'OriginalDestination' -FirewallType asa

        Write-Verbose "$VerbosePrefix Resolving TranslatedDestination, CurrentPolicy Count: $($ResolvedPolicy.Count)"
        $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'TranslatedDestination' -FirewallType asa

        if ($ServiceObjects) {
            Write-Verbose "$VerbosePrefix Resolving OriginalService, CurrentPolicy Count: $($ResolvedPolicy.Count)"
            $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Services $ServiceObjects -FieldName 'OriginalService' -FirewallType asa

            Write-Verbose "$VerbosePrefix Resolving TranslatedService, CurrentPolicy Count: $($ResolvedPolicy.Count)"
            $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Services $ServiceObjects -FieldName 'TranslatedService' -FirewallType asa
        }

        foreach ($nat in $ResolvedPolicy) {
            # Nat Exempt Check
            if ($nat.ResolvedOriginalSource -eq $nat.ResolvedTranslatedSource) {
                if ($nat.ResolvedOriginalDestination -eq $nat.ResolvedTranslatedDestination) {
                    if ($nat.ResolvedOriginalService -eq $nat.ResolvedTranslatedService) {
                        $nat.NatExempt = $true
                    }
                }
            }
        }

        $ReturnArray += $ResolvedPolicy
    }

    End {
        $ReturnArray
    }
}