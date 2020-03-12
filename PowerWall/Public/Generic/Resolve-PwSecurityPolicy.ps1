function Resolve-PwSecurityPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, Position = 0)]
        [SecurityPolicy]$Policy,

        [Parameter(Mandatory = $True, Position = 1)]
        [NetworkObject[]]$NetworkObjects,

        [Parameter(Mandatory = $True, Position = 2)]
        [ServiceObject[]]$ServiceObjects,

        [Parameter(Mandatory = $False)]
        [String]$FirewallType
    )
    Begin {
        # It's nice to be able to see what cmdlet is throwing output isn't it?
        $VerbosePrefix = "Resolve-PwSecurityPolicy:"
        $ReturnArray = @()
    }

    Process {
        Write-Verbose "$VerbosePrefix Resolving Source, CurrentPolicy Count: $($Policy.Count)"
        $ResolvedPolicy = $Policy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'Source' -FirewallType $FirewallType

        Write-Verbose "$VerbosePrefix Resolving Destination, CurrentPolicy Count: $($ResolvedPolicy.Count)"
        $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'Destination' -FirewallType $FirewallType

        Write-Verbose "$VerbosePrefix Resolving Service, CurrentPolicy Count: $($ResolvedPolicy.Count)"
        $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Services $ServiceObjects -FieldName 'Service' -FirewallType $FirewallType

        Write-Verbose "$VerbosePrefix Resolving SourceService, CurrentPolicy Count: $($ResolvedPolicy.Count)"
        $ResolvedPolicy = $ResolvedPolicy | Resolve-PolicyField -Services $ServiceObjects -FieldName 'SourceService' -FirewallType $FirewallType

        $ReturnArray += $ResolvedPolicy
    }

    End {
        $ReturnArray
    }
}