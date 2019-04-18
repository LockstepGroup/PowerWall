function Resolve-PolicyField {
    [CmdletBinding()]
    Param (
        [Parameter(ParameterSetName = "SecurityPolicyAddress", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "SecurityPolicyService", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [SecurityPolicy]$SecurityPolicy,

        [Parameter(ParameterSetName = "NatPolicyAddress", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "NatPolicyService", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [NatPolicy]$NatPolicy,

        [Parameter(ParameterSetName = "SecurityPolicyAddress", Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = "NatPolicyAddress", Mandatory = $true, Position = 1)]
        [NetworkObject[]]$Addresses,

        [Parameter(ParameterSetName = "SecurityPolicyService", Mandatory = $False, Position = 1)]
        [Parameter(ParameterSetName = "NatPolicyService", Mandatory = $False, Position = 1)]
        [ServiceObject[]]$Services,

        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [Parameter(Mandatory = $true)]
        [string]$FirewallType
    )

    Begin {
        $VerbosePrefix = "Resolve-PolicyField:"
        $ReturnObject = @()
    }

    Process {
        if ($SecurityPolicy) {
            $Policy = $SecurityPolicy
        } elseif ($NatPolicy) {
            $Policy = $NatPolicy
        }

        # Source resolution
        switch -Regex ($FieldName) {
            '.*Address' {
                $ResolvedField = Resolve-PwObject -ObjectToResolve $Policy.$FieldName -ObjectList $Addresses -FirewallType $FirewallType
            }
            'Service' {
                $ResolvedField = Resolve-PwObject -ObjectToResolve $Policy.$FieldName -ObjectList $Services -FirewallType $FirewallType
            }
        }

        foreach ($r in $ResolvedField) {
            $NewPolicy = $PaPolicy.Clone()
            $ReturnObject += $NewPolicy
            $NewPolicy.$FieldName = $r
        }
    }

    End {
        $ReturnObject
    }
}