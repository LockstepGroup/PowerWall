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

        [Parameter(ParameterSetName = "SecurityPolicyService", Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = "NatPolicyService", Mandatory = $true, Position = 1)]
        [ServiceObject[]]$Services,

        [Parameter(Mandatory = $true)]
        [string]$FieldName,

        [Parameter(Mandatory = $true)]
        [string]$FirewallType
    )

    Begin {
        $VerbosePrefix = "Resolve-PolicyField:"
        $ResolvedFieldName = 'Resolved' + $FieldName
        $OriginalFieldName = $FieldName -replace 'Translated', 'Original'
        $TranslatedEqualsOrignal = $false
        $ReturnObject = @()
    }

    Process {
        Write-Verbose "$VerbosePrefix ParameterSetName: $($PsCmdlet.ParameterSetName)"
        if ($SecurityPolicy) {
            $Policy = $SecurityPolicy
        } elseif ($NatPolicy) {
            $Policy = $NatPolicy
        }
        $global:RPFPolicy = $Policy
        $global:FieldName = $FieldNametest

        if (($Policy.$FieldName.Count -gt 0) -and ("" -ne $Policy.$FieldName)) {
            Write-Verbose "$VerbosePrefix Policy contains $($Policy.$FieldName.Count) entries in Field: $FieldName"
            if (($FieldName -match 'Translated') -and ($Policy.$FieldName -eq $Policy.$OriginalFieldName)) {
                $NewPolicy = $Policy.Clone()
                $ReturnObject += $NewPolicy

                $NewPolicy.$ResolvedFieldName = $Policy."Resolved$OriginalFieldName"
            } else {
                $Params = @{ }
                $Params.ObjectToResolve = $Policy.$FieldName
                $Params.FirewallType = $FirewallType
                Write-Verbose "$VerbosePrefix Checking Vdom"
                if ($Policy.Vdom) {
                    Write-Verbose "$VerbosePrefix Vdom: $Vdom"
                    $Params.Vdom = $Policy.Vdom
                }
                switch -Regex ($FieldName) {
                    '(Source|Destination)' {
                        Write-Verbose "$VerbosePrefix Resolving Address"
                        $ResolvedField = Resolve-PwObject -ObjectList $Addresses @Params
                    }
                    'Service' {
                        Write-Verbose "$VerbosePrefix Resolving Service for AccessList $($Policy.AccessList) number $($Policy.Number)"
                        $ResolvedField = Resolve-PwObject -ObjectList $Services @Params
                    }
                    default {
                        Throw "$VerbosePrefix FieldName not handled: $FieldName"
                    }
                }

                Write-Verbose "$VerbosePrefix $($Policy.$FieldName) resolves to $($ResolvedField.Count) objects"

                foreach ($r in $ResolvedField) {
                    $NewPolicy = $Policy.Clone()
                    $ReturnObject += $NewPolicy

                    if ($FieldName -match 'Service') {

                        if ($null -eq $r.Protocol) {
                            $NewPolicy.$ResolvedFieldName = $Policy.Protocol + '/' + $r.DestinationPort
                        } else {
                            $NewPolicy.$ResolvedFieldName = $r.Protocol + '/' + $r.DestinationPort
                        }
                    } else {
                        $NewPolicy.$ResolvedFieldName = $r
                    }
                }
            }
        } else {
            $NewPolicy = $Policy.Clone()
            $ReturnObject += $NewPolicy
        }
    }

    End {
        $ReturnObject
    }
}