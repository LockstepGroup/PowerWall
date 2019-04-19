function Resolve-PwNatPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [array]$Policy,

        [Parameter(Mandatory = $True, Position = 1)]
        [array]$NetworkObjects,

        [Parameter(Mandatory = $True, Position = 2)]
        [array]$ServiceObjects,

        [Parameter(Mandatory = $False)]
        [String]$FirewallType
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwNatPolicy:"

    $ReturnArray = $Policy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'OriginalSource' -FirewallType asa
    $ReturnArray = $ReturnArray | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'OriginalDestination' -FirewallType asa
    $ReturnArray = $Policy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'TranslatedSource' -FirewallType asa
    $ReturnArray = $ReturnArray | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'TranslatedDestination' -FirewallType asa

    $ReturnArray = $ReturnArray | Resolve-PolicyField -Services $ServiceObjects -FieldName 'OriginalService' -FirewallType asa
    $ReturnArray = $ReturnArray | Resolve-PolicyField -Services $ServiceObjects -FieldName 'TranslatedService' -FirewallType asa

    $ReturnArray
}

<#
OriginalSource             : vpn_iControl_Management
OriginalDestination        : DM_INLINE_NETWORK_87
OriginalService            :
TranslatedSource           : vpn_iControl_Management
TranslatedDestination      : DM_INLINE_NETWORK_87
TranslatedService          :
 #>