function Resolve-PwSecurityPolicy {
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
    $VerbosePrefix = "Resolve-PwSecurityPolicy:"

    $ReturnArray = $Policy | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'Source' -FirewallType asa
    $ReturnArray = $ReturnArray | Resolve-PolicyField -Addresses $NetworkObjects -FieldName 'Destination' -FirewallType asa

    $ReturnArray = $ReturnArray | Resolve-PolicyField -Services $ServiceObjects -FieldName 'Service' -FirewallType asa

    $ReturnArray
}