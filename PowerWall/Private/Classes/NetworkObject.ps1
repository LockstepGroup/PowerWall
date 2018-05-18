Class NetworkObject {
    static [string] $Type = "Network"
    [string]$Name
    [string]$Comment
    [string[]]$Member

    # Object Nat
    [string]$NatSourceInterface
    [string]$NatDestinationInterface
    [string]$NatType
    [string]$NatSourceAddress
}
