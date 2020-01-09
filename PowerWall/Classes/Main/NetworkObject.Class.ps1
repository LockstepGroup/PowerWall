Class NetworkObject {
    static [string] $Type = "Network"
    [string]$Name
    [string]$Comment
    [string[]]$Member
    [string]$ResolvedMember
    [string[]]$MemberOf

    # Object Nat
    [string]$NatSourceInterface
    [string]$NatDestinationInterface
    [string]$NatType
    [string]$NatSourceAddress

    [string]$Vdom
}
