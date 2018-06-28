Class ServiceObject {
    static [string] $Type = "Service"
    [string]$Name
    [string]$Comment
    [string]$Protocol
    [string[]]$SourcePort
    [string[]]$DestinationPort
    [string[]]$Member
    [string[]]$MemberOf
}
