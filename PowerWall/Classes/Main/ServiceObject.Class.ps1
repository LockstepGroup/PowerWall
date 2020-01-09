Class ServiceObject {
    static [string] $Type = "Service"
    [string]$Name
    [string]$Comment
    [string]$Category
    [string]$Protocol
    [string[]]$SourcePort
    [string[]]$DestinationPort
    [string[]]$Member
    [string]$ResolvedMember
    [string[]]$MemberOf

    ##################################### Initiators #####################################
    # Empty Initiator
    ServiceObject() {
    }

    # Initator with name/protocol/port
    ServiceObject([string] $Name, [string] $Protocol, [string] $DestinationPort) {
        $this.Name = $Name
        $this.Protocol = $Protocol
        $this.DestinationPort = $DestinationPort
    }
}
