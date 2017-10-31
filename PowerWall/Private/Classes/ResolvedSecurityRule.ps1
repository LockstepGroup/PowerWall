Class ResolvedSecurityPolicy {
    [string]$AccessList
    [decimal]$Number
    [string]$Action
    
    [string]$SourceInterface
    [string]$DestinationInterface
    
    [string[]]$Source
    [string[]]$ResolvedSource
    [string[]]$Destination
    [string[]]$ResolvedDestination
    
    [string]$Protocol
    [string]$SourcePort
    [string]$DestinationPort
    [string[]]$Service
    
    [string]$Comment
    [string]$PacketState
    [string]$RejectWith
    [string]$IcmpType
    [string]$Enabled
}
