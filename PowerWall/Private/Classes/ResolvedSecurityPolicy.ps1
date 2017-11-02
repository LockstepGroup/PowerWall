Class ResolvedSecurityPolicy {
    [string]$AccessList
    [decimal]$Number
    [string]$Name
    [string]$Action
    
    [string]$SourceInterface
    [string]$DestinationInterface
    
    $Source
    $ResolvedSource
    [bool]$SourceNegate

    $Destination
    $ResolvedDestination
    [bool]$DestinationNegate
    
    [string]$Protocol
    [string]$SourcePort
    [string]$DestinationPort
    $Service
    
    [string]$Comment
    [string]$PacketState
    [string]$RejectWith
    [string]$IcmpType
    [string]$Enabled
}
