Class SecurityRule {
    [string]$AccessList
    [int]$Number
    [string]$Source
    [string]$Destination
    [string]$Protocol
    [string]$SourcePort
    [string]$DestinationPort
    [string]$Action
    [string]$InboundInterface
    [string]$OutboundInterface
    [string]$State
    [string]$RejectWith
    [string]$IcmpType
}

<#
$IpTablesParams.Chain
$IpTablesParams.Destination       = '-d'
$IpTablesParams.Source            = '-s'
$IpTablesParams.Protocol          = '-p'
$IpTablesParams.DestinationPort   = '--dport'
$IpTablesParams.SourcePort        = '--sport'
$IpTablesParams.Action            = '-j'
$IpTablesParams.InboundInterface  = '-i'
$IpTablesParams.OutboundInterface = '-o'
$IpTablesParams.State             = '--state'
$IpTablesParams.RejectWith        = '--reject-with'
$IpTablesParams.IcmpType          = '--icmp-type'
#>