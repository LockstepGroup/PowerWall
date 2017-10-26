Class SecurityRule {
    [string]$AccessList
    [int]$Number
    [string]$Action
    
    [string]$SourceInterface
    [string]$DestinationInterface
    
    [string]$Source
    [string]$Destination
    
    [string]$Protocol
    [string]$SourcePort
    [string]$DestinationPort
    [string]$Service
    
    [string]$PacketState
    [string]$RejectWith
    [string]$IcmpType
    [string]$Enabled

    SecurityRule([string] $AclType) {
        switch ($AclType) {
            Asa {
                $this.AccessList           = ""
                $this.Number               = 0
                $this.Source               = ""
                $this.Destination          = ""
                $this.Protocol             = ""
                $this.SourcePort           = ""
                $this.DestinationPort      = ""
                $this.Action               = ""
                $this.SourceInterface      = ""
                $this.DestinationInterface = ""
                $this.PacketState          = ""
                $this.RejectWith           = ""
                $this.IcmpType             = ""
                $this.Enabled              = $true
            }
            default {
                $this.AccessList           = ""
                $this.Number               = 0
                $this.Source               = ""
                $this.Destination          = ""
                $this.Protocol             = ""
                $this.SourcePort           = ""
                $this.DestinationPort      = ""
                $this.Action               = ""
                $this.SourceInterface      = ""
                $this.DestinationInterface = ""
                $this.PacketState          = ""
                $this.RejectWith           = ""
                $this.IcmpType             = ""
                $this.Enabled              = $true
            }
        }
    }
}
