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
    [string]$Enabled

    SecurityRule([string] $AclType) {
        switch ($AclType) {
            Asa {
                $this.AccessList        = ""
                $this.Number            = 0
                $this.Source            = ""
                $this.Destination       = ""
                $this.Protocol          = ""
                $this.SourcePort        = ""
                $this.DestinationPort   = ""
                $this.Action            = ""
                $this.InboundInterface  = ""
                $this.OutboundInterface = ""
                $this.State             = ""
                $this.RejectWith        = ""
                $this.IcmpType          = ""
                $this.Enabled           = $true
            }
            default {
                $this.AccessList        = ""
                $this.Number            = 0
                $this.Source            = ""
                $this.Destination       = ""
                $this.Protocol          = ""
                $this.SourcePort        = ""
                $this.DestinationPort   = ""
                $this.Action            = ""
                $this.InboundInterface  = ""
                $this.OutboundInterface = ""
                $this.State             = ""
                $this.RejectWith        = ""
                $this.IcmpType          = ""
            }
        }
    }
}

<#
#Defines Constructor
 Dog([String] $Name, [String] $Breed, [String] $OwnerName, [String]$OwnerAddress, [DateTime]$RegistrationDate)
 {
 $this.Breed = $Breed
 $this.Name = $Name
 $this.OwnerName = $OwnerName
 $this.OwnerAddress = $OwnerAddress
 $this.RegistrationDate = $RegistrationDate
 }#>