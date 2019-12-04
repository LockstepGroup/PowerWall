Class SecurityPolicy:ICloneable {
    [string]$AccessList
    [string]$AclType
    [decimal]$Number
    [string]$Name
    [string]$Action

    [string]$SourceInterface
    [string]$DestinationInterface

    [string[]]$Source
    [bool]$SourceNegate

    [string[]]$Destination

    [bool]$DestinationNegate

    [string]$Protocol
    [string]$SourcePort
    [string]$DestinationPort
    [string[]]$Service

    [string]$ResolvedSource
    [string]$ResolvedDestination
    [string]$ResolvedSourcePort
    [string]$ResolvedDestinationPort
    [string]$ResolvedService

    [string]$Comment
    [string]$PacketState
    [string]$RejectWith
    [string]$IcmpType
    [bool]$Enabled

    [decimal]$RxBytes
    [decimal]$TxBytes

    ####################################### Methods ######################################
    # Clone
    [Object] Clone () {
        $NewObject = [SecurityPolicy]::New()
        foreach ($Property in ($this | Get-Member -MemberType Property)) {
            $NewObject.$($Property.Name) = $this.$($Property.Name)
        } # foreach
        return $NewObject
    }

    ##################################### Initiators #####################################
    # Empty Initiator
    SecurityPolicy() {
    }

    # Initator with AclType
    SecurityPolicy([string] $AclType) {
        switch ($AclType) {
            Asa {
                $this.AccessList = ""
                $this.Number = 0
                $this.Source = ""
                $this.Destination = ""
                $this.Protocol = ""
                $this.SourcePort = ""
                $this.DestinationPort = ""
                $this.Action = ""
                $this.SourceInterface = ""
                $this.DestinationInterface = ""
                $this.PacketState = ""
                $this.RejectWith = ""
                $this.IcmpType = ""
                $this.Enabled = $true
            }
            default {
                $this.AccessList = ""
                $this.Number = 0
                $this.Source = ""
                $this.Destination = ""
                $this.Protocol = ""
                $this.SourcePort = ""
                $this.DestinationPort = ""
                $this.Action = ""
                $this.SourceInterface = ""
                $this.DestinationInterface = ""
                $this.PacketState = ""
                $this.RejectWith = ""
                $this.IcmpType = ""
                $this.Enabled = $true
            }
        }
    }
}