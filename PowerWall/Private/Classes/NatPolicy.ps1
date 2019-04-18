Class NatPolicy:ICloneable {
    [int]$Number
    [string]$Comment
    [bool]$Enabled

    [string]$SourceInterface
    [string]$DestinationInterface

    [string]$OriginalSource
    [string]$OriginalDestination
    [string]$OriginalService

    [string]$TranslatedSource
    [string]$TranslatedDestination
    [string]$TranslatedService

    [string]$SourceTranslationType
    [string]$DestinationTranslationType

    [bool]$ProxyArp
    [bool]$RouteLookup

    [decimal]$RxBytes
    [decimal]$TxBytes

    ####################################### Methods ######################################
    # Clone
    [Object] Clone () {
        $NewObject = [NatPolicy]::New()
        foreach ($Property in ($this | Get-Member -MemberType Property)) {
            $NewObject.$($Property.Name) = $this.$($Property.Name)
        } # foreach
        return $NewObject
    }

    ##################################### Initiators #####################################
    # Empty Initiator
    NatPolicy() {
    }

    # Initator with FirewallType
    NatPolicy([string] $FirewallType) {
        switch ($FirewallType) {
            Asa {
                $this.Number = 0
                $this.ProxyArp = $true
                $this.RouteLookup = $false
                $this.Enabled = $true
            }
            default {
                $this.Number = 0
            }
        }
    }
}
