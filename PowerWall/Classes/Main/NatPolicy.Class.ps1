Class NatPolicy:ICloneable {
    [int]$Number
    [string]$Name
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

    [string]$ResolvedOriginalSource
    [string]$ResolvedOriginalDestination
    [string]$ResolvedOriginalService
    [string]$ResolvedTranslatedSource
    [string]$ResolvedTranslatedDestination
    [string]$ResolvedTranslatedService

    [string]$SourceTranslationType
    [string]$DestinationTranslationType

    [bool]$ProxyArp
    [bool]$RouteLookup
    [bool]$NatExempt
    [bool]$NatSourceVip

    [decimal]$RxBytes
    [decimal]$TxBytes

    # Fortigate Only
    [string]$Vdom

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
