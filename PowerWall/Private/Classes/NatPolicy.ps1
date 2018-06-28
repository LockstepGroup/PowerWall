Class NatPolicy {
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

    NatPolicy([string] $FirewallType) {
        switch ($FirewallType) {
            Asa {
                $this.Number      = 0
                $this.ProxyArp    = $true
                $this.RouteLookup = $false
                $this.Enabled     = $true
            }
            default {
                $this.Number               = 0
            }
        }
    }
}
