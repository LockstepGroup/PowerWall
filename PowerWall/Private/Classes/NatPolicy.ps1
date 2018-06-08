Class NatPolicy {
    [int]$Number
    [bool]$Enabled

    [string]$SourceInterface
    [string]$DestinationInterface

    [string]$OriginalSource
    [string]$OriginalDestination

    [string]$TranslatedSource
    [string]$TranslatedDestination

    [string]$SourceTranslationType
    [string]$DestinationTranslationType

    [bool]$ProxyArp
    [bool]$RouteLookup

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
