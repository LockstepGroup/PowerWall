Class NatPolicy {
    [int]$Number

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
            }
            default {
                $this.Number               = 0
            }
        }
    }
}
