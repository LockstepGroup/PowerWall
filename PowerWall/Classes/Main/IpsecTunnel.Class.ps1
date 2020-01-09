Class IpsecTunnel:ICloneable {
    [string]$LocalIpAddress
    [string]$PeerIpAddress

    [string[]]$LocalNetwork
    [string[]]$RemoteNetwork

    # IKE Settings
    [int]$IkeVersion                # needs enum: 1 or 2
    [string]$IkeMode                # needs enum: main or aggressive
    [array]$IkeProposal
    [string]$PreSharedKey

    # IPSEC Settings
    [int[]]$IpsecDHGroup
    [decimal]$IpsecLifetimeSeconds
    [array]$IpsecProposal

    [bool]$NatTEnabled = $false

    ####################################### Methods ######################################
    # Clone
    [Object] Clone () {
        $NewObject = [IpsecTunnel]::New()
        foreach ($Property in ($this | Get-Member -MemberType Property)) {
            $NewObject.$($Property.Name) = $this.$($Property.Name)
        } # foreach
        return $NewObject
    }

    ##################################### Initiators #####################################
    # Empty Initiator
    IpsecTunnel() {
    }
}
