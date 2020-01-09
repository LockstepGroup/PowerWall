Class IkeProposal:ICloneable {
    [string]$Name
    [string[]]$Encryption
    [string[]]$Authentication
    [int[]]$DhGroup
    [decimal]$LifeTime

    ####################################### Methods ######################################
    # Clone
    [Object] Clone () {
        $NewObject = [IkeProposal]::New()
        foreach ($Property in ($this | Get-Member -MemberType Property)) {
            $NewObject.$($Property.Name) = $this.$($Property.Name)
        } # foreach
        return $NewObject
    }

    ##################################### Initiators #####################################
    # Empty Initiator
    IkeProposal() {
    }
}
