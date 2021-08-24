Class IpsecProposal:ICloneable {
    [string]$Name
    [string[]]$Encryption
    [string[]]$Authentication

    ####################################### Methods ######################################
    # Clone
    [Object] Clone () {
        $NewObject = [IpsecProposal]::New()
        foreach ($Property in ($this | Get-Member -MemberType Property)) {
            $NewObject.$($Property.Name) = $this.$($Property.Name)
        } # foreach
        return $NewObject
    }

    ##################################### Initiators #####################################
    # Empty Initiator
    IpsecProposal() {
    }
}
