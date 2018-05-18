function ConvertTo-MaskLength {
    <#
    .Synopsis
        Returns the length of a subnet mask.
    .Description
        ConvertTo-MaskLength accepts any IPv4 address as input, however the output value
        only makes sense when using a subnet mask.
    .Parameter SubnetMask
        A subnet mask to convert into length
    #>

    [CmdLetBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True)]
        [Alias("Mask")]
        [Net.IPAddress]$SubnetMask
    )
  
    
 
    Process {
        
        function IsValidMaskBits ($Bits) { 
            $Bits = [convert]::ToString($Bits,2).PadLeft(8,'0')
            $Bits = $Bits.ToCharArray()
            $ZeroFound = $false
            foreach ($b in $Bits) {
                switch ($b) {
                    0 {
                        $ZeroFound = $true
                        continue
                    }
                    1 {
                        if ($ZeroFound) {
                            return $false
                        } else {
                            continue
                        }
                    }
                }
            }
            return $true
        }
        
        foreach ($b in $SubnetMask.GetAddressBytes()) {
            #Write-Verbose $b
            $IsValid = IsValidMaskBits $b
        }
        
        
        if ($IsValid) {
            $Bits = "$( $SubnetMask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2) } )" -Replace '[\s0]'
        } else {
            Throw "Not a valid Subnet Mask $SubnetMask"
        }
        Return $Bits.Length#>
    }
}