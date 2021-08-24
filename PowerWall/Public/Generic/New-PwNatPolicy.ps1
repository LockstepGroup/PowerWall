function New-PwNatPolicy {
    [CmdletBinding()]
    Param (
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "New-PwNatPolicy:"

    $NewObject = [NatPolicy]::new()
    $NewObject
}