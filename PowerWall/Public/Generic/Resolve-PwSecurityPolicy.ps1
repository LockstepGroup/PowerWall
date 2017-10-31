function Resolve-PwSecurityPolicy {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True,Position=0)]
        [array]$Policy,

        [Parameter(Mandatory=$True,Position=1)]
        [array]$NetworkObjects,

        [Parameter(Mandatory=$True,Position=2)]
        [array]$ServiceObjects
    )

    # It's nice to be able to see what cmdlet is throwing output isn't it?
    $VerbosePrefix = "Resolve-PwSecurityPolicy:"

    $ReturnArray = @()
    $SourceResolved = @()
    $DestinationResolved = @()
    $ServiceResolved = @()
    
    $MainProgressParams = @{}
    
    
    
    
    
    
    $MainProgressParams.Activity        = 'Resolving Sources'
    $MainProgressParams.Status          = 'Step 1/3: '
    $StartingPercentComplete            = 0
    $MainProgressParams.PercentComplete = $StartingPercentComplete
    Write-Progress @MainProgressParams

    $i = 0
    # Sources
    foreach ($entry in $Policy) {
        Write-Verbose "$VerbosePrefix $($entry.Accesslist): $($entry.Number)"
        $CopyProps = ($entry | Get-Member -MemberType property).name
        
        foreach ($value in $entry.Source) {
            $ResolvedObjects = Resolve-PwObject -ObjectToResolve $value -ObjectList $NetworkObjects
            foreach ($r in $ResolvedObjects) {
                $NewObject = [ResolvedSecurityPolicy]::new()

                foreach ($prop in $CopyProps) {
                    $NewObject.$prop = $entry.$prop
                }

                $NewObject.Source         = $value
                $NewObject.ResolvedSource = $r
                $SourceResolved += $NewObject
            }
        }
        
        # Update Progress Bar
        $i++
        $global:testing = ($i / $Policy.Count / 3 * 100)
        $MainProgressParams.PercentComplete  = ($i / $Policy.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($Policy.Count)"
        Write-Progress @MainProgressParams
    }

    
    $MainProgressParams.Activity        = 'Resolving Destinations'
    $MainProgressParams.Status          = 'Step 2/3: '
    $StartingPercentComplete            = 1 / 3 * 100
    $MainProgressParams.PercentComplete = $StartingPercentComplete
    
    $i = 0
    # Destinations
    foreach ($entry in $SourceResolved) {
        Write-Verbose "$VerbosePrefix $($entry.Accesslist): $($entry.Number)"
        $CopyProps = ($entry | Get-Member -MemberType property).name
        
        foreach ($value in $entry.Destination) {
            $ResolvedObjects = Resolve-PwObject -ObjectToResolve $value -ObjectList $NetworkObjects
            foreach ($r in $ResolvedObjects) {
                $NewObject = [ResolvedSecurityPolicy]::new()

                foreach ($prop in $CopyProps) {
                    $NewObject.$prop = $entry.$prop
                }

                $NewObject.Destination         = $value
                $NewObject.ResolvedDestination = $r
                $DestinationResolved += $NewObject
            }
        }

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete  = ($i / $SourceResolved.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($SourceResolved.Count)"
        Write-Progress @MainProgressParams
    }

    $MainProgressParams.Activity        = 'Resolving Services'
    $MainProgressParams.Status          = 'Step 3/3: '
    $StartingPercentComplete = 2 / 3 * 100
    $MainProgressParams.PercentComplete = $StartingPercentComplete

    $i = 0
    # Services
    foreach ($entry in $DestinationResolved) {
        Write-Verbose "$VerbosePrefix $($entry.Accesslist): $($entry.Number)"
        $CopyProps = ($entry | Get-Member -MemberType property).name
        
        foreach ($value in $entry.Service) {
            $ResolvedObjects = Resolve-PwObject -ObjectToResolve $value -ObjectList $ServiceObjects
            foreach ($r in $ResolvedObjects) {
                $NewObject = [ResolvedSecurityPolicy]::new()

                foreach ($prop in $CopyProps) {
                    $NewObject.$prop = $entry.$prop
                }

                $NewObject.Service         = $value
                $NewObject.Protocol        = $r.Protocol
                $NewObject.SourcePort      = $r.SourcePort
                $NewObject.DestinationPort = $r.DestinationPort
                $ServiceResolved += $NewObject
            }
        }

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete  = ($i / $DestinationResolved.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($DestinationResolved.Count)"
        Write-Progress @MainProgressParams
    }

    $ReturnArray = $ServiceResolved
    $ReturnArray
}