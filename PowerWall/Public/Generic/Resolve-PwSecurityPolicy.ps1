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

    function Resolve-Property {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True,Position=0)]
            $Policy,
    
            [Parameter(Mandatory=$True,Position=1)]
            [ValidateSet("Source","Destination","Service")]             
            [string]$Property,

            [Parameter(Mandatory=$True,Position=2)]
            [array]$Objects
        )

        $ReturnArray = @()
        $CopyProps = ($Policy | Get-Member -MemberType property).name

        foreach ($value in $Policy.$Property) {
            $ResolvedObjects = Resolve-PwObject -ObjectToResolve $value -ObjectList $Objects
            foreach ($r in $ResolvedObjects) {
                $NewObject = [ResolvedSecurityPolicy]::new()
                
                # should convert this to a method on the ResolvedSecurityPolicy class
                foreach ($prop in $CopyProps) {
                    $NewObject.$prop = $entry.$prop
                }

                switch ($Property) {
                    'Service' {
                        $NewObject.Service         = $value
                        $NewObject.Protocol        = $r.Protocol
                        $NewObject.SourcePort      = $r.SourcePort
                        $NewObject.DestinationPort = $r.DestinationPort
                        $ReturnArray += $NewObject
                    }
                    { ($_ -eq 'Source') -or `
                      ($_ -eq 'Destination') } {
                        
                        if ($ResolvedObjects.GetType().Name -eq 'SsExpression') {
                            $ResolvedExpression = Resolve-PwObject -ObjectToResolve $r.Value -ObjectList $Objects
                            foreach ($v in $ResolvedExpression) {
                                $NewObject = [ResolvedSecurityPolicy]::new()
                                
                                # should convert this to a method on the ResolvedSecurityPolicy class
                                foreach ($prop in $CopyProps) {
                                    $NewObject.$prop = $entry.$prop
                                }

                                switch ($ResolvedObjects.Operator) {
                                    'exclusion' {
                                        $NewObject."$Property`Negate" = $true
                                    }
                                    default {
                                        Throw "VerbosePrefix Expression Operator not handled: $($ResolvedObjects.Operator)"
                                    }
                                }
                                
                                $NewObject.$Property = $value
                                $NewObject."Resolved$Property" = $v
                                $ReturnArray                  += $NewObject
                            }
                        } else {
                            $NewObject.$Property = $value
                            $NewObject."Resolved$Property" = $r
                            $ReturnArray                  += $NewObject
                        }

                        
                    }
                    default {
                        Throw "$VerbosePrefix Property not handled: $Property"
                    }
                }

            }
        }

        $ReturnArray
    }

    $i = 0
    # Sources
    foreach ($entry in $Policy) {
        $SourceResolved += Resolve-Property -Policy $entry -Property Source -Objects $NetworkObjects
        
        # Update Progress Bar
        $i++
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
        $DestinationResolved += Resolve-Property -Policy $entry -Property Destination -Objects $NetworkObjects

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
        $ServiceResolved += Resolve-Property -Policy $entry -Property Service -Objects $ServiceObjects

        # Update Progress Bar
        $i++
        $MainProgressParams.PercentComplete  = ($i / $DestinationResolved.Count / 3 * 100) + $StartingPercentComplete
        $MainProgressParams.CurrentOperation = "Rule $i / $($DestinationResolved.Count)"
        Write-Progress @MainProgressParams
    }

    $ReturnArray = $ServiceResolved
    $ReturnArray
}