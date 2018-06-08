Class Route {
    [string]$Destination
    [string]$Interface
    [string]$NextHop
    [string]$Metric
    [string]$VirtualRouter

    [string] GetPaloAltoCommand([String]$VirtualRouter) {
        #set network virtual-router nitel routing-table ip static-route ROUTENAME interface INTERFACE destination 1.1.1.1/1 nexthop ip-address 2.2.2.2
        $Command = "set network virtual-router "
        $Command += $VirtualRouter
        $Command += " routing-table ip static-route "
        $Command += $RouteName
        $Command += " interface "
        $Command += $this.Interface
        $Command += " destination "
        $Command += $this.destination
        $Command += " nexthop ip-address "
        $Command += $this.NextHop

        return $Command
    }
}
