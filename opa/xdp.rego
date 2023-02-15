package xdp

ETH_P_IP := 2048 # Internet Protocol packet
ETH_P_IPV6 := 34525 # IPv6 over bluebook

allowed_protocols := {ETH_P_IP, ETH_P_IPV6}

allow {
    allowed_protocols[input.protocol]
}
