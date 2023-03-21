package xdp

ETH_P_IPV4 := 2048
ETH_P_IPV6 := 34525

allowed_protocols := {ETH_P_IPV4, ETH_P_IPV6}

now := time.now_ns()

allow {
    input.protocol < now # just to test builtins

    allowed_protocols[input.protocol]
}
