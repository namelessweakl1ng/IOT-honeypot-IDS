from ipaddress import ip_address, ip_network


def validate_target(target: str | None, lab_subnet: str) -> str:
    if not target:
        raise ValueError("an explicit target is required")
    address = ip_address(target)
    network = ip_network(lab_subnet, strict=False)
    if not network.is_private:
        raise ValueError("LAB_SUBNET must be private")
    if address.is_loopback or not address.is_private or address not in network:
        raise ValueError("target must be a private, non-loopback address inside LAB_SUBNET")
    if address in {network.network_address, network.broadcast_address}:
        raise ValueError("target must be a usable host address")
    return str(address)
