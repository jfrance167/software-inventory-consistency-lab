"""Iterative observations over supplied nodes/edges only; no discovery."""


def observe(nodes, edges, roots):
    """Return SCCs and optional root reachability, with cycles explicitly allowed."""
    outgoing = {node: set() for node in nodes}
    incoming = {node: set() for node in nodes}
    for source, target in edges:
        outgoing[source].add(target)
        incoming[target].add(source)
    visited, order = set(), []
    for start in sorted(nodes):
        if start in visited:
            continue
        stack = [(start, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                order.append(node)
            elif node not in visited:
                visited.add(node)
                stack.append((node, True))
                stack.extend((child, False) for child in sorted(outgoing[node], reverse=True)
                             if child not in visited)
    assigned, components = set(), []
    for start in reversed(order):
        if start in assigned:
            continue
        members, stack = [], [start]
        while stack:
            node = stack.pop()
            if node in assigned:
                continue
            assigned.add(node)
            members.append(node)
            stack.extend(sorted(incoming[node] - assigned, reverse=True))
        components.append(sorted(members))
    components.sort()
    cycles = [part for part in components if len(part) > 1 or part[0] in outgoing[part[0]]]
    reachable = None
    if roots:
        seen, stack = set(), sorted(roots, reverse=True)
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(sorted(outgoing[node] - seen, reverse=True))
        reachable = sorted(seen)
    return {"available": True, "reasons": [], "sccs": components, "cycles": cycles,
            "reachability": {"status": "requested" if roots else "not_requested",
                             "reachable": reachable,
                             "not_reached": sorted(set(nodes) - set(reachable)) if roots else None}}
