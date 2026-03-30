#!/usr/bin/env python3
"""
Compare two MSSQLHound JSON output files and identify edge differences.

Usage:
    python3 compare_edges.py <file1.json> <file2.json> [--label1 NAME] [--label2 NAME]

Examples:
    python3 compare_edges.py mssql-go-output.json mssql-ps1-output.json
    python3 compare_edges.py file_a.json file_b.json --label1 "Go" --label2 "PS1"
"""

import json
import sys
import argparse
import zipfile
from collections import defaultdict


def load_json(filepath):
    """Load a JSON file or extract the main JSON from a zip file.

    For Go-style zips that separate AD nodes into computers.json, users.json,
    and groups.json alongside the main output, those nodes are merged into the
    main graph so the comparison sees the complete picture.
    """
    if filepath.endswith(".zip"):
        with zipfile.ZipFile(filepath) as zf:
            json_files = [n for n in zf.namelist() if n.endswith(".json")]
            if not json_files:
                raise ValueError(f"No JSON files found in {filepath}")
            # Pick the largest JSON file (the main output)
            main_file = max(json_files, key=lambda n: zf.getinfo(n).file_size)
            print(f"  (extracted '{main_file}' from zip)")
            data = json.loads(zf.read(main_file))

            # Merge AD node files (Go splits Base nodes into separate files)
            ad_files = [n for n in json_files if n in ("computers.json", "users.json", "groups.json")]
            if ad_files and isinstance(data, dict) and "graph" in data:
                merged_count = 0
                existing_ids = {n["id"] for n in data["graph"].get("nodes", [])}
                for ad_file in sorted(ad_files):
                    ad_data = json.loads(zf.read(ad_file))
                    for node in ad_data.get("graph", {}).get("nodes", []):
                        if node.get("id") not in existing_ids:
                            data["graph"].setdefault("nodes", []).append(node)
                            existing_ids.add(node["id"])
                            merged_count += 1
                if merged_count:
                    print(f"  (merged {merged_count} AD nodes from {', '.join(ad_files)})")
            return data
    with open(filepath, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def extract_edges(data):
    """
    Extract edges from the JSON data.
    Handles multiple possible structures:
    - Top-level list of edges
    - Dict with 'data' key containing edges
    - Dict with 'edges' key containing edges
    - Nested structures with 'relationships' key
    """
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Try common key names at top level
        for key in ["data", "edges", "relationships", "rels"]:
            if key in data:
                val = data[key]
                if isinstance(val, list):
                    return val

        # Check nested under 'graph'
        if "graph" in data and isinstance(data["graph"], dict):
            graph = data["graph"]
            for key in ["edges", "relationships", "rels"]:
                if key in graph:
                    val = graph[key]
                    if isinstance(val, list):
                        return val

        # If dict has 'start', 'end', 'kind' — it's a single edge
        if "start" in data and "end" in data and "kind" in data:
            return [data]

        # Look one level deeper
        for key, val in data.items():
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and ("kind" in first or "type" in first):
                    return val

    return []


def build_node_id_mapping(data1, data2):
    """Build a mapping from file1 node IDs to file2 node IDs based on matching node names/kinds.

    This handles the case where one file uses SID-based identifiers and the other
    uses hostname-based identifiers for the same nodes.
    """
    nodes1 = extract_nodes(data1)
    nodes2 = extract_nodes(data2)

    if not nodes1 or not nodes2:
        return {}

    # Build (kinds, name) -> id maps for each file
    def build_name_map(nodes):
        name_map = {}
        for node in nodes:
            node_id = node.get("id", "")
            kinds = tuple(sorted(node.get("kinds", [])))
            props = node.get("properties", {})
            name = props.get("name", "")
            if name:
                key = (kinds, name)
                name_map[key] = node_id
        return name_map

    map1 = build_name_map(nodes1)
    map2 = build_name_map(nodes2)

    # Build file1_id -> file2_id mapping
    id_mapping = {}
    for key, id1 in map1.items():
        if key in map2:
            id2 = map2[key]
            if id1 != id2:
                id_mapping[id1] = id2

    return id_mapping


def normalize_id(value, id_mapping):
    """Normalize a node identifier using the mapping.

    Handles compound identifiers like 'SID:1433\\database' by normalizing
    the base part and preserving suffixes.
    """
    if not id_mapping or value not in id_mapping:
        # Try prefix matching for compound IDs (e.g., "hostname:1433\db")
        for old_id, new_id in id_mapping.items():
            if value.startswith(old_id):
                return new_id + value[len(old_id):]
        return value
    return id_mapping[value]


def make_edge_key(edge, id_mapping=None):
    """Create a hashable key from an edge for comparison (source, target, kind)."""
    start = edge.get("start", {})
    end = edge.get("end", {})

    # Handle both {"value": "..."} and plain string formats
    if isinstance(start, dict):
        source = start.get("value", start.get("objectid", str(start)))
    else:
        source = str(start)

    if isinstance(end, dict):
        target = end.get("value", end.get("objectid", str(end)))
    else:
        target = str(end)

    # Apply ID normalization if mapping provided
    if id_mapping:
        source = normalize_id(source, id_mapping)
        target = normalize_id(target, id_mapping)

    kind = edge.get("kind", edge.get("type", edge.get("label", "UNKNOWN")))

    return (source, target, kind)


def make_full_edge_key(edge):
    """Create a hashable key from an edge including all properties for exact comparison."""
    return json.dumps(edge, sort_keys=True)


def get_edge_properties(edge):
    """Extract edge properties, excluding the structural fields."""
    props = edge.get("properties", {})
    return props


def normalize_value(v, normalize_ws=False):
    """Normalize a value for comparison (handle type differences like bool vs string)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        if normalize_ws:
            return normalize_whitespace(v)
    return v


def normalize_whitespace(s):
    """Normalize whitespace in a string for comparison.

    Handles differences between PS1 (which embeds text in indented heredocs,
    producing leading whitespace and \\r\\n) and Go (which produces clean text).
    """
    import re

    # Normalize line endings
    s = s.replace("\r\n", "\n")
    # Strip leading/trailing whitespace per line
    lines = s.split("\n")
    lines = [l.strip() for l in lines]
    # Remove empty lines (PS1 often has extra blank lines from indentation)
    lines = [l for l in lines if l]
    # Rejoin
    return "\n".join(lines)


def compare_properties(props1, props2, label1, label2, normalize_ws=False):
    """Compare two property dicts and return differences."""
    diffs = []
    all_keys = sorted(set(list(props1.keys()) + list(props2.keys())))

    for key in all_keys:
        if key in props1 and key not in props2:
            diffs.append(f"  Property '{key}' only in {label1}")
        elif key not in props1 and key in props2:
            diffs.append(f"  Property '{key}' only in {label2}")
        else:
            v1 = normalize_value(props1[key], normalize_ws)
            v2 = normalize_value(props2[key], normalize_ws)
            if v1 != v2:
                # Truncate long values
                s1 = str(v1)
                s2 = str(v2)
                if len(s1) > 120:
                    s1 = s1[:120] + "..."
                if len(s2) > 120:
                    s2 = s2[:120] + "..."
                diffs.append(f"  Property '{key}' differs:")
                diffs.append(f"    {label1}: {s1}")
                diffs.append(f"    {label2}: {s2}")

    return diffs


def extract_nodes(data):
    """Extract nodes from the JSON data."""
    if isinstance(data, dict):
        if "graph" in data and isinstance(data["graph"], dict):
            return data["graph"].get("nodes", [])
        if "nodes" in data:
            return data["nodes"]
    return []


def make_node_key(node):
    """Create a hashable key from a node for comparison.
    Uses (kinds_tuple, id) as key. The 'id' field is the primary identifier."""
    kinds = tuple(sorted(node.get("kinds", [])))
    node_id = node.get("id", "")
    return (kinds, node_id)


def compare_nodes(data1, data2, label1, label2, verbose=False, normalize_ws=False):
    """Compare nodes between two datasets and print differences."""
    nodes1 = extract_nodes(data1)
    nodes2 = extract_nodes(data2)

    print(f"\n{'='*80}")
    print("NODE COMPARISON")
    print(f"{'='*80}")
    print(f"  {label1}: {len(nodes1)} nodes")
    print(f"  {label2}: {len(nodes2)} nodes")

    # Count by kinds
    kind_counts1 = defaultdict(int)
    kind_counts2 = defaultdict(int)
    for n in nodes1:
        k = ", ".join(sorted(n.get("kinds", []))) or "(no kind)"
        kind_counts1[k] += 1
    for n in nodes2:
        k = ", ".join(sorted(n.get("kinds", []))) or "(no kind)"
        kind_counts2[k] += 1

    all_kinds = sorted(set(list(kind_counts1.keys()) + list(kind_counts2.keys())))
    if any(kind_counts1.get(k, 0) != kind_counts2.get(k, 0) for k in all_kinds):
        print(f"\n  {'Node Kind':<45} {label1:>8} {label2:>8}  {'Diff':>6}")
        print(f"  {'-'*45} {'-'*8} {'-'*8}  {'-'*6}")
        for k in all_kinds:
            c1 = kind_counts1.get(k, 0)
            c2 = kind_counts2.get(k, 0)
            d = c1 - c2
            m = " <---" if d != 0 else ""
            print(f"  {k or '(no kind)':<45} {c1:>8} {c2:>8}  {d:>+6}{m}")

    # Build node maps by key
    nodes1_by_key = {}
    nodes2_by_key = {}
    for n in nodes1:
        key = make_node_key(n)
        nodes1_by_key[key] = n
    for n in nodes2:
        key = make_node_key(n)
        nodes2_by_key[key] = n

    keys1 = set(nodes1_by_key.keys())
    keys2 = set(nodes2_by_key.keys())

    only_in_1 = sorted(keys1 - keys2)
    only_in_2 = sorted(keys2 - keys1)
    in_both = keys1 & keys2

    print(f"\n  Unique nodes: Only in {label1}: {len(only_in_1)}, Only in {label2}: {len(only_in_2)}, In both: {len(in_both)}")

    if only_in_1:
        print(f"\n  NODES ONLY IN {label1} ({len(only_in_1)}):")
        for kinds_tuple, node_id in only_in_1:
            node = nodes1_by_key[(kinds_tuple, node_id)]
            kinds_str = ", ".join(kinds_tuple) or "(no kind)"
            props = node.get("properties", {})
            name = props.get("name", "")
            print(f"    [{kinds_str}] {node_id}  (name: {name})")
            if verbose and props:
                for pk, pv in sorted(props.items()):
                    sv = str(pv)
                    if len(sv) > 100:
                        sv = sv[:100] + "..."
                    print(f"      {pk}: {sv}")

    if only_in_2:
        print(f"\n  NODES ONLY IN {label2} ({len(only_in_2)}):")
        for kinds_tuple, node_id in only_in_2:
            node = nodes2_by_key[(kinds_tuple, node_id)]
            kinds_str = ", ".join(kinds_tuple) or "(no kind)"
            props = node.get("properties", {})
            name = props.get("name", "")
            print(f"    [{kinds_str}] {node_id}  (name: {name})")
            if verbose and props:
                for pk, pv in sorted(props.items()):
                    sv = str(pv)
                    if len(sv) > 100:
                        sv = sv[:100] + "..."
                    print(f"      {pk}: {sv}")

    # Compare properties of nodes in both
    prop_diff_count = 0
    prop_diffs = []
    for key in sorted(in_both):
        n1 = nodes1_by_key[key]
        n2 = nodes2_by_key[key]
        props1 = n1.get("properties", {})
        props2 = n2.get("properties", {})
        diffs = compare_properties(props1, props2, label1, label2, normalize_ws)
        if diffs:
            prop_diff_count += 1
            if verbose:
                prop_diffs.append((key, diffs))

    if prop_diff_count > 0:
        print(f"\n  Nodes in both with property differences: {prop_diff_count}")
        if verbose:
            for (kinds_tuple, node_id), diffs in prop_diffs:
                kinds_str = ", ".join(kinds_tuple) or "(no kind)"
                print(f"\n    [{kinds_str}] {node_id}")
                for d in diffs:
                    print(f"    {d}")

    return only_in_1, only_in_2


def main():
    parser = argparse.ArgumentParser(
        description="Compare two MSSQLHound JSON output files and identify edge/node differences."
    )
    parser.add_argument("file1", help="First JSON file path")
    parser.add_argument("file2", help="Second JSON file path")
    parser.add_argument(
        "--label1", default=None, help="Label for first file (default: filename)"
    )
    parser.add_argument(
        "--label2", default=None, help="Label for second file (default: filename)"
    )
    parser.add_argument(
        "--show-property-diffs",
        action="store_true",
        default=True,
        help="Show property differences for matching edges (default: True)",
    )
    parser.add_argument(
        "--no-property-diffs",
        action="store_true",
        help="Skip showing property differences",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show all edge details including full properties",
    )
    parser.add_argument(
        "--normalize-ids",
        action="store_true",
        help="Normalize node IDs between files using node labels (handles SID vs hostname differences)",
    )
    parser.add_argument(
        "--normalize-whitespace",
        action="store_true",
        help="Normalize whitespace when comparing properties (handles PS1 indentation vs Go clean text)",
    )
    parser.add_argument(
        "--dedup",
        action="store_true",
        help="Deduplicate edges by (source, target, kind) before comparing (reduces each duplicate set to one edge, "
             "so PS1's duplicate-edge bugs appear as normal property diffs rather than count mismatches)",
    )

    args = parser.parse_args()

    label1 = args.label1 or args.file1.split("/")[-1]
    label2 = args.label2 or args.file2.split("/")[-1]
    show_props = args.show_property_diffs and not args.no_property_diffs

    # Load data
    print(f"Loading {label1}...")
    data1 = load_json(args.file1)
    print(f"Loading {label2}...")
    data2 = load_json(args.file2)

    # Show top-level structure
    print(f"\n{'='*80}")
    print("TOP-LEVEL STRUCTURE")
    print(f"{'='*80}")
    if isinstance(data1, dict):
        print(f"  {label1}: dict with keys {list(data1.keys())}")
    else:
        print(f"  {label1}: {type(data1).__name__} with {len(data1)} items")
    if isinstance(data2, dict):
        print(f"  {label2}: dict with keys {list(data2.keys())}")
    else:
        print(f"  {label2}: {type(data2).__name__} with {len(data2)} items")

    # Compare nodes
    compare_nodes(data1, data2, label1, label2, verbose=args.verbose, normalize_ws=args.normalize_whitespace)

    # Extract edges
    edges1 = extract_edges(data1)
    edges2 = extract_edges(data2)

    print(f"\n  {label1}: {len(edges1)} edges extracted")
    print(f"  {label2}: {len(edges2)} edges extracted")

    # Count edge types
    type_counts1 = defaultdict(int)
    type_counts2 = defaultdict(int)

    for e in edges1:
        kind = e.get("kind", e.get("type", "UNKNOWN"))
        type_counts1[kind] += 1
    for e in edges2:
        kind = e.get("kind", e.get("type", "UNKNOWN"))
        type_counts2[kind] += 1

    all_types = sorted(set(list(type_counts1.keys()) + list(type_counts2.keys())))

    print(f"\n{'='*80}")
    print("EDGE TYPE COUNTS")
    print(f"{'='*80}")
    print(f"  {'Edge Type':<45} {label1:>10} {label2:>10}  {'Diff':>8}")
    print(f"  {'-'*45} {'-'*10} {'-'*10}  {'-'*8}")
    for t in all_types:
        c1 = type_counts1.get(t, 0)
        c2 = type_counts2.get(t, 0)
        diff = c1 - c2
        diff_str = f"+{diff}" if diff > 0 else str(diff) if diff != 0 else ""
        marker = " <---" if diff != 0 else ""
        print(f"  {t:<45} {c1:>10} {c2:>10}  {diff_str:>8}{marker}")

    total1 = sum(type_counts1.values())
    total2 = sum(type_counts2.values())
    print(f"  {'-'*45} {'-'*10} {'-'*10}  {'-'*8}")
    print(f"  {'TOTAL':<45} {total1:>10} {total2:>10}  {total1-total2:>+8}")

    # Build ID normalization mapping if requested
    id_mapping = None
    if args.normalize_ids:
        id_mapping = build_node_id_mapping(data1, data2)
        if id_mapping:
            print(f"\n  ID normalization: mapped {len(id_mapping)} node IDs from {label1} to {label2}")
        else:
            print(f"\n  ID normalization: no mappable differences found")

    # Build edge maps by key (source, target, kind)
    edges1_by_key = defaultdict(list)
    edges2_by_key = defaultdict(list)

    for e in edges1:
        key = make_edge_key(e, id_mapping)
        edges1_by_key[key].append(e)
    for e in edges2:
        key = make_edge_key(e)
        edges2_by_key[key].append(e)

    # Dedup: reduce each key's list to its first element, collapsing duplicates
    if args.dedup:
        deduped1 = sum(len(v) - 1 for v in edges1_by_key.values() if len(v) > 1)
        deduped2 = sum(len(v) - 1 for v in edges2_by_key.values() if len(v) > 1)
        if deduped1 or deduped2:
            print(f"\n  --dedup: removed {deduped1} duplicate(s) from {label1}, {deduped2} from {label2}")
        edges1_by_key = {k: [v[0]] for k, v in edges1_by_key.items()}
        edges2_by_key = {k: [v[0]] for k, v in edges2_by_key.items()}

    keys1 = set(edges1_by_key.keys())
    keys2 = set(edges2_by_key.keys())

    only_in_1 = keys1 - keys2
    only_in_2 = keys2 - keys1
    in_both = keys1 & keys2

    print(f"\n{'='*80}")
    print("EDGE DIFFERENCE SUMMARY")
    print(f"{'='*80}")
    print(f"  Unique edge keys (source, target, kind):")
    print(f"    Only in {label1}: {len(only_in_1)}")
    print(f"    Only in {label2}: {len(only_in_2)}")
    print(f"    In both: {len(in_both)}")

    # Group differences by edge kind
    only1_by_kind = defaultdict(list)
    only2_by_kind = defaultdict(list)

    for key in only_in_1:
        _, _, kind = key
        only1_by_kind[kind].append(key)
    for key in only_in_2:
        _, _, kind = key
        only2_by_kind[kind].append(key)

    # Show edges only in file 1
    if only_in_1:
        print(f"\n{'='*80}")
        print(f"EDGES ONLY IN {label1} ({len(only_in_1)} edges)")
        print(f"{'='*80}")
        for kind in sorted(only1_by_kind.keys()):
            edges_of_kind = only1_by_kind[kind]
            print(f"\n  --- {kind} ({len(edges_of_kind)} edges) ---")
            for source, target, k in sorted(edges_of_kind):
                print(f"    {source}")
                print(f"      -> {target}")
                if args.verbose:
                    for e in edges1_by_key[(source, target, k)]:
                        props = get_edge_properties(e)
                        for pk, pv in sorted(props.items()):
                            sv = str(pv)
                            if len(sv) > 100:
                                sv = sv[:100] + "..."
                            print(f"         {pk}: {sv}")
                print()

    # Show edges only in file 2
    if only_in_2:
        print(f"\n{'='*80}")
        print(f"EDGES ONLY IN {label2} ({len(only_in_2)} edges)")
        print(f"{'='*80}")
        for kind in sorted(only2_by_kind.keys()):
            edges_of_kind = only2_by_kind[kind]
            print(f"\n  --- {kind} ({len(edges_of_kind)} edges) ---")
            for source, target, k in sorted(edges_of_kind):
                print(f"    {source}")
                print(f"      -> {target}")
                if args.verbose:
                    for e in edges2_by_key[(source, target, k)]:
                        props = get_edge_properties(e)
                        for pk, pv in sorted(props.items()):
                            sv = str(pv)
                            if len(sv) > 100:
                                sv = sv[:100] + "..."
                            print(f"         {pk}: {sv}")
                print()

    # Show property differences for matching edges
    if show_props and in_both:
        prop_diff_count = 0
        prop_diff_details = defaultdict(list)

        for key in sorted(in_both):
            source, target, kind = key
            e1_list = edges1_by_key[key]
            e2_list = edges2_by_key[key]

            # Compare first edge of each (most common case: 1:1 match)
            # If there are multiple edges with same key, compare pairwise
            max_len = max(len(e1_list), len(e2_list))

            if len(e1_list) != len(e2_list):
                prop_diff_count += 1
                detail_lines = [
                    f"  {source} -> {target}",
                    f"    Count mismatch: {label1} has {len(e1_list)}, {label2} has {len(e2_list)}",
                ]
                if args.verbose:
                    for idx, e in enumerate(e1_list):
                        detail_lines.append(f"    {label1}[{idx}] properties:")
                        for pk, pv in sorted(e.get("properties", {}).items()):
                            sv = str(pv)
                            if len(sv) > 120:
                                sv = sv[:120] + "..."
                            detail_lines.append(f"      {pk}: {sv}")
                    for idx, e in enumerate(e2_list):
                        detail_lines.append(f"    {label2}[{idx}] properties:")
                        for pk, pv in sorted(e.get("properties", {}).items()):
                            sv = str(pv)
                            if len(sv) > 120:
                                sv = sv[:120] + "..."
                            detail_lines.append(f"      {pk}: {sv}")
                prop_diff_details[kind].append("\n".join(detail_lines))
                continue

            for i in range(min(len(e1_list), len(e2_list))):
                props1 = get_edge_properties(e1_list[i])
                props2 = get_edge_properties(e2_list[i])
                diffs = compare_properties(props1, props2, label1, label2, args.normalize_whitespace)
                if diffs:
                    prop_diff_count += 1
                    detail = f"  {source} -> {target}\n" + "\n".join(diffs)
                    prop_diff_details[kind].append(detail)

        if prop_diff_count > 0:
            print(f"\n{'='*80}")
            print(f"PROPERTY DIFFERENCES IN MATCHING EDGES ({prop_diff_count} edges differ)")
            print(f"{'='*80}")

            # Category summary: (kind, property) -> {only_in_1, only_in_2, value_differs} counts
            # This gives a quick overview of systematic vs incidental differences.
            cat_counts = defaultdict(lambda: {"only_in_1": 0, "only_in_2": 0, "differs": 0, "count_mismatch": 0})
            for key in sorted(in_both):
                source, target, kind = key
                e1_list = edges1_by_key[key]
                e2_list = edges2_by_key[key]
                if len(e1_list) != len(e2_list):
                    cat_counts[(kind, "(count mismatch)")]["count_mismatch"] += 1
                    continue
                for i in range(min(len(e1_list), len(e2_list))):
                    p1 = get_edge_properties(e1_list[i])
                    p2 = get_edge_properties(e2_list[i])
                    all_keys = set(list(p1.keys()) + list(p2.keys()))
                    for pk in all_keys:
                        in1 = pk in p1
                        in2 = pk in p2
                        if in1 and not in2:
                            cat_counts[(kind, pk)]["only_in_1"] += 1
                        elif not in1 and in2:
                            cat_counts[(kind, pk)]["only_in_2"] += 1
                        else:
                            v1 = normalize_value(p1[pk], args.normalize_whitespace)
                            v2 = normalize_value(p2[pk], args.normalize_whitespace)
                            if v1 != v2:
                                cat_counts[(kind, pk)]["differs"] += 1

            print(f"\n  {'Edge Kind':<40} {'Property':<25} {'Only in '+label1:>12} {'Only in '+label2:>12} {'Value diff':>10}")
            print(f"  {'-'*40} {'-'*25} {'-'*12} {'-'*12} {'-'*10}")
            for (kind, prop) in sorted(cat_counts.keys()):
                c = cat_counts[(kind, prop)]
                o1 = c["only_in_1"] or c["count_mismatch"]
                o2 = c["only_in_2"]
                vd = c["differs"]
                print(f"  {kind:<40} {prop:<25} {o1 if o1 else '':>12} {o2 if o2 else '':>12} {vd if vd else '':>10}")

            # Per-edge details (only shown with -v)
            if args.verbose:
                for kind in sorted(prop_diff_details.keys()):
                    details = prop_diff_details[kind]
                    print(f"\n  --- {kind} ({len(details)} edges with property diffs) ---")
                    for d in details:
                        print(d)
                        print()
        else:
            print(f"\n{'='*80}")
            print("PROPERTY DIFFERENCES: None found for matching edges")
            print(f"{'='*80}")

    # Summary
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"  {label1}: {total1} total edges, {len(all_types)} edge types")
    print(f"  {label2}: {total2} total edges, {len(all_types)} edge types")
    print(f"  Only in {label1}: {len(only_in_1)} edges across {len(only1_by_kind)} types")
    print(f"  Only in {label2}: {len(only_in_2)} edges across {len(only2_by_kind)} types")
    if show_props:
        print(f"  Matching edges with property differences: {prop_diff_count}")


if __name__ == "__main__":
    main()
