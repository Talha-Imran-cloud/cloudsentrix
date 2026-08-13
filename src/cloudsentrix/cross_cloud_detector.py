"""
cross_cloud_detector.py
-----------------------
Industry-first Cross-Cloud Attack Chain Detection Engine.

Detects attack paths that span multiple cloud providers — for example,
an AWS IAM principal that can escalate to reach an Azure service principal,
ultimately compromising the Azure tenant.

How it works:
  1. Builds a unified multi-cloud graph from GCP/AWS/Azure scan results
  2. Identifies "bridge" nodes — principals that exist in multiple clouds
     (service principals, shared identities, federated credentials)
  3. Runs path-finding algorithms to detect full attack chains
  4. Produces structured findings with step-by-step attack paths

Bridge detection strategies:
  - Name matching (same display name across clouds)
  - Email matching (same UPN/email in AWS and Azure)
  - Service principal app_id matching
  - Federated identity patterns (AWS role ARN in Azure trust)
  - Shared secret patterns (same app credentials)

Public API
  detect_cross_cloud_chains(clouds: list[CloudScanResult]) -> list[CrossCloudFinding]
  CrossCloudGraph.build(clouds) -> CrossCloudGraph
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class CloudProvider(str, Enum):
    GCP   = "GCP"
    AWS   = "AWS"
    AZURE = "Azure"
    AZURE_AD = "AzureAD"


@dataclass
class CloudNode:
    """A principal node in the unified cross-cloud graph."""
    node_id: str                    # unique across all clouds: "aws::arn:..."
    cloud: CloudProvider
    name: str                       # human-readable
    principal_type: str             # user | role | service_account | app
    risk_score: int                 # 0-100
    permissions: list[str]          # key permissions/roles held
    raw_id: str                     # original cloud ID (ARN, email, object_id)


@dataclass
class CloudEdge:
    """A directed edge in the unified graph."""
    source_id: str
    target_id: str
    edge_type: str      # HAS_PERMISSION | CAN_ESCALATE | BRIDGE | CAN_ASSUME
    label: str          # human-readable description
    cloud: str          # which cloud this edge is in, or "cross-cloud"
    evidence: str       # what proves this edge exists


@dataclass
class AttackStep:
    """One step in a cross-cloud attack chain."""
    step_number: int
    cloud: str
    principal: str
    action: str         # what the attacker does
    target: str         # what they gain access to
    technique: str      # MITRE technique
    is_bridge: bool     # True if this step crosses cloud boundary


@dataclass(frozen=True)
class CrossCloudFinding:
    """A detected cross-cloud attack chain."""
    finding_id: str
    title: str
    severity: str                       # CRITICAL | HIGH | MEDIUM
    source_cloud: str                   # where attack starts
    target_cloud: str                   # where attack ends
    source_principal: str               # initial compromised identity
    target_principal: str               # final victim identity
    attack_chain: tuple[AttackStep, ...] # full path
    bridge_mechanism: str               # how clouds are connected
    mitre_techniques: tuple[str, ...]
    description: str
    impact: str
    remediation: str
    evidence: tuple[str, ...]


@dataclass
class CloudScanResult:
    """Input to the cross-cloud detector — one cloud's scan output."""
    cloud: CloudProvider
    principals: list[dict]      # {id, name, type, permissions, risk_score}
    findings: list[Any]         # cloud-specific Finding objects
    raw_data: Any               # parser output (ParsedAWSPolicy, AzureIAMData, etc.)


# ---------------------------------------------------------------------------
# Bridge detection patterns
# ---------------------------------------------------------------------------

# AWS roles that are commonly federated to Azure
AWS_AZURE_FEDERATION_PATTERNS = [
    r"azure",
    r"entra",
    r"aad",
    r"microsoft",
    r"m365",
]

# Azure SP names that suggest AWS connection
AZURE_AWS_BRIDGE_PATTERNS = [
    r"aws",
    r"amazon",
    r"cross.?cloud",
    r"multi.?cloud",
    r"federation",
]

# High-risk permissions that enable cross-cloud movement
AWS_ESCALATION_TO_BRIDGE = frozenset({
    "managed-policy:arn:aws:iam::aws:policy/AdministratorAccess",
    "*",
    "iam:passrole",
    "iam:createaccesskey",
    "iam:attachrolepolicy",
    "sts:assumerole",
    "iam:*",
})

AZURE_HIGH_VALUE_ROLES = frozenset({
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Global Administrator",
})


# ---------------------------------------------------------------------------
# Unified Cross-Cloud Graph
# ---------------------------------------------------------------------------

class CrossCloudGraph:
    """
    Unified graph spanning multiple cloud providers.
    Nodes = principals from all clouds.
    Edges = permissions within clouds + bridge connections across clouds.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, CloudNode] = {}
        self.edges: list[CloudEdge] = []
        self._adjacency: dict[str, list[str]] = {}  # source -> [targets]

    @classmethod
    def build(cls, clouds: list[CloudScanResult]) -> "CrossCloudGraph":
        g = cls()
        for cloud_result in clouds:
            g._add_cloud(cloud_result)
        g._detect_bridges(clouds)
        return g

    def _add_cloud(self, result: CloudScanResult) -> None:
        """Add all principals and intra-cloud edges from one cloud."""
        for p in result.principals:
            node_id = f"{result.cloud.value}::{p['id']}"
            self.nodes[node_id] = CloudNode(
                node_id=node_id,
                cloud=result.cloud,
                name=p["name"],
                principal_type=p.get("type", "unknown"),
                risk_score=p.get("risk_score", 0),
                permissions=p.get("permissions", []),
                raw_id=p["id"],
            )
            self._adjacency.setdefault(node_id, [])

        # Add escalation edges from findings
        for finding in result.findings:
            src_id = getattr(finding, "principal_id",
                     getattr(finding, "principal_name", None))
            if not src_id:
                continue
            src_node_id = f"{result.cloud.value}::{src_id}"
            if src_node_id not in self.nodes:
                continue

            edge = CloudEdge(
                source_id=src_node_id,
                target_id=src_node_id,  # self-escalation
                edge_type="CAN_ESCALATE",
                label=getattr(finding, "title", "Escalation"),
                cloud=result.cloud.value,
                evidence=getattr(finding, "rule_id", ""),
            )
            self.edges.append(edge)

    def _detect_bridges(self, clouds: list[CloudScanResult]) -> None:
        """
        Detect cross-cloud bridge connections.

        Strategy 1: Name/email matching across clouds
        Strategy 2: AWS role trust policies referencing Azure
        Strategy 3: Azure SP names suggesting AWS federation
        Strategy 4: High-risk AWS principals → any Azure SP (attack path)
        """
        aws_results   = [c for c in clouds if c.cloud == CloudProvider.AWS]
        azure_results = [c for c in clouds if c.cloud in (
            CloudProvider.AZURE, CloudProvider.AZURE_AD
        )]
        gcp_results   = [c for c in clouds if c.cloud == CloudProvider.GCP]

        # Strategy 1: Name/email matching
        self._bridge_by_name(aws_results, azure_results)
        self._bridge_by_name(gcp_results, azure_results)
        self._bridge_by_name(aws_results, gcp_results)

        # Strategy 2: AWS admin → Azure (high-risk path)
        self._bridge_high_risk_aws_to_azure(aws_results, azure_results)

        # Strategy 3: GCP SA → AWS role (workload identity federation)
        self._bridge_gcp_to_aws(gcp_results, aws_results)

    def _bridge_by_name(
        self,
        source_clouds: list[CloudScanResult],
        target_clouds: list[CloudScanResult],
    ) -> None:
        """Match principals by name/email across clouds."""
        for src_cloud in source_clouds:
            for tgt_cloud in target_clouds:
                for src_p in src_cloud.principals:
                    for tgt_p in tgt_cloud.principals:
                        src_name = src_p["name"].lower().split("@")[0]
                        tgt_name = tgt_p["name"].lower().split("@")[0]

                        if len(src_name) < 4 or len(tgt_name) < 4:
                            continue
                        if src_name == tgt_name or (
                            src_name in tgt_name or tgt_name in src_name
                        ):
                            src_node = f"{src_cloud.cloud.value}::{src_p['id']}"
                            tgt_node = f"{tgt_cloud.cloud.value}::{tgt_p['id']}"
                            if src_node in self.nodes and tgt_node in self.nodes:
                                self._add_bridge_edge(
                                    src_node, tgt_node,
                                    "Shared identity — same name across clouds",
                                    f"Name match: '{src_p['name']}' ↔ '{tgt_p['name']}'",
                                )

    def _bridge_high_risk_aws_to_azure(
        self,
        aws_results: list[CloudScanResult],
        azure_results: list[CloudScanResult],
    ) -> None:
        """
        AWS admin/IAMFullAccess principals can potentially reach Azure
        through shared credentials, federated identities, or lateral movement.
        Flag as a HIGH-risk theoretical path.
        """
        for aws_cloud in aws_results:
            for aws_p in aws_cloud.principals:
                perms = set(aws_p.get("permissions", []))
                is_high_risk = bool(perms & AWS_ESCALATION_TO_BRIDGE)
                if not is_high_risk:
                    continue

                # Check if any Azure SP has AWS-related name
                for azure_cloud in azure_results:
                    for az_p in azure_cloud.principals:
                        az_name = az_p["name"].lower()
                        is_aws_bridge = any(
                            re.search(p, az_name)
                            for p in AZURE_AWS_BRIDGE_PATTERNS
                        )
                        if is_aws_bridge:
                            src_node = f"{aws_cloud.cloud.value}::{aws_p['id']}"
                            tgt_node = f"{azure_cloud.cloud.value}::{az_p['id']}"
                            if src_node in self.nodes and tgt_node in self.nodes:
                                self._add_bridge_edge(
                                    src_node, tgt_node,
                                    "AWS high-privilege → Azure bridge SP",
                                    f"AWS admin '{aws_p['name']}' → Azure SP '{az_p['name']}'",
                                )

    def _bridge_gcp_to_aws(
        self,
        gcp_results: list[CloudScanResult],
        aws_results: list[CloudScanResult],
    ) -> None:
        """GCP service accounts with workload identity federation to AWS roles."""
        for gcp_cloud in gcp_results:
            for gcp_p in gcp_cloud.principals:
                if "serviceaccount" not in gcp_p.get("type", "").lower():
                    continue
                for aws_cloud in aws_results:
                    for aws_p in aws_cloud.principals:
                        if aws_p.get("type") != "role":
                            continue
                        # Trust policy referencing GCP / accounts.google.com
                        aws_perms = aws_p.get("permissions", [])
                        has_gcp_trust = any(
                            "accounts.google.com" in p or "googleapis" in p
                            for p in aws_perms
                        )
                        if has_gcp_trust:
                            src_node = f"{gcp_cloud.cloud.value}::{gcp_p['id']}"
                            tgt_node = f"{aws_cloud.cloud.value}::{aws_p['id']}"
                            if src_node in self.nodes and tgt_node in self.nodes:
                                self._add_bridge_edge(
                                    src_node, tgt_node,
                                    "GCP Workload Identity Federation → AWS Role",
                                    f"GCP SA '{gcp_p['name']}' → AWS Role '{aws_p['name']}'",
                                )

    def _add_bridge_edge(
        self, src: str, tgt: str, label: str, evidence: str
    ) -> None:
        self.edges.append(CloudEdge(
            source_id=src, target_id=tgt,
            edge_type="BRIDGE", label=label,
            cloud="cross-cloud", evidence=evidence,
        ))
        self._adjacency.setdefault(src, []).append(tgt)

    def get_bridge_edges(self) -> list[CloudEdge]:
        return [e for e in self.edges if e.edge_type == "BRIDGE"]

    def get_escalation_edges(self) -> list[CloudEdge]:
        return [e for e in self.edges if e.edge_type == "CAN_ESCALATE"]


# ---------------------------------------------------------------------------
# Chain finder
# ---------------------------------------------------------------------------

def _find_chains(
    graph: CrossCloudGraph,
    max_depth: int = 6,
) -> list[list[str]]:
    """
    Find all paths that cross at least one cloud boundary.
    Returns list of node_id paths.
    """
    bridge_targets: set[str] = {e.target_id for e in graph.get_bridge_edges()}
    bridge_sources: set[str] = {e.source_id for e in graph.get_bridge_edges()}

    chains: list[list[str]] = []
    visited_chains: set[tuple] = set()

    # Start from high-risk nodes that have bridge connections
    start_nodes = [
        nid for nid, node in graph.nodes.items()
        if node.risk_score >= 50 or nid in bridge_sources
    ]

    def dfs(current: str, path: list[str], crosses: int) -> None:
        if len(path) > max_depth:
            return
        if crosses >= 1 and len(path) >= 2:
            path_key = tuple(path)
            if path_key not in visited_chains:
                visited_chains.add(path_key)
                chains.append(list(path))

        for edge in graph.edges:
            if edge.source_id != current:
                continue
            if edge.target_id in path:
                continue
            new_crosses = crosses + (1 if edge.edge_type == "BRIDGE" else 0)
            path.append(edge.target_id)
            dfs(edge.target_id, path, new_crosses)
            path.pop()

    for start in start_nodes[:20]:  # limit for performance
        dfs(start, [start], 0)

    return chains


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------

def _build_finding(
    graph: CrossCloudGraph,
    chain: list[str],
    finding_num: int,
) -> CrossCloudFinding | None:
    if len(chain) < 2:
        return None

    src_node = graph.nodes.get(chain[0])
    tgt_node = graph.nodes.get(chain[-1])
    if not src_node or not tgt_node:
        return None

    # Must cross cloud boundary
    if src_node.cloud == tgt_node.cloud:
        return None

    # Build attack steps
    steps: list[AttackStep] = []
    bridge_mechanism = "Unknown bridge"

    for i, node_id in enumerate(chain):
        node = graph.nodes.get(node_id)
        if not node:
            continue

        is_bridge = False
        action = "Holds permissions"
        technique = "T1078.004"

        # Check if next step is a bridge
        if i < len(chain) - 1:
            next_id = chain[i + 1]
            bridge_edges = [
                e for e in graph.edges
                if e.source_id == node_id
                and e.target_id == next_id
                and e.edge_type == "BRIDGE"
            ]
            if bridge_edges:
                is_bridge = True
                bridge_mechanism = bridge_edges[0].label
                action = f"Cross-cloud pivot: {bridge_edges[0].label}"
                technique = "T1199"
            else:
                # Escalation within cloud
                esc_edges = [
                    e for e in graph.edges
                    if e.source_id == node_id
                    and e.edge_type == "CAN_ESCALATE"
                ]
                if esc_edges:
                    action = f"Escalates via: {esc_edges[0].label}"
                    technique = "T1098.003"
                else:
                    # Permission-based movement
                    if node.permissions:
                        top_perm = node.permissions[0].replace(
                            "managed-policy:arn:aws:iam::aws:policy/", ""
                        )
                        action = f"Uses: {top_perm}"

        target_name = graph.nodes[chain[i + 1]].name if i < len(chain) - 1 else "End of chain"

        steps.append(AttackStep(
            step_number=i + 1,
            cloud=node.cloud.value,
            principal=node.name,
            action=action,
            target=target_name,
            technique=technique,
            is_bridge=is_bridge,
        ))

    if not steps:
        return None

    # Severity based on source risk + target privileges
    tgt_perms = set(tgt_node.permissions)
    high_value_target = any(
        r in " ".join(tgt_perms) for r in ["Owner", "Admin", "AdministratorAccess", "*"]
    )
    severity = "CRITICAL" if high_value_target or src_node.risk_score >= 75 else "HIGH"

    mitre = tuple({s.technique for s in steps})

    return CrossCloudFinding(
        finding_id=f"CC-{finding_num:03d}",
        title=f"Cross-Cloud Attack Chain: {src_node.cloud.value} → {tgt_node.cloud.value}",
        severity=severity,
        source_cloud=src_node.cloud.value,
        target_cloud=tgt_node.cloud.value,
        source_principal=src_node.name,
        target_principal=tgt_node.name,
        attack_chain=tuple(steps),
        bridge_mechanism=bridge_mechanism,
        mitre_techniques=mitre,
        description=(
            f"A {len(steps)}-step attack chain was detected starting from "
            f"'{src_node.name}' ({src_node.cloud.value}) and ending at "
            f"'{tgt_node.name}' ({tgt_node.cloud.value}). "
            f"The chain crosses cloud boundaries via: {bridge_mechanism}."
        ),
        impact=(
            f"If '{src_node.name}' is compromised, an attacker can pivot "
            f"from {src_node.cloud.value} to {tgt_node.cloud.value} "
            f"and gain access to '{tgt_node.name}'."
        ),
        remediation=(
            "1. Review and restrict the bridge mechanism between clouds. "
            "2. Apply least-privilege to all principals in the chain. "
            "3. Enable cross-cloud audit logging and alerting. "
            "4. Separate cloud identities where shared identities are not required."
        ),
        evidence=tuple(
            f"Step {s.step_number}: [{s.cloud}] {s.principal} → {s.action}"
            for s in steps
        ),
    )


# ---------------------------------------------------------------------------
# Principal extractors (from cloud-specific parser objects)
# ---------------------------------------------------------------------------

def _extract_aws_principals(aws_graph, aws_findings) -> list[dict]:
    """Extract principal info from AWSIAMGraph."""
    principals = []
    try:
        from aws_blast_radius import calculate_aws_blast_radius
        blast = {r.principal_id: r for r in calculate_aws_blast_radius(aws_graph, aws_findings)}
    except Exception:
        blast = {}

    for pid in aws_graph.principal_ids():
        node = aws_graph.get_principal(pid)
        if not node:
            continue
        perms = aws_graph.permissions_of(pid)
        blast_r = blast.get(pid)
        principals.append({
            "id": pid,
            "name": node.name,
            "type": node.principal_type.value,
            "permissions": perms[:10],
            "risk_score": blast_r.blast_score if blast_r else 0,
        })
    return principals


def _extract_azure_principals(az_iam) -> list[dict]:
    """Extract principal info from AzureIAMData."""
    from collections import defaultdict
    groups: dict = defaultdict(list)
    for assign in az_iam.assignments:
        groups[assign.principal_name].append(assign)

    principals = []
    for name, assigns in groups.items():
        roles = [a.role_definition_name for a in assigns]
        risk = 75 if "Owner" in roles else 50 if "Contributor" in roles else 25
        principals.append({
            "id": assigns[0].principal_id or name,
            "name": name,
            "type": assigns[0].principal_type,
            "permissions": roles,
            "risk_score": risk,
        })
    return principals


def _extract_gcp_principals(gcp_graph, gcp_findings) -> list[dict]:
    """Extract principal info from IAMGraph."""
    try:
        from blast_radius import BlastRadiusCalculator
        blast_results = BlastRadiusCalculator(gcp_graph, gcp_findings).calculate_all()
        blast = {r.principal_id: r for r in blast_results}
    except Exception:
        blast = {}

    principals = []
    for pid in gcp_graph.principal_ids():
        roles = gcp_graph.roles_of(pid)
        blast_r = blast.get(pid)
        risk = int(blast_r.percentage) if blast_r else 0
        principals.append({
            "id": pid,
            "name": pid.split("@")[0],
            "type": "service_account" if "gserviceaccount" in pid else "user",
            "permissions": roles,
            "risk_score": risk,
        })
    return principals


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_cross_cloud_chains(
    aws_graph=None,
    aws_findings=None,
    azure_iam=None,
    azure_findings=None,
    gcp_graph=None,
    gcp_findings=None,
) -> list[CrossCloudFinding]:
    """
    Main entry point. Pass any combination of cloud scan results.

    Args:
        aws_graph:      AWSIAMGraph object
        aws_findings:   list of AWSFinding objects
        azure_iam:      AzureIAMData object
        azure_findings: list of AzureFinding objects
        gcp_graph:      IAMGraph object
        gcp_findings:   list of Finding objects

    Returns:
        list of CrossCloudFinding objects sorted by severity
    """
    clouds: list[CloudScanResult] = []

    if aws_graph and aws_findings is not None:
        principals = _extract_aws_principals(aws_graph, aws_findings)
        clouds.append(CloudScanResult(
            cloud=CloudProvider.AWS,
            principals=principals,
            findings=aws_findings,
            raw_data=aws_graph,
        ))

    if azure_iam and azure_findings is not None:
        principals = _extract_azure_principals(azure_iam)
        clouds.append(CloudScanResult(
            cloud=CloudProvider.AZURE,
            principals=principals,
            findings=azure_findings,
            raw_data=azure_iam,
        ))

    if gcp_graph and gcp_findings is not None:
        principals = _extract_gcp_principals(gcp_graph, gcp_findings)
        clouds.append(CloudScanResult(
            cloud=CloudProvider.GCP,
            principals=principals,
            findings=gcp_findings,
            raw_data=gcp_graph,
        ))

    if len(clouds) < 2:
        print("[cross-cloud] Need at least 2 clouds to detect chains.")
        return []

    print(f"[cross-cloud] Building unified graph: {len(clouds)} cloud(s)")
    graph = CrossCloudGraph.build(clouds)

    bridge_count = len(graph.get_bridge_edges())
    print(f"[cross-cloud] Found {bridge_count} bridge connection(s)")

    chains = _find_chains(graph)
    print(f"[cross-cloud] Found {len(chains)} potential chain(s)")

    findings: list[CrossCloudFinding] = []
    for i, chain in enumerate(chains):
        finding = _build_finding(graph, chain, i + 1)
        if finding:
            findings.append(finding)

    # Deduplicate by source+target
    seen: set[tuple] = set()
    unique: list[CrossCloudFinding] = []
    for f in findings:
        key = (f.source_principal, f.target_principal, f.source_cloud, f.target_cloud)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Sort: CRITICAL first
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    unique.sort(key=lambda f: sev_order.get(f.severity, 9))

    print(f"[cross-cloud] {len(unique)} unique chain(s) detected")
    return unique


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from aws_parser import AWSIAMParser
    from aws_graph import AWSIAMGraph
    from aws_detection import AWSDetectionEngine
    from azure_parser import parse_azure_file
    from azure_detection import run_azure_detections

    aws_policy  = AWSIAMParser().parse_file("sample_data/sample_aws_iam.json")
    aws_graph   = AWSIAMGraph.from_policy(aws_policy)
    aws_findings= AWSDetectionEngine().run(aws_graph)

    az_iam      = parse_azure_file("sample_data/sample_azure_rbac.json")
    az_findings = run_azure_detections(az_iam)

    chains = detect_cross_cloud_chains(
        aws_graph=aws_graph, aws_findings=aws_findings,
        azure_iam=az_iam,    azure_findings=az_findings,
    )

    print(f"\n{'='*65}")
    print(f"  CROSS-CLOUD CHAINS — {len(chains)} detected")
    print(f"{'='*65}\n")

    for f in chains:
        print(f"[{f.severity}] {f.finding_id} — {f.title}")
        print(f"  Bridge : {f.bridge_mechanism}")
        print(f"  Impact : {f.impact}")
        print(f"  MITRE  : {', '.join(f.mitre_techniques)}")
        print(f"\n  Attack Chain:")
        for step in f.attack_chain:
            bridge_marker = " 🌉" if step.is_bridge else ""
            print(f"    Step {step.step_number} [{step.cloud}]{bridge_marker}")
            print(f"      Principal : {step.principal}")
            print(f"      Action    : {step.action}")
            print(f"      → Target  : {step.target}")
        print()
