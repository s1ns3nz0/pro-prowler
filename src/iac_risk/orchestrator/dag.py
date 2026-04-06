"""DAG definition and topological sort for agent execution order."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentNode:
    name: str
    dependencies: list[str] = field(default_factory=list)
    critical: bool = True


class CycleError(Exception):
    pass


class DAG:
    """Directed Acyclic Graph of agent nodes."""

    def __init__(self) -> None:
        self._nodes: dict[str, AgentNode] = {}

    def add_node(self, node: AgentNode) -> None:
        self._nodes[node.name] = node

    def get_node(self, name: str) -> AgentNode | None:
        return self._nodes.get(name)

    @property
    def nodes(self) -> dict[str, AgentNode]:
        return dict(self._nodes)

    def get_execution_order(self) -> list[str]:
        """Return topological sort of nodes. Raises CycleError if cycle detected."""
        visited: set[str] = set()
        in_stack: set[str] = set()
        order: list[str] = []

        def visit(name: str) -> None:
            if name in in_stack:
                raise CycleError(f"Cycle detected involving node '{name}'")
            if name in visited:
                return
            in_stack.add(name)
            node = self._nodes[name]
            for dep in node.dependencies:
                if dep in self._nodes:
                    visit(dep)
            in_stack.remove(name)
            visited.add(name)
            order.append(name)

        for name in self._nodes:
            visit(name)

        return order

    def get_ready_nodes(self, completed: set[str]) -> list[str]:
        """Return nodes whose dependencies are all in the completed set."""
        ready: list[str] = []
        for name, node in self._nodes.items():
            if name in completed:
                continue
            if all(dep in completed for dep in node.dependencies):
                ready.append(name)
        return ready

    def validate(self) -> None:
        """Validate DAG: check for cycles and missing dependencies."""
        self.get_execution_order()  # raises CycleError on cycles
        for name, node in self._nodes.items():
            for dep in node.dependencies:
                if dep not in self._nodes:
                    raise ValueError(f"Node '{name}' depends on unknown node '{dep}'")


def build_default_dag(skip_context: bool = False) -> DAG:
    """Build the default 7-agent pipeline DAG."""
    dag = DAG()

    dag.add_node(AgentNode(name="iac_parser", dependencies=[], critical=True))

    if not skip_context:
        dag.add_node(AgentNode(
            name="repo_analysis", dependencies=[], critical=False,
        ))
        dag.add_node(AgentNode(
            name="context_analysis",
            dependencies=["repo_analysis"],
            critical=False,
        ))

    dag.add_node(AgentNode(name="cloud_misconfig", dependencies=["iac_parser"], critical=True))

    risk_deps = ["iac_parser", "cloud_misconfig"]
    if not skip_context:
        risk_deps.append("context_analysis")
    dag.add_node(AgentNode(
        name="risk_analysis",
        dependencies=risk_deps,
        critical=True,
    ))

    impact_deps = ["risk_analysis"]
    if not skip_context:
        impact_deps.append("context_analysis")
    dag.add_node(AgentNode(name="impact_assessment", dependencies=impact_deps, critical=True))

    dag.add_node(AgentNode(
        name="compliance_mapping",
        dependencies=["cloud_misconfig", "impact_assessment"],
        critical=True,
    ))

    dag.add_node(AgentNode(
        name="change_management",
        dependencies=["compliance_mapping"],
        critical=True,
    ))

    dag.add_node(AgentNode(
        name="report_generation",
        dependencies=["impact_assessment", "compliance_mapping", "change_management"],
        critical=True,
    ))

    dag.validate()
    return dag
