"""
ShadowCoder Engine
Export module for the attack simulation engine.
"""

from .attack_engine import AttackEngine
from .reporter import Reporter
from .sandbox_runner import SandboxRunner
from .sabotage_engine import SabotageEngine
from .exploit_engine import ExploitEngine
from .multi_vector_engine import MultiVectorEngine, multi_vector_report_to_dict
from .architecture_mapper import ArchitectureMapper, arch_map_to_dict

__all__ = [
    "AttackEngine", "Reporter", "SandboxRunner", "SabotageEngine", "ExploitEngine",
    "MultiVectorEngine", "multi_vector_report_to_dict",
    "ArchitectureMapper", "arch_map_to_dict",
]
