from .sumologic import SumoLogicCSEBackend, SumoLogicCSERuleBackend

# Backend registry for sigma-cli
backends = {
    "sumo_logic_cse": SumoLogicCSEBackend,
    "sumo_logic_cse_rule": SumoLogicCSERuleBackend,
}

__all__ = ["SumoLogicCSEBackend", "SumoLogicCSERuleBackend", "backends"]
