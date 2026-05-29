from .sumologic import SumoLogicCSEBackend, SumoLogicCSERuleBackend

# Backend registry for sigma-cli
backends = {
    "sumologic_cse": SumoLogicCSEBackend,
    "sumologic_cse_rule": SumoLogicCSERuleBackend,
}
