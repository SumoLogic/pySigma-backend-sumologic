from .sumologic import sumologic_cse_pipeline

# Pipeline registry for sigma-cli
pipelines = {
    "sumologic_cse": sumologic_cse_pipeline,
}
