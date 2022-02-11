from pathlib import Path


# Don't forget to update this in case this file moves. Otherwise - BAM!
def root_dir() -> Path:
    return Path(__file__).parent.parent.parent.parent
