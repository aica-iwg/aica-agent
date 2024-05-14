import yaml
from packaging.version import Version

def pkg_list_to_dict(depsList: list[str]) -> dict:
    depDict = {}
    for package in depsList:
            pkgName, pkgVer = package.split("==")
            depDict[pkgName] = pkgVer
    return depDict


def process_deps(pipDict : dict, filePath : str) -> None:
    with open(filePath, "r") as inputFile:
        packageStrings = inputFile.readlines()

        
        for package in packageStrings:
            
            pkgName, pkgVer = package.strip(" \n").split("==")
            if pkgName not in pipDict.keys() or Version(pipDict[pkgName]) < Version(pkgVer):
                pipDict[pkgName] = pkgVer


def main() -> None:

    with open("environment-core.yml", "r") as baseEnvFp:
        handle : dict = yaml.load(baseEnvFp, yaml.Loader)
        pipDeps :dict =  pkg_list_to_dict(handle["dependencies"][-1]["pip"])

        for reqLoc in ["manager", "honeypot", "attacker"]:
            process_deps(pipDeps, reqLoc + "/requirements.txt")
        
        handle["dependencies"][-1]["pip"] = [dep + "==" + pipDeps[dep] for dep in pipDeps.keys()]
        handle["name"] = "aica-devel"
        with open("computed-devel-environment.yml", "w") as computedEnvFp:
            computedEnvFp.write("---\n")
            yaml.dump(handle, computedEnvFp)




if __name__ == "__main__":
    main()