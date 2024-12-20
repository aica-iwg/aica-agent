import yaml
from packaging.version import Version

def pkg_list_to_dict(depsList: list[str], isPip: bool) -> dict:
    depDict = {}
    for package in depsList:
            if not isPip and type(package) is not str:
                continue
            try:
                pkgName, pkgVer = package.split("==" if isPip else "=")
            except ValueError:
                raise ValueError(f"Couldn't parse {package} into package name and version (isPip: {isPip})")
            depDict[pkgName] = pkgVer
    return depDict

def dev_corrections(pipDict: dict) -> None:
    if "psycopg2" in pipDict.keys():
        ver = pipDict["psycopg2"]
        del pipDict["psycopg2"]
        pipDict["psycopg2-binary"] = ver
        

                

def main() -> None:
    for reqLoc in ["manager"]:
        with open(reqLoc + "/environment-"+ reqLoc + ".yml", "r") as baseEnvFp:
            handle : dict = yaml.load(baseEnvFp, yaml.Loader)
            handle["name"] = reqLoc + "-dev"

            pipDeps = {}
            print(type(handle["dependencies"][-1]))
            if type(handle["dependencies"][-1]) is dict and "pip" in handle["dependencies"][-1].keys():
                pipDeps :dict =  pkg_list_to_dict(handle["dependencies"][-1]["pip"], True)
                dev_corrections(pipDeps)
            
            deps :dict =  pkg_list_to_dict(handle["dependencies"], False)
            print(deps)
            dev_corrections(deps)
            handle["dependencies"]=[dep + "=" + deps[dep] for dep in deps.keys()]
            
            if len(pipDeps) != 0:
                parsedPip = {"pip":[dep + "==" + pipDeps[dep] for dep in pipDeps.keys()]}
                if "torch" in pipDeps.keys():
                    torchloc = parsedPip["pip"].index("torch=="+ pipDeps["torch"])
                    parsedPip["pip"].insert(torchloc, "--extra-index-url https://download.pytorch.org/whl/cpu")

                handle["dependencies"].append(parsedPip)
                
            
            with open(reqLoc+"/environment.yml", "w") as computedEnvFp:
                computedEnvFp.write("---\n")
                yaml.dump(handle, computedEnvFp)




if __name__ == "__main__":
    main()
