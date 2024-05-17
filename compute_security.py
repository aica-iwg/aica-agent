#In a seperate file for now

import yaml

def quick_figure(package: str, ver):
    return package if ver == -1 else package + "==" + ver

def dev_alt(altList:list, pkg: str) -> list:
    pkgName, pkgVer = pkg.split("==") if len(pkg.split("==")) == 2 else [pkg, -1]
    if pkgName == "psycopg2":
        altList.append(quick_figure("psycopg2-binary",pkgVer))
    elif pkgName == "torch":
        altList.append("-i https://download.pytorch.org/whl/cpu")
        altList.append(pkg)
        

def transcribe(envLoc: str, envName: str):
    with open(envLoc + "environment-"+ envName + ".yml", "r") as baseEnvFp:
            normalDeps=[]
            devDeps=[]

            condaDeps : list = yaml.load(baseEnvFp, yaml.Loader)["dependencies"]
            for dep in condaDeps[:-1]:
                dep = dep.replace("=", "==")
                
                normalDeps.append(dep)
                dev_alt(devDeps, dep)
                
                    
            if type(condaDeps[-1]) is dict and "pip" in condaDeps[-1].keys():
                for dep in condaDeps[-1]["pip"]:
                    normalDeps.append(dep)
                    dev_alt(devDeps, dep)

            #FIXME: Sometimes this doesn't update existing req files
            with open(envLoc+"reqs.txt", "w") as computedReqs:
                for line in normalDeps:
                    computedReqs.write(line + "\n")
            
            print(devDeps)
            with open(envLoc+"reqsDev.txt", "w") as computedDevReqs:
                for line in devDeps:
                    computedDevReqs.write(line + "\n")

def main() -> None:
    envList = [[a+"/",a] for a in ["attacker", "honeypot", "manager"]]
    envList.append(["","core"])

    for r in envList:
        transcribe(*r)
        


if __name__ == "__main__":
    main()