#!/usr/bin/python3
#simple script to generate json file with all branches and repos out of manifest.in
import json

#file location for blacklist 
manifest_loc = "eywa/manifest.json"

def add_branch(branches,repo,branch,project):
    for entry in branches:
        if repo == entry["repourl"]:
            entry["branch"].append(branch)
            return
    branches.append({"repourl":repo,"branch":[branch],"project_name":project})

def get_branches(manifest):
    branches = [] 
    project_base_name="topic_intel_next"
    #we don't want buildbot to trigger on eywa or upstream linux changes
    eywa_branch = r"https://github.com/intel-innersource/os.linux.intelnext.kernel.git"
    upstream_repo=r"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
    blacklist =[eywa_branch,upstream_repo]
    for item in manifest["topic_branches"]:
        branch = item["branch"]
        repo = item["repourl"]
        #Don't track branches where stuck at ref is set
        if repo not in blacklist and item["stuck_at_ref"] == "" :
            branch_name = branch.replace("/","_")
            branch_name = branch_name.replace(".","_")
            project = repo.split("://")[1]
            project = project.replace("/","_")
            project = project.replace(":","_")
            project = project.replace(".","_")
            project = project_base_name  + "_" +project 
            add_branch(branches,repo,branch,project)
    return branches

def main():
    bb_manifest = json.load(open(manifest_loc))
    print(json.dumps(get_branches(bb_manifest),sort_keys=True,indent=4))

if __name__== "__main__":
    main()
