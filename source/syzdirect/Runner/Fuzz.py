
import os, json
from concurrent.futures import ThreadPoolExecutor, thread
import concurrent
import datetime, time
import copy, shutil
import pandas as pd 
import Config



    
def MultirunFuzzer():
    runItems=[]
    CLEAN_IMAGE_PATH = Config.CleanImageTemplatePath
    for datapoint in Config.datapoints:
    
        caseIdx=datapoint['idx']
        template_config=Config.LoadJson(Config.TemplateConfigPath)
        assert template_config, "Fail to load fuzzing config template "
        template_config["sshkey"]=Config.KeyPath
        runCount = 1

        # first build it again
        syzdirect_path = Config.FuzzerDir
        os.system(f"cd {syzdirect_path}; make")

        # collect all xidxs
        tfmap=Config.ParseTargetFunctionsInfoFile(caseIdx)
        print(tfmap)
        
        Config.PrepareDir(Config.getFuzzInpDirPathByCase(caseIdx))
        
        for xidx in tfmap.keys():
            ### check fuzzinp and kernel image ready to fuzz
            
            callfile = Config.getFuzzInpDirPathByCaseAndXidx(caseIdx,xidx)
                
            kernelImage = Config.getInstrumentedKernelImageByCaseAndXidx(caseIdx,xidx)
            assert os.path.exists(callfile), f"[case {caseIdx} xidx {xidx}] fuzz input file not exists, please check!"
            
            assert os.path.exists(kernelImage), f"[case {caseIdx} xidx {xidx}] bzimage file not exists, please check!"
            
            
            workRootDir = Config.getFuzzResultDirByCaseAndXidx(caseIdx, xidx)
            
            customized_syzkaller=Config.getCustomizedSyzByCaseAndXidx(caseIdx,xidx)
            if os.path.exists(customized_syzkaller):
                syzkaller_path = customized_syzkaller
            else:
                syzkaller_path = syzdirect_path
            os.makedirs(workRootDir, exist_ok=True)


            rounds=Config.FuzzRounds
            Config.logging.info(f"[case {caseIdx} xidx {xidx}] Preparing fuzzing for {rounds}")
            for i in range(rounds):
                configPath = os.path.join(workRootDir, f"config{i}")
              
                subWorkDir = os.path.join(workRootDir, f"run{i}")
                config = copy.deepcopy(template_config)

                shutil.rmtree(subWorkDir, ignore_errors=True)

                config["image"] = CLEAN_IMAGE_PATH
                config["workdir"] = subWorkDir
                config["http"] = f"0.0.0.0:{2345+runCount}"
                config['vm']['kernel'] = kernelImage
                config['syzkaller'] = syzkaller_path
                config['hitindex']=int(xidx)
                
                bug_title=datapoint['repro bug title']
                if pd.isna(bug_title):
                    config['bugdesc']=bug_title
                

                with open(configPath, "w") as fp:
                    json.dump(config, fp, indent="\t")

                fuzzer_file = os.path.join(syzkaller_path, "bin",
                                        "syz-manager")

                runItems.append((fuzzer_file, configPath, callfile))
                runCount += 1
            

    with ThreadPoolExecutor(max_workers=75) as executor: 
        futures = []
        for runArg in runItems:
            futures.append(executor.submit(runFuzzer, *runArg))
            time.sleep(5)
        for future in concurrent.futures.as_completed(futures):
            future.result()


def runFuzzer(fuzzerFile, configPath, callFile):
    command = f"{fuzzerFile} -config={configPath} -callfile={callFile} -uptime={Config.FuzzUptime}"
    Config.logging.info(f"Start running {command}")
    os.system(command)
    Config.logging.info(f"Finish running {command}")


