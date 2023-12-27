#include <stdlib.h>
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"

#include "Distance.h"
#include "Common.h"
#include "Analyzer.h"


const int MAX_VALUE = 1000000;
const int C = 100;
const int MAGNIFY_FLOAT = 10;

static bool isBlacklisted(const string &funcName) {
    static const SmallVector<std::string, 14> Blacklist = {
    "panic", "sprintf", "vprintk", "vsnprintf", "vprintk_emit", "___slab_alloc", 
    "kick_process", "do_exit", "mutex_unlock", "add_timer", "kfree", 
    "__kfree_skb", "__alloc_skb", "__dynamic_pr_debug",
    };
    for (auto const &blacklistFunc : Blacklist) {
        if (funcName == blacklistFunc) {
            return true;
        }
    }
    return false;
}


void getInterstFunction(Function* targetFunc, unordered_set<Function*> &interstFuncSet,
                        unordered_set<Function*> &visited) {
    visited.insert(targetFunc);
    if (GlobalCtx.Callers.count(targetFunc) == 0) return;
    for (auto callerInst : GlobalCtx.Callers[targetFunc]) {
        Function *F = callerInst->getFunction();                                                   
        if (visited.count(F) == 0) {
            interstFuncSet.insert(F);
            outs() << targetFunc->getName() << " -> " << F->getName() << "\n";
            getInterstFunction(F, interstFuncSet, visited);
        }
    }
}


// cal function distance a arbitary function to target function
void DistanceCal::getFunctionDistance() {
    Function *targetFunc = (*this->targetBBSet.begin())->getParent();
    // map<Function*, pair<Function*, CallInst*>> callerHistory; // A -> B, (call B) in A
    queue<Function*> q;
    q.push(targetFunc);
    funcDistance[targetFunc] = 0;
    while (!q.empty()) {
        Function * F = q.front();
        q.pop();
        int fdist = funcDistance[F];
        for (auto callerInst: GlobalCtx.Callers[F]) {
            Function *callerFunc = callerInst->getFunction();
            if (isBlacklisted(callerFunc->getName().str())) {
                continue;
            }
           
             if (funcDistance.count(callerFunc) == 0 || funcDistance[callerFunc] > fdist + 1){
                funcDistance[callerFunc] = fdist + 1;
                q.push(callerFunc);
            } 
            if (callInstToTFDistance.count(callerInst) == 0 || callInstToTFDistance[callerInst] > fdist) {
                callInstToTFDistance[callerInst] = fdist;
            } 
        }
    }
    
    for (auto &item: funcDistance) {
        funcMap[item.first->getName()] = item.first;
    }


}

void blockBFS(BasicBlock* interstBlock, BlockToIBsDistance &blockToIBsDistance) {
    // TODO: set limit for visits to avoid path explosion
    queue<BasicBlock*> q;
    q.push(interstBlock);

    int current_layer = 0;
    unordered_map<BasicBlock*, int> distanceFromIB;
    distanceFromIB[interstBlock] = 0;

    while(!q.empty()) {
        BasicBlock *currentBlock = q.front();
        q.pop();
        current_layer = distanceFromIB[currentBlock];

        for (BasicBlock* pred: predecessors(currentBlock)) {
            if (distanceFromIB.count(pred) == 0 || distanceFromIB[pred] > current_layer + 1) {
                distanceFromIB[pred] = current_layer + 1;
                q.push(pred);
            }
        }
    }
    for (auto item: distanceFromIB) {
        BasicBlock *from = item.first;
        int distance = item.second;
    
        auto tmpPair = make_pair(interstBlock, distance);
        // TODO: add check
        blockToIBsDistance[from].push_back(tmpPair);
    }
}

void blockBFSInTargetFunc(set<BasicBlock*> &targetBlockSet, BlockDistanceInTargetFunc &blockDistanceInTagetFunc) {
    // TODO: set limit for visits to avoid path explosion

    for (BasicBlock* targetBlock: targetBlockSet) {
        queue<BasicBlock*> q;
        q.push(targetBlock);

        int current_layer = 0;
        blockDistanceInTagetFunc[targetBlock] = 0;

        set<BasicBlock*> visit;
        visit.insert(targetBlock);

        while(!q.empty()) {
            BasicBlock *currentBlock = q.front();
            q.pop();
            current_layer = blockDistanceInTagetFunc[currentBlock];

            for (BasicBlock* pred: predecessors(currentBlock)) {
                if (visit.count(pred) != 0) continue;
                visit.insert(pred);

                if (blockDistanceInTagetFunc.count(pred) == 0) {
                    blockDistanceInTagetFunc[pred] = current_layer + 1;
                } else {
                    blockDistanceInTagetFunc[pred] = min(blockDistanceInTagetFunc[pred], current_layer + 1);
                }
                q.push(pred);
            }
        }
    }
}


void DistanceCal::getBlockDistanceHelper() {
    Function *targetFunction = (*this->targetBBSet.begin())->getParent();

    for (auto funcItem: funcDistance) {
        // iter achievable functions
        Function *F = funcItem.first;
        for (auto bit = F->begin(); bit != F->end(); ++bit) {
            BasicBlock *BB = &*bit;
            bool hasDistance = false;
            // if there are multiple callsite that can achieve to target function,
            // choose the shortest one.
            int minDistanceInBlock = MAX_VALUE;
            for (auto iit = BB->begin(); iit != BB->end(); ++iit) {
                Instruction *inst = &*iit;
                if (CallInst *CI = dyn_cast<CallInst>(inst)) {
                    // Function *CF = NULL;
                    // if (indirectMap.count(inst) != 0) {
                    //     CF = indirectMap[inst];
                    // } else if (CI->getCalledFunction()) {
                    //     // here get the function declare if called function in different file
                    //     CF = CI->getCalledFunction();
                    //     // here try to get the function defination
                    //     StringRef CFName = CF->getName();
                    //     if (funcMap.count(CFName) != 0) {
                    //         CF = funcMap[CFName];
                    //     }
                    // }

                    // if (!CF) continue;

                    // if (funcDistance.count(CF) != 0 && funcDistance[CF] < minDistanceInBlock) {
                    //     minDistanceInBlock = funcDistance[CF];
                    //     hasDistance = true;
                    // } else if (CF->getName() == targetFunction->getName()) {
                    //     minDistanceInBlock = 0;
                    //     hasDistance = true;
                    //     break;
                    // }
                    if (callInstToTFDistance.count(CI) == 1) {
                        int tmp = callInstToTFDistance[CI];
                        if (tmp < minDistanceInBlock) {
                            minDistanceInBlock = tmp;
                            hasDistance = true;
                        }
                    }
                }
            }
            if (hasDistance) {
                blockDistanceToTF[BB] = minDistanceInBlock;
            }
        }
    }
    // min distance from the each block in the function to interest function
    for (auto blockItem: blockDistanceToTF) {
        BasicBlock *BB = blockItem.first;
        // if (BB->getParent()->getName() == "inet_frag_find") {
        //     outs() << *BB << "\n";
        // }
        blockBFS(BB, blockToIBsDistance);
    }

    // cal block distance from block in target function to target block 
    unordered_map<BasicBlock*, int> distanceFromIB;
    blockBFSInTargetFunc(this->targetBBSet, blockDistanceInTagetFunc);
}


DistanceCal::DistanceCal(set<BasicBlock*> &targetBBSet) {
    this->targetBBSet = set<BasicBlock*>{targetBBSet.begin(), targetBBSet.end()};
    if (this->targetBBSet.size() == 0) {
        errs() << "target block set is empty!" << "\n";
        exit(-1);
    }
    getFunctionDistance();
    getBlockDistanceHelper();
}


void blockBFS_test(BasicBlock* interstBlock, unordered_map<BasicBlock*, int> &distanceFromIB) {
    queue<BasicBlock*> q;
    q.push(interstBlock);

    int current_layer = 0;
    distanceFromIB[interstBlock] = 0;

    while(!q.empty()) {
        BasicBlock *currentBlock = q.front();
        q.pop();
        current_layer = distanceFromIB[currentBlock];

        for (BasicBlock* pred: predecessors(currentBlock)) {
            if (distanceFromIB.count(pred) == 0) {
                distanceFromIB[pred] = current_layer + 1;
                q.push(pred);
            }
        }
    }
    for (auto item: distanceFromIB) {
        outs() << *item.first << "\n";
        outs() << item.second << "\n";
        outs() << "-----\n";
    }
}


int DistanceCal::getBlockDistance(BasicBlock* BB) {
    if (this->targetBBSet.count(BB) != 0) return 0;
    Function *targetFunction = (*this->targetBBSet.begin())->getParent();

    if (BB->getParent() == targetFunction) {
        // BB, targetBB in same function
        if (blockDistanceInTagetFunc.count(BB) != 0) {
            return blockDistanceInTagetFunc[BB] * MAGNIFY_FLOAT;
        } else {
            return -1;
        }
    } else {
        // BB, targetBB in different function
        BasicBlock *entryBB = &*targetFunction->begin();
        int entryToTargetDistance = blockDistanceInTagetFunc[entryBB] + 1;

        if (blockDistanceToTF.count(BB)) {
            // errs() << *BB << "\n";
            return (C * blockDistanceToTF[BB] + entryToTargetDistance) * MAGNIFY_FLOAT;
        } else if (blockToIBsDistance.count(BB)) {
            double divisor = 0;
            int count = 0;
            int distance = MAX_VALUE;
            for (auto itemVec: blockToIBsDistance[BB]) {
                BasicBlock* interestBlock = itemVec.first;
                int thisBlockDistance = itemVec.second;
                int thisFunctionDistance = blockDistanceToTF[interestBlock];

                // errs() << thisBlockDistance << "\n";
                // errs() << thisFunctionDistance << "\n";
                // errs() << entryToTargetDistance << "\n\n";
                // int distance = thisBlockDistance + C * thisFunctionDistance + entryToTargetDistance;
                // distance = min(distance, thisBlockDistance + C * thisFunctionDistance + entryToTargetDistance);

                count += 1;
                divisor += 1.0 / (thisBlockDistance + C * thisFunctionDistance + entryToTargetDistance);
            }
            return double(count) / divisor * MAGNIFY_FLOAT;
            // return distance * MAGNIFY_FLOAT;
        } else {
            // unreachable
            return -1;
        }
    }
}

// find all blocks reachable to tagert block and their distance
// output them in the format of following
// file_name.dist
// function_name    block_idx   distance    
void DistanceCal::outputBlocksDistance(string OutputDir, string bclListBaseDir) {
    if (OutputDir != "") {
        string cmd("mkdir -p " + OutputDir);
        int ret = system(cmd.c_str());
        if (ret) {
            ERR("create dir error!!\n");
        }
    }

    std::error_code OutErrorInfo;
    map<Module*, set<Function*>> ModuleToFuncs;

    for (auto funcItem: funcDistance) {

        Function *F = funcItem.first;
        Module *M = F->getParent();
        ModuleToFuncs[M].insert(F);
    }
    for (auto item: ModuleToFuncs) {
        Module *M = item.first;
        string fullModulePath = static_cast<string>(M->getName());
        string kernelMoudulPath = fullModulePath.substr(bclListBaseDir.size());
        if (kernelMoudulPath[0] == '/') {
            kernelMoudulPath = kernelMoudulPath.substr(1);
        }
        string moduleName;
        size_t findIdx = kernelMoudulPath.rfind(".llbc");
        if (findIdx != string::npos) {
            moduleName = kernelMoudulPath.substr(0, findIdx);
        } else {
            ERR("module name is not formatable!!\n");
        }
        string::size_type pos = 0;
        while ((pos = moduleName.find("/")) != string::npos) {
            moduleName.replace(pos, 1, "-");
        }
        //output format: xxx-xxx-xxx.dist
        string distanceFileName = OutputDir + "/" + moduleName + ".dist";
        raw_fd_ostream *moduleFD = new raw_fd_ostream(StringRef(distanceFileName), OutErrorInfo, sys::fs::CD_CreateAlways);
        for (auto F: item.second) {
            string funcName = static_cast<string>(F->getName());
            
            int block_id = 0;
            for (auto it = F->begin(); it != F->end(); ++it) {
                BasicBlock *BB = &*it;
                int distance = getBlockDistance(BB);
                if (distance != -1) {
                    *moduleFD << funcName << " " << block_id << " " << distance << "\n";
                    // errs() << funcName << " " << block_id << " " << distance << "\n";
                }
                block_id++;
            }
        }
        delete moduleFD;
    }
    return;
}