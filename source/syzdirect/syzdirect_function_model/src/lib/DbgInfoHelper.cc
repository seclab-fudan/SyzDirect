#include <llvm/IR/DebugInfo.h>
#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include "llvm/IR/Instruction.h"
#include <llvm/Support/Debug.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"  
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/BasicBlock.h" 
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include <llvm/IR/LegacyPassManager.h>
#include <map> 
#include <vector> 
#include "llvm/IR/CFG.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h" 
#include "llvm/IR/IRBuilder.h"

#include "DbgInfoHelper.h"
#include "Config.h"
#include "Common.h"

#include "Utils.h"

set<MDNode*> AllMDNodes;

bool DbgInfoHelperPass::doInitialization(Module * M) {
    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) { 
        GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
        if (g == nullptr) {
            continue;
        }
        if (g->getValueType()->isStructTy() && (!g->isDeclaration()) && g->hasInitializer()) {
            Ctx->GlobalStructMap[g->getName().str()] = g;
        }
    }
    return false;
}

map<string, int>* DbgInfoHelperPass::getStructFieldIdx(DIType* TY) { 
    StringRef* fieldType = NULL;
    if(!TY)
        return nullptr;
    DICompositeType* DI = dyn_cast<DICompositeType>(TY);
    if (!DI)
        return nullptr;
    DINodeArray DA = DI->getElements();
    DIDerivedType *DT;
    StringRef element_name;
    map<string, int>* res = new map<string, int>();
    for (int i = 0; i != DA.size(); i++) {
        DT = dyn_cast<DIDerivedType>(DA->getOperand(i));
        if (!DT) {
            continue;
        }
        (*res)[DT->getName().str()] = i;
    }
    return res;
}

void collectMetadata(MDNode *N) {
    if (!N) return;
    if (AllMDNodes.find(N) != AllMDNodes.end()) {
        return;
    }
    AllMDNodes.insert(N);

 
    for (unsigned i = 0, e = N->getNumOperands(); i < e; ++i){
        if (N->getOperand(i)) {
            if(auto Op = dyn_cast<MDNode>(N->getOperand(i))){
                collectMetadata(Op);
            }
        }
    }
}

bool DbgInfoHelperPass::doModulePass(Module * M) {

    AllMDNodes.clear();
    SmallVector<pair<unsigned int, MDNode*>> MDForInst;
    for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
        Function& func = *mi;
        for (auto &BB: func) {
            for (auto &I: BB) {
                if (auto callInst = dyn_cast<CallInst>(&I)) {
                    auto f = callInst->getCalledFunction();
                    if (f && f->hasName() && (f->getName().startswith("llvm."))) {
                        for (auto i = 0; i < I.getNumOperands(); i++) {
                            auto MV = dyn_cast<MetadataAsValue>(I.getOperand(i));
                            if (MV) {
                                auto MD = dyn_cast<MDNode>(MV->getMetadata());
                                if (MD) {
                                    collectMetadata(MD);
                                }
                            }
                        }
                    }
                }
                I.getAllMetadata(MDForInst);
                for(unsigned i = 0, e = MDForInst.size(); i < e; ++i){
                    collectMetadata(MDForInst[i].second);
                }
                MDForInst.clear();
            }
        }
        
    }

    for (auto MDNode: AllMDNodes) {
        auto CT = dyn_cast<DICompositeType>(MDNode);
        if (CT) {
            if (CT->getTag() == dwarf::DW_TAG_structure_type) {
                auto structMap = getStructFieldIdx(CT);
                if (structMap && structMap->size() > 0) {
                    Ctx->StructFieldIdx[CT->getName().str()] = *structMap;
                }
            }
        }
    }
    return false;
} 

bool DbgInfoHelperPass::doFinalization(Module * M) {
    return false;
}
