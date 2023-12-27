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
#include <queue>
#include "llvm/IR/CFG.h" 
#include "llvm/Transforms/Utils/BasicBlockUtils.h" 
#include "llvm/IR/IRBuilder.h"

#include "FopsFinder.h"
#include "Config.h"
#include "Common.h"


using namespace llvm;

// syscall handler function config to
std::map<std::string, std::string> SyscallEntryFunctions = {
	{"ioctl", "__se_sys_ioctl"},
    {"open", "do_dentry_open"},
	{"read", "vfs_read"},
	{"write", "vfs_write"},
    {"setsockopt", "__sys_setsockopt"},
    {"getsockopt", "__sys_getsockopt"},
    {"sendmsg", "____sys_sendmsg"},
};

std::map<std::string, int> SyscallRecrusiveCount = {
    {"ioctl", 5},
    {"open", 2},
    {"read", 2},
    {"write", 2},
    {"setsockopt", 5},
    {"getsockopt", 5},
    {"sendmsg", 5},
};

set<Function*> FopsFinderPass::SyscallHandlerCandidates;

map<Function*, string> FopsFinderPass::SyscallHandlerTypeMap;

set<Function*> visitedFunc;

bool DetermineHandlerFunctionHeuristic(Function *F, string syscallType) {
    if (F->getName().contains(syscallType)) {
        return true;
    } 
    // network interface ioctl
    if (syscallType == "ioctl") {
        if (F->getName() == "dev_ifsioc") {
            return true;
        }
    }
    return false;
}

// bitwise value, 0b1 -> arg 1, 0b10 -> arg 2, 0b100 -> arg 3
map<CallInst*, vector<int>> CallSiteSyscallArgMap;
set<Function*> processedFunc;

void FopsFinderPass::MapSyscallArgToFunctionArg(Function* function) {
    if (processedFunc.find(function) != processedFunc.end()) {
        return;
    }
    processedFunc.insert(function);
    queue<Value*> valueQueue;
    map<Value*, int> valueMap;
    set<Value*> valueVisited;
    for (int i = 0; i < function->arg_size(); i++) {
        valueQueue.push(dyn_cast<Value>(function->getArg(i)));
        if (i >= Ctx->FunctionSyscallArgMap[function].size()) {
            valueMap[dyn_cast<Value>(function->getArg(i))] = 0;
        } else {
            valueMap[dyn_cast<Value>(function->getArg(i))] = Ctx->FunctionSyscallArgMap[function][i];
        }
    }
    while (!valueQueue.empty()) {
        Value* current = valueQueue.front();
        valueQueue.pop();
        if (valueVisited.find(current) != valueVisited.end()) {
            continue;
        }
        valueVisited.insert(current);
        for (auto user : current->users()) {
            if (auto callInst = dyn_cast<CallInst>(user)) {
                if (CallSiteSyscallArgMap.find(callInst) == CallSiteSyscallArgMap.end()) {
                    CallSiteSyscallArgMap[callInst] = vector<int>();
                    for (int i = 0; i < callInst->getNumArgOperands(); i++) {
                        auto operand = dyn_cast<Value>(callInst->getArgOperand(i));
                        CallSiteSyscallArgMap[callInst].push_back(valueMap[operand]);
                    }
                }
                else
                {
                    for(int i = 0; i < callInst->getNumArgOperands(); i++)
                    {
                        auto operand = dyn_cast<Value>(callInst->getArgOperand(i));
                        CallSiteSyscallArgMap[callInst][i] = valueMap[operand];
                    }
                }
            }
            valueQueue.push(user);
            valueMap[user] |= valueMap[current];
        }
    }
    for (auto callInst: Ctx->CallInsts[function]) {
        auto calleeSet = Ctx->Callees[callInst];
        for (auto callee : calleeSet) {
            Ctx->FunctionSyscallArgMap[callee] = CallSiteSyscallArgMap[callInst];
        }
    }
}

void FopsFinderPass::InsertIndirectCall(CallInst* callInst, SmallPtrSet<Function*, 8U>& calleeFuncSet, string syscallType) {
    // insert indirect call
    Function * calledFunc = callInst->getCalledFunction();
    if (calledFunc == nullptr) { // indirect call
        for (auto calleeFunc: calleeFuncSet) {
            if (SyscallHandlerCandidates.find(calleeFunc) == SyscallHandlerCandidates.end() && DetermineHandlerFunctionHeuristic(calleeFunc, syscallType)) {
                outs()  << syscallType << " handler candidate: " << calleeFunc->getName() << "\n";
                for (int i = 0; i < Ctx->FunctionSyscallArgMap[calleeFunc].size(); i++) {
                    outs() << "arg " << i << ": " << Ctx->FunctionSyscallArgMap[calleeFunc][i] << "\n";
                }
                SyscallHandlerCandidates.insert(calleeFunc);
                SyscallHandlerTypeMap[calleeFunc] = syscallType;
            }
        }
    } 
    
}

void FopsFinderPass::FindSyscallCandidatesRecrusively(CalleeMap* Callees, string syscallType, Function* syscallFunc, int depth) {
    // last layer
    if (depth == 0) {
        return;
    }
    // process argument relation analysis
    MapSyscallArgToFunctionArg(syscallFunc);

    for (auto callInst: Ctx->CallInsts[syscallFunc]) {
        auto calleeFuncSet = Ctx->Callees[callInst];
        InsertIndirectCall(callInst, calleeFuncSet, syscallType);
        // traverse next layer of CG
        for (auto calleeFunc: calleeFuncSet) {
            if (visitedFunc.find(calleeFunc) == visitedFunc.end()) {
                visitedFunc.insert(calleeFunc);
                FindSyscallCandidatesRecrusively(Callees, syscallType, calleeFunc, depth - 1);
            }
        }
    }
}

FopsFinderPass::FopsFinderPass(GlobalContext *Ctx_): IterativeModulePass(Ctx_, "FopsFinder") {
    for (auto s: SyscallEntryFunctions) { // in config
        visitedFunc.clear();
        auto syscallType = s.first;
        auto syscallFunc = s.second;
        for (auto item: Ctx_->CallInsts) {
            auto func = item.first;
            if (func->getName() == syscallFunc) {
                Ctx->FunctionSyscallArgMap[func] = vector<int>();
                for (int i = 0; i < func->arg_size(); i++) {
                    Ctx->FunctionSyscallArgMap[func].push_back(1 << i);
                }
                FindSyscallCandidatesRecrusively(&(Ctx_->Callees), syscallType, func, SyscallRecrusiveCount[syscallType]);
                break;
            }
        }
    }
}

bool FopsFinderPass::doFinalization(Module *M) {

	return false;
}

bool FopsFinderPass::doInitialization(Module *M) {

    return false;
}

bool FopsFinderPass::doModulePass(Module *M) {

    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) { 
        GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
        if (g == nullptr) {
            continue;
        }
        if (g->getValueType()->isStructTy()) {
            if (!g->isConstant() || !g->hasInitializer()) {
                continue;
            }
            Constant *constGlobal = g->getInitializer();
            if (constGlobal != nullptr) {
                auto constStruct = dyn_cast<ConstantStruct>(constGlobal);
                if (constStruct != nullptr) {
                    for (int i = 0; i < constStruct->getNumOperands(); i++) {
                        auto val = constStruct->getAggregateElement(i);
                        if (isa<Function>(val)) {
                            auto func = dyn_cast<Function>(val);
                            if (SyscallHandlerCandidates.find(func) != SyscallHandlerCandidates.end()) {
                                if (Ctx->HandlerFunctionsType.find(func) == Ctx->HandlerFunctionsType.end()) {
                                    Ctx->HandlerFunctionsType[func] = SyscallHandlerTypeMap[func];
                                    Ctx->HandlersInOperationStruct[g].insert(func);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return false;
}