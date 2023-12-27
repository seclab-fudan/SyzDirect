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

#include "Constraint.h"
#include "Config.h"
#include "Common.h"


bool ConstraintPass::doInitialization(Module * M) {
    return false;
}

string getCosntName(string srcFileName, CallInst *CI, int constArgIdx) {
	string constName = "";
	if (DILocation *Loc = CI->getDebugLoc()) {
		int lineNum = Loc->getLine();
		if (srcFileName != "" && lineNum != 0) {
			int argNum = CI->arg_size();
			int currentArgNum = 0;

			ifstream file(srcFileName);
			while (currentArgNum < argNum) {
				gotoLine(file, lineNum);
				string line;
				getline(file, line);
				strip(line);
				if (line.size() == 0)
					break;
				vector<string> splitRes;
				splitString(line, splitRes, ",");
				currentArgNum += splitRes.size();
				if (constArgIdx < currentArgNum) {
					if (constArgIdx == 0) {
						string tmp = splitRes[constArgIdx];
						vector<string> tmpSplitRes;
						splitString(tmp, tmpSplitRes, "(");
						constName = tmpSplitRes[1];
						strip(constName);
					} else if (constArgIdx == argNum-1) {
						string tmp = splitRes[constArgIdx];
						vector<string> tmpSplitRes;
						splitString(tmp, tmpSplitRes, ")");
						constName = tmpSplitRes[0];
						strip(constName);
					} else {
						constName = splitRes[constArgIdx];
						strip(constName);
					}
					break;
				}
			}
			file.close();
		}
	}
	return constName;
}

bool ConstraintPass::doModulePass(Module * M) {
    for (auto gv = M->global_begin(); gv != M->global_end(); gv++) {
      GlobalVariable* g = dyn_cast<GlobalVariable>(&*gv);
      if (g == nullptr) {
        continue;
      }
      if (!g->hasInitializer()) {
        continue;
      }
      if (g->getValueType()->isStructTy()) {

        if(!g->isConstant() && (!g->hasSection() || !g->getSection().contains("read_mostly")))
          continue;

        Constant *constGlobal = g->getInitializer();
        if (constGlobal != nullptr) {
          auto constStruct = dyn_cast<ConstantStruct>(constGlobal);
          if (constStruct != nullptr) {
            string res = "";
            for (int i = 0; i < constStruct->getNumOperands(); i++) {
              auto val = constStruct->getAggregateElement(i);
              const ConstantDataArray *currDArray = dyn_cast<ConstantDataArray>(val);
              raw_string_ostream ss(res);
              if(currDArray != nullptr) {
                if(res=="") {
                  raw_string_ostream ss(res);
                  if(currDArray != nullptr && currDArray->isString()) {
                    ss << currDArray->getAsString();
                    res=ss.str().c_str();
                    OP << res << "\n";
                    for(int i=0;i< strlen(res.c_str());i++){
                        if(!isAlnum(res[i])){
                          res = "";
                          break;
                        }
                    }
                  }

                }
                else{
                  // TODO: more than one string in one struct
                  res = "";
                  break;
                }
              }
            }
            if (res=="")
              continue;

            for (int i = 0; i < constStruct->getNumOperands(); i++) {
              auto constStruct = dyn_cast<ConstantStruct>(constGlobal);
              if (constStruct != nullptr) {
                auto val = constStruct->getAggregateElement(i);

                if (Function *F = dyn_cast<Function>(val)) {

                  GlobalCtx.Func2ConstFromFopsMap[F->getName().str()] = res;
                }
              }
            }
          }
        }
      }
    }

    for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
        Function* F = &*mi;
        if (F->hasName()) {
            string funcName = F->getName().str();

            if (GlobalCtx.RegisterFunctionMap.count(funcName) != 0) {
                for (auto posPair: GlobalCtx.RegisterFunctionMap[funcName]) {

                    int constPos = posPair.first;
                    int functionPointerPos = posPair.second;
                    for(User* user:F->users()) {
                        if(CallInst* callInst = dyn_cast<CallInst>(user)) {
                            Value *constOp = callInst->getArgOperand(constPos);
                            Value *functionPointerOp = callInst->getArgOperand(functionPointerPos);
                            if (constOp && functionPointerOp) {
                                ConstantInt* constInt = dyn_cast<ConstantInt>(constOp);
                                Function* functionPointer = dyn_cast<Function>(functionPointerOp);
                                if (constInt == nullptr || functionPointer == nullptr) {
                                    continue;
                                }
                                string functionPointerName = functionPointer->getName().str();
                                if (functionPointerName == "") {
                                    continue;
                                }
                                uint64_t constIntVal = constInt->getZExtValue();
                                Function *targetF = callInst->getFunction();
                                string srcFileName = targetF->getParent()->getSourceFileName();

                                string constName = getCosntName(srcFileName, callInst, constPos);
                                errs() << "dc1: " << constIntVal << " " << functionPointer->getName() << " " << constName << "\n";
								if (constName == "") continue;
                                GlobalCtx.HandlerConstraint[functionPointerName].insert(make_pair(constIntVal, constName));
                            }
                        }
                    }
                }
            }
            if (funcName=="bt_sock_register"){
              for(User* user:F->users()) {
                if(CallInst* callInst = dyn_cast<CallInst>(user)) {
                    auto theProto=dyn_cast<Constant>(callInst->getOperand(0));
                    auto theOps=dyn_cast<GlobalVariable>(callInst->getOperand(1));
                    OP << "callsite of bt_sock_register: " << *callInst << "\n";
                    OP << "extracted proto: " << *theProto << "|" << "theOps: " << *theOps << "\n";
                    if(theOps->hasInitializer()){
                      auto constStruct = dyn_cast<ConstantStruct>(theOps->getInitializer());
                      Constant* createPtr=constStruct->getOperand(1);
                      if(createPtr->isNullValue())
                        continue;
                      Function* funcPtr= dyn_cast<Function>(createPtr);
                      string functionPointerName = funcPtr->getName().str();
                      ConstantInt* constInt = dyn_cast<ConstantInt>(theProto);
                      uint64_t constIntVal = constInt->getZExtValue();
                      Function *targetF = callInst->getFunction();
                      string srcFileName = targetF->getParent()->getSourceFileName();
                      string constName = getCosntName(srcFileName, callInst, 0);
                      GlobalCtx.HandlerConstraint[functionPointerName].insert(make_pair(constIntVal, constName));
                    }
                }
              }
            }
        }
    }
    return false;
} 

bool ConstraintPass::doFinalization(Module * M) {
    return false;
}