//===-- Analyzer.cc - the kernel-analysis framework--------------===//
//
// This file implements the analysis framework. It calls the pass for
// building call-graph and the pass for finding security checks.
//
// ===-----------------------------------------------------------===//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/JSON.h"
#include <llvm/IR/InstIterator.h>



#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>
#include <filesystem>
#include <boost/algorithm/string/predicate.hpp>

#include "Analyzer.h"
#include "CallGraph.h"
#include "Constraint.h"
#include "Config.h"

#include "TypeInitializer.h"

#include "Distance.h"
#include <time.h>
#include <llvm/IR/Dominators.h>

using namespace llvm;

// Command line parameters.
// cl::list<string> InputFilenames(
//     cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<string> TargetPointFile(
	"target-points", cl::desc("File that contain target point information (idx src_file:line)")
);

cl::opt<string> TargetPoint(
	"target-point", cl::desc("src file:line")
);

cl::opt<string> distanceOutput(
	"distance-output", cl::desc("block distance ouput dir")
);

cl::opt<string> MultiPositionPoints(
	"multi-pos-points", cl::desc("declare target function if has multiple function position")
);

cl::opt<int> TargetIndex(
	"target-index", cl::desc("target xidx"),  cl::init(-1)
		);

cl::opt<string> KernelInterfaceFile(
	"kernel-interface-file", cl::desc("kernel interface file (syztg result) path"), cl::init("")
);

cl::opt<string> kernelBCDir(
	cl::Positional, cl::OneOrMore, cl::desc("kernel bitcode dir")
);

cl::opt<unsigned> VerboseLevel(
		"verbose-level", cl::desc("Print information at which verbose level"),
		cl::init(0));

cl::opt<string> SourceLocation(
				"source-location", cl::desc("Input the target source code location"),
				cl::init("linux"));

cl::opt<bool> SecurityChecks(
		"sc",
		cl::desc("Identify sanity checks"),
		cl::NotHidden, cl::init(false));

cl::opt<bool> MissingChecks(
		"mc",
		cl::desc("Identify missing-check bugs"),
		cl::NotHidden, cl::init(false));

// GlobalContext GlobalCtx;
GlobalContext GlobalCtx = GlobalContext();
map<string,pair<string,string>> SpecialConstraintMap;
void IterativeModulePass::run(ModuleList &modules) {

	ModuleList::iterator i, e;
	OP << "[" << ID << "] Initializing " << modules.size() << " modules ";
	bool again = true;
	while (again) {
		again = false;
		for (i = modules.begin(), e = modules.end(); i != e; ++i) {
			again |= doInitialization(i->first);
			OP << ".";
		}
	}
	OP << "\n";

	unsigned iter = 0, changed = 1;
	while (changed) {
		++iter;
		changed = 0;
		unsigned counter_modules = 0;
		unsigned total_modules = modules.size();
		for (i = modules.begin(), e = modules.end(); i != e; ++i) {
			OP << "[" << ID << " / " << iter << "] ";
			OP << "[" << ++counter_modules << " / " << total_modules << "] ";
			OP << "[" << i->second << "]\n";

			bool ret = doModulePass(i->first);
			if (ret) {
				++changed;
				OP << "\t [CHANGED]\n";
			} else
				OP << "\n";
		}
		OP << "[" << ID << "] Updated in " << changed << " modules.\n";
	}

	OP << "[" << ID << "] Postprocessing ...\n";
	again = true;
	while (again) {
		again = false;
		for (i = modules.begin(), e = modules.end(); i != e; ++i) {
			// TODO: Dump the results.
			again |= doFinalization(i->first);
		}
	}

//  OP << "[" << ID << "] Done!\n\n";
}

void ProcessResults(GlobalContext *GCtx) {
}

void PrintResults(GlobalContext *GCtx) {
	OP<<"############## Result Statistics ##############\n";
	OP<<"# Number of sanity checks: \t\t\t"<<GCtx->NumSecurityChecks<<"\n";
	OP<<"# Number of conditional statements: \t\t"<<GCtx->NumCondStatements<<"\n";
}


bool isSyscall(Function* F) {
	string FuncName = static_cast<string>(F->getName());
	if (FuncName.size() > 0) {
		if (startsWith(FuncName, "__do_sys_") || startsWith(FuncName, "__se_sys_")) {
			return true;
		}
		if (startsWith(FuncName, "__x64_sys_")) {
			return true;
		}
	}
	return false;
}

string getSyscallName(Function* F) {
	string FuncName = static_cast<string>(F->getName());
	if (FuncName.size() > 0) {
		if (startsWith(FuncName, "__do_sys_") || startsWith(FuncName, "__se_sys_")) {
			return FuncName.substr(9);
		}
		if (startsWith(FuncName, "__x64_sys_")) {
			return FuncName.substr(10);
		}
	}
	return "";
}

void getCallTrace(BasicBlock* targetBlock, vector<CallTraceInfo> &callTraces) {
	// input: target block
	// output: call trace: from syscall to target block
	// return a <Function*, Inst*> pair vector for each syscall,
	// the last pair is <Function*, the first inst in the target block>
	// the other pair is <Function*, call inst of next function>
	queue<pair<Function*, int>> q;
	map<Function*, set<pair<Function*, CallInst*>>> callerHistory; // A -> set of <B, (call B) in A>
	unordered_set<Function*> entryList;
	map<Function*, int> visit;

	Function* targetFunction = targetBlock->getParent();
	string targetFunctionName = targetFunction->getName().str();


	q.push(make_pair(targetFunction, 0));
	visit[targetFunction] = 1;

	int maxCallTrace = 2;
	int maxIndirectCallNum = 2;

	map<Function*, unordered_set<Function*>> preNodeSet;

	while (!q.empty()) {
		Function *F = q.front().first;
		int original_currentIndirectCallNum = q.front().second;
		q.pop();

		for (auto callerFunc: GlobalCtx.MissingCallerMap[F]) {
			if (visit.count(callerFunc) != 0) continue;
			visit[callerFunc] += 1;
			callerHistory[callerFunc].insert(make_pair(F, nullptr));
			q.push(make_pair(callerFunc, original_currentIndirectCallNum));
		}
		size_t fh = funcHash(F);
		Function* unifiedFunc= GlobalCtx.UnifiedFuncMap[fh];
		for (auto callInst: GlobalCtx.Callers[unifiedFunc]) {
			Function *callerFunc = callInst->getFunction();
			int currentIndirectCallNum = original_currentIndirectCallNum;
			if (GlobalCtx.FPCallerMap.count(F) != 0 && GlobalCtx.FPCallerMap[F].count(callerFunc) != 0) {
				continue;
			}

			if (entryList.count(callerFunc) != 0) {
				if (visit[callerFunc] >= maxCallTrace) continue;
			} else {

				if (visit.count(callerFunc) != 0) {
					continue;
					// if (visit[callerFunc] >= maxCallTrace) continue;
					// if (preNodeSet.count(callerFunc) != 0 && preNodeSet[callerFunc].count(F) != 0) continue;
				}
			}

			if (callInst->isIndirectCall()) {
				currentIndirectCallNum += 1;
				if (currentIndirectCallNum > maxIndirectCallNum) continue;
			}

			visit[callerFunc] += 1;

			callerHistory[callerFunc].insert(make_pair(F, callInst));

			string FuncName = callerFunc->getName().str();
			if (FuncName.size() > 0) {
				if (GlobalCtx.kernelSig2syscallVariant.count(FuncName) != 0) {
					entryList.insert(callerFunc);
					continue;
				}
				if (isSyscall(callerFunc)) {
					entryList.insert(callerFunc);
					continue;
				}
			}
			q.push(make_pair(callerFunc, currentIndirectCallNum));
		}
	}

	for (Function* entry: entryList) {
		Function *F = entry;


		// callerHistory  node: A -> set of <B, (call B) in A>
		queue<pair<Function*, Instruction*>> nodeQueue; // node: <B, call B in A>
		queue<vector<pair<Function*, Instruction*>>> pathQueue; // node: <A, call B in A>

		for (auto item: callerHistory[F]) {
			Function *nextFunc = item.first;
			CallInst *callInst = item.second;
			if (callInst) {
				Instruction *inst = dyn_cast<Instruction>(callInst);
				vector<pair<Function*, Instruction*>> tmp;
				tmp.push_back(make_pair(F, inst));
				pathQueue.push(tmp);
				nodeQueue.push(make_pair(nextFunc, inst));
			} else {
				vector<pair<Function*, Instruction*>> tmp;
				tmp.push_back(make_pair(F, nullptr));
				pathQueue.push(tmp);
				nodeQueue.push(make_pair(nextFunc, nullptr));
			}
		}

		while (!nodeQueue.empty()) {
			pair<Function*, Instruction*> node = nodeQueue.front();
			vector<pair<Function*, Instruction*>> path = pathQueue.front();
			nodeQueue.pop();
			pathQueue.pop();

			Function *F = node.first;

// A -> set of <B, (call B) in A>
			if (callerHistory.count(F) == 0) {
				path.push_back(make_pair(F, &*targetBlock->begin()));
				CallTraceInfo callTraceInfo;
				callTraceInfo.callTrace = path;
				if (GlobalCtx.kernelSig2syscallVariant.count(targetFunctionName) != 0){
					callTraceInfo.depth = 1;
					callTraceInfo.icallNum = 0;
					callTraceInfo.isSyscallEntry = isSyscall(targetFunction);
					callTraces.push_back(callTraceInfo);
					return;
				}
				else {
					int depth = path.size();
					int icallNum = 0;
					for (auto item: path) {
						if (item.second == nullptr) { continue; }
						if (CallInst *callInst = dyn_cast<CallInst>(item.second)) {
							if (callInst->isIndirectCall()) {
								icallNum += 1;
							}
						}
					}
					callTraceInfo.depth = depth;
					callTraceInfo.icallNum = icallNum;
					callTraceInfo.isSyscallEntry = isSyscall(path[0].first);
					callTraces.push_back(callTraceInfo);
				}

			} else {
				for (auto item: callerHistory[F]) {
					Function *nextFunc = item.first;
					if (item.second) {
						Instruction *inst = dyn_cast<Instruction>(item.second);
						nodeQueue.push(make_pair(nextFunc, inst));
						path.push_back(make_pair(F, inst));
						pathQueue.push(path);
					} else {
						nodeQueue.push(make_pair(nextFunc, nullptr));
						path.push_back(make_pair(F, nullptr));
						pathQueue.push(path);
					}
				}
			}
		}
	}
}


bool findConstInSwitch(vector<pair<Function*, Instruction*>> &callTrace, string &importFunc, uint64_t &constNum, string &constStrName) {
	// return true if successfully find the target const option
	// else return false
	// constNum: case concrete number
	// srcFileName and lineNum are helpful to find case string name, and used to filter "const number -> multiple syscall variant"

	int callTraceNum = callTrace.size();
	if (callTraceNum == 0) return false;
	for (int i = callTraceNum-1; i >=0; --i) {
		Function *F = callTrace[i].first;
		Instruction *I = callTrace[i].second;
		if (I == nullptr) continue;
		string funcName = static_cast<string>(F->getName());
		// iter pred to find switch
		BasicBlock *BB = I->getParent();

		queue<pair<BasicBlock*, BasicBlock*>> q;
		set<BasicBlock*> visit;
		visit.insert(BB);

		for (BasicBlock *predBB: predecessors(BB)) {
			q.push(make_pair(predBB, BB));
			visit.insert(predBB);
		}
		while (!q.empty()) {
			BasicBlock *B = q.front().first;
			BasicBlock *nextB = q.front().second;
			q.pop();
			// find switch
			for (auto it = B->begin(); it != B->end(); ++it) {
				Instruction *inst = &*it;
				if (SwitchInst *SI = dyn_cast<SwitchInst>(inst)) {
					if (SI->getNumOperands() == 0) continue;

					for (auto c: SI->cases()) {
						int lineNum = -1;
						string srcFileName;
						if (c.getCaseSuccessor() != nextB) continue;
						// try to get the line number of "case xxx:"

						// if nextB like following:
						//  call void @__sanitizer_cov_trace_pc() #10, !dbg !12804
						//  br label %883, !dbg !12804
						// the line number is incorrect, so we need to find the correct line number using the next block of nextB
						bool specialCase = false;
						if (nextB->getInstList().size() == 2) {
							Instruction* I = &nextB->getInstList().front();
							if (CallInst* CI = dyn_cast<CallInst>(I)) {
								Function* calledF = CI->getCalledFunction();
								if (calledF && calledF->getName().str() == "__sanitizer_cov_trace_pc") {
									specialCase = true;
								}
							}
						}
						if (specialCase)
							nextB = nextB->getSingleSuccessor();


						for (auto nextBiter=nextB->begin(); nextBiter != nextB->end(); nextBiter++) {
							Instruction *nextBinst = &*nextBiter;
							if (DILocation *Loc = nextBinst->getDebugLoc()) {
								if (Loc->getLine() == 0) {
									if (Loc->getInlinedAt()) {
										lineNum = Loc->getInlinedAt()->getLine();
										break;
									} else {
										continue;
									}
								} else {
									lineNum = Loc->getLine();
									break;
								}
							}
						}
						importFunc = funcName;
						srcFileName =  F->getParent()->getSourceFileName();
						constNum = c.getCaseValue()->getZExtValue();
						lineNum -= 1;

						// loop 2 times to deal with conner case like following:
						// case xxx:
						// {

						for (int j = 0; j < 2; j++) {
							if (srcFileName != "" && lineNum > 0) {
								ifstream file(srcFileName);
								gotoLine(file, lineNum);
								string line;
								getline(file, line);
								strip(line);
								int idx = line.find(":");
								// TODO: 一连串case的情况，可以匹配多个case
								// TODO: case33 case下一行是一个括号
								if (startsWith(line, "case ") && idx != string::npos) {
									string caseStr = line.substr(5, idx-5);
									if (caseStr == "") continue;
									if (caseStr[0] >= '0' && caseStr[0] <= '9') continue;
									// find succ
									constStrName = caseStr;
									file.close();
									return true;
								}
								file.close();
							}
							lineNum -= 1;
						}
					}
				}
			}
			// iter bb
			for (BasicBlock *predBB: predecessors(B)) {
				if (visit.count(predBB) != 0) continue;
				visit.insert(predBB);
				q.push(make_pair(predBB, B));
			}
		}
	}
	return false;
}

void collectAllPredBlock(BasicBlock *bb, set<BasicBlock*> &predBlockSet) {
	predBlockSet.insert(bb);
	for (BasicBlock *pred: predecessors(bb)) {
		if (predBlockSet.count(pred) == 0) {
			collectAllPredBlock(pred, predBlockSet);
		}
	}
}

void collectAllPredBlock(BasicBlock *bb, vector<BasicBlock*> &predBlockVector) {
	predBlockVector.push_back(bb);
	for (BasicBlock *pred: predecessors(bb)) {
		if (std::find(predBlockVector.begin(),predBlockVector.end(),pred) == predBlockVector.end()) {
			collectAllPredBlock(pred, predBlockVector);
		}
	}
}


void dumpValueAsOperand(Value* v){
	v->printAsOperand(OP);
	OP << "\n";
}

string GetConstName(Function* F,Instruction* Target){

	string line,constname;
	getSourceCodeLine(Target,line);

	string srcFileName =  F->getParent()->getSourceFileName();

	int lineNum=-1;
	if (DILocation *Loc = Target->getDebugLoc()) {
		if (Loc->getLine() == 0) {
			if (Loc->getInlinedAt()) {
				lineNum = Loc->getInlinedAt()->getLine();
				return "";
			} else {
				return "";
			}
		} else {
			lineNum = Loc->getLine();
		}
	}
	if(lineNum==-1){
		DEBUG("Fail to get linenum!!!\n");
	}
	line = getSourceLine(srcFileName,lineNum);
	if (line!="") {

		// TODO: REGEX
		int leftpos = line.find("[");
		int rightpos = line.find("]",leftpos);
		constname = line.substr(leftpos+1,rightpos-leftpos-1);

		for(auto c:constname) {
			// into->attr[idx] where idx is a variable
			if (islower(c)) {
				constname = "";
				break;
			}
		}
	}
	return constname;
}
void findConstFromIf(vector<pair<Function*, Instruction*>> &callTrace, set<pair<uint64_t,string>> &constSet){
	int callTraceNum = callTrace.size();
	if (callTraceNum == 0) return;
	constSet.clear();
	for (int i = callTraceNum-1; i >=0; --i) {
		Function *F = callTrace[i].first;
		Instruction *I = callTrace[i].second;
		if (I == nullptr) continue;
		string funcName = static_cast<string>(F->getName());
		// iter pred to find switch
		BasicBlock *BB = I->getParent();
		set<BasicBlock*> visit;
		collectAllPredBlock(BB,visit);

		Value* ArrayRoot=NULL;
		for(auto BB:visit){
			for (BasicBlock::iterator I = BB->begin(),
									 IE = BB->end(); I != IE; ++I) {
				if (LoadInst *LI = dyn_cast<LoadInst>(&*I)) {
					auto oriType = LI->getType();
					int id=0;
					while (oriType->isPointerTy()) {
						oriType = oriType->getPointerElementType();
						id++;
					}
					if (!oriType->isStructTy() || oriType->getStructName() != "struct.nlattr" || id!=2)
						continue;
					ArrayRoot=LI;

					break;

				}
			}
			if(ArrayRoot)
				break;
		}
//  what if the argument itself is nlattr**?
		if (!ArrayRoot){
			for(auto& arg: F->args()){
				auto argType = arg.getType();
				int id=0;
				while (argType->isPointerTy()) {
					argType = argType->getPointerElementType();
					id++;
				}
				if (!argType->isStructTy() || argType->getStructName() != "struct.nlattr" || id!=2)
					continue;
				ArrayRoot=&arg;
			}
		}
		if(!ArrayRoot)
			continue;

		// For if (!attr[B]) callsite;
		// Find direct precondition block
		BasicBlock* CurrentBlock=I->getParent();
		BasicBlock* pred = CurrentBlock->getUniquePredecessor();

		if(pred){
			if(BranchInst* BI= dyn_cast<BranchInst>(pred->getTerminator())){
				int takenIdx = BI->getSuccessor(1)==CurrentBlock;
				if(ICmpInst* ICmp= dyn_cast<ICmpInst>(BI->getCondition())){
					if(isa<ConstantPointerNull>(ICmp->getOperand(1))){
						if(((ICmp->getPredicate()==llvm::CmpInst::ICMP_NE) && !takenIdx) || ((ICmp->getPredicate()==llvm::CmpInst::ICMP_EQ) && takenIdx)){
						 if(Instruction* target= dyn_cast<Instruction>(ICmp->getOperand(0))){
							 if(LoadInst* LI= dyn_cast<LoadInst>(target)){
								 if(GetElementPtrInst* Gep= dyn_cast<GetElementPtrInst>(LI->getPointerOperand())){
									 if(Gep->getNumOperands()==2 && Gep->getOperand(0)==ArrayRoot){
										 ConstantInt* offset= dyn_cast<ConstantInt>(Gep->getOperand(1));
										 string constname=GetConstName(F,BI);
										 if(constname!=""){
											 constSet.insert(make_pair(offset->getZExtValue(),constname));

											 INFO("Successfully get constname from precondition:" << constname << "\n");
										 }
									 }
								 }
							 }
						 }
						}
					}
				}


			}

		}



		// collect all block return error
		set<ReturnInst*> retset;
		findReturnInFunc(F,retset);
		if(retset.empty())
			continue;
		ReturnInst* RI=*retset.begin();
		Value* RV=RI->getReturnValue();
		set<BasicBlock *> ReturnErrorBlocks;
		if(RV) {
			int phi_layer = 2;

			if (PHINode *PHIRV = dyn_cast<PHINode>(RV)) {
				queue<pair<PHINode *, int>> q;
				q.push(make_pair(PHIRV, 0));
				set<PHINode *> visitedPHI;
				set<pair<BasicBlock *, BasicBlock *>> ReturnErrorEdges;
				set<BasicBlock *> visitedBBs;
				queue<BasicBlock *> toPropagate;
				while (!q.empty()) {
					PHINode *PHI = q.front().first;
					int currentlayer = q.front().second;
					q.pop();
					visitedPHI.insert(PHI);
					visitedBBs.insert(PHI->getParent());
					for (int i = 0; i < PHI->getNumIncomingValues(); i++) {
						Value *IncomingV = PHI->getIncomingValue(i);
						if (ConstantInt *ConstInt = dyn_cast<ConstantInt>(IncomingV)) {
							int intval = ConstInt->getSExtValue();
							if (intval < 0 && intval > -4096) {
								BasicBlock *IncomingBB = PHI->getIncomingBlock(i);
								ReturnErrorEdges.insert(make_pair(PHI->getIncomingBlock(i), PHI->getParent()));
								toPropagate.push(IncomingBB);
								visitedBBs.insert(IncomingBB);
							}
						} else if (PHINode *NPHI = dyn_cast<PHINode>(IncomingV)) {
							if (currentlayer + 1 < phi_layer && visitedPHI.find(NPHI) == visitedPHI.end()) {
								q.push(make_pair(NPHI, currentlayer + 1));
							}
						}
					}
				}

				while (!toPropagate.empty()) {
					BasicBlock *currBB = toPropagate.front();
					toPropagate.pop();
					ReturnErrorBlocks.insert(currBB);
					for (auto pred: predecessors(currBB)) {
						if(ReturnErrorBlocks.find(pred)!=ReturnErrorBlocks.end())
							continue;
						bool AllErr = true;
						for (auto succ: successors(pred)) {
							if (succ != currBB && ReturnErrorEdges.find(make_pair(pred, succ)) == ReturnErrorEdges.end()) {
								AllErr = false;
								break;
							}
						}
						if (AllErr) {
							ReturnErrorEdges.insert(make_pair(pred, currBB));
							toPropagate.push(pred);
						}
					}
				}
			} else
				continue;
		}
		else{
			// TODO: return void
			;
		}

		DominatorTree DT = DominatorTree();
		DT.recalculate(*F);

		for (auto usr: ArrayRoot->users()) {
			if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(usr)) {
				if(visit.count(GEP->getParent())==0)
					continue;
				if(GEP->getNumOperands()<2 || !isa<ConstantInt>(GEP->getOperand(1)))
					continue;
				for(auto gepusr: GEP->users()) {
					if(!isa<LoadInst>(gepusr))
						continue;
					if(visit.count(GEP->getParent())==0)
						continue;
					for(auto liuser: gepusr->users()){
						if(ICmpInst* icmp= dyn_cast<ICmpInst>(liuser)){
							if(icmp->getOperand(0) != gepusr)
								continue;
							for(auto icmpusr: icmp->users()){
								BranchInst* BI= dyn_cast<BranchInst>(icmpusr);
								if(!BI || BI->isUnconditional())
									continue;
								int takenIdx= -1;
								if(isa<ConstantPointerNull>(icmp->getOperand(1))){
									if(icmp->getPredicate()==CmpInst::ICMP_EQ)
										takenIdx=1;
								}
								else{
									if(icmp->getPredicate()==CmpInst::ICMP_NE)
										takenIdx=0;
								}
								if(takenIdx==-1)
									continue;

								// if(!attr[something])
								BasicBlock* nextblock=BI->getSuccessor(!takenIdx);
								bool reject=false;
								if(RV)
									reject = (ReturnErrorBlocks.find(nextblock)!=ReturnErrorBlocks.end());
								else{
									if(succ_size(nextblock)==1 && nextblock->size()<10 && nextblock->getSingleSuccessor()==RI->getParent()){
										// only easy return
										reject=true;
									}
								}
								if(!reject)
									continue;



								// nested if check
								bool nested=false;
								queue<BasicBlock*> worklistsucc,worklistpred;
								worklistsucc.push(BI->getSuccessor(takenIdx));
								set<BasicBlock*> visitedsuccbbs;
								while(!worklistsucc.empty()){
									BasicBlock *bb=worklistsucc.front();
									worklistsucc.pop();
									if(visitedsuccbbs.find(bb)!=visitedsuccbbs.end())
										continue;
									visitedsuccbbs.insert(bb);
									for(auto succ: successors(bb)){
										if(pred_size(succ)==1){
											worklistsucc.push(bb);
										}
										else if(bb==RI->getParent())
											continue;
										else if(pred_size(succ)>1){
											for(auto pred: predecessors(succ)){
												if(pred!=bb)
													worklistpred.push(pred);
											}

										}
									}
								}
								while(!worklistpred.empty()){
									BasicBlock *bb=worklistpred.front();

									worklistpred.pop();
									for(auto pred: predecessors(bb)){
										if(succ_size(pred)==1)
											worklistpred.push(bb);
										else if(succ_size(pred)>1){
											if(DT.dominates(pred,BI->getParent())){
												nested=true;
												break;
											}

										}
									}
								}

								if(nested)
									continue;

								string constname=GetConstName(F,BI);
								if(constname=="")
									continue;
								INFO("Successfully get constname:" << constname << "\n");
								ConstantInt* constval= dyn_cast<ConstantInt>(GEP->getOperand(1));
								constSet.insert(make_pair(constval->getZExtValue(),constname));
							}



						}
					}
				}
			}
		}


	}

}


ConstraintInfo constraintExtraction(CallTraceInfo &callTraceInfo) {
	ConstraintInfo constraintInfo;
	auto callTrace = callTraceInfo.callTrace;
	uint64_t constNum = 0;
	string importFunc;
	int lineNum;
	string constStrName;
	bool flag = findConstInSwitch(callTrace, importFunc, constNum, constStrName);
	if (flag) {
		constraintInfo.switchConstSet.insert(make_pair(constNum, constStrName));
	}

	findConstFromIf(callTrace,constraintInfo.ifNotConstSet);

	for (auto &trace: callTrace) {
		string funcName = trace.first->getName().str();
		for (auto constInfo: GlobalCtx.HandlerConstraint[funcName]) {
			constraintInfo.handlerConstSet.insert(constInfo);
		}

		if(constraintInfo.relateModule=="" && GlobalCtx.Func2ConstFromFopsMap.count(funcName)!=0){
			constraintInfo.relateModule=GlobalCtx.Func2ConstFromFopsMap[funcName];
		}
	}

	for(auto cst: constraintInfo.switchConstSet){
		string cstName=cst.second;
		if(cstName.find("NETLBL_NLTYPE_")!=-1){
			string newcstName=cstName+"_NAME";
			if(SpecialConstraintMap.count(newcstName)!=-1){
				if(SpecialConstraintMap[newcstName].first=="string")
					constraintInfo.relateModule=SpecialConstraintMap[newcstName].second;
				else{
					constraintInfo.switchConstSet.insert(make_pair(atoi(SpecialConstraintMap[newcstName].second.c_str()), constStrName));
				}
			}
		}
	}
	return constraintInfo;
}

void initializeBasicBlock2IdxMap(Function* F){
	if(GlobalCtx.BasicBlockIndexMap.count(F)!=0){
		return;
	}
	GlobalCtx.BasicBlockIndexMap[F]=map<BasicBlock*,string>();
	int idx = -1;
	for (auto it = F->begin(), end = F->end(); it != end; it++) {
		idx += 1;
		BasicBlock *it2BB = &*it;
		GlobalCtx.BasicBlockIndexMap[F][it2BB]=to_string(idx);
	}
}
vector<TargetSignature> collectSignature(BasicBlock* targetBlock, int index) {
	vector<TargetSignature> targetSigList;
	vector<CallTraceInfo> callTraceInfoList;
	getCallTrace(targetBlock, callTraceInfoList);
	std::sort(callTraceInfoList.begin(), callTraceInfoList.end(), [](CallTraceInfo a, CallTraceInfo b) {
		if (a.depth != b.depth) {
			return a.depth < b.depth;
		} else {
			return a.icallNum < b.icallNum;
		}
	});

	const int maxCallTrace = 2;
	int idxSyscall = 0;
	int idxHandler = 0;
	bool firstEntrySyscall = true;
	bool firstEntryHandler = true;
	CallTraceInfo lastCallTraceSyscall;
	CallTraceInfo lastCallTraceEntry;

	for (auto callTraceInfo: callTraceInfoList) {
		auto callTrace = callTraceInfo.callTrace;
		bool isSyscallEntry = callTraceInfo.isSyscallEntry;
		if (isSyscallEntry) {
			if (firstEntrySyscall) {
				firstEntrySyscall = false;
				lastCallTraceSyscall = callTraceInfo;
			} else {
				if (lastCallTraceSyscall.depth != callTraceInfo.depth || lastCallTraceSyscall.icallNum != callTraceInfo.icallNum) {
					idxSyscall += 1;
					lastCallTraceSyscall = callTraceInfo;
				}
			}
		} else {
			if (firstEntryHandler) {
				firstEntryHandler = false;
				lastCallTraceEntry = callTraceInfo;
			} else {
				if (lastCallTraceEntry.depth != callTraceInfo.depth || lastCallTraceEntry.icallNum != callTraceInfo.icallNum) {
					idxHandler += 1;
					lastCallTraceEntry = callTraceInfo;
				}
			}
		}

		if (idxSyscall+idxHandler >= maxCallTrace) break;

		TargetSignature sig;
		if (isSyscallEntry) {
			sig.rank = idxSyscall;
		} else {
			sig.rank = idxHandler;
		}

		INFO("------------------------------------\n")
		INFO("index: " << index << "\n");
		string syscallName = getSyscallName(callTrace[0].first);
		if (syscallName != "") {
			sig.commonSyscall = syscallName;
		}

		int cnt = 0;

		for (auto tracePoint: callTrace) {
			if (cnt == 0) {
				sig.handler = tracePoint.first->getName().str();
			}
			Function *functionPoint = tracePoint.first;
			sig.functionList.push_back(functionPoint->getName().str());
			Instruction *instPoint = tracePoint.second;

			INFO(functionPoint->getName() << "\n");
			if (instPoint != nullptr) {
				INFO(*instPoint << "\n");
			} else {
				sig.blockSigList.push_back(vector<string>());
				continue;
			}

			BasicBlock *blockPoint = instPoint->getParent();
			vector<BasicBlock*> blockPointVec;
			collectAllPredBlock(blockPoint, blockPointVec);

			initializeBasicBlock2IdxMap(functionPoint);
			vector<string> blockNameList;
			for(auto block:blockPointVec){
				blockNameList.push_back(GlobalCtx.BasicBlockIndexMap[functionPoint][block]);
			}
			sig.blockSigList.push_back(blockNameList);
			cnt += 1;
		}
		ConstraintInfo constraintInfo = constraintExtraction(callTraceInfo);
		sig.constraintInfo = constraintInfo;
		targetSigList.push_back(sig);
	}
	return targetSigList;
}

void loadSyscallFile() {
	string exepath = sys::fs::getMainExecutable(NULL, NULL);
	string exedir = exepath.substr(0, exepath.find_last_of('/'));
	string line;
	ifstream syscallFile(exedir + "/configs/syscall.txt");
	if (syscallFile.is_open()) {
		while (!syscallFile.eof()) {
			getline(syscallFile, line);
			strip(line);
			if (line.empty()) continue;
			GlobalCtx.syscallSet.insert(line);
		}
		syscallFile.close();
	}
	string fileName = KernelInterfaceFile;
	INFO("parsing file " << fileName << '\n');
	ifstream fileStream(fileName);
	string content((istreambuf_iterator<char>(fileStream)),
									(istreambuf_iterator<char>()));
	auto E = json::parse(content);	
	if(!E){
		ERR("Error reading json: "+fileName);
		exit(1);
	}
	json::Path::Root R("");
	json::fromJSON(E.get(), GlobalCtx.kernelSig2syscallVariant, R);

	ifstream fpCallerFile(exedir + "/configs/fp-cg-edge.txt");
	if (fpCallerFile.is_open()) {
		while (!fpCallerFile.eof()) {
			getline(fpCallerFile, line);
			strip(line);
			if (line.empty()) continue;
			vector<string> splitRes;
			splitString(line, splitRes, "<-");
			strip(splitRes[0]);
			strip(splitRes[1]);
			string to = splitRes[0];
			string from =  splitRes[1];
			if (GlobalCtx.FunctionNameMap.count(to) == 0 || GlobalCtx.FunctionNameMap.count(from) == 0) {
				continue;
			}
			Function* toF = GlobalCtx.FunctionNameMap[to];
			Function *fromF = GlobalCtx.FunctionNameMap[from];
			GlobalCtx.FPCallerMap[toF].insert(fromF);
		}
	} else {
		outs() << exedir << "dont contain fp-cg-edge file\n";
	}


	ifstream missingCallerFile(exedir + "/configs/miss-cg-edge.txt");
	if (missingCallerFile.is_open()) {
		while (!missingCallerFile.eof()) {
			getline(missingCallerFile, line);
			strip(line);
			if (line.empty()) continue;
			vector<string> splitRes;
			splitString(line, splitRes, "<-");
			strip(splitRes[0]);
			strip(splitRes[1]);
			string to = splitRes[0];
			string from =  splitRes[1];
			if (GlobalCtx.FunctionNameMap.count(to) == 0 || GlobalCtx.FunctionNameMap.count(from) == 0) {
				continue;
			}
			Function* toF = GlobalCtx.FunctionNameMap[to];
			Function *fromF = GlobalCtx.FunctionNameMap[from];
			DEBUG("missing cg: " << toF->getName() << " " << fromF->getName() << "\n");
			GlobalCtx.MissingCallerMap[toF].insert(fromF);
		}
	}

	ifstream registerFunctionFile(exedir + "/configs/register-funcs.txt");
	if (registerFunctionFile.is_open()) {
		while (!registerFunctionFile.eof()) {
			getline(registerFunctionFile, line);
			strip(line);
			vector<string> splitRes;
			splitString(line, splitRes, " ");
			string registerF = splitRes[0];
			int constPos = stoi(splitRes[1]);
			int functionPointerPos = stoi(splitRes[2]);
			GlobalCtx.RegisterFunctionMap[registerF].insert(make_pair(constPos, functionPointerPos));
			DEBUG("register: " << registerF << " " << constPos << " " << constPos << "\n");
		}
	}
}

map<string, BasicBlock*> NewParseDataset(){

	map<int, string> index2functionName;
	ifstream multiPositionPointsFile(MultiPositionPoints);
	if (multiPositionPointsFile.is_open()) {
		while (!multiPositionPointsFile.eof()) {
			string line;
			getline(multiPositionPointsFile, line);
			strip(line);
			if (line == "")
				break;
			DEBUG("multi-point" << MultiPositionPoints << "\n");
			DEBUG("line: " << line << "\n");
			vector<string> splitRes;
			splitString(line, splitRes, " ");
			strip(splitRes[0]);
			strip(splitRes[1]);
			int index = stoi(splitRes[0]);
			string functionName = splitRes[1];
			index2functionName[index] = functionName;
		}
	}

	map<string, BasicBlock*> Dataset;
	map<string, set<string>> DuplicateCases;
	DEBUG("Starting parsing dataset...\n")
	for(auto p: GlobalCtx.Modules){
		Module* M=p.first;
		for (auto mi = M->begin(), ei = M->end(); mi != ei; mi++) {
			Function *F = &*mi;
			for(auto &inst: instructions(F)){
				if(CallInst* CI= dyn_cast<CallInst>(&inst)){
					if(getCalledFuncName(CI)=="kcov_mark_block"){
						if(ConstantInt *CCI = dyn_cast<ConstantInt>(CI->getOperand(0))){
							int caseIdx=CCI->getZExtValue();
							INFO("index: " << caseIdx << " | currentfunction: " << CI->getFunction()->getName() << "\n");
							if (index2functionName.count(caseIdx)!=0){
								auto DesignatedTargetFunction=index2functionName[caseIdx];
								INFO("multipoints " << caseIdx << " designate tf:" << DesignatedTargetFunction << "\n");
								DEBUG("currentfunction: " << CI->getFunction()->getName() << "\n");
								if (DesignatedTargetFunction!=CI->getFunction()->getName()){
										continue;
								}
							}
							else if(Dataset.count(to_string(caseIdx))!=0 && Dataset[to_string(caseIdx)]->getParent()!=F){
								INFO("===\n");
								INFO("case " << caseIdx << ": More than one point!!!\n");
								INFO(Dataset[to_string(caseIdx)]->getParent()->getName() << " --- " << F->getName() << "\n");
								INFO("===\n");
								if (DuplicateCases.find(to_string(caseIdx))==DuplicateCases.end()){
									DuplicateCases[to_string(caseIdx)]=set<string>();
									DuplicateCases[to_string(caseIdx)].insert(Dataset[to_string(caseIdx)]->getParent()->getName().str());
								}
								DuplicateCases[to_string(caseIdx)].insert(F->getName().str());
							}
							if (TargetIndex == -1 || caseIdx == TargetIndex)
								Dataset[to_string(caseIdx)]=CI->getParent();
						}
					}
				}
			}
		}
	}
	std::error_code OutErrorInfo;
	if(DuplicateCases.size()>0){
		raw_fd_ostream DuplicatePoints(StringRef("./duplicate_points.txt"),OutErrorInfo, sys::fs::CD_CreateAlways);
		for(auto p: DuplicateCases){
			string xidx=p.first;
			DuplicatePoints << "xidx: " << p.first << "\n";
			DuplicatePoints << "duplicate point numbers: " << p.second.size() << "\n";
			for (auto r: DuplicateCases[xidx]){
				DuplicatePoints << "function name: " << r << "\n";
			}
			DuplicatePoints << "*********************\n";
		}
		exit(1);
	}
	return Dataset;
}


set<string> filesystem_set{"sysfs", "rootfs", "ramfs", "tmpfs", "devtmpfs", "debugfs", "securityfs", "sockfs", "pipefs", "anon_inodefs", "devpts", "ext3", "ext2", "ext4", "hugetlbfs", "vfat", "ecryptfs", "fuseblk", "fuse", "rpc_pipefs", "nfs", "nfs4", "nfsd", "binfmt_misc", "autofs", "xfs", "jfs", "msdos", "ntfs", "minix", "hfs", "hfsplus", "qnx4", "ufs", "btrfs", "configfs", "ncpfs", "qnx6", "exofs", "befs", "vxfs", "gfs2", "gfs2meta", "fusectl", "bfs", "nsfs", "efs", "cifs", "efivarfs", "affs", "tracefs", "bdev", "ocfs2", "ocfs2_dlmfs", "hpfs", "proc", "afs", "reiserfs", "jffs2", "romfs", "aio", "sysv", "v7", "udf", "ceph", "pstore", "adfs", "9p", "hostfs", "squashfs", "cramfs", "iso9660", "coda", "nilfs2", "logfs", "overlay", "f2fs", "omfs", "ubifs", "openpromfs", "bpf", "cgroup", "cgroup2", "cpuset", "mqueue", "aufs", "selinuxfs", "dax", "erofs", "virtiofs", "exfat", "binder", "zonefs", "pvfs2", "incremental-fs", "esdfs"};

int main(int argc, char **argv) {
	clock_t startTime, endTime;
	startTime = clock();

	// Print a stack trace if we signal out.
	sys::PrintStackTraceOnErrorSignal(argv[0]);
	PrettyStackTraceProgram X(argc, argv);

	clock_t begin = clock();
	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

	cl::ParseCommandLineOptions(argc, argv, "Syzdirect: kernel global analysis\n");
	SMDiagnostic Err;

	// full file path -> Module class
	map<string, Module*> ModuleMap;

	vector<string> InputFilenames;

	for (const auto& p : filesystem::recursive_directory_iterator(std::string(kernelBCDir))) {
			if (!filesystem::is_directory(p)) {
					filesystem::path path = p.path();
					if (boost::algorithm::ends_with(path.string(), ".llbc")) {
						InputFilenames.push_back(path.string());
					}
					// cout << (path.u8string()) << endl;
			}
	}

	// Loading modules
	OP << "Total " << InputFilenames.size() << " file(s)\n";

	for (unsigned i = 0; i < InputFilenames.size(); ++i) {

		LLVMContext *LLVMCtx = new LLVMContext();
		unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

		if (M == NULL) {
				Err.print("Analyzer.cc",OP);
				OP << "\n";
			OP << argv[0] << ": error loading file '"
				<< InputFilenames[i] << "'\n";
			continue;
		}

		Module *Module = M.release();
		StringRef MName = StringRef(strdup(InputFilenames[i].data()));
		GlobalCtx.Modules.push_back(make_pair(Module, MName));
		GlobalCtx.ModuleMaps[Module] = InputFilenames[i];

		string location = InputFilenames[i];
		vector<string> splitRes;
		splitString(location, splitRes, ".");
		location = splitRes[0];
		for (auto it = Module->begin(); it != Module->end(); ++it) {
			Function *F = &*it;
			if (!F->hasName())
				continue;
			string functionName = static_cast<string>(F->getName());
			if (functionName == "") 
				continue;
			auto tmpPair = make_pair(Module->getSourceFileName(), functionName);
			GlobalCtx.FunctionMap[tmpPair] = F;
			if (!F->isDeclaration()) {
				GlobalCtx.FunctionNameMap[functionName] = F;
			}
		}
		ModuleMap[Module->getSourceFileName()] = Module;
	}


	// Main workflow
	// Initilaize global type map
	TypeInitializerPass TIPass(&GlobalCtx);
	TIPass.run(GlobalCtx.Modules);
	TIPass.BuildTypeStructMap();

	// Build global callgraph.
	CallGraphPass CGPass(&GlobalCtx);
	CGPass.run(GlobalCtx.Modules);

	std::error_code OutErrorInfo;

	loadSyscallFile();
	raw_fd_ostream shrinkOutput(StringRef("./syscall_shrink.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);


	ConstraintPass CtPass(&GlobalCtx);
	CtPass.run(GlobalCtx.Modules);

	raw_fd_ostream targetFunctionInfoFile(StringRef("./target_functions_info.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);


	// for debug
	// raw_fd_ostream calleeFile(StringRef("./callee.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);
	// raw_fd_ostream callerFile(StringRef("./caller.txt"), OutErrorInfo, sys::fs::CD_CreateAlways);

	// calleeFile << "===callees info===" << "\n";
	// for (auto item: GlobalCtx.Callees) {
	// 	CallInst *callInst = item.first;
	// 	Function *FuncFrom = callInst->getFunction();
	// 	for (auto FuncTo: item.second) {
	// 		calleeFile << FuncFrom->getName() << " -> " << FuncTo->getName() << "\n";
	// 	}
	// }
	// callerFile << "===callers info===" << "\n";
	// for (auto item: GlobalCtx.Callers) {
	// 	Function *FuncFrom = item.first;
	// 	for (auto callInst: item.second) {
	// 		callerFile << FuncFrom->getName() << " <- " << callInst->getFunction()->getName() << "\n";
	// 	}
	// }


	raw_fd_ostream OutputJ(StringRef("./CompactOutput.json"), OutErrorInfo, sys::fs::CD_CreateAlways);
 	json::OStream J(OutputJ,4);

 	struct OutputFrame{
		string caseIdx;
		struct tcallinfoFrame{
			string tcall;
			int rank;
			struct constraintFrame{
					struct fuconstraintFrame{
							string name;
							uint64_t value;
							fuconstraintFrame(string _name,uint64_t _value):name(_name),value(_value){}
					};
					vector<struct fuconstraintFrame> flag_union_constraints;
					string string_constraint;
			}constraint;
		};
		map<string,struct tcallinfoFrame> tcall_info_map;
	};

 	vector<struct OutputFrame> outputFrames;
	map<string, BasicBlock*> Dataset = NewParseDataset();

	for (auto item: Dataset) {
		string caseIdx = item.first;
		struct OutputFrame currentOF;
		currentOF.caseIdx = item.first;

		BasicBlock *targetBB = item.second;
		Function *targetFunc = targetBB->getParent();

		INFO("cid: " << caseIdx << "|" << targetFunc->getName() << "\n");
		if (targetFunc->getName() == "") 
			continue;

		targetFunctionInfoFile << caseIdx << " " << targetFunc->getName() << " " << targetFunc->getParent()->getSourceFileName() << "\n";

		map<string, int> targetSyscallRank;
		map<string, ConstraintInfo> targetSyscallConstraint;
		vector<TargetSignature> targetSignatures = collectSignature(targetBB, stoi(caseIdx));
		int minCalltraceLen=-1;
		for (const auto& sig: targetSignatures) {
			ConstraintInfo constraintInfo = sig.constraintInfo;
			if (minCalltraceLen==-1)
				minCalltraceLen=sig.functionList.size();
			else if (minCalltraceLen>sig.functionList.size())
				minCalltraceLen=sig.functionList.size();

			DEBUG("Calltrace length: " << sig.functionList.size() << " while min calltrace length is " << minCalltraceLen << "\n");
			bool hasConstraintInfo = false;
			if (constraintInfo.switchConstSet.size() > 0 ||
					constraintInfo.handlerConstSet.size() > 0 ||
					constraintInfo.ifNotConstSet.size()>0) {
				hasConstraintInfo = true;
			}

			string commonSyscall = sig.commonSyscall;
			int rank = sig.rank;
			if (commonSyscall != "") {
				if (targetSyscallRank.count(commonSyscall) == 0 || targetSyscallRank[commonSyscall] > rank) {
					targetSyscallRank[commonSyscall] = rank;
					if (hasConstraintInfo) {
						targetSyscallConstraint[commonSyscall] = constraintInfo;
					} else {
						targetSyscallConstraint.erase(commonSyscall);
					}
				}
			}
			string handler = sig.handler;
			
			// from bottom to top
			for (int cmdEntryFuncIdx = sig.functionList.size()-1; cmdEntryFuncIdx>=0; cmdEntryFuncIdx--) {
				string cmdEntryFunc = sig.functionList[cmdEntryFuncIdx];
				int exactMatchBlock = 0, exactMatchBlockNumMax=2;

				DEBUG("Current cmdEntryFunc: " << cmdEntryFunc << " in interface json: " << GlobalCtx.kernelSig2syscallVariant.count(cmdEntryFunc) << "\n");

				/// accurate match according to block idx
				for (auto &blockIdxStr: sig.blockSigList[cmdEntryFuncIdx]) {

					if (GlobalCtx.kernelSig2syscallVariant.count(cmdEntryFunc) != 0 && GlobalCtx.kernelSig2syscallVariant[cmdEntryFunc].count(blockIdxStr) != 0) {

						for (auto &syscall: GlobalCtx.kernelSig2syscallVariant[cmdEntryFunc][blockIdxStr]) {
							if (targetSyscallRank.count(syscall) == 0 || targetSyscallRank[syscall] > rank) {
								targetSyscallRank[syscall] = rank;
								if (hasConstraintInfo) {
									targetSyscallConstraint[syscall] = constraintInfo;
								} else {
									targetSyscallConstraint.erase(syscall);
								}
							}
							exactMatchBlock++;
							DEBUG("exact match block: " << "blockidx(" << blockIdxStr << ")" << "|" << syscall << "\n");
							if(exactMatchBlock>=exactMatchBlockNumMax){
								break;
							}
						}
						if(exactMatchBlock>=exactMatchBlockNumMax){
							break;
						}
					}
				}

				/// match with all block idx when fail
				bool findVariant = false;

				if (sig.functionList.size()-minCalltraceLen<2){
					if (!exactMatchBlock && GlobalCtx.kernelSig2syscallVariant.count(cmdEntryFunc) != 0) {
						for (auto &blockSigs: GlobalCtx.kernelSig2syscallVariant[cmdEntryFunc]) {
							if (blockSigs.second.size() > 10 && targetFunc->getName() != "netlink_sendmsg" && cmdEntryFunc != "nfnetlink_rcv_msg") {
								INFO("[-] too much syscall variant for handler: " << cmdEntryFunc << " : " << blockSigs.first << "\n");
								continue;
							}
							int syscallCount = 0;
							for (auto &syscall: blockSigs.second) {
								if (targetFunc->getName() == "netlink_sendmsg" && syscallCount > 5) break;
								if (targetSyscallRank.count(syscall) == 0 || targetSyscallRank[syscall] > rank || (hasConstraintInfo && targetSyscallConstraint.count(syscall)==0)) {
									targetSyscallRank[syscall] = rank;
									INFO("Not exact match of " << cmdEntryFunc << " : " << syscall << "\n");
									if (hasConstraintInfo) {
										targetSyscallConstraint[syscall] = constraintInfo;
									} else {
										targetSyscallConstraint.erase(syscall);
									}
								}
								findVariant = true;
								syscallCount += 1;
							}
						}
					}
				}
				if (exactMatchBlock || findVariant) {
					break;
				}
			}
		}

		map<string, vector<pair<string, int>>> syscall2Variant;
		for (auto syscallItem: targetSyscallRank) {
			string syscallVariant = syscallItem.first;
			int rank = syscallItem.second;
			if (syscallVariant.find('$') != string::npos) {
				vector<string> splitRes;
				splitString(syscallVariant, splitRes, "$");
				string syscall = splitRes[0];
				string variant = splitRes[1];
				syscall2Variant[syscall].push_back(make_pair(variant, rank));
			} else {
				syscall2Variant[syscallVariant].push_back(make_pair("", rank));
			}
		}
		set<pair<string, int>> finaltargetSyscallSet;

		for (auto syscallItem: syscall2Variant) {
			string syscall = syscallItem.first;
			vector<pair<string, int>> variantList = syscallItem.second;
			for (auto variantItem: variantList) {
				string variant = variantItem.first;
				int rank = variantItem.second;
				if (variant == "") {
					if (variantList.size() > 1)
						continue;
					else
						finaltargetSyscallSet.insert(make_pair(syscall, rank));
				} else {
					finaltargetSyscallSet.insert(make_pair(syscall + "$" + variant, rank));
				}
			}
		}

		for (auto syscall: finaltargetSyscallSet) {
			struct OutputFrame::tcallinfoFrame currentTIF;
			currentTIF.tcall=syscall.first;
			currentTIF.rank=syscall.second;
			currentOF.tcall_info_map[currentTIF.tcall]=currentTIF;
			
			string fullPath = targetFunc->getParent()->getSourceFileName();
			vector<string> splitRes;
			splitString(fullPath, splitRes, "/");
			for (auto subItem: splitRes) {
				if (filesystem_set.count(subItem) != 0) {
					string filesystem = subItem;
					ConstraintInfo constraintInfo;
					constraintInfo.relateModule = filesystem;
					targetSyscallConstraint["mount"] = constraintInfo;
					break;
				}
			}
		}

		if (targetSyscallConstraint.size() > 0) {

			for (auto citem: targetSyscallConstraint) {
				string syscall = citem.first;
				ConstraintInfo constraintInfo = citem.second;


				if(currentOF.tcall_info_map.count(syscall)==0){
					DEBUG("constraint for unknown syscall!\n");
					currentOF.tcall_info_map[syscall]=OutputFrame::tcallinfoFrame();
					currentOF.tcall_info_map[syscall].tcall=syscall;
				}
				for (auto c: constraintInfo.switchConstSet) {
					DEBUG("switchConstSet: " << syscall << "\t\t" << c.second << " " << c.first << "\n");
					currentOF.tcall_info_map[syscall].constraint.flag_union_constraints.push_back(OutputFrame::tcallinfoFrame::constraintFrame::fuconstraintFrame(c.second,c.first));
				}
				for (auto c: constraintInfo.handlerConstSet) {
					DEBUG("handlerConstSet:" << syscall << "\t\t" << c.second << " " << c.first << "\n");
					currentOF.tcall_info_map[syscall].constraint.flag_union_constraints.push_back(OutputFrame::tcallinfoFrame::constraintFrame::fuconstraintFrame(c.second,c.first));
				}
				for (auto c: constraintInfo.ifNotConstSet) {
					DEBUG("ifNotConstSet:" << syscall << "\t\t" << c.second << " " << c.first << "\n");
					currentOF.tcall_info_map[syscall].constraint.flag_union_constraints.push_back(OutputFrame::tcallinfoFrame::constraintFrame::fuconstraintFrame(c.second,c.first));
				}
				shrinkOutput << "\t\t" << constraintInfo.relateModule << "\n";
				currentOF.tcall_info_map[syscall].constraint.string_constraint=constraintInfo.relateModule;
			}
		}
	
		outputFrames.push_back(currentOF);

		INFO("[+] index: " << caseIdx << " distance cal...\n"); 
		set<BasicBlock*> targetBBSet;
		targetBBSet.insert(targetBB);
    	DistanceCal *distanceCal = new DistanceCal(targetBBSet);
    	string outputDir = "distance_xidx" + caseIdx + "/";
    	distanceCal->outputBlocksDistance(outputDir, kernelBCDir);
	}


	J.array([&]{
		for(auto OF:outputFrames){
			J.object([&] {
				J.attribute("case index", OF.caseIdx);

					J.attributeArray("target syscall infos",[&] {
						for (auto p: OF.tcall_info_map) {
							J.object([&] {
									OutputFrame::tcallinfoFrame &TIF = p.second;
									J.attribute("target syscall", TIF.tcall);
									J.attribute("rank", TIF.rank);

									J.attributeObject("constraints", [&] {
										if(TIF.constraint.flag_union_constraints.size()!=0) {
											J.attributeArray("int", [&] {
													for (auto c: TIF.constraint.flag_union_constraints) {
														J.object([&] {
																J.attribute("name", c.name);
																string res = "";
																raw_string_ostream ss(res);
																ss << c.value;
																J.attribute("value", ss.str());
														});
													}
											});
										}
										if(TIF.constraint.string_constraint!="")
											J.attribute("string", TIF.constraint.string_constraint);
									});
							});
						}
					});
				});
			}
		});

	endTime = clock();
	double time = (double)(endTime - startTime) / CLOCKS_PER_SEC;
	outs() << "[+] time: " << time << "\n";
}
