#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Format.h>

#include <set>
#include <unordered_set>
#include <unordered_map>
#include <queue>
#include <vector>
#include <string>

#include "Analyzer.h"
#include "Common.h"

// block -> [(interst block1, distance1), (interst block2, distance2), ..]
typedef unordered_map<BasicBlock*, vector<pair<BasicBlock*, int>>> BlockToIBsDistance;
typedef map<BasicBlock*, int> BlockDistanceInTargetFunc;

void getInterstFunction(Function* targetFunc, unordered_set<Function*> &interstFuncSet,
                        unordered_set<Function*> &visited);

void getFunctionDistance(Function* targetFunc, unordered_map<Function*, int> &funcDistance,
                        map<StringRef, Function*> &funcMap, unordered_map<Instruction*, Function*> &indirectMap);

class DistanceCal {
    private:
    // used when test finish
    //     unordered_map<Function*, int> funcDistance;
    //     unordered_map<BasicBlock*, int> blockDistanceToTF;
    //     BlockToIBsDistance twoBlockDistance;
        void getFunctionDistance();
        void getBlockDistanceHelper();
    public:
        set<BasicBlock*> targetBBSet;
        unordered_map<Function*, int> funcDistance; // intersted function
        unordered_map<BasicBlock*, int> blockDistanceToTF;
        unordered_map<BasicBlock*, int> blockDistanceTOTb;
        BlockToIBsDistance blockToIBsDistance;
        BlockDistanceInTargetFunc blockDistanceInTagetFunc;

        unordered_map<CallInst*, int> callInstToTFDistance;

        map<StringRef, Function*> funcMap; //function name -> function
        unordered_map<Instruction*, Function*> indirectMap; // indirect call -> function

        DistanceCal(set<BasicBlock*> &targetBB);
        int getBlockDistance(BasicBlock* BB); // block distance from BB to target BB
        void outputBlocksDistance(string OutputDir="", string bclListBaseDir="");
};

// TODO2: file:line -> block