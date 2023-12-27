#ifndef CODE_FEATURES_H
#define CODE_FEATURES_H

#include "Analyzer.h"

typedef struct CastOp
{
    Instruction::CastOps op;
    Type* srcTy;
    Type* dstTy;
} CastOp;

typedef vector<CastOp*> CastOpPath;
typedef vector<Value*> OperandPath;
class TraceOperand
{
private:
    /* data */
public:
    Value* value;
    CastOpPath castOps;
    OperandPath opPath;
    OperandPath andOps;
    TraceOperand(/* args */);
    TraceOperand(Value*, CastOpPath);
    TraceOperand(Value*, CastOpPath, OperandPath);
    TraceOperand(Value*, CastOpPath, OperandPath, OperandPath);
    void updateCastOps(CastOp*);
    void updateOps(Value*);
    void updateAndOps(Value*);
    ~TraceOperand();
};

class CMDConst
{
private:
    /* data */
public:
    ConstantInt* value;
    CastOpPath castOps;
    BasicBlock* switchBlock;
    BasicBlock* targetBlock;
    OperandPath opPath;
    OperandPath andOps;
    vector<vector<BasicBlock*>> paths;
    vector<pair<CallInst*, Function*>> calledFunctions;

    string compareString;

    int location;   //the location of cmd in the structure

    CMDConst(/* args */);
    CMDConst(CMDConst&);
    CMDConst(CMDConst*);
    CMDConst(ConstantInt*, CastOpPath, BasicBlock*, BasicBlock*, string);
    CMDConst(ConstantInt*, CastOpPath, BasicBlock*, BasicBlock*, OperandPath, string);
    CMDConst(ConstantInt*, CastOpPath, BasicBlock*, BasicBlock*, OperandPath, OperandPath, string);
    void updateCastOps(CastOpPath, bool front=false);
    void updateOps(OperandPath, bool front=false);

    bool isEnoughPaths();
    bool isRetFixedNegative();
    bool isRequestModuleInKernel();
    bool shouldFuzzing();
    // vector<pair<CallInst*, Function*>> getCalledFunctionsFromPath()
    ~CMDConst();
};

class BBConstraint
{
    public:
    unsigned argIdx;
    set<CMDConst*> cmdConstSet;
    BasicBlock* bb;
    BBConstraint();
    BBConstraint(unsigned, CMDConst*, BasicBlock*);
    ~BBConstraint();
    void insertCMDConst(CMDConst*);
};

typedef struct DFSStartBB
{
    BasicBlock* BB;
    vector<CallInst*> callList;
} DFSStartBB;

#define MAX_PATH_NUM_IN_FUNC 100
#define MAX_BB_NUM_IN_PATH 100
#define TOTAL_BLOCK 100

bool getPathFromBlockToRet(BasicBlock* BB, std::vector<std::vector<BasicBlock*>>& paths, unsigned& times, std::set<BasicBlock*>& blocks, std::vector<BasicBlock*> path, unsigned max_path_num=MAX_PATH_NUM_IN_FUNC, unsigned max_bb_num=MAX_BB_NUM_IN_PATH, unsigned total_block=TOTAL_BLOCK);
void output_paths(std::vector<std::vector<BasicBlock*>>& paths);
vector<pair<CallInst*, Function*>> getCalledFunctionInBlock(BasicBlock* BB);
std::vector<CMDConst*> getTargetBlockByArg(Function* F, unsigned argIdx, std::map<Function*, set<unsigned>>& visited, int depth);
typedef std::vector<CMDConst*> ConstBlockMap;
std::map<unsigned, ConstBlockMap> getTargetBlocksInFunc(Function* F);
void outputBlocks(std::map<unsigned, ConstBlockMap> map, raw_fd_ostream& outfile);
void testFindBlocks(Function* F);
bool isRetFixedValueInPath(ReturnInst* retInst, std::vector<BasicBlock*> path, int64_t* value);
bool isRetFixedNegativeInPaths(vector<vector<BasicBlock*>>& paths);
vector<pair<CallInst*, Function*>> getCalledFunctionInPaths(vector<vector<BasicBlock*>>& paths);
bool functionInPaths(vector<vector<BasicBlock*>>& paths, string funcName);

#define MAX_DEPTH 5
void getCalledFuncitonInter(Function* func, vector<pair<CallInst*, Function*>>& calledFunction, unsigned depth, bool ignoreIndirectCall=true, unsigned maxDepth=MAX_DEPTH);
vector<pair<CallInst*, Function*>> getCalledFunctionInPathsInter(vector<vector<BasicBlock*>>& paths, bool ignoreIndirectCall=true, unsigned maxDepth=MAX_DEPTH);

pair<CallInst*, Function*> getCallInstByCalledFunctionName(vector<pair<CallInst*, Function*>> res, string funcName);
bool isRequestModuleInKernelTest1(CallInst* requestModuleCall);

vector<string> getNetDeviceNameByAllocNetdev();

vector<CMDConst*> getValueInSwitchCase(Function* F);

void handleSndSeqIoctl(Function* targetFucntion, InfoItem* info, raw_fd_ostream& outfile=outs());
void handleAutofsDevIoctl(Function* targetFunction, InfoItem* info, raw_fd_ostream& outfile=outs());
void handleUcmaWrite(Function* targetFunction, InfoItem* info, raw_fd_ostream& outfile);
set<vector<BBConstraint*>> getBBConstraintsPathsInFunc(Function* F, set<Function*> visitedFunctions);

vector<map<unsigned, ConstBlockMap>> getConstraintsWrapper(Function* F, map<unsigned, ConstBlockMap>& argConstMap, raw_fd_ostream& outfile=outs());

map<BasicBlock*, vector<map<unsigned, ConstBlockMap>>> getConstraintsWrapperNew(Function* F, map<unsigned, ConstBlockMap>& argConstMap, raw_fd_ostream& outfile);

void getPathFromBasicBlockDFS(BasicBlock* BB, vector<CallInst*> callList, vector<BBConstraint*> path, set<vector<BBConstraint*>>& paths, set<BasicBlock*> visited, set<Function*> visitedFuncs, bool flag=false);

void getPathFromBasicBlockDFSNew(BasicBlock* BB, vector<CallInst*> callList, vector<BBConstraint*> path, set<vector<BBConstraint*>>& paths, set<BasicBlock*> visited, set<Function*> visitedFuncs, bool flag=false, int loop=0);

vector<DFSStartBB*> getDFSStartBBsBFSInFunc(Function* F);

map<unsigned, ConstBlockMap> getTargetBlocksInFuncByArgMap(Function* F, vector<vector<int>>& argMap, Function* entryFunc);

map<unsigned, ConstBlockMap> getTargetBlocksInFuncByArgMap(Function* F, vector<vector<int>>& argMap, string syscall);

void handleDrmIoctl(map<string, Module*> &ModuleMap, raw_fd_ostream& signatureFile);
map<unsigned, Function*> handleArrayHandlers(GlobalVariable* ioctls, long bias);

void handleSpecial(ModuleList &MList, raw_fd_ostream& signatureFile);
#endif