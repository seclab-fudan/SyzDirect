#include "Analyzer.h"
#include "CallGraph.h"
#include "CallGraphSearch.h"

#include <queue>

unordered_map<Function*, bool> visited;

bool SubgraphBuildImpl(CallerMap CallInsts, CalleeMap Callees, SubgraphNode* current, unordered_map<Function*, bool> terminators, int maxDepth) {
    for (int i = 0; i < (6 - maxDepth); i++) {
        outs() << " ";
    }
    outs() << current->function->getName() << "\n";
    if (visited.count(current->function)) {
        return visited[current->function];
    }
    if (maxDepth == 0 && !terminators.count(current->function)) {
        delete current;
        visited[current->function] = false;
        return false;
    } 
    if (terminators.count(current->function)) {
        visited[current->function] = true;
        return true; 
    }
    bool val = false;
    for (auto item: CallInsts[current->function]) {
        for (auto nextFunc: Callees[item]) {
            if (visited.count(nextFunc)) {
                val |= visited[nextFunc];
                continue;
            }
            SubgraphNode* newNode = new SubgraphNode();
            newNode->function = nextFunc;
            current->children[newNode] = true;
            newNode->parents[current] = true;
            val |= SubgraphBuildImpl(CallInsts, Callees, newNode, terminators, maxDepth - 1);
        }
    }
    if (!val) {
        // all children are not reachable
        for (auto item : current->parents) {
            auto parent = item.first;
            parent->children.erase(current);
        }
        delete current;
    }
    visited[current->function] = val;
    return val;
}

SubgraphNode* SubgraphBuild(CallerMap CallInsts, CalleeMap Callees, Function* start, unordered_map<Function*, bool> terminators, int maxDepth) {
    visited.clear();
    SubgraphNode* root = new SubgraphNode();
    root->function = start;
    SubgraphBuildImpl(CallInsts, Callees, root, terminators, maxDepth);
    return root;
}

bool GenerateFunctionCandidateImpl(GlobalContext* Ctx, string syscall, Function* start, unordered_map<Function*, bool> terminators, int maxDepth) {
    if (terminators.count(start)) {
        Ctx->SyscallHandlerCandidates[syscall].push_back(start);
        return true;
    }
    if (maxDepth == 0) {
        visited[start] = false;
        return false;
    }
    bool val = false;
        for (auto callInst: Ctx->CallInsts[start]) {
            auto calleeFuncSet = Ctx->Callees[callInst];
            // traverse next layer of CG
            for (auto calleeFunc: calleeFuncSet) {
                if (!visited.count(calleeFunc) && calleeFunc != start) {
                    bool newVal = GenerateFunctionCandidateImpl(Ctx, syscall, calleeFunc, terminators, maxDepth - 1);
                    val |= newVal;
                    visited[calleeFunc] = newVal;
                } else if(visited.count(calleeFunc)){
                    val |= visited[calleeFunc];
                }
            }
        }
    // }
    if (val) {
        Ctx->SyscallHandlerCandidates[syscall].push_back(start);
    }
    return val;
}

void GenerateFunctionCandidate(GlobalContext* Ctx, string syscall, Function* start, unordered_map<Function*, bool> terminators, int maxDepth) {
    visited.clear();
    Ctx->SyscallHandlerCandidates[syscall] = vector<Function*>();
    GenerateFunctionCandidateImpl(Ctx, syscall, start, terminators, maxDepth);
}