#ifndef CALL_GRAPH_SEARCH_H
#define CALL_GRAPH_SEARCH_H

#include "Analyzer.h"

struct SubgraphNode {
    Function* function;
    std::unordered_map<SubgraphNode*, bool> children;
    std::unordered_map<SubgraphNode*, bool> parents;
};

class Probe {
    public: 
        virtual void visit(SubgraphNode*) = 0 ;
};

class FunctionProbe : public Probe {
    public:
        void visit(SubgraphNode* node) {
            return;
        }
};

SubgraphNode* SubgraphBuild(CallerMap CallInsts, CalleeMap Callees, Function* start, unordered_map<Function*, bool> terminators, int maxDepth);

void GenerateFunctionCandidate(GlobalContext* Ctx, string syscall, Function* start, unordered_map<Function*, bool> terminators, int maxDepth);

#endif