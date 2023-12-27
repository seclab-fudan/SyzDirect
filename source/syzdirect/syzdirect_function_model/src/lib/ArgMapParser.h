#ifndef ARGMAPPARSER_H
#define ARGMAPPARSER_H

#include "Analyzer.h"
#include "CodeFeatures.h"

// map<string, vector<int>> SpecailFuncArgMap;

map<string, vector<int>> getArgMapFromFile();
vector<int> getArgIdx(int mappedArg, int argNum=10);
vector<vector<int>> getArgMapByFunc(Function* F);

vector<map<unsigned, ConstBlockMap>> transArgConstMapVec(vector<map<unsigned, ConstBlockMap>>& argConstMapVec, vector<vector<int>>& argMap);

#endif