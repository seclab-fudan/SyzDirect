#include <fstream>
#include <sstream>
#include <bitset>
#include <llvm/IR/Function.h>
#include "ArgMapParser.h"
#include "llvm/Support/FileSystem.h"

map<string, vector<int>> SpecailFuncArgMap = {
    {"do_arch_prctl_64", {0, 1, 2}},
    {"do_arch_prctl_common", {0, 1, 2}},
    {"block_ioctl", {1, 2, 4}},
    {"blkdev_ioctl", {1, 0, 2, 4}},
    {"dm_blk_ioctl", {1, 0, 2, 4}},
    {"blkdev_common_ioctl", {1, 1, 2, 4, 4}},
    {"chrdev_open", {0, 1}},
    {"open_proxy_open", {0, 1}},
    {"full_proxy_open", {0, 1}},
    {"ptmx_open", {0, 1}},
    {"do_dentry_open", {1, 0, 0}},
    {"do_epoll_ctl", {1, 2, 4, 8, 0}}
};

map<string, vector<int>> getArgMapFromFile()
{
    string exepath = sys::fs::getMainExecutable(NULL, NULL);
    string exedir = exepath.substr(0, exepath.find_last_of('/'));
    string filePath = exedir + "/configs/arg_map1";
    map<string, vector<int>> res;
    string line;
    ifstream argMapFile(filePath, ios::in);
    if(!argMapFile.is_open())
    {
        cout << "target file is not opened" << endl;
        return res;
    }
    while(getline(argMapFile, line))
    {
        string funcName = line.substr(0, line.find(':'));
        stringstream ss(line.substr(line.find(":") + 1));
        vector<int> argMap = vector<int>();
        int x;
        while(ss >> x)
        {
            argMap.push_back(x);
        }
        if(argMap.size() != 0)
        {
            res[funcName] = argMap;
        }
    }
    for(auto item : SpecailFuncArgMap)
    {
        res[item.first] = item.second;
    }
    return res;
}

vector<int> getArgIdx(int mappedArg, int argNum)
{
    vector<int> res;
    bitset<32> bs(mappedArg);
    for(int i = 0; i < argNum; i++)
    {
        if(bs.test(i))
        {
            res.push_back(i);
        }
    }
    return res;
}

vector<vector<int>> getArgMapByFunc(Function* F)
{
    vector<vector<int>> res;
    if(GlobalCtx.FunctionArgMap.count(F->getName().str()) == 0)
    {
        for(int i = 0; i < F->arg_size(); i++)
        {
            res.push_back(vector<int>({i}));
        }
        return res;
    }
    vector<int> argMap = GlobalCtx.FunctionArgMap[F->getName().str()];
    for(int i : argMap)
    {
        res.push_back(getArgIdx(i));
    }
    return res;
}

map<unsigned, ConstBlockMap> transArgumentConstMap(map<unsigned, ConstBlockMap>& argConstMap, vector<vector<int>>& argMap)
{
    map<unsigned, ConstBlockMap> res;
    for(auto v : argMap)
    {
        for(int i : v)
        {
            if(res.count(i) == 0)
            {
                res[i] = ConstBlockMap();
            }
        }
    }
    for(auto item : argConstMap)
    {
        unsigned argIdx = item.first;
        vector<int> mappedArgs = argMap[argIdx];
        for(auto idx : mappedArgs)
        {
            if(res.count(idx) == 0)
            {
                res[idx] = ConstBlockMap();
            }
            res[idx].insert(res[idx].end(), item.second.begin(), item.second.end());
        }
    }
    return res;
}

vector<map<unsigned, ConstBlockMap>> transArgConstMapVec(vector<map<unsigned, ConstBlockMap>>& argConstMapVec, vector<vector<int>>& argMap)
{
    if(argConstMapVec.size() == 0)
    {

    }
    vector<map<unsigned, ConstBlockMap>> res;
    for(auto item : argConstMapVec)
    {
        res.push_back(transArgumentConstMap(item, argMap));
    }
    return res;
}