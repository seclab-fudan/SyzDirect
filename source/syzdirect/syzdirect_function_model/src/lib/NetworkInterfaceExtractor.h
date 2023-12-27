#ifndef NETWORK_INTERFACE_EXTRACTOR_H
#define NETWORK_INTERFACE_EXTRACTOR_H

#include "Analyzer.h"

#include "DataFlowAnalysis.h"

#define AF_NETLINK 16
#define PF_NETLINK AFNETLINK
#define NETLINK_ROUTE 0
#define NETLINK_GENERIC 16
#define NETLINK_XFRM 6
#define NETLINK_NETFILTER 12
#define NETLINK_RDMA 20

class NetworkInterfaceInfoItem : public InfoItem {
	public:
	int family;
	int type;
	int protocol;
	map<string, Function*> SyscallHandler;
	Function* CreateFunction;
};

class NetlinkInfoItem : public NetworkInterfaceInfoItem
{
	public:
	Function* SendmsgHandler;
	NetlinkInfoItem();
	NetlinkInfoItem(NetworkInterfaceInfoItem*);
	virtual vector<string> generateSendmsgSignature();
};

class RtnetlinkInfoItem : public NetlinkInfoItem
{
	public:
	vector<tuple<unsigned, unsigned, Function*, Function*>> RtnetlinkHandlers;
	RtnetlinkInfoItem();
	RtnetlinkInfoItem(NetlinkInfoItem*);
	vector<string> generateSendmsgSignature();
};

class RDMAInfoItem : public NetlinkInfoItem
{
	public:
	vector<tuple<unsigned, unsigned, Function*, Function*>> RDMAHandlers;
	RDMAInfoItem();
	RDMAInfoItem(NetlinkInfoItem*);
	vector<string> generateSendmsgSignature();
};

class GenlFamilyInfo
{
	public:
	Value* familyStruct;
	Value* policy;
	string familyName;
	vector<tuple<unsigned, Function*, Function*>> GenlHandlers;
};
class GenlInfoItem : public NetlinkInfoItem
{
	public:
	vector<GenlFamilyInfo*> GenlInfos;
	GenlInfoItem();
	GenlInfoItem(NetlinkInfoItem*);
	vector<string> generateSendmsgSignature();
}; 

#define XFRM_MSG_BASE 0x10
class XfrmInfoItem : public NetlinkInfoItem
{
	public:
	vector<tuple<unsigned, Function*, Function*>> XfrmHandlers;
	XfrmInfoItem();
	XfrmInfoItem(NetlinkInfoItem*);
	vector<string> generateSendmsgSignature();
};

class NfSubsysInfo
{
	public:
	Value* subsysStruct;
	string subsysName;
	unsigned subsysID;
	map<unsigned, Function*> NetfilterHandlers;
};
class NetfilterInfoItem : public NetlinkInfoItem
{
	public:
	vector<NfSubsysInfo*> NfSubsysInfos;
	NetfilterInfoItem();
	NetfilterInfoItem(NetlinkInfoItem*);
	vector<string> generateSendmsgSignature();
};
class NetworkInterfaceExtractorPass : public IterativeModulePass {

	private:

		set<Value*>* GetAliasOfStructType(Value* value, string structName);
		Value* ExtractPtrAssignment(Value* ptrValue);

		void ProcessInetRegisterProtosw(CallInst* callInst);
		void ProcessProtoRegister(CallInst* callInst);

		void ProcessInetProtosw(ConstantStruct* protosw);
		void getProtoOpsFromCreateFunction(Function* F, ConstantStruct** protoOps, set<Function*>&visited, int depth);
		void ProcessNetlink(NetworkInterfaceInfoItem* infoItem);
		void ProcessNetlinkKernelCreate(NetworkInterfaceInfoItem* infoItem, CallInst* callInst);
		Function* getSendmsgHandler(Value* cfgOp);
		vector<tuple<unsigned, unsigned, Function*, Function*>> getRtnetlinkHandlers();
		vector<GenlFamilyInfo*> getGenlInfos();
		GenlFamilyInfo* getGenlFamilyInfo(ConstantStruct* familyStruct);
		vector<tuple<unsigned, Function*, Function*>> getGenlFamilyHandlers(ConstantStruct* familyStruct);
		vector<tuple<unsigned, Function*, Function*>> getXfrmHandlers();
		vector<NfSubsysInfo*> getNfInfos();
		NfSubsysInfo* getNfSubsysInfo(ConstantStruct* subsysStruct);
		map<unsigned, Function*> getNfSubsysHandlers(ConstantStruct* nfSubsysStruct);
		vector<tuple<unsigned, unsigned, Function*, Function*>> getRDMAHandlers();

		DataFlowAnalysis* DFA = nullptr;


		// FIXME: ad-hoc config

		map<string, int> ProtoOpsTypeMap = {
			{"unix_stream_ops", 1},
			{"unix_dgram_ops", 2},
			{"unix_seqpacket_ops", 5},
			{"packet_ops_spkt", 10},
			{"packet_ops", 2},
		};

		map<string, int> ProtoOpsProtocolMap = {
			{"unix_stream_ops", 0},
			{"unix_dgram_ops", 0},
			{"unix_seqpacket_ops", 0},
			{"packet_ops_spkt", 768},
			{"packet_ops", 768},
		};

		// functions
	public:
		NetworkInterfaceExtractorPass(GlobalContext *Ctx_): IterativeModulePass(Ctx_, "NetworkInterfaceExtractor") { }

		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
		virtual bool doModulePass(llvm::Module *);

};

#endif