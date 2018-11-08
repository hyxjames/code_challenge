#include "Rule.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>

class Firewall{
private:
	unordered_set<uint64_t> set;
	unordered_set<uint64_t> parseCsvFile(char** argv);
	uint32_t ip2Ipcode(string ip);
	void addRules(vector<string> rawData, unordered_set<uint64_t>& ruleSet);
	bool getisTcp(string s);
	bool getisIn(string s);
	vector<uint32_t> getips(string s);
	vector<short> getports(string s);
public:
	Firewall(char** argv);

	bool acceptPacket(string direction, string protocol, int port, string ip);
};