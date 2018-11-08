#include "Firewall.h"
#include <string>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <stdio.h>
#include <string.h>

using namespace std;

Firewall::Firewall(char** argv){
	set = parseCsvFile(argv);
}

unordered_set<uint64_t> Firewall::parseCsvFile(char** argv){
	unordered_set<uint64_t> set;
    string line;
    string fileName = "";
    fileName.append(argv[1]);
    ifstream in(fileName);
    while(getline(in, line)  && in.good() )
    {
    	vector<string> rawData;
        int startPos = 0;
		for(int i=0;i<3;i++){
			int dPos = line.find(',',startPos);
			rawData.push_back(line.substr(startPos, dPos-startPos));
			startPos = dPos+1;
		}
		rawData.push_back(line.substr(startPos, line.size()-startPos));	
		addRules(rawData, set);
    }
    in.close();
    return set;
}

uint32_t Firewall::ip2Ipcode(string ip){
	uint32_t result = 0;
	int offset = 0;
	int startPos = 0;
	for(int i=0;i<3;i++){
		int dPos = ip.find('.',startPos);
		char c = stoi(ip.substr(startPos, dPos-startPos));
		memcpy((char*)(&result)+offset, &c, sizeof(char));
		offset += sizeof(char);
		startPos = dPos+1;
	}
	char c = stoi(ip.substr(startPos, ip.size()-startPos));
	memcpy((char*)(&result)+offset, &c, sizeof(char));
	offset += sizeof(char);
	return result;
}

void Firewall::addRules(vector<string> rawData, unordered_set<uint64_t>& ruleSet){
	bool isIn = getisIn(rawData[0]);
	bool isTcp = getisTcp(rawData[1]);
	vector<uint32_t> ips = getips(rawData[2]);
	vector<short> ports = getports(rawData[3]);
	for(int i=0;i<ips.size();i++){
		for(int j=0;j<ports.size();j++){
			Rule rule(isIn, isTcp, ips[i], ports[j]);
			ruleSet.insert(rule.getCode());
		}
	}
}

bool Firewall::getisTcp(string s){
	return s=="tcp";
}

bool Firewall::getisIn(string s){
	return s=="inbound";
}

vector<uint32_t> Firewall::getips(string s){
	vector<uint32_t> result;
	int pos = s.find('-');
	if(pos == string::npos){
		result.push_back(ip2Ipcode(s));
	} else{
		uint32_t start = ip2Ipcode(s.substr(0, pos));
		uint32_t end = ip2Ipcode(s.substr(pos+1, s.size()-pos-1));
		for(uint32_t ip = start; ip<=end; ip++){
			result.push_back(ip);
		}
	}
	return result;
}

vector<short> Firewall::getports(string s){
	vector<short> result;
	int pos = s.find('-');
	if(pos == string::npos){
		result.push_back((short)stoi(s));
	} else{
		short start = short(stoi(s.substr(0, pos)));
		short end = short(stoi(s.substr(pos+1, s.size()-pos-1)));
		for(short ip = start; ip<=end; ip++){
			result.push_back(ip);
		}
	}
	return result;
}

bool Firewall::acceptPacket(string direction, string protocol, int port, string ip){
	Rule rule(getisIn(direction), getisTcp(protocol), ip2Ipcode(ip) ,(short)port);
	return set.find(rule.getCode())==set.end();
}