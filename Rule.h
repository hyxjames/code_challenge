#include <string>
#include <vector>
#include <stdio.h>
#include <inttypes.h>

using namespace std;

class Rule{
private: 
	//rulecode = isIn|isTcp|ipcode|port
	uint64_t ruleCode;
	bool isIn;
	bool isTcp;
	string ip;
	short port;


	uint32_t ip2code(string ip);
public:
	Rule(bool isIn, bool isTcp, uint32_t ipCode, short port);

	bool getIsIn();

	bool getIsTcp();

	string getIp();

	short getPort();

	uint64_t getCode();
};