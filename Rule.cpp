#include "Rule.h"
#include <string>
#include <vector>
#include <stdio.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

Rule::Rule(bool isIn, bool isTcp, uint32_t ipCode, short port){
	this->isIn = isIn;
	this->isTcp = isTcp;
	this->ip = ip;
	this->port = port;
	int offset = 0;
	memcpy((char*)(&ruleCode)+offset, &isIn, sizeof(bool));
	offset += sizeof(bool);
	memcpy((char*)(&ruleCode)+offset, &isTcp, sizeof(bool));
	offset += sizeof(bool);
	memcpy((char*)(&ruleCode)+offset, &ipCode, sizeof(uint32_t));
	offset += sizeof(uint32_t);
	memcpy((char*)(&ruleCode)+offset, &port, sizeof(short));
	offset += sizeof(short);
}

bool Rule::getIsIn(){
	return isIn;
}

bool Rule::getIsTcp(){
	return isTcp;
}

string Rule::getIp(){
	return ip;
}

short Rule::getPort(){
	return port;
}

uint64_t Rule::getCode(){
	return ruleCode;
}