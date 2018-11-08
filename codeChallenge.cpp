#include "Firewall.h"

using namespace std;

int main(int argc, char** argv){
	Firewall firewall(argv);
	cout<<firewall.acceptPacket("inbound", "tcp", 80, "192.168.1.2");
	return 0;
}