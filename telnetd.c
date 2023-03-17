#include <WS2tcpip.h>
#include <WinSock2.H>  
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
//#include <time.h>
#pragma comment(lib, "ws2_32.lib")   
struct _ipset {
	char ipStatus; //0=off, 1=0.0.0.0 ,4=ipv4,6=ipv6
	char bind[16];
	int bindPort;
};
struct _cfdIdx {
	char cmdbuf[512];
	char buf[1536];
	char MSTelnet;
	char catchbuf[512];
};

struct _cfdIdx loIdx[4];

struct _ipset ipset;
char passwd[64] = "M\t\n\t\r\n\tM";
int localfd[5];
char logind[4] = "";
char logfail[4];
int bindFd;
char kevent[256]="";


void __log(char *str1,char *str2,char *str3){
	char timebuf[256];
	time_t time1;
	struct tm *time2;
	time(&time1);
	time2=localtime(&time1);
	memcpy(timebuf,asctime(time2),256);
	char *null=NULL;
	strtok_s(timebuf, "\n",&null);
	printf("telnetd: [time]:[%s], %s%s%s",timebuf,str1,str2,str3);
}

int local_fork(char i){
	int n;
	loIdx[i].buf[0]=0;loIdx[i].buf[1]=0;loIdx[i].buf[2]=0;loIdx[i].buf[3]=0;loIdx[i].buf[4]=0;loIdx[i].buf[5]=0;
	if ((n = recv(localfd[i], loIdx[i].buf, 1536, 0)) < 0) {
		if (GetLastError() == WSAEWOULDBLOCK) {
			return -1;
		}
		if (GetLastError() == WSAEINPROGRESS) {
			return -1;
		}
		closesocket(localfd[i]);
		localfd[i] = -1;
		logind[i] = 0;
		__log("user connect reset"," ","\n");
		return -1;
	}

	if (n == 0) {
		closesocket(localfd[i]);
		localfd[i] = -1;
		logind[i] = 0;
		__log("user break connect"," ","\n");
		return -1;
	}
	loIdx[i].buf[n]=0;
	if (loIdx[i].MSTelnet==-1) {
		if (loIdx[i].buf[n-1]=='\n') {	
		if (strlen(loIdx[i].buf)==2){
			if (loIdx[i].buf[0]=='\r') {
			loIdx[i].MSTelnet=1;	
			} else {
				loIdx[i].MSTelnet=0;
			}
		} else {
			loIdx[i].MSTelnet=0;
		}
		} else {
			if (n<2){
			loIdx[i].MSTelnet=1;
			} else {
			char buf[] = "invalid command!\r\npassword:";
			send(localfd[i], buf, sizeof(buf), 0);
			loIdx[i].MSTelnet=0;
			return 0;
			}
		}			
	}
	
	
	if (loIdx[i].MSTelnet==1) {
		
	if (loIdx[i].buf[n-1]!='\n'){
		loIdx[i].buf[10]=0;loIdx[i].buf[11]=0;loIdx[i].buf[12]=0;
		if (strlen(loIdx[i].catchbuf)>420) {memset(loIdx[i].catchbuf,0,512);}
		strcat_s(loIdx[i].catchbuf,512,loIdx[i].buf);
		return 0;
	} else {
		if (strlen(loIdx[i].buf)<3){
		memcpy(loIdx[i].buf,loIdx[i].catchbuf,512);
		memset(loIdx[i].catchbuf,0,512);
		}
	}
		
	}
	char *null=NULL;
	strtok_s(loIdx[i].buf, "\n",&null);
	strtok_s(loIdx[i].buf, "\r",&null);
	if (logind[i]) {
		if (loIdx[i].buf[0]=='e' && loIdx[i].buf[1]=='x' && loIdx[i].buf[2]=='i' && loIdx[i].buf[3]=='t') {
		closesocket(localfd[i]);
		localfd[i] = -1;
		logind[i] = 0;	
		__log("user exit "," ","\n");
		return 0;
		}
		memset(loIdx[i].cmdbuf, 0, 256);
		FILE *filed=NULL;
		if ((filed = _popen(loIdx[i].buf, "r")) != NULL){
			while (fgets(loIdx[i].cmdbuf, 256, filed) != NULL){
				send(localfd[i], loIdx[i].cmdbuf, strlen(loIdx[i].cmdbuf), 0);
			}
			_pclose(filed);
			if (loIdx[i].MSTelnet == 1){
				char buf[] = "\r\n";
				send(localfd[i], buf, sizeof(buf), 0); 
				}
			send(localfd[i], kevent, strlen(kevent), 0);
		}
	}
	else {
		if (!strcmp(loIdx[i].buf, passwd)) {
			char buflogin[] = "login success!\r\n";
			__log("info",":",buflogin);
			send(localfd[i], buflogin, sizeof(buflogin), 0);
			logind[i] = 1;
			send(localfd[i], kevent, strlen(kevent), 0);
		}
		else {
			__log("invalid password of \"",loIdx[i].buf, "\"\n");
			
			char buflogin[] = "login fail!\r\npassword:";
			send(localfd[i], buflogin, sizeof(buflogin), 0);
			logfail[i]++;
			if (logfail[i]>4) {
				closesocket(localfd[i]);
				localfd[i] = -1;
				logind[i] = 0;
				__log("login fail too much",",","closed\n");
			}
		}
	}


	return 0;
}

int accpetfd(){
	struct sockaddr_in clientaddr;
	int addrlen;
	char able_fd = 4;
	addrlen = sizeof(clientaddr);

	for (int i = 0; i<4; i++){
		if ((localfd[i] <0)) { able_fd = i; }
	}

	localfd[able_fd] = accept(bindFd, (struct sockaddr *)&clientaddr, &addrlen);
	if (localfd[able_fd] <0) {
		__log("accept connect ","err"," \n");
		return -1;
	}
	char ipaddr[16];
	inet_ntop(AF_INET,&(clientaddr.sin_addr),(PSTR )&ipaddr,16);
	__log("connect from ", ipaddr," \n");
	
	if (able_fd == 4){
		char buf[] = "connect too much\n";
		__log("info",":", buf);
		int io = 1;
		ioctlsocket(localfd[4], FIONBIO, &io);
		send(localfd[4], buf, sizeof(buf), 0);
		closesocket(localfd[4]);
		localfd[4] = -1;
		return -1;
	}
	int io = 1;
	ioctlsocket(localfd[able_fd], FIONBIO, &io);
	logfail[able_fd]=0;
	loIdx[able_fd].MSTelnet=-1;
	memset(loIdx[able_fd].catchbuf,0,512);
	
	char buflogin[] = "wellcome to telnet server!\r\npassword:";
	send(localfd[able_fd], buflogin, sizeof(buflogin), 0);
	return 0;
}
void helpf(char *argv){
	fprintf(stdout, "Usage: %s [ options ]\n", argv);
	fprintf(stdout, "  -l, --listen address\n");
	fprintf(stdout, "  -p, --port\n");
	fprintf(stdout, "  -k, --key, set password\n");
	fprintf(stdout, "  -h, --help\n");
	fprintf(stdout, "Examples:\n");
	fprintf(stdout, "%s -l 127.0.0.1 -p 23 -k 123456789\n", argv);
	exit(0); 
}
int main(int argc, char *argv[],char *env[])
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0){
		printf("Init WSAStartup error.\n");
		return -1;
	}
	if (argc<=1){
	helpf(argv[0]);
		}
		
	if (!strcmp(argv[1], "/h")){
	helpf(argv[0]);
	}
	
	if (!strcmp(argv[1], "-h")){
	helpf(argv[0]);
	}
	
	if (!strcmp(argv[1], "-?")){
	helpf(argv[0]);
	}
	
	if (!strcmp(argv[1], "/?")){
	helpf(argv[0]);
	}
	
	if (!strcmp(argv[1], "--h")){
	helpf(argv[0]);
	}
	
	char used=0;
	ipset.bindPort=23;
	ipset.ipStatus=4;
	memcpy(ipset.bind, "0.0.0.0", 10);
	
if (argc>2){
	//--------------------------------------------------------
	if (!strcmp(argv[1], "-l")){
		if (strlen(argv[2])<16){ memcpy(ipset.bind, argv[2], 16); }
		used=1;
	}
		
	if (!strcmp(argv[1], "-p")){
		if (strlen(argv[2])<7){ ipset.bindPort = atoi(argv[2]); }
		used=1;
	} 
		
	if (!strcmp(argv[1], "-k")){
		if (strlen(argv[2])<64){ strcpy_s(passwd,64, argv[2]); }
		used=1;
	}	
}

if (argc>4){
	//---------------------------------------------------
	if (!strcmp(argv[3], "-p")){
		if (strlen(argv[4])<7){ ipset.bindPort = atoi(argv[4]); }
	}
	if (!strcmp(argv[3], "-l")){
		if (strlen(argv[4])<16){ memcpy(ipset.bind, argv[4], 16); }
	}
	if (!strcmp(argv[3], "-k")){
		if (strlen(argv[4])<64){ strcpy_s(passwd,64, argv[4]); }
	}
}
if (argc>6){
	//------------------------------------------------------
	
	if (!strcmp(argv[5], "-k")){
		if (strlen(argv[6])<64){ strcpy_s(passwd,64, argv[6]); }
	}
	if (!strcmp(argv[5], "-p")){
		if (strlen(argv[6])<7){ ipset.bindPort = atoi(argv[6]); }
	}
	if (!strcmp(argv[5], "-l")){
		if (strlen(argv[6])<16){ memcpy(ipset.bind, argv[6], 16); }
	}
	//----------------------------------------------------------
}
	if (!used) {
		helpf(argv[0]);
	}
	
	printf("telnet server starting,listen on %s:%d,using ipv%d\n", ipset.bind,ipset.bindPort,ipset.ipStatus);
	
	char *buf=NULL;
	size_t len=0;
	_dupenv_s(&buf,&len,"USERPROFILE");
	sprintf_s(kevent,256, "%s>", buf);
	struct sockaddr_in serveraddr;


	localfd[0] = -1;
	localfd[1] = -1;
	localfd[2] = -1;
	localfd[3] = -1;

	bindFd = socket(AF_INET, SOCK_STREAM, 0);
	if (bindFd < 0) {
		fprintf(stderr, "couldn't create "
			"server socket!\n");
		bindFd = -1;
		exit(-1);
	}
	int io = 1;
	setsockopt(bindFd, SOL_SOCKET, SO_REUSEADDR, (const char *)&io, sizeof(io));

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	inet_pton(AF_INET, ipset.bind, &(serveraddr.sin_addr));
	serveraddr.sin_port = htons(ipset.bindPort);
	if (bind(bindFd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
	{

		fprintf(stderr, "Error: couldn't Bind to address %s port %d\n", ipset.bind, ipset.bindPort);
		closesocket(bindFd);
		exit(-1);
	}

	if (listen(bindFd, 5) < 0) {

		fprintf(stderr, "Error: couldn't listen to ip address %s port %d\n", ipset.bind, ipset.bindPort);
		closesocket(bindFd);
		exit(-1);
	}

	io = 1;
	ioctlsocket(bindFd, FIONBIO, &io);

	while (1){
		int maxfd = 0;
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(bindFd, &readfds);

		for (int i = 1; i<4; i++){
		if (localfd[i] != -1){
			FD_SET(localfd[i], &readfds);
		}
	}

	for (int i = 1; i<4; i++){
		if (localfd[i]>maxfd) { maxfd = localfd[i]; }
	}

	if (select(maxfd + 1, &readfds, NULL, NULL, 0) == 0) {
		printf("timeout sleeping\n");
		Sleep(16);
		continue;
	}

	if (FD_ISSET(bindFd, &readfds)) { accpetfd(); }

	for (int i = 1; i<4; i++){
	if (localfd[i] != -1){
		if (FD_ISSET(localfd[i], &readfds)) { local_fork(i); }
	}

}

	}
	return 0;
}