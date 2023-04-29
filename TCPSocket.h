#ifndef _TCP_SOCKET_H_
#define _TCP_SOCKET_H_

#include <vector>
#include <string>
#include <stdint.h>
#include <stdexcept>
#include <algorithm>

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <endian.h>
#include <netdb.h>
#include <cstring>
#define closeSocket(fd) \
	do { \
		shutdown(fd, SHUT_RDWR); \
		::close(fd); \
	} while(0)

#define ntohll(x) be64toh(x)
#define htonll(x) htobe64(x)
#define set_ip_sockaddr_in(sockobj, ip) do { sockobj.sin_addr.s_addr = (ip); } while (0)
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef int socklen_t;
#define closeSocket(fd) closesocket(fd)

#if __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#define set_ip_sockaddr_in(sockobj, ip) do { sockobj.sin_addr.S_un.S_addr = (ip); } while (0)
#endif

#endif

#define NOOP_FUNC(x) (x)
#define EXCEPTION_DEF(name) class name : public std::runtime_error { public: name(std::string what) : std::runtime_error(what) {} }

#define RECEIVE_TYPE(type, funcname, convfunc) 	\
type receive##funcname() {						\
	try {										\
		auto buffer = receive(sizeof(type)); 	\
		return convfunc(*(type*)buffer.data()); \
	} catch(...) { throw; }						\
}

#define SEND_TYPE(type, convfunc) 						\
void send(type arg0) {									\
	try {												\
		vector<uint8_t> bytes(sizeof(type));			\
		type converted = convfunc(arg0);				\
		memcpy(bytes.data(), &converted, sizeof(type));	\
		send(bytes);									\
	} catch(...) { throw; }								\
}

using std::vector, std::string;

class TCPSocket {

	sockaddr_in remote;
	int socketFd = 0;

	static inline timeval create_timeout(uint32_t ms) {
		timeval time;
		time.tv_sec = ms / 1000;
		time.tv_usec = (ms - (time.tv_sec * 1000)) * 1000;
		return time;
	}

	bool readReady(uint32_t timeoutMs) {
		fd_set fdSet;
		FD_ZERO(&fdSet);
		FD_SET(socketFd, &fdSet);

		timeval timeout = create_timeout(timeoutMs);
		int ret = select(FD_SETSIZE, &fdSet, 0, 0, &timeout);
		return (ret <= 0 || !FD_ISSET(socketFd, &fdSet)) ? false : true;
	}

	bool writeReady(uint32_t timeoutMs) {
		fd_set fdSet;
		FD_ZERO(&fdSet);
		FD_SET(socketFd, &fdSet);

		timeval timeout = create_timeout(timeoutMs);
		int ret = select(FD_SETSIZE, 0, &fdSet, 0, &timeout);
		return (ret <= 0 || !FD_ISSET(socketFd, &fdSet)) ? false : true;
	}

#ifdef _WIN32
	inline static bool wsaReady = false;
	inline static WSADATA wsaData;

	static void startWSA() {
		if(wsaReady) return;
		if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) throw std::runtime_error("WSAStartup failed!");

		wsaReady = true;
	}
#endif

  public:
	
	TCPSocket() {}
	TCPSocket(int socket) {
		this->socketFd = socket;
		int tmp = sizeof(sockaddr_in);
		getpeername(socket, (sockaddr*)&remote, (socklen_t*)&tmp);
	}

	sockaddr_in getRemote() {
		return remote;
	}

	EXCEPTION_DEF(TimeoutException);
	EXCEPTION_DEF(NetworkException);
	EXCEPTION_DEF(CloseException);

	bool connect(string host, uint16_t port) {
#ifdef _WIN32
		startWSA();
#endif
		disconnect();

		uint8_t ip[4] = {0};
		uint8_t results = sscanf(host.c_str(), "%3u.%3u.%3u.%3u", &ip[0], &ip[1], &ip[2], &ip[3]);

		// isn't an ip address - parse dns
		if(results != 4) {
			hostent* dnsResults = gethostbyname(host.c_str());

			if(dnsResults == NULL) return false;

            set_ip_sockaddr_in(remote, *(uint32_t*)dnsResults->h_addr_list[0]);
		} else {
            set_ip_sockaddr_in(remote, *(uint32_t*)ip);
		}

		// Address family
		remote.sin_family = AF_INET;

		// Set port
		remote.sin_port = htons(port);

		socketFd = socket(AF_INET, SOCK_STREAM, 0);

		if(::connect(socketFd, (const sockaddr*)&remote, sizeof(remote)) < 0) return false;
		return true;
	}

	void disconnect() {
		remote = {0};
		if(socketFd == 0) return;
		closeSocket(socketFd);
	}

	void send(vector<uint8_t>& bytes) {
		int sentTotal = 0;

		while(sentTotal < bytes.size()) {
			if(!writeReady(15 * 1000)) throw TimeoutException("send timed out after 15s");
			int sentBytes = ::send(socketFd, (char*)bytes.data() + sentTotal, bytes.size() - sentTotal, 0);

			if(sentBytes > 0)
				sentTotal += sentBytes;
			else if(sentBytes == 0)
				throw CloseException("socket was closed during send");
			else
				throw NetworkException("connection was aborted during send");
		}
	}

	SEND_TYPE(uint8_t, NOOP_FUNC);
	SEND_TYPE(uint16_t, htons);
	SEND_TYPE(uint32_t, htonl);
	SEND_TYPE(uint64_t, htonll);

	vector<uint8_t> receiveAvailable() {
		uint8_t buffer[4096];
		if(!readReady(15 * 1000)) throw TimeoutException("receive timed out after 15s");
		int receivedBytes = recv(socketFd, (char*)buffer, 4096, 0);
		
		if(receivedBytes == 0)
			throw CloseException("socket is closed");
		else if(receivedBytes < 0)
			throw NetworkException("connection was aborted during receive");

		return vector<uint8_t>(buffer, buffer + receivedBytes);
	}

	vector<uint8_t> receiveUntil(vector<uint8_t> byteSequence) {
		vector<uint8_t> buffer;

		uint8_t peekBuffer[4096];

		while(1) {
			if(!readReady(15 * 1000)) throw TimeoutException("receive timed out after 15s");
			int receivedBytes = recv(socketFd, (char*)peekBuffer, 4096, MSG_PEEK);

			if(receivedBytes == 0)
				throw CloseException("socket is closed");
			else if(receivedBytes < 0)
				throw NetworkException("connection was aborted during receive");

			buffer.insert(buffer.end(), peekBuffer, peekBuffer + receivedBytes);
			auto iter = std::search(buffer.begin(), buffer.end(), byteSequence.begin(), byteSequence.end());
			if(iter != buffer.end()) {
				int readSize = iter - (buffer.end() - receivedBytes) + byteSequence.size();
				buffer.erase(iter + byteSequence.size(), buffer.end());
				recv(socketFd, (char*)peekBuffer, readSize, 0); // remove until found from receive queue
				return buffer;
			}
		}
	}

	vector<uint8_t> receive(uint64_t amount) {
		vector<uint8_t> buffer(amount);

		int receivedTotal = 0;

		while(receivedTotal < amount) {
			if(!readReady(15 * 1000)) throw TimeoutException("receive timed out after 15s");
			int receivedBytes = recv(socketFd, (char*)buffer.data() + receivedTotal, amount - receivedTotal, 0);

			if(receivedBytes > 0)
				receivedTotal += receivedBytes;
			else if(receivedBytes == 0)
				throw CloseException("socket was closed during receive");
			else
				throw NetworkException("connection was aborted during receive");
		}

		return buffer;
	}

	RECEIVE_TYPE(uint8_t, Byte, NOOP_FUNC);
	RECEIVE_TYPE(uint16_t, Short, ntohs);
	RECEIVE_TYPE(uint32_t, Int, ntohl);
	RECEIVE_TYPE(uint64_t, LongInt, ntohll);
};

#undef RECEIVE_TYPE
#undef SEND_TYPE
#undef NOOP_FUNC
#undef EXCEPTION_DEF

#endif