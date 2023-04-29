#ifndef WEB_SOCKET_SERVER_H_
#define WEB_SOCKET_SERVER_H_

#include <stdint.h>
#include <vector>
#include <string>
#include <functional>
#include <stdexcept>
#include <thread>
#include <list>
#include <unordered_map>
#include <algorithm>
#include <memory>
#include <mutex>

#include "TCPSocket.h"

#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WEBSOCKET_SWITCH_PROTOCOLS \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Upgrade: websocket\r\n" \
	"Connection: Upgrade\r\n" \
	"Sec-WebSocket-Accept: "

using std::function, std::string, std::vector, std::runtime_error, std::thread, std::list, std::unordered_map, std::shared_ptr,
	std::mutex, std::lock_guard;

namespace util {

static inline string b64_encode(const vector<uint8_t>& toEncode) {
	const uint8_t base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	size_t outLen = toEncode.size() * 4 / 3 + 4;

	vector<uint8_t> encoded(outLen);

	auto encodeIter = encoded.begin();
	auto toEncodeIter = toEncode.begin();

	while(toEncode.end() - toEncodeIter >= 3) {
		uint8_t first = toEncodeIter[0];
		uint8_t second = toEncodeIter[1];
		uint8_t third = toEncodeIter[2];

		encodeIter[0] = base64_table[first >> 2];
		encodeIter[1] = base64_table[((first & 0b00000011) << 4) | (second >> 4)];
		encodeIter[2] = base64_table[((second & 0b00001111) << 2) | (third >> 6)];
		encodeIter[3] = base64_table[third & 0b00111111];

		encodeIter += 4;
		toEncodeIter += 3;
	}

	if(toEncode.end() - toEncodeIter > 0) {
		encodeIter[0] = base64_table[toEncodeIter[0] >> 2];

		if(toEncode.end() - toEncodeIter == 2) {
			encodeIter[1] = base64_table[((toEncodeIter[0] & 0b00000011) << 4) | (toEncodeIter[1] >> 4)];
			encodeIter[2] = base64_table[((toEncodeIter[1] & 0b00001111) << 2)];
		} else {
			encodeIter[1] = base64_table[((toEncodeIter[0] & 0b00000011) << 4)];
			encodeIter[2] = '=';
		}

		encodeIter[3] = '=';
	}

	return string((char*)encoded.data());
}

struct URL {

	std::string queryString;
	std::string path = "/";
	std::string protocol;
	std::string host;
	short port = 80;

	URL(const char* toParse) : URL(std::string(toParse)) {}
	URL(std::string toParse) {

		size_t pos = toParse.find("://");
		if(pos == std::string::npos) throw std::runtime_error("no protocol");

		protocol = toParse.substr(0, pos);
		toParse = toParse.substr(pos + 3);

		size_t pathPos = toParse.find("/");

		host = pathPos != std::string::npos ? toParse.substr(0, pathPos) : toParse;

		if((pos = host.find(":")) != std::string::npos) {
			port = std::stoi(host.substr(pos + 1));
			host = host.substr(0, pos);
		} else if(protocol == "https" || protocol == "wss") {
			port = 443;
		}

		if(pathPos == std::string::npos) return; // no path no need to parse it

		path = toParse.substr(pathPos);

		if((pos = path.find("?")) != std::string::npos) {
			queryString = path.substr(pos);
			path = path.substr(0, pos);
		}
	}
};

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | (rol(block->l[i], 8) & 0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) \
	(block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) \
	z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R1(v, w, x, y, z, i) \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R2(v, w, x, y, z, i) \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); \
	w = rol(w, 30);
#define R3(v, w, x, y, z, i) \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
	w = rol(w, 30);
#define R4(v, w, x, y, z, i) \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
	w = rol(w, 30);

class SHA1 {

	uint32_t state[5];
	uint32_t count[2];
	uint8_t buffer[64];

	void transform(const uint8_t buffer[64]) {
		uint32_t a, b, c, d, e;

		typedef union {
			uint8_t c[64];
			uint32_t l[16];
		} CHAR64LONG16;

		CHAR64LONG16 block[1];

		memcpy(block, buffer, 64);

		/* Copy context->state[] to working vars */
		a = state[0];
		b = state[1];
		c = state[2];
		d = state[3];
		e = state[4];
		/* 4 rounds of 20 operations each. Loop unrolled. */
		R0(a, b, c, d, e, 0);
		R0(e, a, b, c, d, 1);
		R0(d, e, a, b, c, 2);
		R0(c, d, e, a, b, 3);
		R0(b, c, d, e, a, 4);
		R0(a, b, c, d, e, 5);
		R0(e, a, b, c, d, 6);
		R0(d, e, a, b, c, 7);
		R0(c, d, e, a, b, 8);
		R0(b, c, d, e, a, 9);
		R0(a, b, c, d, e, 10);
		R0(e, a, b, c, d, 11);
		R0(d, e, a, b, c, 12);
		R0(c, d, e, a, b, 13);
		R0(b, c, d, e, a, 14);
		R0(a, b, c, d, e, 15);
		R1(e, a, b, c, d, 16);
		R1(d, e, a, b, c, 17);
		R1(c, d, e, a, b, 18);
		R1(b, c, d, e, a, 19);
		R2(a, b, c, d, e, 20);
		R2(e, a, b, c, d, 21);
		R2(d, e, a, b, c, 22);
		R2(c, d, e, a, b, 23);
		R2(b, c, d, e, a, 24);
		R2(a, b, c, d, e, 25);
		R2(e, a, b, c, d, 26);
		R2(d, e, a, b, c, 27);
		R2(c, d, e, a, b, 28);
		R2(b, c, d, e, a, 29);
		R2(a, b, c, d, e, 30);
		R2(e, a, b, c, d, 31);
		R2(d, e, a, b, c, 32);
		R2(c, d, e, a, b, 33);
		R2(b, c, d, e, a, 34);
		R2(a, b, c, d, e, 35);
		R2(e, a, b, c, d, 36);
		R2(d, e, a, b, c, 37);
		R2(c, d, e, a, b, 38);
		R2(b, c, d, e, a, 39);
		R3(a, b, c, d, e, 40);
		R3(e, a, b, c, d, 41);
		R3(d, e, a, b, c, 42);
		R3(c, d, e, a, b, 43);
		R3(b, c, d, e, a, 44);
		R3(a, b, c, d, e, 45);
		R3(e, a, b, c, d, 46);
		R3(d, e, a, b, c, 47);
		R3(c, d, e, a, b, 48);
		R3(b, c, d, e, a, 49);
		R3(a, b, c, d, e, 50);
		R3(e, a, b, c, d, 51);
		R3(d, e, a, b, c, 52);
		R3(c, d, e, a, b, 53);
		R3(b, c, d, e, a, 54);
		R3(a, b, c, d, e, 55);
		R3(e, a, b, c, d, 56);
		R3(d, e, a, b, c, 57);
		R3(c, d, e, a, b, 58);
		R3(b, c, d, e, a, 59);
		R4(a, b, c, d, e, 60);
		R4(e, a, b, c, d, 61);
		R4(d, e, a, b, c, 62);
		R4(c, d, e, a, b, 63);
		R4(b, c, d, e, a, 64);
		R4(a, b, c, d, e, 65);
		R4(e, a, b, c, d, 66);
		R4(d, e, a, b, c, 67);
		R4(c, d, e, a, b, 68);
		R4(b, c, d, e, a, 69);
		R4(a, b, c, d, e, 70);
		R4(e, a, b, c, d, 71);
		R4(d, e, a, b, c, 72);
		R4(c, d, e, a, b, 73);
		R4(b, c, d, e, a, 74);
		R4(a, b, c, d, e, 75);
		R4(e, a, b, c, d, 76);
		R4(d, e, a, b, c, 77);
		R4(c, d, e, a, b, 78);
		R4(b, c, d, e, a, 79);
		/* Add the working vars back into context.state[] */
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
	}

  public:
	SHA1() {
		state[0] = 0x67452301;
		state[1] = 0xEFCDAB89;
		state[2] = 0x98BADCFE;
		state[3] = 0x10325476;
		state[4] = 0xC3D2E1F0;
		count[0] = count[1] = 0;
	}

	SHA1& update(std::vector<uint8_t>& data) {
		uint32_t i;
		size_t len = data.size();

		uint32_t j;

		j = count[0];
		if((count[0] += len << 3) < j) count[1]++;
		count[1] += (len >> 29);
		j = (j >> 3) & 63;
		if((j + len) > 63) {
			memcpy(&buffer[j], data.data(), (i = 64 - j));
			transform(buffer);
			for(; i + 63 < len; i += 64) transform(&data[i]);
			j = 0;
		} else
			i = 0;
		memcpy(&buffer[j], &data[i], len - i);
		return *this;
	}

	std::vector<uint8_t> final() {

		std::vector<uint8_t> digest(20);
		std::vector<uint8_t> finalcount(8);

		std::vector<uint8_t> c(1);

		for(int i = 0; i < 8; i++) finalcount[i] = (uint8_t)((count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);

		c[0] = 0200;
		update(c);

		while((count[0] & 504) != 448) {
			c[0] = 0000;
			update(c);
		}

		update(finalcount);

		for(int i = 0; i < 20; i++) digest[i] = (uint8_t)((state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
		return digest;
	}
};
#undef R0
#undef R1
#undef R2
#undef R3
#undef R4
#undef rol
#undef blk
#undef blk0

} // namespace util

class WebSocket {
	friend class WebSocketServer;

  private:
	static inline vector<uint8_t> pingData = {'p', 'i', 'n', 'g', 'd', 'a', 't', 'a'};

	function<void(vector<uint8_t>&, bool)> messageHandler = 0;
	function<void()> closeHandler = 0;
	bool clientMode = true;
	TCPSocket sock;

	enum Opcode {
		Continuation = 0x00, ///< %x0 denotes a continuation frame
		Text = 0x01,		 ///< %x1 denotes a text frame
		Binary = 0x02,		 ///< %x2 denotes a binary frame
							 ///< %x3-7 are reserved for further non-control frames
		Close = 0x08,		 ///< %x8 denotes a connection close
		Ping = 0x09,		 ///< %x9 denotes a ping
		Pong = 0x0A			 ///< %xA denotes a pong
							 ///< %xB-F are reserved for further control frames
	};

	struct Frame {
		bool fin;
		Opcode opcode;
		bool masked;
		uint8_t maskingKey[4];
		uint64_t payloadLength;
		vector<uint8_t> payload;
	};

	inline void terminate() {
		sock.disconnect();
		if(closeHandler) closeHandler();
	}

	inline Frame readFrame() {
		Frame frame;
		try {
			uint8_t flags = sock.receiveByte();

			frame.fin = flags >> 7;
			frame.opcode = (Opcode)(flags & 0x0f);

			uint8_t payloadInf = sock.receiveByte();
			frame.masked = payloadInf >> 7;

			frame.payloadLength = payloadInf & 0x7f;

			if(frame.payloadLength == 126) {
				frame.payloadLength = sock.receiveShort();
			} else if(frame.payloadLength == 127) {
				frame.payloadLength = sock.receiveLongInt();
			}

			if(frame.masked) {
				frame.payload = sock.receive(4);
				memcpy(frame.maskingKey, frame.payload.data(), 4);
				frame.payload = vector<uint8_t>();
			}

			if(frame.payloadLength == 0) return frame;

			frame.payload = sock.receive(frame.payloadLength);

			return frame;
		} catch(...) { throw; }
	}

#define SAFE_SEND(args) \
	do { \
		try { \
			sock.send(args); \
		} catch(...) { \
			terminate(); \
			return; \
		} \
	} while(0)

	mutex sendLock;

	inline void sendFrame(Opcode opcode, vector<uint8_t>& data) {

		lock_guard<mutex> lock(sendLock);

		uint8_t flags = 0b10000000 | opcode; // fin = 1, opcode is lower 4 bits

		SAFE_SEND(flags);

		uint8_t payloadInf;
		if(data.size() > 125) {
			payloadInf = (data.size() > 0xffff) ? 127 : 126; // 127 if > uint16 else len is < 65535 byte
		} else {
			payloadInf = data.size();
		}

		if(clientMode) payloadInf |= 0b10000000; // set masking bit

		SAFE_SEND(payloadInf);

		if(data.size() > 125) {
			if(data.size() > 0xffff) SAFE_SEND((uint64_t)data.size());
			else
				SAFE_SEND((uint16_t)data.size());
		}

		if(clientMode) {
			vector<uint8_t> copy(data.begin(), data.end());
			vector<uint8_t> maskingKey(4);
			(*(uint32_t*)maskingKey.data()) = rand(); // TODO: use strong entropy source
			for(size_t i = 0; i < copy.size(); i++) copy[i] ^= maskingKey[i % 4];

			SAFE_SEND(maskingKey);

			if(copy.size() == 0) return;
			SAFE_SEND(copy);

		} else {
			SAFE_SEND(data);
		}
	}

#undef SAFE_SEND

	void receiveLoop() {
		while(1) {

			Frame frame;

			try {
				frame = readFrame();
			} catch(TCPSocket::TimeoutException&) {
				if(clientMode) {
					terminate();
					return;
				}
				ping();
				continue;
			} catch(...) {
				terminate();
				return;
			}

			if(frame.opcode == Close) {
				terminate();
				return;
			}

			if(frame.masked) {
				if(clientMode) {
					terminate();
					return;
				}
				// decode XOR
				for(size_t i = 0; i < frame.payloadLength; i++) frame.payload[i] ^= frame.maskingKey[i % 4];
			}

			if(frame.opcode == Ping) { sendFrame(Pong, frame.payload); }

			// also close if ping data does not match pong response
			if(frame.opcode == Pong && pingData != frame.payload) {
				terminate();
				return;
			}

			if(frame.opcode == Text || frame.opcode == Binary) {
				if(messageHandler) messageHandler(frame.payload, frame.opcode == Binary);
				if(!clientMode) ping(); // send ping after every received frame for good measure
			}
		}
	}

	WebSocket() {}

  public:
	WebSocket(string url, function<void(WebSocket&)> onOpen = 0, bool backgroundThread = false) {
		util::URL uri = url;
		sock.connect(uri.host, uri.port);
		string request = "GET ";
		request += uri.path;
		request += uri.queryString;
		request += " HTTP/1.1\r\n";
		request += "Host: ";
		request += uri.host;

		if(!(uri.port == 80 || uri.port == 443)) {
			request += ":";
			request += std::to_string(uri.port);
		}

		vector<uint8_t> secKey(16);
		for(int i = 0; i < 4; i++) (*(uint32_t*)&secKey[i * 4]) = rand();
		string b64Key = util::b64_encode(secKey);

		request += "\r\n";
		request += "Connection: Upgrade\r\n";
		request += "Upgrade: websocket\r\n";
		request += "Sec-WebSocket-Version: 13\r\n";
		request += "Sec-WebSocket-Key: ";
		request += b64Key;
		request += "\r\n\r\n";

		vector<uint8_t> outgoingRequest(request.begin(), request.end());
		sock.send(outgoingRequest);

		auto binResponse = sock.receiveUntil({'\r', '\n', '\r', '\n'});
		string response(binResponse.begin(), binResponse.end());

		string firstline = response.substr(0, response.find("\r\n"));

		int status;
		int httpMajor;
		int httpMinor;
		sscanf(firstline.c_str(), "HTTP/%d.%d %d", &httpMajor, &httpMinor, &status);

		if(status != 101) throw runtime_error("http response code was != 101");

		string headersRaw = response.substr(response.find("\r\n") + 2);
		headersRaw = headersRaw.substr(0, headersRaw.find("\r\n\r\n") + 2);
		unordered_map<string, string> headers;

		size_t pos;
		while((pos = headersRaw.find("\r\n")) != string::npos) {
			auto header = headersRaw.substr(0, pos);

			size_t delim = header.find(": ");
			auto headerName = header.substr(0, delim);
			std::transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);
			headers[headerName] = header.substr(delim + 2);

			headersRaw = headersRaw.substr(pos + 2);
		}

		if(headers.count("upgrade") == 0 || headers["upgrade"] != "websocket") throw runtime_error("invalid upgrade header");

		if(headers.count("connection") == 0 || headers["connection"] != "Upgrade")
			throw runtime_error("invalid connection header");

		if(headers.count("sec-websocket-accept") == 0) throw runtime_error("invalid sec-websocket-accept header");

		string tmp = b64Key + MAGIC_STRING;
		vector<uint8_t> tmpBin(tmp.begin(), tmp.end());
		tmpBin = util::SHA1().update(tmpBin).final();
		string compareKey = util::b64_encode(tmpBin);

		if(compareKey != headers["sec-websocket-accept"]) throw runtime_error("sec-websocket-accept header != computed key");

		if(onOpen) onOpen(*this);
		thread receiverThread([&]() { receiveLoop(); });
		if(!backgroundThread) receiverThread.join();
		else receiverThread.detach();
	}

	void close() {
		vector<uint8_t> nullData;
		sendFrame(Close, nullData);
		sock.disconnect();
		if(closeHandler) closeHandler();
	}

	void onMessage(function<void(vector<uint8_t>&, bool)> handler) { messageHandler = handler; }
	void onClose(function<void()> handler) { closeHandler = handler; }

	void send(string message) {
		vector<uint8_t> toSend(message.begin(), message.end());
		send(toSend, false);
	}

	void send(vector<uint8_t>& data, bool binary = true) { sendFrame(binary ? Binary : Text, data); }

	void ping() {
		// debugging stuff
		// printf("%s\n", "sending ping");
		sendFrame(Ping, pingData);
	}
};

class WebSocketServer {

#ifdef _WIN32
	inline static bool wsaReady = false;
	inline static WSADATA wsaData;

	static void startWSA() {
		if(wsaReady) return;
		if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) throw runtime_error("WSAStartup failed!");

		wsaReady = true;
	}
#endif

	list<const WebSocket*> clients;

	sockaddr_in server;
	uint32_t socketPtr = 0;

	bool running = false;

	function<void(WebSocket&)> connectionHandler;

	void tryUpgrade(uint32_t fd) {

		TCPSocket sock(fd);

		unordered_map<string, string> headers;

		try {
			auto request = sock.receiveUntil({'\r', '\n', '\r', '\n'});
			string httpRequest(request.begin(), request.end());

			auto requestMethod = httpRequest.substr(0, httpRequest.find(" "));

			auto path = httpRequest.substr(httpRequest.find(requestMethod) + requestMethod.length() + 1);
			path = path.substr(0, path.find(" HTTP"));

			auto headersRaw = httpRequest.substr(httpRequest.find("\r\n") + 2);
			headersRaw = headersRaw.substr(0, headersRaw.find("\r\n\r\n") + 2);

			size_t pos;
			while((pos = headersRaw.find("\r\n")) != string::npos) {
				auto header = headersRaw.substr(0, pos);

				size_t delim = header.find(": ");
				auto headerName = header.substr(0, delim);
				std::transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);
				headers[headerName] = header.substr(delim + 2);

				headersRaw = headersRaw.substr(pos + 2);
			}

		} catch(...) {
			// either the incoming http request timed out or it got closed during transport
			// drop this connection
			sock.disconnect();
			return;
		}

		if(headers.count("connection") == 0 || !(headers["connection"] == "Upgrade" || headers["connection"] == "upgrade")) {
			// this request isn't for establishing a websocket connection
			// drop it
			sock.disconnect();
			return;
		}

		if(headers.count("sec-websocket-key") == 0) {
			// this request for establishing a websocket connection has no key to sign
			// drop it
			sock.disconnect();
			return;
		}

		string key = headers["sec-websocket-key"];
		string toHash = key + MAGIC_STRING;
		vector<uint8_t> asBytes(toHash.begin(), toHash.end());
		string signedKey = util::b64_encode(util::SHA1().update(asBytes).final());

		string response = WEBSOCKET_SWITCH_PROTOCOLS;
		response += signedKey;
		response += "\r\n\r\n";

		vector<uint8_t> responseBin(response.begin(), response.end());
		sock.send(responseBin);

		WebSocket newClient;

		newClient.clientMode = false;
		newClient.sock = sock;
		clients.push_back(&newClient);

		connectionHandler(newClient);

		newClient.receiveLoop();

		clients.remove(&newClient);
	}

  public:
	WebSocketServer(uint16_t port, int host = INADDR_ANY, bool launchThread = false) {
#ifdef _WIN32
		startWSA();
#endif

		server.sin_family = AF_INET;
		server.sin_addr.s_addr = htonl(host);
		server.sin_port = htons(port);

		socketPtr = socket(AF_INET, SOCK_STREAM, 0);

		if(socketPtr < 0) throw runtime_error("failed to create socket");

#ifndef _WIN32
		const int enable = 1;
		if(setsockopt(socketPtr, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
			throw runtime_error("failed to create socket");
#endif

		if(bind(socketPtr, (struct sockaddr*)&server, sizeof(server)) < 0) throw runtime_error("failed to bind socket");

		if(launchThread) {
			thread([&]() { run(); }).detach();
		}
	}

	void onConnection(function<void(WebSocket&)> handler) { connectionHandler = handler; }

	void run() {
		if(running) return;

		running = true;
		listen(socketPtr, 0);

		while(running) {
			sockaddr_in clientAddress;
			int len = sizeof(clientAddress);

			uint32_t clientSocket = accept(socketPtr, (sockaddr*)&clientAddress, (socklen_t*)&len);

			thread([&]() { tryUpgrade(clientSocket); }).detach();
		}
	}
};

#endif