#ifndef WIN_WEBSOCK_H_
#define WIN_WEBSOCK_H_

#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <locale>
#include <codecvt>
#include <thread>
#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include <mutex>

class WinWebsock {

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

	HANDLE hConnectionHandle;
	HANDLE hWebSocketHandle;

	std::function<void(std::vector<uint8_t>&, bool)> handler = 0;
	std::function<void()> closeHandler;

	void receiver() {
		uint32_t dwError;
		uint8_t buffer[4096];

		WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType;

		DWORD bytesReceived;

		while(1) {
			std::vector<uint8_t> received;

			do {
				dwError = WinHttpWebSocketReceive(hWebSocketHandle, buffer, 4096, &bytesReceived, &bufferType);

				if(dwError != ERROR_SUCCESS) {
					close();
					return;
				}

				received.insert(received.end(), buffer, buffer + bytesReceived);
			} while(bufferType == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE ||
					bufferType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE);

			if(bufferType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
				close();
				return;
			}

			if(handler) handler(received, bufferType == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE);
		}
	}

	std::mutex sendLock;

  public:
	void close() {
		if(hConnectionHandle == 0) return;
		WinHttpWebSocketShutdown(hWebSocketHandle, WINHTTP_WEB_SOCKET_EMPTY_CLOSE_STATUS, 0, 0);
		WinHttpCloseHandle(hConnectionHandle);
		hWebSocketHandle = 0;
		hConnectionHandle = 0;
		if(closeHandler) closeHandler();
	}

	void onClose(std::function<void()> handler) { this->closeHandler = handler; }
	void onMessage(std::function<void(std::vector<uint8_t>&, bool)> handler) { this->handler = handler; }

	void send(std::string message) {
		std::vector<uint8_t> toSend(message.begin(), message.end());
		send(toSend, false);
	}

	void send(const std::vector<uint8_t>& data, bool binary = true) {
		std::lock_guard lock(sendLock);
		WinHttpWebSocketSend(hWebSocketHandle, binary ? WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE : WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, (void*)data.data(), data.size());
	}

	WinWebsock(std::string uri, std::function<void(WinWebsock&)> onConnect = 0, bool runOnSeperateThread = false) {
		URL parsed = uri;

		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

		HANDLE hSessionHandle = WinHttpOpen(L"cmplx-WSClient 1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 0, 0, 0);
		if(hSessionHandle == NULL) throw std::runtime_error("Failed to create WinHTTP session");

		hConnectionHandle = WinHttpConnect(hSessionHandle, converter.from_bytes(parsed.host).c_str(), parsed.port, 0);
		if(hConnectionHandle == NULL) throw std::runtime_error("HTTP Connect Failed");

		HINTERNET hRequestHandle = WinHttpOpenRequest(hConnectionHandle, L"GET", converter.from_bytes(parsed.path).c_str(), 0,
													  0, 0, (parsed.protocol == "https" ? WINHTTP_FLAG_SECURE : 0));
		if(hRequestHandle == NULL) throw std::runtime_error("HTTP Open Request Failed.");

		if(!WinHttpSetOption(hRequestHandle, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, 0, 0))
			throw std::runtime_error("HTTP WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET Failed.");

		if(!WinHttpSendRequest(hRequestHandle, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 0, 0, 0, 0))
			throw std::runtime_error("HTTP WinHttpSendRequest Failed.");

		if(!WinHttpReceiveResponse(hRequestHandle, 0)) throw std::runtime_error("HTTP WinHttpReceiveResponse Failed.");

		DWORD dwStatusCode = 0;
		DWORD dwSize = sizeof(dwStatusCode);

		WinHttpQueryHeaders(hRequestHandle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
							&dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

		if(dwStatusCode != 101) throw std::runtime_error("HTTP WinHttpWebSocketCompleteUpgrade Failed. Status != 101");

		hWebSocketHandle = WinHttpWebSocketCompleteUpgrade(hRequestHandle, 0);
		if(hWebSocketHandle == NULL) throw std::runtime_error("HTTP WinHttpWebSocketCompleteUpgrade Failed.");

		WinHttpCloseHandle(hRequestHandle);
		hRequestHandle = NULL;

		if(onConnect) onConnect(*this);
		std::thread recvThread([&]() { receiver(); });
		if(!runOnSeperateThread)
			recvThread.join();
		else
			recvThread.detach();
	}
};

#endif