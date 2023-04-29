#ifndef WINTUN_H_
#define WINTUN_H_

#include <winsock2.h>
#include <netioapi.h>
#include <stdint.h>
#include <ifdef.h>
#include <netioapi.h>
#include <stdexcept>
#include <functional>
#include <string>
#include <vector>
#include <thread>
#include <mutex>

#include <locale>
#include <codecvt>

using std::runtime_error, std::string, std::vector, std::function, std::thread, std::mutex;

class Adapter {

	struct IPv4 {

		union {
			uint32_t dwordVal;
			uint8_t ipParts[4];
		};

		IPv4(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth) {
			ipParts[0] = first;
			ipParts[1] = second;
			ipParts[2] = third;
			ipParts[3] = fourth;
		}

		IPv4(uint32_t address) { dwordVal = address; }

		IPv4(string address) : IPv4(address.c_str()) {}
		IPv4(const char* address) {
			int results = sscanf(address, "%3u.%3u.%3u.%3u", &ipParts[0], &ipParts[1], &ipParts[2], &ipParts[3]);
			if(results != 4) throw runtime_error("invalid ip address");
		}

		operator string() {
			return std::to_string(ipParts[0]) + "." + std::to_string(ipParts[1]) + "." + std::to_string(ipParts[2]) + "." +
				   std::to_string(ipParts[3]);
		}

		operator uint32_t() { return dwordVal; }
	};

	typedef struct WintunSessionHandle* SessionHandle;
	typedef struct WintunAdapterHandle* AdapterHandle;

	static inline HMODULE wintun = 0;

	/**
	 * Creates a new Wintun adapter.
	 *
	 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
	 *                      characters.
	 *
	 * @param TunnelType    Name of the adapter tunnel type. Zero-terminated string of up to MAX_ADAPTER_NAME-1
	 *                      characters.
	 *
	 * @param RequestedGUID The GUID of the created network adapter, which then influences NLA generation deterministically.
	 *                      If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is
	 *                      created for each new adapter. It is called "requested" GUID because the API it uses is
	 *                      completely undocumented, and so there could be minor interesting complications with its usage.
	 *
	 * @return If the function succeeds, the return value is the adapter handle. Must be released with
	 * WintunCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call
	 * GetLastError.
	 */
	static inline AdapterHandle(WINAPI* CreateAdapter)(const wchar_t* Name, const wchar_t* TunnelType,
													   const GUID* RequestedGUID) = 0;

	/**
	 * Releases Wintun adapter resources and, if adapter was created with WintunCreateAdapter, removes adapter.
	 *
	 * @param Adapter       Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter.
	 */
	static inline void(WINAPI* CloseAdapter)(AdapterHandle Adapter) = 0;

	/**
	 * Deletes the Wintun driver if there are no more adapters in use.
	 *
	 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
	 *         get extended error information, call GetLastError.
	 */
	static inline bool(WINAPI* DeleteDriver)() = 0;

	/**
	 * Returns the LUID of the adapter.
	 *
	 * @param Adapter       Adapter handle obtained with WintunCreateAdapter or WintunOpenAdapter
	 *
	 * @param Luid          Pointer to LUID to receive adapter LUID.
	 */
	static inline void(WINAPI* GetAdapterLUID)(AdapterHandle Adapter, NET_LUID* Luid) = 0;

	/**
	 * Determines the version of the Wintun driver currently loaded.
	 *
	 * @return If the function succeeds, the return value is the version number. If the function fails, the return value is
	 *         zero. To get extended error information, call GetLastError. Possible errors include the following:
	 *         ERROR_FILE_NOT_FOUND  Wintun not loaded
	 */
	static inline uint32_t(WINAPI* GetDriverVersion)() = 0;

	/**
	 * Starts Wintun session.
	 *
	 * @param Adapter       Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter
	 *
	 * @param Capacity      Rings capacity. Must be between WINTUN_MIN_RING_CAPACITY and WINTUN_MAX_RING_CAPACITY (incl.)
	 *                      Must be a power of two.
	 *
	 * @return Wintun session handle. Must be released with WintunEndSession. If the function fails, the return value is
	 *         NULL. To get extended error information, call GetLastError.
	 */
	static inline SessionHandle(WINAPI* StartSession)(AdapterHandle Adapter, uint32_t Capacity) = 0;

	/**
	 * Ends Wintun session.
	 *
	 * @param Session       Wintun session handle obtained with WintunStartSession
	 */
	static inline void(WINAPI* EndSession)(SessionHandle Handle) = 0;

	/**
	 * Gets Wintun session's read-wait event handle.
	 *
	 * @param Session       Wintun session handle obtained with WintunStartSession
	 *
	 * @return Pointer to receive event handle to wait for available data when reading. Should
	 *         WintunReceivePackets return ERROR_NO_MORE_ITEMS (after spinning on it for a while under heavy
	 *         load), wait for this event to become signaled before retrying WintunReceivePackets. Do not call
	 *         CloseHandle on this event - it is managed by the session.
	 */
	static inline HANDLE(WINAPI* GetReadWaitEvent)(SessionHandle Handle) = 0;

	/**
	 * Retrieves one or packet. After the packet content is consumed, call WintunReleaseReceivePacket with Packet returned
	 * from this function to release internal buffer. This function is thread-safe.
	 *
	 * @param Session       Wintun session handle obtained with WintunStartSession
	 *
	 * @param PacketSize    Pointer to receive packet size.
	 *
	 * @return Pointer to layer 3 IPv4 or IPv6 packet. Client may modify its content at will. If the function fails, the
	 *         return value is NULL. To get extended error information, call GetLastError. Possible errors include the
	 *         following:
	 *         ERROR_HANDLE_EOF     Wintun adapter is terminating;
	 *         ERROR_NO_MORE_ITEMS  Wintun buffer is exhausted;
	 *         ERROR_INVALID_DATA   Wintun buffer is corrupt
	 */
	static inline uint8_t*(WINAPI* ReceivePacket)(SessionHandle Handle, uint32_t* PacketSize) = 0;

	/**
	 * Releases internal buffer after the received packet has been processed by the client. This function is thread-safe.
	 *
	 * @param Session       Wintun session handle obtained with WintunStartSession
	 *
	 * @param Packet        Packet obtained with WintunReceivePacket
	 */
	static inline void(WINAPI* FreeReceivedPacket)(SessionHandle Handle, const uint8_t* Packet) = 0;

	/**
	 * Allocates memory for a packet to send. After the memory is filled with packet data, call WintunSendPacket to send
	 * and release internal buffer. WintunAllocateSendPacket is thread-safe and the WintunAllocateSendPacket order of
	 * calls define the packet sending order.
	 *
	 * @param Session       Wintun session handle obtained with WintunStartSession
	 *
	 * @param PacketSize    Exact packet size. Must be less or equal to WINTUN_MAX_IP_PACKET_SIZE.
	 *
	 * @return Returns pointer to memory where to prepare layer 3 IPv4 or IPv6 packet for sending. If the function fails,
	 *         the return value is NULL. To get extended error information, call GetLastError. Possible errors include the
	 *         following:
	 *         ERROR_HANDLE_EOF       Wintun adapter is terminating;
	 *         ERROR_BUFFER_OVERFLOW  Wintun buffer is full;
	 */
	static inline uint8_t*(WINAPI* AllocSendPacket)(SessionHandle Handle, uint32_t PacketSize) = 0;

	/**
	 * Sends the packet and releases internal buffer. WintunSendPacket is thread-safe, but the WintunAllocateSendPacket
	 * order of calls define the packet sending order. This means the packet is not guaranteed to be sent in the
	 * WintunSendPacket yet.
	 *
	 * @param Session       Wintun session handle obtained with WintunStartSession
	 *
	 * @param Packet        Packet obtained with WintunAllocateSendPacket
	 */
	static inline void(WINAPI* SendPacket)(SessionHandle Session, const uint8_t* Packet) = 0;

	static inline bool initialize() {
		wintun = LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
		if(!wintun) return false;
		*(FARPROC*)&CreateAdapter = GetProcAddress(wintun, "WintunCreateAdapter");
		*(FARPROC*)&CloseAdapter = GetProcAddress(wintun, "WintunCloseAdapter");
		*(FARPROC*)&DeleteDriver = GetProcAddress(wintun, "WintunDeleteDriver");
		*(FARPROC*)&GetAdapterLUID = GetProcAddress(wintun, "WintunGetAdapterLUID");
		*(FARPROC*)&GetDriverVersion = GetProcAddress(wintun, "WintunGetRunningDriverVersion");
		*(FARPROC*)&StartSession = GetProcAddress(wintun, "WintunStartSession");
		*(FARPROC*)&EndSession = GetProcAddress(wintun, "WintunEndSession");
		*(FARPROC*)&GetReadWaitEvent = GetProcAddress(wintun, "WintunGetReadWaitEvent");
		*(FARPROC*)&ReceivePacket = GetProcAddress(wintun, "WintunReceivePacket");
		*(FARPROC*)&FreeReceivedPacket = GetProcAddress(wintun, "WintunReleaseReceivePacket");
		*(FARPROC*)&AllocSendPacket = GetProcAddress(wintun, "WintunAllocateSendPacket");
		*(FARPROC*)&SendPacket = GetProcAddress(wintun, "WintunSendPacket");

		return CreateAdapter && CloseAdapter && DeleteDriver && GetAdapterLUID && GetDriverVersion && StartSession &&
			   EndSession && ReceivePacket && FreeReceivedPacket && AllocSendPacket && SendPacket;
	}

	void collectPackets() {
		while(1) {
			uint32_t len;
			uint8_t* packet = ReceivePacket(session, &len);

			if(!packet) {

				if(GetLastError() == ERROR_NO_MORE_ITEMS) {
					if(WaitForSingleObject(GetReadWaitEvent(session), INFINITE) == WAIT_OBJECT_0) continue;
					else
						throw runtime_error("what the fuck?");
				} else {
					throw runtime_error("packet read failed");
				}
			}

			if(handler) {
				vector<uint8_t> vectorisedPacket(packet, packet + len);
				handler(vectorisedPacket);
			}

			FreeReceivedPacket(session, packet);
		}
	}

	function<void(const vector<uint8_t>& data)> handler = 0;

	AdapterHandle adapter = 0;
	SessionHandle session = 0;

	mutex sendLock;
	thread receiver;

  public:
	Adapter(string name, string tunnel, const GUID* adapterID = 0) {
		if(wintun == 0 && !initialize()) throw runtime_error("failed to load wintun.dll");

		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

		adapter = CreateAdapter(converter.from_bytes(name).c_str(), converter.from_bytes(tunnel).c_str(), adapterID);
		if(!adapter) throw runtime_error("failed to create adapter");

		session = StartSession(adapter, 0x400000);
		if(!session) throw runtime_error("failed to start session");

		receiver = thread([&]() { collectPackets(); });
	}

	void setIP(IPv4 ip, uint8_t prefixLength = 24) {
		MIB_UNICASTIPADDRESS_ROW AddressRow;
		InitializeUnicastIpAddressEntry(&AddressRow);
		AddressRow.InterfaceLuid = getLUID();
		AddressRow.Address.Ipv4.sin_family = AF_INET;
		AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = ip.dwordVal;
		AddressRow.OnLinkPrefixLength = prefixLength;
		AddressRow.DadState = IpDadStatePreferred;
		CreateUnicastIpAddressEntry(&AddressRow);
	}

	void setDNS(IPv4 ip) {
		string ipStr = ip;

		GUID guid;
		NET_LUID luid = getLUID();
		ConvertInterfaceLuidToGuid(&luid, &guid);

		char guid_string[40]; // 32 hex chars + 4 hyphens + null terminator
		snprintf(guid_string, sizeof(guid_string), "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", guid.Data1, guid.Data2,
				 guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
				 guid.Data4[6], guid.Data4[7]);

		string strKeyName = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
		strKeyName += guid_string;
		HKEY key;
		if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, strKeyName.c_str(), 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS)
			throw runtime_error("failed to open reg key");

		RegSetValueExA(key, "NameServer", 0, REG_SZ, (BYTE*)ipStr.c_str(), ipStr.size() + 1);
		RegCloseKey(key);
	}

	void setGateway(IPv4 ip) {
		MIB_IPFORWARD_ROW2 gateway;
		InitializeIpForwardEntry(&gateway);
		gateway.InterfaceLuid = getLUID();

		gateway.NextHop.Ipv4.sin_family = AF_INET;
		gateway.NextHop.Ipv4.sin_addr.S_un.S_addr = ip.dwordVal;
		gateway.DestinationPrefix.PrefixLength = 0;
		gateway.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = 0;
		gateway.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
		gateway.Metric = 0;

		CreateIpForwardEntry2(&gateway);
	}

	void setMTU(unsigned int mtu) {
		MIB_IPINTERFACE_ROW interfaceSettings = {0};
		InitializeIpInterfaceEntry(&interfaceSettings);
		interfaceSettings.InterfaceLuid = getLUID();
		interfaceSettings.Family = AF_INET;
		GetIpInterfaceEntry(&interfaceSettings);

		interfaceSettings.NlMtu = mtu;

		SetIpInterfaceEntry(&interfaceSettings);
	}

	void setPreferredAdapter(bool preferred = true) {
		MIB_IPINTERFACE_ROW interfaceSettings = {0};
		InitializeIpInterfaceEntry(&interfaceSettings);
		interfaceSettings.InterfaceLuid = getLUID();
		interfaceSettings.Family = AF_INET;
		GetIpInterfaceEntry(&interfaceSettings);
		
		interfaceSettings.SitePrefixLength = 0;

		if(preferred) {
			interfaceSettings.UseAutomaticMetric = false;
			interfaceSettings.Metric = 1;
		} else {
			interfaceSettings.UseAutomaticMetric = true;
		}

		SetIpInterfaceEntry(&interfaceSettings);
	}

	void dispatchPacket(const vector<uint8_t>& packet) {
		std::lock_guard lock(sendLock);

		uint8_t* Packet = AllocSendPacket(session, packet.size());
		memcpy(Packet, packet.data(), packet.size());
		SendPacket(session, Packet);
	}

	void onPacket(function<void(const vector<uint8_t>& data)> handler) { this->handler = handler; }

	NET_LUID getLUID() {
		NET_LUID luid;
		GetAdapterLUID(adapter, &luid);
		return luid;
	}

	void getDriverVersion(uint8_t& major, uint8_t& minor) {
		uint32_t version = GetDriverVersion();
		major = (version >> 16) & 0xff;
		minor = version & 0xff;
	}

	~Adapter() {
		EndSession(session);
		CloseAdapter(adapter);
	}
};

#endif