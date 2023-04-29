#ifndef TRAY_H_
#define TRAY_H_

#include <windows.h>
#include <vector>
#include <string>
#include <functional>

using std::vector, std::string, std::function;

class TrayEntry {

	function<void(TrayEntry&)> clickHandler;

	enum { DIVIDER, MENU_ENTRY, SUBMENU } type;

  public:
	vector<TrayEntry> submenu;

	string text;
	bool enabled = true;
	bool checked = false;

	TrayEntry() { type = DIVIDER; }

	TrayEntry(string text, function<void(TrayEntry&)> clickHandler = 0, bool enabled = true, bool checked = false) {
		this->text = text;
		this->clickHandler = clickHandler;
		this->enabled = enabled;
		this->checked = checked;
		type = MENU_ENTRY;
	}

	TrayEntry(string text, vector<TrayEntry> submenu) {
		this->submenu = submenu;
		this->text = text;
		type = SUBMENU;
	}

	friend class Tray;
};

#define WM_TRAY_CB_MSG (WM_USER + 1)

class Tray {

	HWND hwnd;
	NOTIFYICONDATAA nid = {0};
	HMENU menuHandle = 0;

	LRESULT HandleMessage(UINT msg, WPARAM wparam, LPARAM lparam) {
		switch(msg) {
		case WM_CLOSE: DestroyWindow(hwnd); return 0;
		case WM_DESTROY: PostQuitMessage(0); return 0;
		case WM_TRAY_CB_MSG:
			if(lparam == WM_LBUTTONUP || lparam == WM_RBUTTONUP) {
				POINT p;
				GetCursorPos(&p);
				SetForegroundWindow(hwnd);
				WORD cmd = TrackPopupMenu(menuHandle, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, p.x, p.y, 0, hwnd, NULL);
				SendMessageA(hwnd, WM_COMMAND, cmd, 0);
				return 0;
			}
			break;
		case WM_COMMAND:
			if(wparam >= 1) {
				MENUITEMINFOA item = {
					.cbSize = sizeof(MENUITEMINFO),
					.fMask = MIIM_ID | MIIM_DATA,
				};
				if(GetMenuItemInfoA(menuHandle, wparam, FALSE, &item)) {
					TrayEntry* entry = (TrayEntry*)item.dwItemData;
					if(entry && entry->clickHandler) {
						entry->clickHandler(*entry);
						update();
					}
				}
				return 0;
			}
			break;
		}
		return DefWindowProc(hwnd, msg, wparam, lparam);
	}

	static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
		Tray* pThis = 0;

		if(uMsg == WM_NCCREATE) {
			pThis = (Tray*)((CREATESTRUCT*)lParam)->lpCreateParams;
			pThis->hwnd = hwnd;
			SetWindowLongPtrA(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
		} else
			pThis = (Tray*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);

		if(pThis)
			return pThis->HandleMessage(uMsg, wParam, lParam);
		else
			return DefWindowProcA(hwnd, uMsg, wParam, lParam);
	};

	HMENU createMenu(vector<TrayEntry>& menu, int& id) {
		HMENU newMenu = CreatePopupMenu();

		for(int i = 0; i < menu.size(); i++) {
			if(menu[i].type == TrayEntry::DIVIDER) {
				InsertMenuA(newMenu, id++, MF_SEPARATOR, true, "");
			} else {
				MENUITEMINFOA item = {0};
				item.cbSize = sizeof(MENUITEMINFOA);
				item.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE | MIIM_DATA;
				item.fType = 0;
				item.fState = 0;

				if(menu[i].type == TrayEntry::MENU_ENTRY) {
					if(!menu[i].enabled) { item.fState |= MFS_DISABLED; }
					if(menu[i].checked) { item.fState |= MFS_CHECKED; }
				} else if(menu[i].type == TrayEntry::SUBMENU) {
					item.fMask = item.fMask | MIIM_SUBMENU;
					item.hSubMenu = createMenu(menu[i].submenu, id);
				}

				item.wID = id++;
				item.dwTypeData = (LPSTR)menu[i].text.c_str();
				item.dwItemData = (ULONG_PTR)&menu[i];

				InsertMenuItemA(newMenu, item.wID, true, &item);
			}
		}

		return newMenu;
	}

  public:

	vector<TrayEntry> menu;

	void update() {
		HMENU prev = menuHandle;

		int id = 1;
		menuHandle = createMenu(menu, id);
		SendMessageA(hwnd, WM_INITMENUPOPUP, (WPARAM)menuHandle, 0);

		if(prev) DestroyMenu(prev);
	}

	Tray(string title, string iconPath, vector<TrayEntry> menu) {
		this->menu = menu;
		WNDCLASSA wc = {0};
		wc.lpfnWndProc = WindowProc;
		wc.hInstance = GetModuleHandleA(0);
		wc.lpszClassName = "TRAY_CLASS_CPP";
		RegisterClassA(&wc);
		hwnd = CreateWindowExA(0, wc.lpszClassName, NULL, 0, 0, 0, 0, 0, 0, 0, 0, this);
		UpdateWindow(hwnd);

		nid.cbSize = sizeof(NOTIFYICONDATAA);
		nid.hWnd = hwnd;
		nid.uID = 0;
		nid.uFlags = NIF_ICON | NIF_MESSAGE;
		nid.uCallbackMessage = WM_TRAY_CB_MSG;

		ExtractIconExA(iconPath.c_str(), 0, 0, &nid.hIcon, 1);
		Shell_NotifyIconA(NIM_ADD, &nid);

		update();
	}

	void popup(string title, string message) {
		NOTIFYICONDATAA notification = {0};

		notification.cbSize = sizeof(NOTIFYICONDATAA);
		notification.hWnd = GetWindow(0, 0);
		notification.uFlags = NIF_INFO;
		notification.dwInfoFlags = NIIF_INFO;
		strcpy(notification.szInfoTitle, title.c_str());
		strcpy(notification.szInfo, message.c_str());

		Shell_NotifyIconA(NIM_ADD, &notification);
		Shell_NotifyIconA(NIM_DELETE, &notification);
	}

	void run() {
		MSG msg = {0};
		while(GetMessageA(&msg, 0, 0, 0)) {
			TranslateMessage(&msg);
			DispatchMessageA(&msg);
		}
		Shell_NotifyIconA(NIM_DELETE, &nid);
	}
};

#endif