#ifndef LOG_H_
#define LOG_H_

#pragma warning(disable:4996)

#include <windows.h>
#include <cstdio>
#include <clocale>
#include <ctime>
#include "Str.h"

class Log {
public:

	static void Init(const char* s = "Debug Console") {
		if (!GetStdHandle(STD_OUTPUT_HANDLE)) {
			AllocConsole();
			SetConsoleTitleA(s);
			//SetConsoleCtrlHandler(ctrlHandler, true);
			freopen("CONOUT$", "w", stdout);
			freopen("CONOUT$", "w", stderr);
			freopen("CONIN$", "r", stdin);
		}
		setlocale(0, "");
	}

	static void Close() {
		fclose(stdout);
		fclose(stdin);
		fclose(stderr);
		FreeConsole();
	}

	static void d(const char* s) { color(9); printf("%s\n", str(curTime() + "[Debug]: " + s)); }
	static void i(const char* s) { color(7); printf("%s\n", str(curTime() + "[INFO]: " + s)); }
	static void w(const char* s) { color(6); printf("%s\n", str(curTime() + "[WARN]: " + s)); }
	static void e(const char* s) { color(12); printf("%s\n", str(curTime() + "[ERR]: " + s)); }

private:
	// disable instantiating a Log() object.
	Log() {}

	static const char* curTime() {
		static char buffer[16];
		long long t = time(nullptr);
		strftime(buffer, 16, "[%T]", localtime(&t));
		return buffer;
	}

	static void color(const char& fg, const char& bg = 0) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), bg << 4 | fg);
	}

	static int ctrlHandler(DWORD t) {
		if (t == 0) printf("^C\n");
		return 1;
	}

};

#endif // !LOG_H_
