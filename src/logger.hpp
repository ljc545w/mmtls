#pragma once
#if defined(_WIN32)
#include <windows.h>
#else
#include <iostream>
#include <memory>
#include <cstring>
#include <time.h>
#include <stdarg.h>
#include <ctime>
#endif

#include <iostream>
#include <chrono>
#include <thread>
#include <mutex>

constexpr unsigned MAX_LOG_SIZE = 0xffff;

inline void LOG(const char* level, const char* file, const char* function, int line, const char* _Format, ...) {
	static std::mutex mtx;
	std::string szFile(file);
#if defined(_WIN32)
	auto pos = szFile.find_last_of("\\");
#else
	auto pos = szFile.find_last_of("/");
#endif
	szFile = szFile.substr(pos + 1);
	struct tm time_tm = { 0 };
	auto now = std::chrono::system_clock::now();
	uint64_t dis_millseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()
		- std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() * 1000;
	time_t tt = std::chrono::system_clock::to_time_t(now);
#if defined(_WIN32)
	_localtime64_s(&time_tm, &tt);
#else
	localtime_r(&tt, &time_tm);
#endif
	char strTime[30] = { 0 };
#if defined(_WIN32)
	sprintf_s(strTime, "%d-%02d-%02d %02d:%02d:%02d.%03d", time_tm.tm_year + 1900,
		time_tm.tm_mon + 1, time_tm.tm_mday, time_tm.tm_hour,
		time_tm.tm_min, time_tm.tm_sec, (int)dis_millseconds);
#else
	snprintf(strTime, sizeof(strTime), "%d-%02d-%02d %02d:%02d:%02d.%03d", time_tm.tm_year + 1900,
		time_tm.tm_mon + 1, time_tm.tm_mday, time_tm.tm_hour,
		time_tm.tm_min, time_tm.tm_sec, (int)dis_millseconds);
#endif
	std::unique_ptr<char[]> msg_buf = std::make_unique<char[]>(MAX_LOG_SIZE);
	va_list args;
	va_start(args, _Format);
#if defined(_WIN32)
	vsprintf_s(msg_buf.get(), MAX_LOG_SIZE, _Format, args);
#else
	vsnprintf(msg_buf.get(), MAX_LOG_SIZE, _Format, args);
#endif
	va_end(args);
	std::string msg(msg_buf.get());
	memset(msg_buf.get(), 0, MAX_LOG_SIZE);
#if defined(_WIN32)
	const char* log_format = "%s|%s|%lu|%s[line:%d] - %s : %s";
#else
	const char* log_format = "%s|%s|%llu|%s[line:%d] - %s : %s";
#endif
	std::thread::id id = std::this_thread::get_id();
#if defined(_WIN32)
	sprintf_s(msg_buf.get(), MAX_LOG_SIZE, log_format, strTime, level, *(unsigned int*)&id, szFile.c_str(), line, function, msg.c_str());
#else
	snprintf(msg_buf.get(), MAX_LOG_SIZE, log_format, strTime, level, *(unsigned long long*)&id, szFile.c_str(), line, function, msg.c_str());
#endif
	std::string output(msg_buf.get());
	mtx.lock();
	try {
		std::cout << output << std::endl;
	}
	catch (...) {
	}
	mtx.unlock();
}

#define LL_INFO(_Format, ...) LOG("INFO",__FILE__,__FUNCTION__,__LINE__,_Format, ##__VA_ARGS__)
#define LL_WARNING(_Format, ...) LOG("WARNING",__FILE__,__FUNCTION__,__LINE__,_Format, ##__VA_ARGS__)
#define LL_DEBUG(_Format, ...) LOG("DEBUG",__FILE__,__FUNCTION__,__LINE__,_Format, ##__VA_ARGS__)
#define LL_ERROR(_Format, ...) LOG("ERROR",__FILE__,__FUNCTION__,__LINE__,_Format, ##__VA_ARGS__)