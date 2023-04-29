#pragma once

#include <mutex>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <functional>

class Timeout {
	std::mutex* mtx;
	std::condition_variable* cv;
	int _milis;
	std::function<void()> _callback;

  public:
	Timeout(int milis, std::function<void()> callback) {
		mtx = new std::mutex;
		cv = new std::condition_variable;
		_milis = milis;
		_callback = callback;
		std::thread([&] {
			std::unique_lock<std::mutex> l(*mtx);
			if(cv->wait_for(l, std::chrono::milliseconds(_milis)) == std::cv_status::timeout)
				_callback();
		}).detach();
	}

	~Timeout() {
		delete mtx;
		delete cv;
	}

	inline void cancel() {
		std::unique_lock<std::mutex> lock(*mtx);
		cv->notify_one();
	}
};