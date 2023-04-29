#pragma

#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>
#include <any>
#include <functional>

#include "Semaphore.h"

using std::any;
using std::pair;
using std::queue;
using std::string;
using std::unordered_map;
using std::vector;

class EventEmitter {

  private:
	unordered_map<string, vector<std::function<void(vector<any>)>>> events;
	queue<pair<string, vector<any>>> eventQueue;
	Semaphore lock;
	bool run = true;

  public:
	void process() {
		while(run) {
			lock.wait();

			if(eventQueue.empty()) continue;

			for(auto handler : events[eventQueue.front().first]) {
				auto args = eventQueue.front().second;
				handler(args);
			}

			eventQueue.pop();
		}
	}

	template <typename Handler> void on(string event, Handler handler) {
		// events[event].push_back([&](vector<any> args) {

			

		// 	for(size_t i = 0; i < sizeof...(Args); i++) {
		// 		//std::bind(handler, std::any_cast<function_traits<EventHandler>::arg<i>::type>(args[i]));
		// 	}

		// });
	}

	void queueStop() {
		run = false;
		lock.notify();
	}

	template <typename... Args> void emit(string event, Args... args) {
		vector<any> eventArgs = {args...};
		eventQueue.push({event, eventArgs});
		lock.notify();
	}
};