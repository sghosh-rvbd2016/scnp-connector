#ifndef SAFEQUEUE_HH
#define SAFEQUEUE_HH
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
 
template <typename T>
class SafeQueue
{
 public:
 
  SafeQueue() : _high_watermark(0) { }

  T pop()
  {
    std::unique_lock<std::mutex> mlock(_mutex);
    while (_queue.empty())
    {
      _cond.wait(mlock);
    }
    T item = _queue.front();
    _queue.pop();
    return item;
  }
 
  void push(const T& item)
  {
    std::unique_lock<std::mutex> mlock(_mutex);
    _queue.push(item);
    size_t s = _queue.size();
    if (s > _high_watermark)
      _high_watermark = s;
    mlock.unlock();
    _cond.notify_one();
  }
 
  size_t size()
  {
    std::unique_lock<std::mutex> mlock(_mutex);
    return _queue.size();
  }

  size_t high_watermark()
  {
    std::unique_lock<std::mutex> mlock(_mutex);
    return _high_watermark;
  }

  void clear_stats()
  {
    std::unique_lock<std::mutex> mlock(_mutex);
    _high_watermark = 0;
  }

 private:
  std::queue<T> _queue;
  std::mutex _mutex;
  std::condition_variable _cond;
  size_t _high_watermark;
};
#endif
