//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <any>
#include <cassert>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <atomic>
#include <optional>
#include <functional>
#if defined(__has_include)
#if __has_include(<coroutine>)
#include <coroutine>
#include <future>
#endif
#else
#error "Compiler version too low to support coroutine !!!"
#endif

#if defined(DEBUG) || defined(_DEBUG)
#if defined(ENABLE_DEBUG_CORO_LEAK)

#define DEBUG_CORO_PROMISE_LEAK

#include <unordered_set>
inline std::unordered_set<void*> debug_coro_leak;

#endif
#endif

namespace coo
{
    template<typename T>
	struct await_transformer;

	template<typename T>
	struct awaitable;

	template<typename T>
	struct awaitable_promise;

	template<typename T, typename CallbackFunction>
	struct callback_awaiter;

	template<typename T>
	struct local_storage_t {
	};

	inline constexpr local_storage_t<void> local_storage;

	namespace mate
	{
		//////////////////////////////////////////////////////////////////////////
		// 用于从 A = U<T> 类型里提取 T 参数
		template<typename Testee, template<typename> typename FromTemplate>
		struct template_mate;

		// 接着定义一个偏特化，匹配 template_mate<模板名<参数>, 模板名>
		template<template<typename> typename ClassTemplate, typename TemplateParameter>
		struct template_mate<ClassTemplate<TemplateParameter>, ClassTemplate>
		{
			using template_parameter = TemplateParameter ;
		};

		// 最后，定义一个简化用法的 using 让用户的地方代码变短点
		template<typename TesteeType, template<typename> typename FromTemplate>
		using template_mate_of = typename template_mate<
									std::decay_t<TesteeType>, FromTemplate>::template_parameter;

		// 利用 通用工具 template_ma te_of 萃取 local_storage_t<T> 里的 T
		template<typename LocalStorage>
		using local_storage_value_type = template_mate_of<LocalStorage, local_storage_t>;

		// 利用 通用工具 template_mate_of 萃取 awaitable<T> 里的 T
		template<typename AwaitableType>
		using awaitable_of_type = template_mate_of<AwaitableType, awaitable>;

		template<typename T>
        struct result_with_exception
        {
            struct type {
                std::exception_ptr exception_; 
                T value_;

                bool has_value() const noexcept { return !exception_; }
                
                T& get() {
                    if (exception_) std::rethrow_exception(exception_);

                    return value_;
                }

                std::exception_ptr get_exception() const noexcept { return exception_; }
            };
        };

        // 针对 void 的特化
        template<>
        struct result_with_exception<void>
        {
            struct type {
                std::exception_ptr exception_;

                bool has_value() const noexcept { return !exception_; }

                void get() {
                    if (exception_) std::rethrow_exception(exception_);
                }

                std::exception_ptr get_exception() const noexcept { return exception_; }
            };
        };

        template<typename T>
        using result_with_exception_t = typename result_with_exception<T>::type;
	} // namespace mate

	//////////////////////////////////////////////////////////////////////////
	// 存储协程 promise 的返回值
	template<typename T>
	struct awaitable_promise_value
	{
		template<typename V>
		void return_value(V&& val) noexcept {
			value_.emplace(std::forward<V>(val));
		}

		void unhandled_exception() noexcept { exception_ = std::current_exception(); }

		T get_value(){
            if (exception_) std::rethrow_exception(exception_);
			return std::move(*value_);;
		}

        std::exception_ptr get_exception() const noexcept{ return exception_; }

        // 检查状态
        bool has_value() const noexcept { return value_.has_value(); }
        bool has_exception() const noexcept { return exception_ != nullptr; }
        bool is_ready() const noexcept { return value_.has_value() || exception_; }

        std::exception_ptr exception_ = nullptr; ; // 存储异常，确保协程健壮性
		std::optional<T> value_;
	};

	//////////////////////////////////////////////////////////////////////////
	// 存储协程 promise 的返回值 void 的特化实现
	template<>
	struct awaitable_promise_value<void>
	{
		constexpr void return_void() noexcept {ready_ = true; }

		void unhandled_exception() noexcept {exception_ = std::current_exception(); ready_ = true;}

		void get_value() const {if (exception_) std::rethrow_exception(exception_);}

        std::exception_ptr get_exception() const noexcept{ return exception_;}

        // 状态接口
        bool has_value() const noexcept { return ready_ && !exception_; }
        bool has_exception() const noexcept { return exception_ != nullptr; }
        bool is_ready() const noexcept { return ready_; }

        std::exception_ptr exception_ = nullptr;
        bool ready_ = false; // 标记协程是否真正触发了 co_return;
	};

	//////////////////////////////////////////////////////////////////////////

	template<typename T>
	struct final_awaitable
	{
		awaitable_promise<T> * holder;

		bool await_ready() noexcept {
			return !holder->continuation_;
			// 如果 continuation_ 为空，则说明此乃调用链上的最后一个 promise
			// 返回 true 让协程框架 自动调用 coroutine_handle::destory()
		}

		std::coroutine_handle<> await_suspend(std::coroutine_handle<awaitable_promise<T>> h) noexcept
		{
			//return h.promise().continuation_;// same holder->continuation_ ,but 需要各种类型转换
            if (holder->continuation_) {
                return holder->continuation_;
            }
            return std::noop_coroutine();
		}

        constexpr void await_resume() noexcept {
		}
	};

	//////////////////////////////////////////////////////////////////////////
	// 返回 T 的协程 awaitable_promise 实现.
    // 主模板：默认不是 local_storage
    template<typename T>
    struct is_local_storage : std::false_type {};

    // 特化：匹配 local_storage_t<T>
    template<typename T>
    struct is_local_storage<local_storage_t<T>> : std::true_type {};

    // 值版本
    template<typename T>
    inline constexpr bool is_local_storage_v = is_local_storage<T>::value;

	// Promise 类型实现...
	template<typename T>
	struct awaitable_promise : public awaitable_promise_value<T>
	{
		awaitable<T> get_return_object();

		auto final_suspend() noexcept {
			return final_awaitable<T>{this};
		}

		auto initial_suspend() { return std::suspend_always{}; }

		void set_local(std::any local){
			local_ = std::make_shared<std::any>(std::move(local));
		}

		template<typename V>
		struct local_storage_awaiter
		{
			const awaitable_promise* this_;

			constexpr bool await_ready() const noexcept { return true; }
			constexpr void await_suspend(std::coroutine_handle<>) const noexcept {}

			auto await_resume() const noexcept {
				if constexpr (std::is_void_v<V>){
					return *this_->local_;
				}
				else {
					return std::any_cast<const V&>(*this_->local_);
				}
			}
		};

        template<typename A>
        auto await_transform(A&& awaiter)
        {
            using decayed_type = std::decay_t<A>;

            // 只需要处理 local_storage 的情况
            if constexpr (is_local_storage_v<decayed_type>) {
                using value_type = mate::local_storage_value_type<decayed_type>;
                return local_storage_awaiter<value_type>{this};
            }
            else if constexpr (requires { await_transformer<decayed_type>::await_transform(std::forward<A>(awaiter), *this); }) {
                return await_transformer<decayed_type>::await_transform(std::forward<A>(awaiter), *this);
            }
            else if constexpr (requires { await_transformer<decayed_type>::await_transform(std::forward<A>(awaiter));} ){
                // 调用 co_await 其他写了 await_transformer 的自定义类型.
				// 例如包含了 asio_glue.hpp 后，就可以 co_await asio::awaitable<T>;
                return await_transformer<decayed_type>::await_transform(std::forward<A>(awaiter));
            }
            else if constexpr (requires { awaiter.set_local(local_); }) {
                if (local_) awaiter.set_local(local_);
                return std::forward<A>(awaiter);
            }
            else {
                // 其他情况直接转发（假设是 awaiter）
                return std::forward<A>(awaiter);
            }
        }

		std::coroutine_handle<> continuation_; //std::noop_coroutine()
		std::shared_ptr<std::any> local_;
		//void* local_ = nullptr;
	};

	//////////////////////////////////////////////////////////////////////////
    template<typename T>
    struct is_awaitable_promise : std::false_type {};

    template<typename T>
    struct is_awaitable_promise<awaitable_promise<T>> : std::true_type {};

    template<typename T>
    inline constexpr bool is_awaitable_promise_v = is_awaitable_promise<T>::value;

	// awaitable 协程包装...
	template<typename T>
	struct awaitable
	{
		using promise_type = awaitable_promise<T>;

		explicit awaitable(std::coroutine_handle<promise_type> h)
			: current_coro_handle_(h) {}

		~awaitable() {
			if (current_coro_handle_){
				if (current_coro_handle_.done()){
						current_coro_handle_.destroy();
				}
				else{
						current_coro_handle_.resume();
				}
			}
		}
		
		awaitable(awaitable&& t) noexcept
			: current_coro_handle_(t.current_coro_handle_) {
			t.current_coro_handle_ = nullptr;
		}

		awaitable& operator=(awaitable&& t) noexcept {
			if (&t != this) {
				if (current_coro_handle_) {
					current_coro_handle_.destroy();
				}
				current_coro_handle_ = t.current_coro_handle_;
				t.current_coro_handle_ = nullptr;
			}
			return *this;
		}

		awaitable(const awaitable&) = delete;
		awaitable(awaitable&) = delete;
		awaitable& operator=(const awaitable&) = delete;
		awaitable& operator=(awaitable&) = delete;

		constexpr bool await_ready() const noexcept {
			return false;
		}

		T await_resume() {
			return current_coro_handle_.promise().get_value();
		}

		template<typename PromiseType>
		auto await_suspend(std::coroutine_handle<PromiseType> continuation) noexcept {
			if constexpr (is_awaitable_promise_v<PromiseType>)
			{
				current_coro_handle_.promise().local_ = continuation.promise().local_;
			}

			current_coro_handle_.promise().continuation_ = continuation;
			return current_coro_handle_;
		}

		void set_local(std::any local) {
			assert("local has value" && !current_coro_handle_.promise().local_);
			current_coro_handle_.promise().set_local(std::move(local));
		}

		void detach(std::any local = {}){
			if (local.has_value()){
				set_local(std::move(local));
			}

            //Fire-and-forget
            struct auto_launch {
                struct promise_type {
                    std::suspend_never initial_suspend() noexcept { return {}; }
                    std::suspend_never final_suspend() noexcept { return {}; }
                    void return_void() noexcept {}
                    void unhandled_exception() { 
                        // 注意：没有回调时，这里的异常如果抛出将导致程序崩溃
                        try { std::rethrow_exception(std::current_exception()); }
                        catch (const std::exception& e) { fprintf(stderr, "Error: %s\n", e.what()); }
                    }
                    auto_launch get_return_object() noexcept { return {}; }
                };
            };

            [](awaitable<T> task) -> auto_launch {
				co_await std::move(task);
			}(std::move(*this));
		}

        bool is_done() const 
        { 
            return current_coro_handle_ && current_coro_handle_.done(); 
        }

		template<typename Function> requires std::is_invocable_v<Function, coo::mate::result_with_exception_t<T>>
		auto detach_with_callback(Function completion_handler)
		{
			return detach_with_callback<Function>(std::any{}, completion_handler);
		}

		template<typename Function> requires std::is_invocable_v<Function, coo::mate::result_with_exception_t<T>>
		auto detach_with_callback(std::any local, Function completion_callback)
		{
			auto launched_coro = [task = std::move(*this), callback = std::move(completion_callback)]() mutable -> awaitable<void> 
			{
				using result_wrapper = coo::mate::result_with_exception_t<T>;
				try {
					if constexpr (std::is_void_v<T>) {
						co_await std::move(task);
						callback(result_wrapper{nullptr});
					}
					else {
						callback(result_wrapper{co_await std::move(task)});
					}
				}
				catch(...) {
					//callback(result_wrapper{std::current_exception()});
                    std::invoke(callback, result_wrapper{std::current_exception()});
				}
			}();

			if (local.has_value()) {
				launched_coro.set_local(std::move(local));
			}

			return launched_coro;
		}

		std::coroutine_handle<promise_type> current_coro_handle_;
	};

	//////////////////////////////////////////////////////////////////////////

	template<typename T>
	awaitable<T> awaitable_promise<T>::get_return_object()
	{
		auto result = awaitable<T>{std::coroutine_handle<awaitable_promise<T>>::from_promise(*this)};
		return result;
	}

} // namespace coo

//////////////////////////////////////////////////////////////////////////

namespace coo
{
	template<typename T>
	struct callback_awaiter_base {
		T await_resume() noexcept {
			return std::move(result_);
		}

		T result_;
	};

	template<>
	struct callback_awaiter_base<void> {
		void await_resume() noexcept { }
	};

	template<typename T, typename CallbackFunction>
	struct callback_awaiter : public callback_awaiter_base<T>
	{

		callback_awaiter(const callback_awaiter&) = delete;
		callback_awaiter& operator = (const callback_awaiter&) = delete;
	public:
		explicit callback_awaiter(CallbackFunction&& callback_function)
			: callback_function_(std::forward<CallbackFunction>(callback_function)) {
		}
		
		callback_awaiter(callback_awaiter&&) = default;
		// 手动实现移动构造，绕过 atomic_flag 的移动限制
		/*
		callback_awaiter(callback_awaiter&& other) noexcept
			: callback_function_(std::move(other.callback_function_)) {
			// flag 不支持移动，所以新对象重置为 clear 状态
			// 逻辑上是安全的，因为此时 await_suspend 还没被调用
			call_flag_.clear(); 
		}
		*/
		constexpr bool await_ready() noexcept {
			return false;//调用await_suspend
		}

		// 用户调用 handle( ret_value ) 就是在这里执行的.
		void resume_coro(std::coroutine_handle<> handle) {
			//if (call_flag_.test_and_set(std::memory_order_acq_rel)) {
			if(is_done){
				// 如果执行到这里，说明 call_flag_ 运行在 callback_function_ 返回之后，所以也就
				// 是说运行在 executor 中。
				handle.resume();
			}
			else{
				is_done = true;
			}
		}

		bool await_suspend(std::coroutine_handle<> handle)
		{
			//call_flag_.clear();
			is_done = false;
			try {
				if constexpr (std::is_void_v<T>) {
					callback_function_([this, handle]() mutable {
						resume_coro(handle); // return 
					});
				}
				else {
					callback_function_([this, handle](T t) mutable {
						this->result_ = std::move(t);
						resume_coro(handle); //return 
					});
				}
			}
			catch (...) {
				is_done = true;
				//call_flag_.test_and_set(std::memory_order_relaxed);
				//std::rethrow_exception(std::current_exception())；
				throw;
			}

			if(!is_done) {
				is_done = true;
				return true;
			}

			return false;
			//return !call_flag_.test_and_set(std::memory_order_acq_rel);
		}

	private:
		CallbackFunction callback_function_;
		bool is_done = false;
		//std::atomic_flag call_flag_ = ATOMIC_FLAG_INIT;
		//std::unique_ptr<std::atomic_flag> call_flag_;
	};

} // namespace coo

//////////////////////////////////////////////////////////////////////////

struct auto_launch {
    struct promise_type {
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() { 
            // 注意：没有回调时，这里的异常如果抛出将导致程序崩溃
            // 工业级做法是：记录日志或 std::terminate()
            try { std::rethrow_exception(std::current_exception()); }
            catch (const std::exception& e) { fprintf(stderr, "Error: %s\n", e.what()); }
        }
        auto_launch get_return_object() noexcept { return {}; }
    };
};

template <typename T>
void co_launch(coo::awaitable<T> task) {
    // 立即启动一个匿名协程来消费并驱动 task
    [](coo::awaitable<T> t) -> auto_launch {
        try {
            // 这里会触发 task 的 await_suspend 并执行 resume()
            // 无论 T 是什么类型，co_await 都会正常工作
            co_await std::move(t); 
        } catch (...) {
            // 在没有回调的情况下，必须在这里捕获异常
            // 否则会流转到 promise_type::unhandled_exception
        }
    }(std::move(task));
}

template<typename T, typename callback>
auto inner_awaitable(callback&& cb) 
{
	return coo::callback_awaiter<T, std::decay_t<callback>>{std::forward<callback>(cb)};
}

template<typename T, typename callback>
auto callback_awaitable(callback&& cb) -> coo::awaitable<T>
{
    // 在协程体内，必须明确使用 std::move，因为 cb 已经是协程帧里的局部变量了
    co_return co_await coo::callback_awaiter<T, std::decay_t<callback>>{std::move(cb)};
	//return callback_wrapper<T, std::decay_t<callback>>{std::forward<callback>(cb)};
}

template<typename Awaitable, typename Local, typename CompleteFunction>
auto coro_start(Awaitable&& coro, Local&& local, CompleteFunction completer)
{
	return coro.detach_with_callback(local, completer);
}

template<typename Awaitable, typename Local>
auto coro_start(Awaitable&& coro, Local&& local)
{
	return coro.detach(local);
}

template<typename Awaitable>
auto coro_start(Awaitable&& coro)
{
	return coro.detach();
}

template<typename T>
auto wait_get(coo::awaitable<T> task, std::any local_ = {}) -> T
{
    std::promise<coo::mate::result_with_exception_t<T>> promise;
    auto future = promise.get_future();

    task.detach_with_callback(std::move(local_), [promise = std::move(promise)](coo::mate::result_with_exception_t<T> result_) mutable
    {
        // 协程完成后，将结果填充进 promise
        promise.set_value(std::move(result_));
    });

    //阻塞当前线程，直到回调完成
    coo::mate::result_with_exception_t<T> result = future.get();

	if constexpr (std::is_void_v<T>)
	{
		result.get(); 
	}
	else
	{
		return result.get(); 
	}
}

