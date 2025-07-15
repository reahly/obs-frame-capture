#pragma once

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <expected>
#include <span>
#include <cstdint>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

namespace obs_capture {
	enum class capture_error {
		WindowNotFound,
		KeepAliveInitFailed,
		NoExistingHook,
		HookInfoInitFailed,
		EventInitFailed,
		D3D11InitFailed,
		ResourceMappingFailed,
		FileOperationFailed,
		InvalidData,
		NotCapturing,
		ProcessAccessDenied,
		DllNotFound,
		InjectionFailed,
		TimeoutError
	};

	enum class capture_format : std::uint32_t {
		BGRA = 87,
		RGBA = 28,
		RGB = 2
	};

	struct frame_format {
		std::uint32_t width{ 0 };
		std::uint32_t height{ 0 };
		std::uint32_t pitch{ 0 };
		capture_format format{ capture_format::BGRA };

		[[nodiscard]] bool is_valid( ) const noexcept {
			return width > 0 && height > 0 && pitch > 0;
		}

		[[nodiscard]] std::size_t bytes_per_pixel( ) const noexcept {
			switch ( format ) {
			case capture_format::BGRA:
			case capture_format::RGBA:
				return 4;
			case capture_format::RGB:
				return 3;
			}

			return 4;
		}

		[[nodiscard]] std::size_t expected_data_size( ) const noexcept {
			return static_cast<std::size_t>( pitch ) * height;
		}
	};

	struct frame_data {
		std::vector<std::uint8_t> data;
		frame_format format;
		std::chrono::steady_clock::time_point timestamp;

		[[nodiscard]] bool empty( ) const noexcept {
			return data.empty( );
		}

		[[nodiscard]] std::size_t size( ) const noexcept {
			return data.size( );
		}

		[[nodiscard]] std::span<const std::uint8_t> bytes( ) const noexcept {
			return data;
		}

		[[nodiscard]] bool is_valid( ) const noexcept {
			return !data.empty( ) && format.is_valid( ) &&
			data.size( ) == format.expected_data_size( );
		}
	};

	struct BGRA8 {
		std::uint8_t b, g, r, a;

		constexpr BGRA8( ) noexcept = default;

		constexpr BGRA8( const std::uint8_t r, const std::uint8_t g, const std::uint8_t b, const std::uint8_t a = 255 ) noexcept
			: b( b ), g( g ), r( r ), a( a ) {
		}

		[[nodiscard]] constexpr bool operator==( const BGRA8& other ) const noexcept = default;
	};

	template <typename HandleType = HANDLE, HandleType InvalidValue = nullptr>
	class unique_handle {
	public:
		unique_handle( ) = default;

		explicit unique_handle( HandleType handle ) noexcept : handle_( handle ) {
		}

		~unique_handle( ) {
			reset( );
		}

		unique_handle( const unique_handle& ) = delete;
		unique_handle& operator=( const unique_handle& ) = delete;

		unique_handle( unique_handle&& other ) noexcept : handle_( other.release( ) ) {
		}

		unique_handle& operator=( unique_handle&& other ) noexcept {
			if ( this != &other ) {
				reset( other.release( ) );
			}
			return *this;
		}

		[[nodiscard]] HandleType get( ) const noexcept {
			return handle_;
		}

		[[nodiscard]] HandleType release( ) noexcept {
			HandleType h = handle_;
			handle_ = InvalidValue;
			return h;
		}

		void reset( HandleType handle = InvalidValue ) {
			if ( handle_ != InvalidValue && handle_ != INVALID_HANDLE_VALUE ) {
				CloseHandle( handle_ );
			}
			handle_ = handle;
		}

		[[nodiscard]] explicit operator bool( ) const noexcept {
			return handle_ != InvalidValue && handle_ != INVALID_HANDLE_VALUE;
		}

	private:
		HandleType handle_ = InvalidValue;
	};

	template <typename T>
	class com_ptr {
	public:
		com_ptr( ) = default;

		explicit com_ptr( T* ptr ) : ptr_( ptr ) {
		}

		~com_ptr( ) {
			reset( );
		}

		com_ptr( const com_ptr& ) = delete;
		com_ptr& operator=( const com_ptr& ) = delete;

		com_ptr( com_ptr&& other ) noexcept : ptr_( other.release( ) ) {
		}

		com_ptr& operator=( com_ptr&& other ) noexcept {
			if ( this != &other ) {
				reset( other.release( ) );
			}
			return *this;
		}

		[[nodiscard]] T* get( ) const noexcept {
			return ptr_;
		}

		[[nodiscard]] T** put( ) noexcept {
			reset( );
			return &ptr_;
		}

		[[nodiscard]] T* release( ) noexcept {
			T* p = ptr_;
			ptr_ = nullptr;
			return p;
		}

		void reset( T* ptr = nullptr ) {
			if ( ptr_ )
				ptr_->Release( );
			ptr_ = ptr;
		}

		[[nodiscard]] T* operator->( ) const noexcept {
			return ptr_;
		}

		[[nodiscard]] T& operator*( ) const noexcept {
			return *ptr_;
		}

		[[nodiscard]] explicit operator bool( ) const noexcept {
			return ptr_ != nullptr;
		}

	private:
		T* ptr_ = nullptr;
	};

	class ObsCapture {
	public:
		using FrameCallback = std::function<void( const frame_data& )>;
		using ErrorCallback = std::function<void( capture_error, const std::string& )>;

		explicit ObsCapture( std::string window_class_name );
		~ObsCapture( );

		ObsCapture( const ObsCapture& ) = delete;
		ObsCapture& operator=( const ObsCapture& ) = delete;
		ObsCapture( ObsCapture&& ) noexcept;
		ObsCapture& operator=( ObsCapture&& ) noexcept;

		[[nodiscard]] std::expected<void, capture_error> initialize( );
		[[nodiscard]] std::expected<frame_data, capture_error> capture_frame( );
		[[nodiscard]] std::expected<void, capture_error> stop_capture( );

		[[nodiscard]] bool is_capturing( ) const noexcept {
			return capturing_.load( );
		}

		[[nodiscard]] std::expected<frame_format, capture_error> get_frame_format( ) const;

		void set_error_callback( ErrorCallback callback ) {
			error_callback_ = std::move( callback );
		}

		[[nodiscard]] static std::expected<void, capture_error> save_as_bmp(
			const frame_data& frame_data, const std::string& filename );
		[[nodiscard]] static std::vector<BGRA8> to_bgra_pixels( const frame_data& frame_data );

	private:
		enum class CaptureType : std::uint32_t {
			Memory = 0,
			Texture = 1
		};

		struct HookInfo {
			std::uint32_t hook_ver_major;
			std::uint32_t hook_ver_minor;
			CaptureType capture_type;
			std::uint32_t window;
			std::uint32_t format;
			std::uint32_t cx, cy;
			std::uint32_t base_cx, base_cy;
			std::uint32_t pitch;
			std::uint32_t map_id;
			std::uint32_t map_size;
			bool flip;
			std::uint64_t frame_interval;
			bool use_scale;
			bool force_shmem;
			bool capture_overlay;
			std::uint8_t graphics_offsets[128];
			std::uint32_t reserved[128];
		};

		struct shared_texture_data {
			std::uint32_t tex_handle;
			std::uint64_t frame_counter;
		};

		std::string window_class_name_;
		std::atomic<bool> capturing_{ false };
		std::atomic<bool> should_stop_{ false };
		mutable std::mutex frame_mutex_;
		ErrorCallback error_callback_;

		HWND hwnd_ = nullptr;
		std::uint32_t pid_ = 0;
		std::uint32_t thread_id_ = 0;
		std::uint64_t texture_handle_ = 0;

		unique_handle<> keepalive_mutex_;
		unique_handle<> hook_restart_;
		unique_handle<> hook_stop_;
		unique_handle<> hook_init_;
		unique_handle<> hook_ready_;
		unique_handle<> hook_exit_;

		com_ptr<ID3D11Device> device_;
		com_ptr<ID3D11DeviceContext> device_context_;
		com_ptr<ID3D11Resource> resource_;
		com_ptr<IDXGISurface1> frame_surface_;

		frame_format current_format_{ };
		std::uint64_t last_frame_counter_ = 0;

		[[nodiscard]] std::expected<void, capture_error> find_window( );
		[[nodiscard]] std::expected<void, capture_error> init_keepalive( );
		[[nodiscard]] std::expected<void, capture_error> attempt_existing_hook( );
		[[nodiscard]] std::expected<void, capture_error> init_hook_info( );
		[[nodiscard]] std::expected<void, capture_error> init_events( );
		[[nodiscard]] std::expected<void, capture_error> init_d3d11( );
		[[nodiscard]] std::expected<void, capture_error> inject_graphics_hook( );
		[[nodiscard]] std::expected<void, capture_error> wait_for_hook_initialization( );
		[[nodiscard]] std::expected<void, capture_error> setup_direct_capture( );

		[[nodiscard]] std::expected<void, capture_error> inject_dll_into_process(
			std::uint32_t pid, const std::string& dll_path ) const;
		[[nodiscard]] static std::expected<void, capture_error> inject_library_direct(
			HANDLE process, const std::wstring& dll_path );
		[[nodiscard]] static std::expected<void, capture_error> inject_library_safe(
			std::uint32_t thread_id, const std::wstring& dll_path );

		[[nodiscard]] bool is_hook_injected( ) const;
		[[nodiscard]] std::string get_hook_dll_path( ) const;
		[[nodiscard]] std::expected<void, capture_error> wait_for_hook_resources( );

		void cleanup( );
		[[nodiscard]] std::expected<frame_data, capture_error> get_frame_data( );
		[[nodiscard]] std::expected<void, capture_error> map_resource(
			DXGI_MAPPED_RECT& mapped_rect, frame_format& format );

		[[nodiscard]] static unique_handle<> open_event( const std::string& name );
		[[nodiscard]] static unique_handle<> create_mutex( const std::string& name );

		void report_error( capture_error error, const std::string& message ) const;
		static void log_debug( const std::string& message );

		static constexpr auto EVENT_CAPTURE_RESTART = "CaptureHook_Restart";
		static constexpr auto EVENT_CAPTURE_STOP = "CaptureHook_Stop";
		static constexpr auto EVENT_HOOK_READY = "CaptureHook_HookReady";
		static constexpr auto EVENT_HOOK_EXIT = "CaptureHook_Exit";
		static constexpr auto EVENT_HOOK_INIT = "CaptureHook_Initialize";
		static constexpr auto WINDOW_HOOK_KEEPALIVE = "CaptureHook_KeepAlive";
		static constexpr auto SHMEM_HOOK_INFO = "CaptureHook_HookInfo";
		static constexpr auto SHMEM_TEXTURE = "CaptureHook_Texture";
	};

	[[nodiscard]] std::string to_string( capture_error error );
	[[nodiscard]] std::string get_windows_error_string( DWORD error_code );

}
