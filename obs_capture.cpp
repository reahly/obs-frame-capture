#include "obs_capture.hh"
#include <psapi.h>
#include <iostream>
#include <fstream>
#include <utility>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "d3d11.lib")wwwww
#pragma comment(lib, "dxgi.lib")

namespace obs_capture {
	std::string to_string( const capture_error error ) {
		switch ( error ) {
		case capture_error::WindowNotFound:
			return "Window not found";
		case capture_error::KeepAliveInitFailed:
			return "Keep-alive initialization failed";
		case capture_error::NoExistingHook:
			return "No existing hook found";
		case capture_error::HookInfoInitFailed:
			return "Hook info initialization failed";
		case capture_error::EventInitFailed:
			return "Event initialization failed";
		case capture_error::D3D11InitFailed:
			return "D3D11 initialization failed";
		case capture_error::ResourceMappingFailed:
			return "Resource mapping failed";
		case capture_error::FileOperationFailed:
			return "File operation failed";
		case capture_error::InvalidData:
			return "Invalid data";
		case capture_error::NotCapturing:
			return "Not currently capturing";
		case capture_error::ProcessAccessDenied:
			return "Process access denied";
		case capture_error::DllNotFound:
			return "Hook DLL not found";
		case capture_error::InjectionFailed:
			return "DLL injection failed";
		case capture_error::TimeoutError:
			return "Operation timed out";
		}
		return "Unknown error";
	}

	std::string get_windows_error_string( const DWORD error_code ) {
		char* buffer = nullptr;
		const DWORD size = FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			error_code,
			MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
			reinterpret_cast<LPSTR>( &buffer ),
			0,
			nullptr );

		if ( size == 0 || !buffer ) {
			return std::format( "Windows error code: {}", error_code );
		}

		std::string result( buffer, size );
		LocalFree( buffer );

		result.erase( result.find_last_not_of( "\r\n" ) + 1 );
		return result;
	}

	ObsCapture::ObsCapture( std::string window_class_name )
		: window_class_name_( std::move( window_class_name ) ) {
	}

	ObsCapture::~ObsCapture( ) {
		cleanup( );
	}

	ObsCapture::ObsCapture( ObsCapture&& other ) noexcept
		: window_class_name_( std::move( other.window_class_name_ ) )
		, capturing_( other.capturing_.load( ) )
		, should_stop_( other.should_stop_.load( ) )
		, error_callback_( std::move( other.error_callback_ ) )
		, hwnd_( other.hwnd_ )
		, pid_( other.pid_ )
		, thread_id_( other.thread_id_ )
		, texture_handle_( other.texture_handle_ )
		, keepalive_mutex_( std::move( other.keepalive_mutex_ ) )
		, hook_restart_( std::move( other.hook_restart_ ) )
		, hook_stop_( std::move( other.hook_stop_ ) )
		, hook_init_( std::move( other.hook_init_ ) )
		, hook_ready_( std::move( other.hook_ready_ ) )
		, hook_exit_( std::move( other.hook_exit_ ) )
		, device_( std::move( other.device_ ) )
		, device_context_( std::move( other.device_context_ ) )
		, resource_( std::move( other.resource_ ) )
		, frame_surface_( std::move( other.frame_surface_ ) )
		, current_format_( other.current_format_ )
		, last_frame_counter_( other.last_frame_counter_ ) {
		other.hwnd_ = nullptr;
		other.pid_ = 0;
		other.thread_id_ = 0;
		other.texture_handle_ = 0;
		other.current_format_ = { };
		other.last_frame_counter_ = 0;
	}

	ObsCapture& ObsCapture::operator=( ObsCapture&& other ) noexcept {
		if ( this != &other ) {
			cleanup( );

			window_class_name_ = std::move( other.window_class_name_ );
			capturing_.store( other.capturing_.load( ) );
			should_stop_.store( other.should_stop_.load( ) );
			error_callback_ = std::move( other.error_callback_ );
			hwnd_ = other.hwnd_;
			pid_ = other.pid_;
			thread_id_ = other.thread_id_;
			texture_handle_ = other.texture_handle_;
			keepalive_mutex_ = std::move( other.keepalive_mutex_ );
			hook_restart_ = std::move( other.hook_restart_ );
			hook_stop_ = std::move( other.hook_stop_ );
			hook_init_ = std::move( other.hook_init_ );
			hook_ready_ = std::move( other.hook_ready_ );
			hook_exit_ = std::move( other.hook_exit_ );
			device_ = std::move( other.device_ );
			device_context_ = std::move( other.device_context_ );
			resource_ = std::move( other.resource_ );
			frame_surface_ = std::move( other.frame_surface_ );
			current_format_ = other.current_format_;
			last_frame_counter_ = other.last_frame_counter_;

			other.hwnd_ = nullptr;
			other.pid_ = 0;
			other.thread_id_ = 0;
			other.texture_handle_ = 0;
			other.current_format_ = { };
			other.last_frame_counter_ = 0;
		}
		return *this;
	}

	std::expected<void, capture_error> ObsCapture::initialize( ) {
		log_debug( "Starting initialization" );

		if ( auto result = find_window( ); !result ) {
			return std::unexpected( result.error( ) );
		}

		if ( const auto result = init_keepalive( ); !result ) {
			return std::unexpected( result.error( ) );
		}

		if ( const auto hook_result = attempt_existing_hook( ); hook_result ) {
			log_debug( "Found existing hook, attempting to use it" );
			if ( const auto info_result = init_hook_info( ); info_result ) {
				if ( const auto events_result = init_events( ); events_result ) {
					if ( hook_init_ ) {
						SetEvent( hook_init_.get( ) );
					}
					if ( const auto d3d_result = init_d3d11( ); d3d_result ) {
						capturing_.store( true );
						log_debug( "Successfully initialized with existing hook" );
						return { };
					}
				}
			}
		}

		if ( is_hook_injected( ) ) {
			log_debug( "Hook already injected, setting up direct capture" );
			if ( const auto setup_result = setup_direct_capture( ); setup_result ) {
				capturing_.store( true );
				return { };
			}
		}

		log_debug( "Injecting new graphics hook" );
		if ( auto inject_result = inject_graphics_hook( ); !inject_result ) {
			return std::unexpected( inject_result.error( ) );
		}

		if ( auto setup_result = setup_direct_capture( ); !setup_result ) {
			return std::unexpected( setup_result.error( ) );
		}

		capturing_.store( true );
		log_debug( "Initialization completed successfully" );
		return { };
	}

	std::expected<frame_data, capture_error> ObsCapture::capture_frame( ) {
		if ( !capturing_.load( ) ) {
			return std::unexpected( capture_error::NotCapturing );
		}

		if ( hook_restart_ && WaitForSingleObject( hook_restart_.get( ), 0 ) == WAIT_OBJECT_0 ) {
			log_debug( "Hook restart requested, reinitializing" );
			if ( auto result = initialize( ); !result ) {
				return std::unexpected( result.error( ) );
			}
		}

		std::lock_guard<std::mutex> lock( frame_mutex_ );
		return get_frame_data( );
	}

	std::expected<void, capture_error> ObsCapture::stop_capture( ) {
		log_debug( "Stopping capture" );

		should_stop_.store( true );
		capturing_.store( false );

		if ( hook_stop_ ) {
			SetEvent( hook_stop_.get( ) );
		}

		cleanup( );
		return { };
	}

	std::expected<frame_format, capture_error> ObsCapture::get_frame_format( ) const {
		if ( !capturing_.load( ) ) {
			return std::unexpected( capture_error::NotCapturing );
		}
		return current_format_;
	}

	std::expected<void, capture_error> ObsCapture::save_as_bmp(
		const frame_data& frame_data, const std::string& filename ) {
		if ( !frame_data.is_valid( ) ) {
			return std::unexpected( capture_error::InvalidData );
		}

		const auto& data = frame_data.bytes( );
		const auto& format = frame_data.format;

#pragma pack(push, 1)
		struct BMPFileHeader {
			std::uint16_t bfType = 0x4D42;
			std::uint32_t bfSize;
			std::uint16_t bfReserved1 = 0;
			std::uint16_t bfReserved2 = 0;
			std::uint32_t bfOffBits = 54;
		};

		struct BMPInfoHeader {
			std::uint32_t biSize = 40;
			std::int32_t biWidth;
			std::int32_t biHeight;
			std::uint16_t biPlanes = 1;
			std::uint16_t biBitCount = 32;
			std::uint32_t biCompression = 0;
			std::uint32_t biSizeImage;
			std::int32_t biXPelsPerMeter = 0;
			std::int32_t biYPelsPerMeter = 0;
			std::uint32_t biClrUsed = 0;
			std::uint32_t biClrImportant = 0;
		};
#pragma pack(pop)

		const std::size_t pixels_per_row = format.pitch / format.bytes_per_pixel( );

		BMPFileHeader fileHeader;
		BMPInfoHeader infoHeader;

		const std::uint32_t imageSize = static_cast<std::uint32_t>( data.size( ) );

		fileHeader.bfSize = sizeof( BMPFileHeader ) + sizeof( BMPInfoHeader ) + imageSize;
		infoHeader.biWidth = static_cast<std::int32_t>( pixels_per_row );
		infoHeader.biHeight = -static_cast<std::int32_t>( format.height ); 
		infoHeader.biSizeImage = imageSize;

		std::ofstream file( filename, std::ios::binary );
		if ( !file ) {
			return std::unexpected( capture_error::FileOperationFailed );
		}

		file.write( reinterpret_cast<const char*>( &fileHeader ), sizeof( BMPFileHeader ) );
		file.write( reinterpret_cast<const char*>( &infoHeader ), sizeof( BMPInfoHeader ) );

		for ( std::uint32_t row = 0; row < format.height; ++row ) {
			const auto* row_data = data.data( ) + row * format.pitch;
			file.write( reinterpret_cast<const char*>( row_data ), format.pitch );
		}

		if ( !file.good( ) ) {
			return std::unexpected( capture_error::FileOperationFailed );
		}

		return { };
	}

	std::vector<BGRA8> ObsCapture::to_bgra_pixels( const frame_data& frame_data ) {
		const auto& data = frame_data.data;

		const std::size_t pixel_count = data.size( ) / sizeof( BGRA8 );
		std::vector<BGRA8> pixels;
		pixels.reserve( pixel_count );

		const auto* pixel_data = reinterpret_cast<const BGRA8*>( data.data( ) );
		pixels.assign( pixel_data, pixel_data + pixel_count );

		return pixels;
	}

	std::expected<void, capture_error> ObsCapture::find_window( ) {
		hwnd_ = FindWindowA( window_class_name_.c_str( ), nullptr );
		if ( !hwnd_ ) {
			const auto error_msg = std::format( "Window not found: {}", window_class_name_ );
			report_error( capture_error::WindowNotFound, error_msg );
			return std::unexpected( capture_error::WindowNotFound );
		}

		DWORD temp_pid;
		thread_id_ = GetWindowThreadProcessId( hwnd_, &temp_pid );
		pid_ = temp_pid;

		log_debug( std::format( "Found window - PID: {}, Thread ID: {}", pid_, thread_id_ ) );
		return { };
	}

	std::expected<void, capture_error> ObsCapture::init_keepalive( ) {
		const std::string name = std::format( "{}{}", WINDOW_HOOK_KEEPALIVE, pid_ );
		keepalive_mutex_ = create_mutex( name );

		if ( !keepalive_mutex_ ) {
			const auto error_msg = std::format( "Failed to create keepalive mutex: {} ({})",
												name,
												get_windows_error_string( GetLastError( ) ) );
			report_error( capture_error::KeepAliveInitFailed, error_msg );
			return std::unexpected( capture_error::KeepAliveInitFailed );
		}

		return { };
	}

	std::expected<void, capture_error> ObsCapture::attempt_existing_hook( ) {
		const std::string name = std::format( "{}{}", EVENT_CAPTURE_RESTART, pid_ );
		const auto event = open_event( name );

		if ( event ) {
			SetEvent( event.get( ) );
			return { };
		}

		return std::unexpected( capture_error::NoExistingHook );
	}

	std::expected<void, capture_error> ObsCapture::init_hook_info( ) {
		const std::string name = std::format( "{}{}", SHMEM_HOOK_INFO, pid_ );
		const HANDLE mapping = OpenFileMappingA( FILE_MAP_ALL_ACCESS, FALSE, name.c_str( ) );

		if ( !mapping ) {
			const auto error_msg = std::format( "Failed to open hook info mapping: {} ({})",
												name,
												get_windows_error_string( GetLastError( ) ) );
			report_error( capture_error::HookInfoInitFailed, error_msg );
			return std::unexpected( capture_error::HookInfoInitFailed );
		}

		const auto hook_info = static_cast<HookInfo*>( MapViewOfFile( mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof( HookInfo ) ) );

		if ( !hook_info ) {
			CloseHandle( mapping );
			report_error( capture_error::HookInfoInitFailed, "Failed to map hook info view" );
			return std::unexpected( capture_error::HookInfoInitFailed );
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(500));

		current_format_.width = hook_info->cx;
		current_format_.height = hook_info->cy;
		current_format_.pitch = hook_info->pitch;
		current_format_.format = static_cast<capture_format>( hook_info->format );

		log_debug( std::format( "Hook info - Size: {}x{}, Pitch: {}, Format: {}",
								current_format_.width,
								current_format_.height,
								current_format_.pitch,
								static_cast<uint32_t>( current_format_.format ) ) );

		const std::string texture_name = std::format( "{}_{}_{}",
													SHMEM_TEXTURE,
													hook_info->window,
													hook_info->map_id );

		const HANDLE texture_mapping = OpenFileMappingA( FILE_MAP_ALL_ACCESS, FALSE, texture_name.c_str( ) );

		if ( !texture_mapping ) {
			UnmapViewOfFile( hook_info );
			CloseHandle( mapping );
			const auto error_msg = std::format( "Failed to open texture mapping: {} ({})",
												texture_name,
												get_windows_error_string( GetLastError( ) ) );
			report_error( capture_error::HookInfoInitFailed, error_msg );
			return std::unexpected( capture_error::HookInfoInitFailed );
		}

		const auto texture_data = static_cast<shared_texture_data*>(
			MapViewOfFile( texture_mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof( shared_texture_data ) ) );

		if ( !texture_data ) {
			UnmapViewOfFile( hook_info );
			CloseHandle( mapping );
			CloseHandle( texture_mapping );
			report_error( capture_error::HookInfoInitFailed, "Failed to map texture data view" );
			return std::unexpected( capture_error::HookInfoInitFailed );
		}

		texture_handle_ = texture_data->tex_handle;
		last_frame_counter_ = texture_data->frame_counter;

		UnmapViewOfFile( texture_data );
		CloseHandle( texture_mapping );
		UnmapViewOfFile( hook_info );
		CloseHandle( mapping );

		return { };
	}

	std::expected<void, capture_error> ObsCapture::init_events( ) {
		auto open_required_event = [this]( const char* event_name, unique_handle<>& handle ) -> bool{
			const std::string name = std::format( "{}{}", event_name, pid_ );
			handle = open_event( name );
			if ( !handle ) {
				const auto error_msg = std::format( "Failed to open event: {} ({})",
													name,
													get_windows_error_string( GetLastError( ) ) );
				report_error( capture_error::EventInitFailed, error_msg );
				return false;
			}
			return true;
		};

		if ( !open_required_event( EVENT_CAPTURE_RESTART, hook_restart_ ) ||
			!open_required_event( EVENT_CAPTURE_STOP, hook_stop_ ) ||
			!open_required_event( EVENT_HOOK_INIT, hook_init_ ) ||
			!open_required_event( EVENT_HOOK_READY, hook_ready_ ) ||
			!open_required_event( EVENT_HOOK_EXIT, hook_exit_ ) ) {
			return std::unexpected( capture_error::EventInitFailed );
		}

		return { };
	}

	std::expected<void, capture_error> ObsCapture::init_d3d11( ) {
		const HRESULT hr = D3D11CreateDevice(
			nullptr,
			D3D_DRIVER_TYPE_HARDWARE,
			nullptr,
			0,
			nullptr,
			0,
			D3D11_SDK_VERSION,
			device_.put( ),
			nullptr,
			device_context_.put( )
		);

		if ( FAILED( hr ) ) {
			const auto error_msg = std::format( "Failed to create D3D11 device: 0x{:x}", hr );
			report_error( capture_error::D3D11InitFailed, error_msg );
			return std::unexpected( capture_error::D3D11InitFailed );
		}

		const HRESULT resource_hr = device_->OpenSharedResource(
			reinterpret_cast<HANDLE>( texture_handle_ ),
			__uuidof(ID3D11Resource),
			reinterpret_cast<void**>( resource_.put( ) )
		);

		if ( FAILED( resource_hr ) ) {
			const auto error_msg = std::format( "Failed to open shared resource: 0x{:x}", resource_hr );
			report_error( capture_error::D3D11InitFailed, error_msg );
			return std::unexpected( capture_error::D3D11InitFailed );
		}

		log_debug( "D3D11 initialization completed successfully" );
		return { };
	}

	std::expected<void, capture_error> ObsCapture::inject_graphics_hook( ) {
		if ( is_hook_injected( ) ) {
			log_debug( "Hook already injected" );
			return { };
		}

		const std::string dll_path = get_hook_dll_path( );
		if ( dll_path.empty( ) ) {
			report_error( capture_error::DllNotFound, "Could not determine hook DLL path" );
			return std::unexpected( capture_error::DllNotFound );
		}

		log_debug( std::format( "Injecting DLL: {}", dll_path ) );

		if ( auto inject_result = inject_dll_into_process( pid_, dll_path ); !inject_result ) {
			return std::unexpected( inject_result.error( ) );
		}

		if ( auto wait_result = wait_for_hook_initialization( ); !wait_result ) {
			return std::unexpected( wait_result.error( ) );
		}

		return { };
	}

	std::expected<void, capture_error> ObsCapture::inject_dll_into_process(
		const std::uint32_t pid, const std::string& dll_path ) const {
		const HANDLE process = OpenProcess(
			PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
			FALSE,
			pid
		);

		if ( !process ) {
			const auto error_msg = std::format( "Failed to open process {}: {}",
												pid,
												get_windows_error_string( GetLastError( ) ) );
			report_error( capture_error::ProcessAccessDenied, error_msg );
			return std::unexpected( capture_error::ProcessAccessDenied );
		}

		const std::wstring wide_dll_path( dll_path.begin( ), dll_path.end( ) );

		if ( const auto safe_result = inject_library_safe( thread_id_, wide_dll_path ); safe_result ) {
			CloseHandle( process );
			log_debug( "Safe injection successful" );
			return { };
		}

		if ( const auto direct_result = inject_library_direct( process, wide_dll_path ); direct_result ) {
			CloseHandle( process );
			log_debug( "Direct injection successful" );
			return { };
		}

		CloseHandle( process );
		report_error( capture_error::InjectionFailed, "Both safe and direct injection methods failed" );
		return std::unexpected( capture_error::InjectionFailed );
	}

	std::expected<void, capture_error> ObsCapture::inject_library_direct(
		const HANDLE process, const std::wstring& dll_path ) {
		const size_t size = ( dll_path.length( ) + 1 ) * sizeof( wchar_t );

		void* remote_mem = VirtualAllocEx( process,
											nullptr,
											size,
											MEM_RESERVE | MEM_COMMIT,
											PAGE_READWRITE );
		if ( !remote_mem ) {
			return std::unexpected( capture_error::InjectionFailed );
		}

		auto cleanup_mem = [process, remote_mem]( ){
			VirtualFreeEx( process, remote_mem, 0, MEM_RELEASE );
		};

		size_t written_size = 0;
		if ( !WriteProcessMemory( process, remote_mem, dll_path.c_str( ), size, &written_size ) ) {
			cleanup_mem( );
			return std::unexpected( capture_error::InjectionFailed );
		}

		const HMODULE kernel32 = GetModuleHandleW( L"kernel32.dll" );
		if ( !kernel32 ) {
			cleanup_mem( );
			return std::unexpected( capture_error::InjectionFailed );
		}

		const FARPROC load_library_addr = GetProcAddress( kernel32, "LoadLibraryW" );
		if ( !load_library_addr ) {
			cleanup_mem( );
			return std::unexpected( capture_error::InjectionFailed );
		}

		DWORD thread_id;
		const HANDLE thread = CreateRemoteThread(
			process,
			nullptr,
			0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>( load_library_addr ),
			remote_mem,
			0,
			&thread_id
		);

		if ( !thread ) {
			cleanup_mem( );
			return std::unexpected( capture_error::InjectionFailed );
		}

		const DWORD wait_result = WaitForSingleObject( thread, 5000 );
		DWORD exit_code = 0;
		GetExitCodeThread( thread, &exit_code );
		CloseHandle( thread );
		cleanup_mem( );

		if ( wait_result == WAIT_OBJECT_0 && exit_code != 0 ) {
			return { };
		}

		return std::unexpected( capture_error::InjectionFailed );
	}

	std::expected<void, capture_error> ObsCapture::inject_library_safe(
		const std::uint32_t thread_id, const std::wstring& dll_path ) {
		const HMODULE lib = LoadLibraryW( dll_path.c_str( ) );
		if ( !lib ) {
			return std::unexpected( capture_error::DllNotFound );
		}

		auto cleanup_lib = [lib]( ){
			FreeLibrary( lib );
		};

		HOOKPROC proc;
#ifdef _WIN64
		proc = reinterpret_cast<HOOKPROC>( GetProcAddress( lib, "dummy_debug_proc" ) );
#else
        proc = reinterpret_cast<HOOKPROC>( GetProcAddress( lib, "_dummy_debug_proc@12" ) );
#endif

		if ( !proc ) {
			cleanup_lib( );
			return std::unexpected( capture_error::DllNotFound );
		}

		const HHOOK hook = SetWindowsHookExW( WH_GETMESSAGE, proc, lib, thread_id );
		if ( !hook ) {
			cleanup_lib( );
			return std::unexpected( capture_error::InjectionFailed );
		}

		for ( int i = 0; i < 50; i++ ) {
			Sleep( 100 );
			PostThreadMessageW( thread_id, WM_USER + 432, 0, reinterpret_cast<LPARAM>( hook ) );
		}

		UnhookWindowsHookEx( hook );
		return { };
	}

	bool ObsCapture::is_hook_injected( ) const {
		const HANDLE process = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_ );
		if ( !process ) {
			return false;
		}

		auto cleanup_process = [process]( ){
			CloseHandle( process );
		};

		HMODULE modules[1024];
		DWORD needed;
		if ( !K32EnumProcessModules( process, modules, sizeof( modules ), &needed ) ) {
			cleanup_process( );
			return false;
		}

		const DWORD module_count = needed / sizeof( HMODULE );
		for ( DWORD i = 0; i < module_count; ++i ) {
			char module_name[MAX_PATH];
			if ( K32GetModuleBaseNameA( process, modules[i], module_name, sizeof( module_name ) ) ) {
				if ( strstr( module_name, "graphics-hook" ) != nullptr ) {
					cleanup_process( );
					return true;
				}
			}
		}

		cleanup_process( );
		return false;
	}

	std::string ObsCapture::get_hook_dll_path( ) const {
		std::string dll_name = "graphics-hook64.dll";

		const HANDLE process = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid_ );
		if ( process ) {
			USHORT process_machine = 0;
			USHORT native_machine = 0;

			if ( IsWow64Process2( process, &process_machine, &native_machine ) ) {
				switch ( process_machine ) {
				case IMAGE_FILE_MACHINE_AMD64:
				case IMAGE_FILE_MACHINE_ARM64:
					dll_name = "graphics-hook64.dll";
					break;
				case IMAGE_FILE_MACHINE_I386:
					dll_name = "graphics-hook32.dll";
					break;
				default:
					break;
				}
			}
			CloseHandle( process );
		}
		return dll_name;
	}

	std::expected<void, capture_error> ObsCapture::wait_for_hook_initialization( ) {
		const auto start_time = std::chrono::steady_clock::now( );

		while ( std::chrono::steady_clock::now( ) - start_time < std::chrono::milliseconds( 5000 ) ) {
			const std::string hook_info_name = std::format( "{}{}", SHMEM_HOOK_INFO, pid_ );
			const HANDLE mapping = OpenFileMappingA( FILE_MAP_READ, FALSE, hook_info_name.c_str( ) );

			if ( mapping ) {
				CloseHandle( mapping );
				log_debug( "Hook initialization completed" );
				return { };
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );
		}

		report_error( capture_error::TimeoutError, "Hook initialization timed out" );
		return std::unexpected( capture_error::TimeoutError );
	}

	std::expected<void, capture_error> ObsCapture::setup_direct_capture( ) {
		log_debug( "Setting up direct capture" );

		if ( auto wait_result = wait_for_hook_resources( ); !wait_result ) {
			return std::unexpected( wait_result.error( ) );
		}

		if ( auto result = init_hook_info( ); !result ) {
			return std::unexpected( result.error( ) );
		}

		if ( auto result = init_d3d11( ); !result ) {
			return std::unexpected( result.error( ) );
		}

		return { };
	}

	std::expected<void, capture_error> ObsCapture::wait_for_hook_resources( ) {
		const auto start_time = std::chrono::steady_clock::now( );

		while ( std::chrono::steady_clock::now( ) - start_time < std::chrono::milliseconds( 5000 ) ) {
			const std::string hook_info_name = std::format( "{}{}", SHMEM_HOOK_INFO, pid_ );
			const HANDLE info_mapping = OpenFileMappingA( FILE_MAP_READ, FALSE, hook_info_name.c_str( ) );

			if ( info_mapping ) {
				const auto hook_info = static_cast<HookInfo*>(
					MapViewOfFile( info_mapping, FILE_MAP_READ, 0, 0, sizeof( HookInfo ) ) );

				if ( hook_info ) {
					const std::string texture_name = std::format( "{}_{}_{}",
																SHMEM_TEXTURE,
																hook_info->window,
																hook_info->map_id );

					UnmapViewOfFile( hook_info );
					CloseHandle( info_mapping );

					const HANDLE texture_mapping = OpenFileMappingA( FILE_MAP_READ, FALSE, texture_name.c_str( ) );
					if ( texture_mapping ) {
						CloseHandle( texture_mapping );
						return { };
					}
				}
				else {
					CloseHandle( info_mapping );
				}
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );
		}

		report_error( capture_error::TimeoutError, "Hook resources not available within timeout" );
		return std::unexpected( capture_error::TimeoutError );
	}

	void ObsCapture::cleanup( ) {
		log_debug( "Cleaning up resources" );

		frame_surface_.reset( );
		resource_.reset( );
		device_context_.reset( );
		device_.reset( );

		keepalive_mutex_.reset( );
		hook_restart_.reset( );
		hook_stop_.reset( );
		hook_init_.reset( );
		hook_ready_.reset( );
		hook_exit_.reset( );
	}

	std::expected<frame_data, capture_error> ObsCapture::get_frame_data( ) {
		DXGI_MAPPED_RECT mapped_rect;
		frame_format format;

		if ( auto result = map_resource( mapped_rect, format ); !result ) {
			return std::unexpected( result.error( ) );
		}

		const std::size_t frame_size = static_cast<std::size_t>( mapped_rect.Pitch ) * format.height;

		frame_data frame_data;
		frame_data.format = format;
		frame_data.timestamp = std::chrono::steady_clock::now( );
		frame_data.data.resize( frame_size );

		std::memcpy( frame_data.data.data( ), mapped_rect.pBits, frame_size );

		frame_surface_->Unmap( );

		return frame_data;
	}

	std::expected<void, capture_error> ObsCapture::map_resource(
		DXGI_MAPPED_RECT& mapped_rect, frame_format& format ) {
		frame_surface_.reset( );

		com_ptr<ID3D11Texture2D> frame_texture;
		HRESULT hr = resource_->QueryInterface( __uuidof(ID3D11Texture2D),
												reinterpret_cast<void**>( frame_texture.put( ) ) );
		if ( FAILED( hr ) ) {
			const auto error_msg = std::format( "Failed to get texture from resource: 0x{:x}", hr );
			report_error( capture_error::ResourceMappingFailed, error_msg );
			return std::unexpected( capture_error::ResourceMappingFailed );
		}

		D3D11_TEXTURE2D_DESC texture_desc;
		frame_texture->GetDesc( &texture_desc );

		format.width = texture_desc.Width;
		format.height = texture_desc.Height;
		format.format = static_cast<capture_format>( texture_desc.Format );

		texture_desc.Usage = D3D11_USAGE_STAGING;
		texture_desc.BindFlags = 0;
		texture_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
		texture_desc.MiscFlags = 0;

		com_ptr<ID3D11Texture2D> readable_texture;
		hr = device_->CreateTexture2D( &texture_desc, nullptr, readable_texture.put( ) );
		if ( FAILED( hr ) ) {
			const auto error_msg = std::format( "Failed to create readable texture: 0x{:x}", hr );
			report_error( capture_error::ResourceMappingFailed, error_msg );
			return std::unexpected( capture_error::ResourceMappingFailed );
		}

		readable_texture->SetEvictionPriority( DXGI_RESOURCE_PRIORITY_MAXIMUM );

		device_context_->CopyResource( readable_texture.get( ), frame_texture.get( ) );

		hr = readable_texture->QueryInterface( __uuidof(IDXGISurface1),
												reinterpret_cast<void**>( frame_surface_.put( ) ) );
		if ( FAILED( hr ) ) {
			const auto error_msg = std::format( "Failed to get surface interface: 0x{:x}", hr );
			report_error( capture_error::ResourceMappingFailed, error_msg );
			return std::unexpected( capture_error::ResourceMappingFailed );
		}

		hr = frame_surface_->Map( &mapped_rect, DXGI_MAP_READ );
		if ( FAILED( hr ) ) {
			const auto error_msg = std::format( "Failed to map surface: 0x{:x}", hr );
			report_error( capture_error::ResourceMappingFailed, error_msg );
			frame_surface_.reset( );
			return std::unexpected( capture_error::ResourceMappingFailed );
		}

		format.pitch = mapped_rect.Pitch;
		return { };
	}

	unique_handle<> ObsCapture::open_event( const std::string& name ) {
		return unique_handle<>( OpenEventA( EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name.c_str( ) ) );
	}

	unique_handle<> ObsCapture::create_mutex( const std::string& name ) {
		return unique_handle<>( CreateMutexA( nullptr, FALSE, name.c_str( ) ) );
	}

	void ObsCapture::report_error( const capture_error error, const std::string& message ) const {
		if ( error_callback_ ) {
			error_callback_( error, message );
		}
	}

	void ObsCapture::log_debug( const std::string& message ) {
#ifdef _DEBUG
		std::cout << "[ObsCapture] " << message << std::endl;
#endif
	}
}
