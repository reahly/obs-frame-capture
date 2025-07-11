# obs-frame-capture
A modern C++ library for capturing frames from OBS's DLL. This project is inspired by [obs-rs](https://github.com/not-matthias/obs-rs).

### Example Usage
```cpp
#include "obs_capture.hh"
#include <iostream>

using namespace obs_capture;

int main( ) {
	try {
		printf( "initializing OBS capture... \n" );

		ObsCapture capture( "Class Name" );

		capture.set_error_callback( []( const capture_error error, const std::string& message ){
			printf( "error: %s | %s \n", to_string( error ).c_str( ), message.c_str( ) );
		} );

		if ( const auto result = capture.initialize( ); !result ) {
			printf( "failed to initialize: %s \n", to_string( result.error( ) ).c_str( ) );
			return 1;
		}

		if ( const auto format_result = capture.get_frame_format( ) ) {
			const auto& format = format_result.value( );

			printf( "capture initialized! \n" );
			printf( "resolution: %i %i \n", format.width, format.height );
			printf( "format: %u \n", format.format );
			printf( "pitch: %i bytes \n", format.pitch );
		}


		if ( auto frame_result = capture.capture_frame( ) ) {
			const auto& frame = frame_result.value( );

			if ( auto save_result = ObsCapture::save_as_bmp( frame, "screenshot.bmp" ) ) {
				printf( "Screenshot saved successfully! \n" );
			}

			if ( !frame.data.empty( ) ) {
				const auto pixels = ObsCapture::to_bgra_pixels( frame );
				if ( !pixels.empty( ) ) {
					const auto center_idx = pixels.size( ) / 2;
					const auto& center_pixel = pixels[center_idx];

					printf( "R:%i\nG:%i\nB:%i\n", center_pixel.r, center_pixel.g, center_pixel.b );
				}
			}
		}
		else {
			printf( "Failed capturing frame: %s \n", to_string( frame_result.error( ) ).c_str( ) );
			return 1;
		}
	}
	catch ( const std::exception& e ) {
		printf( "exception: %s \n", e.what( ) );
		return 1;
	}


	std::cin.ignore( );
	std::cin.get( );

	return 0;
}
```
